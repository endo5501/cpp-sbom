"""Qt 同梱 SBOM (タグバリュー .spdx) のパースと Qt6::<Module> の解決。

Qt は <install>/sbom/ に Qt リポジトリ単位 (qtbase, qt5compat, ...) の
SPDX 2.3 タグバリュードキュメントを同梱している。本モジュールはそれらを
インデックス化し、CMake ターゲット名 (例: "Qt6::Core") から

  - 属するドキュメント (ファイル / DocumentNamespace / ファイル SHA1)
  - モジュールパッケージの SPDXID

を解決する。照合は PackageName を主キーとし、SPDXID の命名規則
("-qt-module-") は同名衝突時の優先判定にのみ使う (命名規則は Qt の
内部実装でありバージョン間で変わり得るため)。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

_QT_TARGET_PREFIX = "Qt6::"

# "qtbase-6.11.1.spdx" -> repo "qtbase"
_REPO_FROM_STEM = re.compile(r"^(?P<repo>.+?)-\d")


@dataclass(frozen=True)
class QtModuleRef:
    """Qt モジュール 1 つ分の解決結果"""

    repo: str
    module: str
    document_file: Path
    document_namespace: str
    document_sha1: str
    package_spdx_id: str


def _sha1_of_file(path: Path) -> str:
    return hashlib.sha1(path.read_bytes()).hexdigest()


def _parse_tag_value(path: Path) -> tuple[str, list[tuple[str, str]]]:
    """タグバリュー .spdx から (DocumentNamespace, [(PackageName, SPDXID), ...]) を抽出"""
    namespace = ""
    packages: list[tuple[str, str]] = []
    pending_name: str | None = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("DocumentNamespace:"):
            namespace = line.split(":", 1)[1].strip()
        elif line.startswith("PackageName:"):
            pending_name = line.split(":", 1)[1].strip()
        elif line.startswith("SPDXID:") and pending_name is not None:
            packages.append((pending_name, line.split(":", 1)[1].strip()))
            pending_name = None
    return namespace, packages


class QtSbomIndex:
    def __init__(self, by_module: dict[str, list[QtModuleRef]]):
        self._by_module = by_module

    @classmethod
    def load(cls, sbom_dir: str | Path) -> "QtSbomIndex":
        sbom_dir = Path(sbom_dir)
        by_module: dict[str, list[QtModuleRef]] = {}
        for spdx_file in sorted(sbom_dir.glob("*.spdx")):
            # *.source.spdx は REUSE 由来のソース情報 (SPDX 2.1) — 解決対象外
            if spdx_file.name.endswith(".source.spdx"):
                continue
            m = _REPO_FROM_STEM.match(spdx_file.stem)
            repo = m.group("repo") if m else spdx_file.stem
            namespace, packages = _parse_tag_value(spdx_file)
            if not namespace:
                continue
            sha1 = _sha1_of_file(spdx_file)
            for pkg_name, spdx_id in packages:
                by_module.setdefault(pkg_name, []).append(
                    QtModuleRef(
                        repo=repo,
                        module=pkg_name,
                        document_file=spdx_file,
                        document_namespace=namespace,
                        document_sha1=sha1,
                        package_spdx_id=spdx_id,
                    )
                )
        return cls(by_module)

    def resolve(self, target: str) -> QtModuleRef | None:
        """CMake ターゲット名 (例 "Qt6::Core") をモジュールパッケージに解決する"""
        if not target.startswith(_QT_TARGET_PREFIX):
            return None
        module = target[len(_QT_TARGET_PREFIX):]
        candidates = self._by_module.get(module)
        if not candidates:
            return None
        # 同名パッケージが複数ある場合は qt-module 系 SPDXID を優先
        for ref in candidates:
            if "-qt-module-" in ref.package_spdx_id:
                return ref
        return candidates[0]
