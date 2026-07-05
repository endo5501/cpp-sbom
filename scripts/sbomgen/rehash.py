"""署名サーバ側での SBOM 再ハッシュ (標準ライブラリのみ)。

構成B の運用:
  ビルドサーバが Qt/vendor 等との Relation を張った SBOM 群を生成した後、
  署名サーバが EXE/DLL に署名する。署名すると PE ファイルのバイト列が変わり
  成果物ハッシュが変わるため、生成済み SBOM のハッシュを署名済みバイナリの
  ものへ更新する。

このツールが必要とする入力は「生成済み SBOM ディレクトリ」と「署名済み
バイナリのディレクトリ」だけ。Qt SBOM・vendor SBOM・ビルドマニフェストは
不要 (署名サーバに配布しなくてよい)。

再ハッシュは相互参照の SHA1 連鎖を維持する:
  - 各ドキュメント内の成果物パッケージ (packageFileName + checksums を持つもの)
    のチェックサムを、署名済みバイナリのハッシュへ更新する。
  - 成果物ハッシュを書き換えると SBOM ファイル自体の SHA1 が変わるため、
    それを ExternalDocumentRef で参照している他ドキュメントの SHA1 を
    依存順 (参照先を先に確定) に更新する。
  - Qt/vendor などローカルに存在しないドキュメントへの参照は変更しない
    (署名対象外でファイルも変わらないため)。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .generator import dumps_spdx


def _sha1_bytes(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_docs(sbom_dir: Path) -> list[tuple[Path, dict]]:
    docs = []
    for path in sorted(sbom_dir.glob("*.spdx.json")):
        docs.append((path, json.loads(path.read_text(encoding="utf-8"))))
    return docs


def _topo_order(
    by_ns: dict[str, tuple[Path, dict]]
) -> list[tuple[Path, dict]]:
    """ローカルドキュメント間を、参照先が先に来る順序で並べる"""
    order: list[tuple[Path, dict]] = []
    visited: set[str] = set()
    visiting: set[str] = set()

    def local_deps(doc: dict) -> list[str]:
        return sorted(
            ref["spdxDocument"]
            for ref in doc.get("externalDocumentRefs", [])
            if ref["spdxDocument"] in by_ns
        )

    def visit(ns: str) -> None:
        if ns in visited:
            return
        if ns in visiting:
            raise ValueError(f"circular document reference involving {ns}")
        visiting.add(ns)
        _, doc = by_ns[ns]
        for dep_ns in local_deps(doc):
            visit(dep_ns)
        visiting.discard(ns)
        visited.add(ns)
        order.append(by_ns[ns])

    for ns in sorted(by_ns):
        visit(ns)
    return order


def rehash_sboms(
    sbom_dir: str | Path,
    artifact_dir: str | Path,
    out_dir: str | Path | None = None,
) -> dict:
    """生成済み SBOM 群を署名済みバイナリのハッシュで更新する。

    戻り値は summary (更新した成果物ファイル名・参照更新数・書き出しパス)。
    out_dir 省略時は sbom_dir を上書き (in-place)。
    """
    sbom_dir = Path(sbom_dir)
    artifact_dir = Path(artifact_dir)
    out_dir = Path(out_dir) if out_dir else sbom_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    docs = _load_docs(sbom_dir)
    by_ns = {doc["documentNamespace"]: (path, doc) for path, doc in docs}

    # 署名済みバイナリのハッシュをファイル名でキャッシュ
    signed_cache: dict[str, dict[str, str]] = {}

    def signed_hashes(filename: str) -> dict[str, str] | None:
        if filename not in signed_cache:
            bin_path = artifact_dir / filename
            if not bin_path.is_file():
                return None
            data = bin_path.read_bytes()
            signed_cache[filename] = {
                "SHA1": _sha1_bytes(data),
                "SHA256": _sha256_bytes(data),
            }
        return signed_cache[filename]

    summary = {"rehashed_artifacts": [], "updated_refs": 0, "written": [],
               "unmatched_artifacts": []}
    ns_sha1: dict[str, str] = {}  # 確定済みローカルドキュメントのファイル SHA1

    for path, doc in _topo_order(by_ns):
        # a) 成果物パッケージのチェックサムを署名済みバイナリへ更新
        for pkg in doc.get("packages", []):
            filename = pkg.get("packageFileName")
            if not filename or "checksums" not in pkg:
                continue
            new = signed_hashes(filename)
            if new is None:
                summary["unmatched_artifacts"].append(filename)
                continue
            for checksum in pkg["checksums"]:
                if checksum["algorithm"] in new:
                    checksum["checksumValue"] = new[checksum["algorithm"]]
            summary["rehashed_artifacts"].append(filename)

        # b) ローカルドキュメントへの ExternalDocumentRef SHA1 を更新
        #    (依存順に処理しているので参照先の ns_sha1 は確定済み)
        for ref in doc.get("externalDocumentRefs", []):
            target_ns = ref["spdxDocument"]
            if target_ns in ns_sha1:
                if ref["checksum"]["checksumValue"] != ns_sha1[target_ns]:
                    ref["checksum"]["checksumValue"] = ns_sha1[target_ns]
                    summary["updated_refs"] += 1

        # 書き出してこのドキュメントのファイル SHA1 を確定
        out_path = out_dir / path.name
        out_path.write_text(dumps_spdx(doc), encoding="utf-8")
        ns_sha1[doc["documentNamespace"]] = _sha1_bytes(out_path.read_bytes())
        summary["written"].append(out_path)

    return summary
