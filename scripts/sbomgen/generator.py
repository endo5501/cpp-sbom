"""ビルドマニフェスト (CMake が出力する JSON) から SPDX 2.3 JSON を生成する。

生成物:
  - リポジトリ単位ドキュメント <repo>-<version>.spdx.json
      EXE/DLL ごとに 1 Package (チェックサム付き)。依存は
        * Qt モジュール          -> ExternalDocumentRef + DYNAMIC_LINK
        * 受領 SBOM (vendorlib)  -> ExternalDocumentRef + DYNAMIC_LINK
        * 他リポジトリの成果物   -> ExternalDocumentRef + DYNAMIC_LINK
        * 静的ライブラリ (SQLite)-> 埋め込み Package + STATIC_LINK
      記録するのは各ターゲットの直接依存のみ。
  - 製品単位ドキュメント <product>-<version>.spdx.json
      構成リポジトリ/受領 SBOM を ExternalDocumentRef で束ね DEPENDS_ON を張る。

ExternalDocumentRef の SHA1 は参照先ドキュメントファイルそのものに対して
計算する (Qt はタグバリュー .spdx、自リポジトリ/受領分は .spdx.json)。
リポジトリ間参照があるため、依存されるリポジトリから先に生成する。
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .qt_sbom import QtSbomIndex

TOOL_NAME = "cpp-sbom-generator"
TOOL_VERSION = "0.1.0"

_ARTIFACT_TYPES = {"EXECUTABLE", "SHARED_LIBRARY", "MODULE_LIBRARY"}

_ID_SANITIZE = re.compile(r"[^A-Za-z0-9.\-]+")


def _sha1(path: Path) -> str:
    return hashlib.sha1(path.read_bytes()).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sanitize_id(name: str) -> str:
    return _ID_SANITIZE.sub("-", name)


def _package_id(name: str) -> str:
    return f"SPDXRef-Package-{_sanitize_id(name)}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _ReceivedSbom:
    """受領した SPDX 2.3 JSON ドキュメント (vendorlib 等)"""

    def __init__(self, path: Path):
        self.path = path
        doc = json.loads(path.read_text(encoding="utf-8"))
        self.namespace: str = doc["documentNamespace"]
        self.sha1: str = _sha1(path)
        self.root_package_id: str = self._find_root_package(doc)
        root_name = next(
            (p["name"] for p in doc.get("packages", [])
             if p["SPDXID"] == self.root_package_id),
            path.stem,
        )
        self.doc_ref_id = f"DocumentRef-{_sanitize_id(root_name)}"

    @staticmethod
    def _find_root_package(doc: dict) -> str:
        described = doc.get("documentDescribes")
        if described:
            return described[0]
        for rel in doc.get("relationships", []):
            if (
                rel.get("relationshipType") == "DESCRIBES"
                and rel.get("spdxElementId") == "SPDXRef-DOCUMENT"
            ):
                return rel["relatedSpdxElement"]
        packages = doc.get("packages", [])
        if packages:
            return packages[0]["SPDXID"]
        raise ValueError(f"received SBOM has no packages: {doc.get('name')}")


class _DocBuilder:
    """SPDX 2.3 JSON ドキュメント 1 つ分の組み立て"""

    def __init__(self, name: str, namespace: str, creators: list[str]):
        self.name = name
        self.namespace = namespace
        self.creators = creators
        self.packages: list[dict] = []
        self._package_ids: set[str] = set()
        self.relationships: list[dict] = []
        self._relationship_keys: set[tuple] = set()
        self.external_refs: dict[str, dict] = {}
        self.extracted_licenses: dict[str, dict] = {}

    def add_extracted_license(self, definition: dict) -> None:
        self.extracted_licenses.setdefault(definition["licenseId"], definition)

    def add_package(self, package: dict) -> None:
        if package["SPDXID"] not in self._package_ids:
            self._package_ids.add(package["SPDXID"])
            self.packages.append(package)

    def add_relationship(self, element: str, rel_type: str, related: str) -> None:
        key = (element, rel_type, related)
        if key not in self._relationship_keys:
            self._relationship_keys.add(key)
            self.relationships.append(
                {
                    "spdxElementId": element,
                    "relationshipType": rel_type,
                    "relatedSpdxElement": related,
                }
            )

    def add_external_ref(self, doc_ref_id: str, namespace: str, sha1: str) -> None:
        self.external_refs.setdefault(
            doc_ref_id,
            {
                "externalDocumentId": doc_ref_id,
                "spdxDocument": namespace,
                "checksum": {"algorithm": "SHA1", "checksumValue": sha1},
            },
        )

    def to_dict(self) -> dict:
        doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self.name,
            "documentNamespace": self.namespace,
            "creationInfo": {
                "created": _now_iso(),
                "creators": self.creators,
            },
            "packages": self.packages,
            "relationships": self.relationships,
        }
        if self.external_refs:
            doc["externalDocumentRefs"] = [
                self.external_refs[k] for k in sorted(self.external_refs)
            ]
        if self.extracted_licenses:
            doc["hasExtractedLicensingInfos"] = [
                self.extracted_licenses[k] for k in sorted(self.extracted_licenses)
            ]
        return doc

    def write(self, path: Path) -> None:
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


class _Generator:
    def __init__(self, manifest: dict, out_dir: Path):
        self.manifest = manifest
        self.out_dir = out_dir
        self.supplier: str = manifest.get("supplier", "NOASSERTION")
        self.namespace_base: str = manifest["namespace_base"].rstrip("/")
        self.build_id: str = str(manifest.get("build_id", "local"))
        self.creators = [self.supplier, f"Tool: {TOOL_NAME}-{TOOL_VERSION}"]

        # 独自ライセンス定義 (LicenseRef-*) — 参照するドキュメントに埋め込む
        self.license_defs: dict[str, dict] = {}
        for lic in manifest.get("licenses", []):
            definition = {
                "licenseId": lic["id"],
                "extractedText": lic.get("text", "NOASSERTION"),
            }
            if lic.get("name"):
                definition["name"] = lic["name"]
            self.license_defs[lic["id"]] = definition

        qt_dir = manifest.get("qt_sbom_dir")
        self.qt_index = (
            QtSbomIndex.load(qt_dir)
            if qt_dir and Path(qt_dir).is_dir()
            else QtSbomIndex({})
        )

        self.targets: dict[str, dict] = {t["name"]: t for t in manifest["targets"]}
        self.received: dict[str, _ReceivedSbom] = {
            name: _ReceivedSbom(Path(info["spdx_document"]))
            for name, info in manifest.get("externals", {}).items()
        }

        # リポジトリ -> 成果物ターゲット群
        self.repo_targets: dict[str, list[dict]] = {}
        for t in manifest["targets"]:
            if t["type"] in _ARTIFACT_TYPES:
                self.repo_targets.setdefault(t["repo"], []).append(t)

        # 生成済みリポジトリドキュメントの情報 (repo -> {...})
        self.generated: dict[str, dict] = {}

    # ---- 依存解決 ------------------------------------------------------

    def _repo_of_target(self, name: str) -> str | None:
        t = self.targets.get(name)
        return t["repo"] if t else None

    def _repo_dependencies(self, repo: str) -> set[str]:
        """repo の成果物が直接リンクする他リポジトリ成果物の repo 集合"""
        deps: set[str] = set()
        for t in self.repo_targets.get(repo, []):
            for link in t.get("links", []):
                lt = self.targets.get(link)
                if lt and lt["type"] in _ARTIFACT_TYPES and lt["repo"] != repo:
                    deps.add(lt["repo"])
        return deps

    def _topo_repo_order(self) -> list[str]:
        """依存されるリポジトリが先に来る順序 (ExternalDocumentRef の SHA1 確定のため)"""
        order: list[str] = []
        visiting: set[str] = set()
        done: set[str] = set()

        def visit(repo: str) -> None:
            if repo in done:
                return
            if repo in visiting:
                raise ValueError(f"circular repository dependency involving '{repo}'")
            visiting.add(repo)
            for dep in sorted(self._repo_dependencies(repo)):
                visit(dep)
            visiting.discard(repo)
            done.add(repo)
            order.append(repo)

        for repo in sorted(self.repo_targets):
            visit(repo)
        return order

    # ---- 生成 -----------------------------------------------------------

    def _namespace(self, doc_name: str) -> str:
        seed = f"{self.namespace_base}/{doc_name}/{self.build_id}"
        return f"{self.namespace_base}/{doc_name}-{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"

    def _describe_package_dict(self, describe: dict) -> dict:
        pkg = {
            "name": describe["name"],
            "SPDXID": _package_id(describe["name"]),
            "downloadLocation": describe.get("download", "NOASSERTION"),
            "filesAnalyzed": False,
            "licenseConcluded": describe.get("license", "NOASSERTION"),
            "licenseDeclared": describe.get("license", "NOASSERTION"),
            "copyrightText": "NOASSERTION",
        }
        if describe.get("version"):
            pkg["versionInfo"] = describe["version"]
        if describe.get("supplier"):
            pkg["supplier"] = describe["supplier"]
        if describe.get("purl"):
            pkg["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE_MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": describe["purl"],
                }
            ]
        return pkg

    def _artifact_package_dict(self, target: dict) -> dict:
        file = Path(target["file"])
        return {
            "name": target["name"],
            "SPDXID": _package_id(target["name"]),
            "versionInfo": target.get("version", "NOASSERTION"),
            "supplier": self.supplier,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": target.get("license_concluded", "NOASSERTION"),
            "licenseDeclared": target.get("license_declared", "NOASSERTION"),
            "copyrightText": target.get("copyright", "NOASSERTION"),
            "packageFileName": file.name,
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": _sha1(file)},
                {"algorithm": "SHA256", "checksumValue": _sha256(file)},
            ],
        }

    def _add_link(
        self, doc: _DocBuilder, from_pkg_id: str, link: str, repo: str,
        visited_static: set[str],
    ) -> None:
        """成果物パッケージ from_pkg_id の直接依存 link 1 件をドキュメントに反映"""
        # 1) Qt モジュール
        qt_ref = self.qt_index.resolve(link)
        if qt_ref is not None:
            doc_ref = f"DocumentRef-{_sanitize_id(qt_ref.repo)}"
            doc.add_external_ref(
                doc_ref, qt_ref.document_namespace, qt_ref.document_sha1
            )
            doc.add_relationship(
                from_pkg_id, "DYNAMIC_LINK", f"{doc_ref}:{qt_ref.package_spdx_id}"
            )
            return

        # 2) 受領 SBOM 付きバイナリ (vendorlib)
        received = self.received.get(link)
        if received is not None:
            doc.add_external_ref(received.doc_ref_id, received.namespace, received.sha1)
            doc.add_relationship(
                from_pkg_id,
                "DYNAMIC_LINK",
                f"{received.doc_ref_id}:{received.root_package_id}",
            )
            return

        # 3) マニフェスト内の他ターゲット
        lt = self.targets.get(link)
        if lt is None:
            return  # システムライブラリ等 — SBOM 対象外

        if lt["type"] == "STATIC_LIBRARY":
            # 静的ライブラリは成果物に埋め込まれる: describe があれば
            # Package として埋め込み STATIC_LINK。その先の直接依存も
            # 成果物側に畳み込む (静的リンクで実体が取り込まれるため)。
            if link in visited_static:
                return
            visited_static.add(link)
            describe = lt.get("describe")
            if describe:
                pkg = self._describe_package_dict(describe)
                doc.add_package(pkg)
                doc.add_relationship(from_pkg_id, "STATIC_LINK", pkg["SPDXID"])
            for sub_link in lt.get("links", []):
                self._add_link(doc, from_pkg_id, sub_link, repo, visited_static)
            return

        if lt["type"] in _ARTIFACT_TYPES:
            if lt["repo"] == repo:
                # 同一リポジトリ内の成果物間依存
                doc.add_relationship(
                    from_pkg_id, "DYNAMIC_LINK", _package_id(lt["name"])
                )
            else:
                info = self.generated[lt["repo"]]
                doc_ref = f"DocumentRef-{_sanitize_id(lt['repo'])}"
                doc.add_external_ref(doc_ref, info["namespace"], info["sha1"])
                doc.add_relationship(
                    from_pkg_id,
                    "DYNAMIC_LINK",
                    f"{doc_ref}:{_package_id(lt['name'])}",
                )

    def _embed_referenced_license_defs(self, doc: _DocBuilder) -> None:
        """ドキュメント内のパッケージが参照する LicenseRef-* の定義を埋め込む
        (SPDX 2.3 では LicenseRef を使うドキュメント内に定義が必要)"""
        if not self.license_defs:
            return
        for pkg in doc.packages:
            for field in ("licenseConcluded", "licenseDeclared"):
                expr = pkg.get(field, "")
                for ref in re.findall(r"LicenseRef-[A-Za-z0-9.\-]+", expr):
                    definition = self.license_defs.get(ref)
                    if definition:
                        doc.add_extracted_license(definition)

    def _generate_repo_doc(self, repo: str) -> Path:
        targets = self.repo_targets[repo]
        version = targets[0].get("version", "0")
        doc_name = f"{repo}-{version}"
        doc = _DocBuilder(doc_name, self._namespace(doc_name), self.creators)

        for target in targets:
            pkg = self._artifact_package_dict(target)
            doc.add_package(pkg)
            doc.add_relationship("SPDXRef-DOCUMENT", "DESCRIBES", pkg["SPDXID"])
            for link in target.get("links", []):
                self._add_link(doc, pkg["SPDXID"], link, repo, visited_static=set())

        self._embed_referenced_license_defs(doc)
        out_file = self.out_dir / f"{doc_name}.spdx.json"
        doc.write(out_file)
        self.generated[repo] = {
            "file": out_file,
            "namespace": doc.namespace,
            "sha1": _sha1(out_file),
            "doc_name": doc_name,
        }
        return out_file

    # ---- 製品ドキュメント ------------------------------------------------

    def _product_closure(self, root_targets: list[str]) -> tuple[list[dict], list[str]]:
        """ルートから直接依存を辿った推移的閉包
        -> (成果物ターゲット列, 受領 SBOM リンク名列)"""
        artifacts: list[dict] = []
        received: list[str] = []
        seen: set[str] = set()
        queue = list(root_targets)
        while queue:
            name = queue.pop(0)
            if name in seen:
                continue
            seen.add(name)
            if name in self.received:
                received.append(name)
                continue
            t = self.targets.get(name)
            if t is None:
                continue
            if t["type"] in _ARTIFACT_TYPES:
                artifacts.append(t)
            queue.extend(t.get("links", []))
        return artifacts, received

    def _generate_product_doc(self, product: dict) -> Path:
        name = product["name"]
        version = product.get("version", "0")
        doc_name = f"{name}-{version}"
        doc = _DocBuilder(doc_name, self._namespace(doc_name), self.creators)

        product_pkg_id = _package_id(name)
        doc.add_package(
            {
                "name": name,
                "SPDXID": product_pkg_id,
                "versionInfo": version,
                "supplier": self.supplier,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        doc.add_relationship("SPDXRef-DOCUMENT", "DESCRIBES", product_pkg_id)

        artifacts, received_names = self._product_closure(product["root_targets"])
        for target in artifacts:
            info = self.generated[target["repo"]]
            doc_ref = f"DocumentRef-{_sanitize_id(target['repo'])}"
            doc.add_external_ref(doc_ref, info["namespace"], info["sha1"])
            doc.add_relationship(
                product_pkg_id,
                "DEPENDS_ON",
                f"{doc_ref}:{_package_id(target['name'])}",
            )
        for link_name in received_names:
            r = self.received[link_name]
            doc.add_external_ref(r.doc_ref_id, r.namespace, r.sha1)
            doc.add_relationship(
                product_pkg_id, "DEPENDS_ON", f"{r.doc_ref_id}:{r.root_package_id}"
            )

        self._embed_referenced_license_defs(doc)
        out_file = self.out_dir / f"{doc_name}.spdx.json"
        doc.write(out_file)
        return out_file

    # ---- エントリポイント -------------------------------------------------

    def run(self) -> list[Path]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        for repo in self._topo_repo_order():
            written.append(self._generate_repo_doc(repo))
        for product in self.manifest.get("products", []):
            written.append(self._generate_product_doc(product))
        return written


def generate_sboms(manifest: dict, out_dir: str | Path) -> list[Path]:
    """マニフェストから SPDX ドキュメント群を生成し、書き出したパスを返す"""
    return _Generator(manifest, Path(out_dir)).run()
