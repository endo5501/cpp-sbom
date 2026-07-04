"""generate_sboms: CMake が出力したビルドマニフェスト (JSON) から
リポジトリ単位 + 製品単位の SPDX 2.3 JSON ドキュメントを生成する。"""

import json
from pathlib import Path

import pytest

from conftest import sha1_of, sha256_of

from sbomgen.generator import generate_sboms


def make_fake_binary(bin_dir: Path, filename: str) -> Path:
    path = bin_dir / filename
    path.write_bytes(f"FAKE-PE-BINARY:{filename}".encode())
    return path


@pytest.fixture
def manifest(tmp_path, qt_sbom_dir, vendor_sbom_file):
    """実プロジェクト構成を模したビルドマニフェスト (CMake の file(GENERATE) 出力相当)"""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    files = {
        name: make_fake_binary(bin_dir, filename)
        for name, filename in [
            ("corelib", "corelib.dll"),
            ("gui1lib", "gui1lib.dll"),
            ("gui2lib", "gui2lib.dll"),
            ("app1", "app1.exe"),
            ("app2", "app2.exe"),
            ("service", "service.exe"),
        ]
    }
    return {
        "qt_sbom_dir": str(qt_sbom_dir),
        "supplier": "Organization: Example Corp",
        "supplier_url": "https://sbom.example.com",
        "namespace_base": "https://sbom.example.com/spdxdocs",
        "build_id": "test-build-1",
        "targets": [
            {
                "name": "sqlite",
                "type": "STATIC_LIBRARY",
                "repo": "sqlite",
                "version": "3.53.3",
                "links": [],
                "describe": {
                    "name": "SQLite",
                    "version": "3.53.3",
                    "license": "blessing",
                    "supplier": "Organization: SQLite Consortium",
                    "purl": "pkg:generic/sqlite@3.53.3",
                    "download": "https://www.sqlite.org/2026/sqlite-amalgamation-3530300.zip",
                },
            },
            {
                "name": "corelib",
                "type": "SHARED_LIBRARY",
                "repo": "corelib",
                "version": "1.2.0",
                "file": str(files["corelib"]),
                "links": ["Qt6::Core", "sqlite"],
                "license_declared": "LicenseRef-MyCompany-Proprietary",
                "license_concluded": "LicenseRef-MyCompany-Proprietary",
                "copyright": "Copyright (c) 2026 Example Corp",
            },
            {
                "name": "gui1lib",
                "type": "SHARED_LIBRARY",
                "repo": "gui1lib",
                "version": "2.0.1",
                "file": str(files["gui1lib"]),
                "links": ["Qt6::Core", "Qt6::Widgets", "Qt6::Xml"],
            },
            {
                "name": "gui2lib",
                "type": "SHARED_LIBRARY",
                "repo": "gui2lib",
                "version": "2.1.0",
                "file": str(files["gui2lib"]),
                "links": ["Qt6::Core", "Qt6::Widgets", "Qt6::Core5Compat"],
            },
            {
                "name": "app1",
                "type": "EXECUTABLE",
                "repo": "app1",
                "version": "1.0.0",
                "file": str(files["app1"]),
                "links": [
                    "Qt6::Core",
                    "Qt6::Widgets",
                    "corelib",
                    "gui1lib",
                    "Vendorlib::vendorlib",
                ],
            },
            {
                "name": "app2",
                "type": "EXECUTABLE",
                "repo": "app2",
                "version": "2.0.0",
                "file": str(files["app2"]),
                "links": [
                    "Qt6::Core",
                    "Qt6::Widgets",
                    "Qt6::Network",
                    "corelib",
                    "gui2lib",
                    "Vendorlib::vendorlib",
                ],
            },
            {
                "name": "service",
                "type": "EXECUTABLE",
                "repo": "service",
                "version": "0.9.0",
                "file": str(files["service"]),
                "links": ["sqlite"],
            },
        ],
        "externals": {
            "Vendorlib::vendorlib": {"spdx_document": str(vendor_sbom_file)}
        },
        "licenses": [
            {
                "id": "LicenseRef-MyCompany-Proprietary",
                "name": "Example Corp Proprietary License",
                "text": (
                    "Proprietary software of Example Corp.\n"
                    "All rights reserved. Redistribution prohibited."
                ),
            }
        ],
        "products": [
            {"name": "product-app1", "version": "1.0.0", "root_targets": ["app1"]},
            {"name": "product-app2", "version": "1.0.0", "root_targets": ["app2"]},
            {"name": "product-service", "version": "1.0.0", "root_targets": ["service"]},
        ],
    }


@pytest.fixture
def out_dir(tmp_path):
    return tmp_path / "sbom-out"


@pytest.fixture
def generated(manifest, out_dir):
    generate_sboms(manifest, out_dir)
    return out_dir


def load_doc(out_dir: Path, name: str) -> dict:
    return json.loads((out_dir / name).read_text(encoding="utf-8"))


def relationships_of(doc: dict, rel_type: str) -> list[tuple[str, str]]:
    return [
        (r["spdxElementId"], r["relatedSpdxElement"])
        for r in doc.get("relationships", [])
        if r["relationshipType"] == rel_type
    ]


def external_refs_of(doc: dict) -> dict[str, dict]:
    return {r["externalDocumentId"]: r for r in doc.get("externalDocumentRefs", [])}


def package_by_id(doc: dict, spdx_id: str) -> dict:
    for p in doc.get("packages", []):
        if p["SPDXID"] == spdx_id:
            return p
    raise AssertionError(f"package {spdx_id} not found")


class TestRepoDocuments:
    def test_one_document_per_repo_with_artifacts(self, generated):
        # 成果物 (EXE/DLL) を持つリポジトリのみドキュメントが生成される
        names = {p.name for p in generated.glob("*.spdx.json")}
        for expected in [
            "corelib-1.2.0.spdx.json",
            "gui1lib-2.0.1.spdx.json",
            "gui2lib-2.1.0.spdx.json",
            "app1-1.0.0.spdx.json",
            "app2-2.0.0.spdx.json",
            "service-0.9.0.spdx.json",
        ]:
            assert expected in names
        # STATIC ライブラリだけの sqlite リポジトリは成果物ではない → ドキュメントなし
        assert not any(n.startswith("sqlite-") for n in names)

    def test_document_header(self, generated):
        doc = load_doc(generated, "corelib-1.2.0.spdx.json")
        assert doc["spdxVersion"] == "SPDX-2.3"
        assert doc["dataLicense"] == "CC0-1.0"
        assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
        assert doc["documentNamespace"].startswith(
            "https://sbom.example.com/spdxdocs/corelib-1.2.0"
        )

    def test_artifact_package_checksums_and_metadata(self, generated, manifest):
        doc = load_doc(generated, "corelib-1.2.0.spdx.json")
        pkg = package_by_id(doc, "SPDXRef-Package-corelib")
        assert pkg["versionInfo"] == "1.2.0"
        assert pkg["supplier"] == "Organization: Example Corp"
        assert pkg["filesAnalyzed"] is False

        target = next(t for t in manifest["targets"] if t["name"] == "corelib")
        checksums = {c["algorithm"]: c["checksumValue"] for c in pkg["checksums"]}
        assert checksums["SHA256"] == sha256_of(Path(target["file"]))
        assert checksums["SHA1"] == sha1_of(Path(target["file"]))

    def test_document_describes_artifact(self, generated):
        doc = load_doc(generated, "app1-1.0.0.spdx.json")
        describes = relationships_of(doc, "DESCRIBES")
        assert ("SPDXRef-DOCUMENT", "SPDXRef-Package-app1") in describes


class TestQtRelations:
    def test_dynamic_link_to_qt_module_via_external_ref(self, generated, qt_sbom_dir):
        doc = load_doc(generated, "corelib-1.2.0.spdx.json")

        refs = external_refs_of(doc)
        assert "DocumentRef-qtbase" in refs
        ref = refs["DocumentRef-qtbase"]
        assert ref["spdxDocument"].startswith("https://qt.io/spdxdocs/qtbase-fixture")
        assert ref["checksum"]["algorithm"] == "SHA1"
        assert ref["checksum"]["checksumValue"] == sha1_of(
            qt_sbom_dir / "qtbase-6.11.1.spdx"
        )

        links = relationships_of(doc, "DYNAMIC_LINK")
        assert (
            "SPDXRef-Package-corelib",
            "DocumentRef-qtbase:SPDXRef-Package-qtbase-qt-module-Core-abc123def456",
        ) in links

    def test_core5compat_references_qt5compat_document(self, generated, qt_sbom_dir):
        # gui2lib は qtbase と qt5compat の 2 つの Qt ドキュメントを参照する
        doc = load_doc(generated, "gui2lib-2.1.0.spdx.json")

        refs = external_refs_of(doc)
        assert "DocumentRef-qtbase" in refs
        assert "DocumentRef-qt5compat" in refs
        assert refs["DocumentRef-qt5compat"]["checksum"]["checksumValue"] == sha1_of(
            qt_sbom_dir / "qt5compat-6.11.1.spdx"
        )

        links = relationships_of(doc, "DYNAMIC_LINK")
        assert (
            "SPDXRef-Package-gui2lib",
            "DocumentRef-qt5compat:SPDXRef-Package-qt5compat-qt-module-Core5Compat-fedcba987654",
        ) in links

    def test_service_has_no_qt_references(self, generated):
        doc = load_doc(generated, "service-0.9.0.spdx.json")
        assert external_refs_of(doc) == {}
        assert relationships_of(doc, "DYNAMIC_LINK") == []


class TestStaticLink:
    def test_sqlite_embedded_as_package_with_static_link(self, generated):
        # 静的リンクされる SQLite は独立成果物ではなく、リンク元ドキュメントに
        # Package として埋め込まれ STATIC_LINK が張られる
        for doc_name, artifact in [
            ("corelib-1.2.0.spdx.json", "SPDXRef-Package-corelib"),
            ("service-0.9.0.spdx.json", "SPDXRef-Package-service"),
        ]:
            doc = load_doc(generated, doc_name)
            pkg = package_by_id(doc, "SPDXRef-Package-SQLite")
            assert pkg["versionInfo"] == "3.53.3"
            assert pkg["licenseDeclared"] == "blessing"
            assert pkg["supplier"] == "Organization: SQLite Consortium"
            purls = [
                r["referenceLocator"]
                for r in pkg.get("externalRefs", [])
                if r["referenceType"] == "purl"
            ]
            assert purls == ["pkg:generic/sqlite@3.53.3"]

            links = relationships_of(doc, "STATIC_LINK")
            assert (artifact, "SPDXRef-Package-SQLite") in links


class TestCrossRepoRelations:
    def test_app1_references_corelib_document(self, generated):
        # リポジトリ間の依存: app1 → corelib は生成済み corelib ドキュメントへの
        # ExternalDocumentRef + DYNAMIC_LINK になる
        doc = load_doc(generated, "app1-1.0.0.spdx.json")

        refs = external_refs_of(doc)
        assert "DocumentRef-corelib" in refs
        corelib_doc = load_doc(generated, "corelib-1.2.0.spdx.json")
        assert refs["DocumentRef-corelib"]["spdxDocument"] == corelib_doc["documentNamespace"]
        # SHA1 は生成された corelib ドキュメントファイル自体に対して計算される
        assert refs["DocumentRef-corelib"]["checksum"]["checksumValue"] == sha1_of(
            generated / "corelib-1.2.0.spdx.json"
        )

        links = relationships_of(doc, "DYNAMIC_LINK")
        assert (
            "SPDXRef-Package-app1",
            "DocumentRef-corelib:SPDXRef-Package-corelib",
        ) in links


class TestVendorRelations:
    def test_app1_references_received_vendor_sbom(self, generated, vendor_sbom_file):
        doc = load_doc(generated, "app1-1.0.0.spdx.json")

        refs = external_refs_of(doc)
        assert "DocumentRef-vendorlib" in refs
        ref = refs["DocumentRef-vendorlib"]
        assert ref["spdxDocument"] == (
            "https://vendor.example.org/spdxdocs/"
            "vendorlib-1.2.3-11111111-2222-3333-4444-555555555555"
        )
        assert ref["checksum"]["checksumValue"] == sha1_of(vendor_sbom_file)

        # 参照先 SPDXID は受領 SBOM の documentDescribes から自動取得される
        links = relationships_of(doc, "DYNAMIC_LINK")
        assert (
            "SPDXRef-Package-app1",
            "DocumentRef-vendorlib:SPDXRef-Package-vendorlib",
        ) in links


class TestProductDocuments:
    def test_product_app1_bundles_component_documents(self, generated, vendor_sbom_file):
        doc = load_doc(generated, "product-app1-1.0.0.spdx.json")

        # 製品パッケージが存在し、DOCUMENT が DESCRIBES する
        pkg = package_by_id(doc, "SPDXRef-Package-product-app1")
        assert pkg["versionInfo"] == "1.0.0"
        assert ("SPDXRef-DOCUMENT", "SPDXRef-Package-product-app1") in relationships_of(
            doc, "DESCRIBES"
        )

        # 構成要素 (推移的閉包): app1, corelib, gui1lib, vendorlib
        refs = external_refs_of(doc)
        for expected in [
            "DocumentRef-app1",
            "DocumentRef-corelib",
            "DocumentRef-gui1lib",
            "DocumentRef-vendorlib",
        ]:
            assert expected in refs, f"{expected} missing in product-app1"
        # app2 の構成要素は含まれない
        assert "DocumentRef-gui2lib" not in refs
        assert "DocumentRef-app2" not in refs

        depends = relationships_of(doc, "DEPENDS_ON")
        assert (
            "SPDXRef-Package-product-app1",
            "DocumentRef-app1:SPDXRef-Package-app1",
        ) in depends
        assert (
            "SPDXRef-Package-product-app1",
            "DocumentRef-corelib:SPDXRef-Package-corelib",
        ) in depends
        assert (
            "SPDXRef-Package-product-app1",
            "DocumentRef-vendorlib:SPDXRef-Package-vendorlib",
        ) in depends

    def test_product_service_is_minimal(self, generated):
        doc = load_doc(generated, "product-service-1.0.0.spdx.json")
        refs = external_refs_of(doc)
        assert set(refs) == {"DocumentRef-service"}


class TestLicenseAndCopyright:
    def test_artifact_license_and_copyright_from_manifest(self, generated):
        doc = load_doc(generated, "corelib-1.2.0.spdx.json")
        pkg = package_by_id(doc, "SPDXRef-Package-corelib")
        assert pkg["licenseDeclared"] == "LicenseRef-MyCompany-Proprietary"
        assert pkg["licenseConcluded"] == "LicenseRef-MyCompany-Proprietary"
        assert pkg["copyrightText"] == "Copyright (c) 2026 Example Corp"

    def test_defaults_are_noassertion(self, generated):
        doc = load_doc(generated, "gui1lib-2.0.1.spdx.json")
        pkg = package_by_id(doc, "SPDXRef-Package-gui1lib")
        assert pkg["licenseDeclared"] == "NOASSERTION"
        assert pkg["licenseConcluded"] == "NOASSERTION"
        assert pkg["copyrightText"] == "NOASSERTION"

    def test_custom_license_definition_embedded_where_referenced(self, generated):
        # LicenseRef- を使うドキュメントには hasExtractedLicensingInfos で
        # 定義が埋め込まれる (SPDX 2.3 の要求)
        doc = load_doc(generated, "corelib-1.2.0.spdx.json")
        infos = {
            i["licenseId"]: i for i in doc.get("hasExtractedLicensingInfos", [])
        }
        assert "LicenseRef-MyCompany-Proprietary" in infos
        info = infos["LicenseRef-MyCompany-Proprietary"]
        assert info["name"] == "Example Corp Proprietary License"
        assert "Proprietary software of Example Corp." in info["extractedText"]

    def test_custom_license_not_embedded_where_unreferenced(self, generated):
        # LicenseRef-MyCompany-Proprietary を参照しないドキュメントには定義を入れない
        doc = load_doc(generated, "gui1lib-2.0.1.spdx.json")
        infos = doc.get("hasExtractedLicensingInfos", [])
        assert all(
            i["licenseId"] != "LicenseRef-MyCompany-Proprietary" for i in infos
        )


class TestNamespaceStability:
    def test_same_build_id_gives_same_namespace(self, manifest, tmp_path):
        out1 = tmp_path / "out1"
        out2 = tmp_path / "out2"
        generate_sboms(manifest, out1)
        generate_sboms(manifest, out2)
        ns1 = load_doc(out1, "corelib-1.2.0.spdx.json")["documentNamespace"]
        ns2 = load_doc(out2, "corelib-1.2.0.spdx.json")["documentNamespace"]
        assert ns1 == ns2

    def test_different_build_id_gives_different_namespace(self, manifest, tmp_path):
        out1 = tmp_path / "out1"
        out2 = tmp_path / "out2"
        generate_sboms(manifest, out1)
        manifest["build_id"] = "test-build-2"
        generate_sboms(manifest, out2)
        ns1 = load_doc(out1, "corelib-1.2.0.spdx.json")["documentNamespace"]
        ns2 = load_doc(out2, "corelib-1.2.0.spdx.json")["documentNamespace"]
        assert ns1 != ns2


class TestSpdxValidity:
    def test_all_generated_documents_are_valid_spdx_2_3(self, generated):
        # SPDX 公式ツール (spdx-tools) によるパース + バリデーション
        from spdx_tools.spdx.parser.parse_anything import parse_file
        from spdx_tools.spdx.validation.document_validator import (
            validate_full_spdx_document,
        )

        for doc_file in sorted(generated.glob("*.spdx.json")):
            document = parse_file(str(doc_file))
            messages = validate_full_spdx_document(document)
            assert messages == [], f"{doc_file.name}: {[str(m) for m in messages]}"
