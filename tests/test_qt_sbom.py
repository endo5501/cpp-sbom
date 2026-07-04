"""QtSbomIndex: Qt 同梱のタグバリュー .spdx をパースし、
Qt6::<Module> ターゲット名を (ドキュメント, パッケージ SPDXID) に解決する。"""

import pytest

from conftest import REAL_QT_SBOM_DIR, sha1_of

from sbomgen.qt_sbom import QtSbomIndex


class TestResolve:
    def test_resolve_core(self, qt_sbom_dir):
        index = QtSbomIndex.load(qt_sbom_dir)
        ref = index.resolve("Qt6::Core")
        assert ref is not None
        assert ref.repo == "qtbase"
        assert ref.package_spdx_id == "SPDXRef-Package-qtbase-qt-module-Core-abc123def456"
        assert (
            ref.document_namespace
            == "https://qt.io/spdxdocs/qtbase-fixture-host-windows-amd64-target-windows-msvc-amd64-00000000-0000-0000-0000-000000000001"
        )
        assert ref.document_file.name == "qtbase-6.11.1.spdx"

    def test_resolve_core5compat_lives_in_qt5compat_document(self, qt_sbom_dir):
        # Core5Compat は qtbase ではなく qt5compat リポジトリの SBOM に属する
        index = QtSbomIndex.load(qt_sbom_dir)
        ref = index.resolve("Qt6::Core5Compat")
        assert ref is not None
        assert ref.repo == "qt5compat"
        assert (
            ref.package_spdx_id
            == "SPDXRef-Package-qt5compat-qt-module-Core5Compat-fedcba987654"
        )

    @pytest.mark.parametrize("module", ["Widgets", "Xml", "Network"])
    def test_resolve_qtbase_modules(self, qt_sbom_dir, module):
        index = QtSbomIndex.load(qt_sbom_dir)
        ref = index.resolve(f"Qt6::{module}")
        assert ref is not None
        assert ref.repo == "qtbase"
        assert f"qt-module-{module}-" in ref.package_spdx_id

    def test_resolve_unknown_module_returns_none(self, qt_sbom_dir):
        index = QtSbomIndex.load(qt_sbom_dir)
        assert index.resolve("Qt6::DoesNotExist") is None

    def test_non_qt_target_returns_none(self, qt_sbom_dir):
        index = QtSbomIndex.load(qt_sbom_dir)
        assert index.resolve("corelib") is None
        assert index.resolve("Vendorlib::vendorlib") is None

    def test_attribution_package_is_not_matched_as_module(self, qt_sbom_dir):
        # PackageName "Core_Attribution_pcre2" が "Core" の解決を汚染しないこと
        index = QtSbomIndex.load(qt_sbom_dir)
        ref = index.resolve("Qt6::Core")
        assert "Attribution" not in ref.package_spdx_id

    def test_source_spdx_documents_are_ignored(self, qt_sbom_dir):
        # *.source.spdx (REUSE 由来 / SPDX-2.1) は解決対象外
        index = QtSbomIndex.load(qt_sbom_dir)
        ref = index.resolve("Qt6::Core")
        assert "must-not-match" not in ref.package_spdx_id
        assert ".source." not in ref.document_file.name


class TestDocumentChecksum:
    def test_document_sha1_matches_file_content(self, qt_sbom_dir):
        # ExternalDocumentRef に載せる SHA1 はタグバリュー .spdx ファイル自体のもの
        index = QtSbomIndex.load(qt_sbom_dir)
        ref = index.resolve("Qt6::Core")
        assert ref.document_sha1 == sha1_of(qt_sbom_dir / "qtbase-6.11.1.spdx")


@pytest.mark.skipif(
    not REAL_QT_SBOM_DIR.is_dir(), reason="real Qt 6.11.1 install not present"
)
class TestRealQtInstall:
    """実機の Qt 6.11.1 インストールに対する統合テスト"""

    @pytest.mark.parametrize(
        "target, expected_repo",
        [
            ("Qt6::Core", "qtbase"),
            ("Qt6::Widgets", "qtbase"),
            ("Qt6::Xml", "qtbase"),
            ("Qt6::Network", "qtbase"),
            ("Qt6::Core5Compat", "qt5compat"),
        ],
    )
    def test_resolve_against_real_install(self, target, expected_repo):
        index = QtSbomIndex.load(REAL_QT_SBOM_DIR)
        ref = index.resolve(target)
        assert ref is not None, f"{target} not resolved in real Qt SBOM"
        assert ref.repo == expected_repo
        assert ref.document_namespace.startswith("https://qt.io/spdxdocs/")
        assert ref.document_sha1 == sha1_of(ref.document_file)
