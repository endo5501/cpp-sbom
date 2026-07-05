"""rehash_sboms: 署名サーバ側での再ハッシュ。

運用 (構成B):
  1. ビルドサーバ: build → generate_sboms で Qt/vendor 等との Relation を
     完全に張った SBOM 群を生成 (この時点のハッシュは未署名バイナリのもの)
  2. 署名サーバ: USB トークンで EXE/DLL に署名 → rehash_sboms で
     生成済み SBOM 群のハッシュだけを署名済みバイナリのものへ更新する

rehash_sboms が入力に必要とするのは「生成済み SBOM ディレクトリ」と
「署名済みバイナリのあるディレクトリ」だけ。Qt SBOM・vendor SBOM・
ビルドマニフェストは不要 (= 署名サーバに配布しなくてよい)。

再ハッシュは相互参照の SHA1 連鎖も維持する: 成果物ハッシュを書き換えると
その SBOM ファイル自体の SHA1 が変わるため、それを ExternalDocumentRef で
参照している他ドキュメントの SHA1 も依存順に更新する。Qt/vendor など
ローカルにないドキュメントへの参照 (署名対象外) は変更しない。
"""

import json
from pathlib import Path

import pytest

from conftest import sha1_of, sha256_of

from sbomgen.generator import generate_sboms
from sbomgen.rehash import rehash_sboms

# test_generator.py の manifest フィクスチャ (fake binaries + qt/vendor) を再利用
from test_generator import manifest, out_dir  # noqa: F401


def load_doc(d: Path, name: str) -> dict:
    return json.loads((d / name).read_text(encoding="utf-8"))


def external_refs_of(doc: dict) -> dict[str, dict]:
    return {r["externalDocumentId"]: r for r in doc.get("externalDocumentRefs", [])}


def package_by_id(doc: dict, spdx_id: str) -> dict:
    return next(p for p in doc["packages"] if p["SPDXID"] == spdx_id)


def checksums_of(pkg: dict) -> dict[str, str]:
    return {c["algorithm"]: c["checksumValue"] for c in pkg["checksums"]}


@pytest.fixture
def artifact_dir(manifest) -> Path:
    # manifest の成果物ファイルは全て同じ bin ディレクトリにある
    first = next(t["file"] for t in manifest["targets"] if "file" in t)
    return Path(first).parent


@pytest.fixture
def generated(manifest, out_dir) -> Path:
    generate_sboms(manifest, out_dir)
    return out_dir


def sign_all_binaries(artifact_dir: Path) -> None:
    """署名を模擬: 各バイナリ末尾にバイト列を追記してハッシュを変える"""
    for f in artifact_dir.iterdir():
        if f.suffix in (".exe", ".dll"):
            with open(f, "ab") as fh:
                fh.write(b"\x00AUTHENTICODE-SIGNATURE-SIMULATION\x00")


class TestArtifactRehash:
    def test_artifact_checksums_updated_to_signed_binary(
        self, generated, artifact_dir
    ):
        before = checksums_of(
            package_by_id(load_doc(generated, "app1-1.0.0.spdx.json"),
                          "SPDXRef-Package-app1")
        )
        sign_all_binaries(artifact_dir)
        rehash_sboms(generated, artifact_dir)

        pkg = package_by_id(
            load_doc(generated, "app1-1.0.0.spdx.json"), "SPDXRef-Package-app1"
        )
        after = checksums_of(pkg)
        signed = artifact_dir / "app1.exe"
        assert after["SHA256"] == sha256_of(signed)
        assert after["SHA1"] == sha1_of(signed)
        assert after["SHA256"] != before["SHA256"]

    def test_all_artifact_documents_rehashed(self, generated, artifact_dir):
        sign_all_binaries(artifact_dir)
        rehash_sboms(generated, artifact_dir)
        for name, pkg_id, filename in [
            ("corelib-1.2.0.spdx.json", "SPDXRef-Package-corelib", "corelib.dll"),
            ("gui1lib-2.0.1.spdx.json", "SPDXRef-Package-gui1lib", "gui1lib.dll"),
            ("service-0.9.0.spdx.json", "SPDXRef-Package-service", "service.exe"),
        ]:
            pkg = package_by_id(load_doc(generated, name), pkg_id)
            assert checksums_of(pkg)["SHA256"] == sha256_of(artifact_dir / filename)


class TestCrossReferenceChain:
    def test_local_external_ref_sha1_follows_rehashed_file(
        self, generated, artifact_dir
    ):
        sign_all_binaries(artifact_dir)
        rehash_sboms(generated, artifact_dir)

        app1 = load_doc(generated, "app1-1.0.0.spdx.json")
        refs = external_refs_of(app1)
        # app1 → corelib / gui1lib: 参照先 SBOM ファイル (再ハッシュ後) の SHA1 と一致
        assert refs["DocumentRef-corelib"]["checksum"]["checksumValue"] == sha1_of(
            generated / "corelib-1.2.0.spdx.json"
        )
        assert refs["DocumentRef-gui1lib"]["checksum"]["checksumValue"] == sha1_of(
            generated / "gui1lib-2.0.1.spdx.json"
        )

    def test_product_doc_refs_follow_rehashed_repo_docs(
        self, generated, artifact_dir
    ):
        sign_all_binaries(artifact_dir)
        rehash_sboms(generated, artifact_dir)

        product = load_doc(generated, "product-app1-1.0.0.spdx.json")
        refs = external_refs_of(product)
        assert refs["DocumentRef-app1"]["checksum"]["checksumValue"] == sha1_of(
            generated / "app1-1.0.0.spdx.json"
        )
        assert refs["DocumentRef-corelib"]["checksum"]["checksumValue"] == sha1_of(
            generated / "corelib-1.2.0.spdx.json"
        )
        assert refs["DocumentRef-gui1lib"]["checksum"]["checksumValue"] == sha1_of(
            generated / "gui1lib-2.0.1.spdx.json"
        )


class TestExternalRefsUntouched:
    def test_qt_and_vendor_refs_unchanged(self, generated, artifact_dir):
        # 署名対象外 (ローカルにない) の Qt/vendor 参照 SHA1 は変えない
        app1_before = load_doc(generated, "app1-1.0.0.spdx.json")
        qt_before = external_refs_of(app1_before)["DocumentRef-qtbase"][
            "checksum"
        ]["checksumValue"]
        vendor_before = external_refs_of(app1_before)["DocumentRef-vendorlib"][
            "checksum"
        ]["checksumValue"]

        sign_all_binaries(artifact_dir)
        rehash_sboms(generated, artifact_dir)

        app1_after = load_doc(generated, "app1-1.0.0.spdx.json")
        refs = external_refs_of(app1_after)
        assert refs["DocumentRef-qtbase"]["checksum"]["checksumValue"] == qt_before
        assert (
            refs["DocumentRef-vendorlib"]["checksum"]["checksumValue"] == vendor_before
        )


class TestNoBuildInputsNeeded:
    def test_rehash_works_from_copied_sbom_dir_only(
        self, generated, artifact_dir, tmp_path
    ):
        # 署名サーバを模擬: SBOM 群と署名済みバイナリだけを別ディレクトリへコピー。
        # qt_sbom_dir / vendor SBOM / manifest は一切無い状態で rehash が完結する。
        import shutil

        sign_all_binaries(artifact_dir)
        sign_dir = tmp_path / "signserver-sbom"
        sign_dir.mkdir()
        for f in generated.glob("*.spdx.json"):
            shutil.copy(f, sign_dir)
        sign_bin = tmp_path / "signserver-bin"
        sign_bin.mkdir()
        for f in artifact_dir.iterdir():
            if f.suffix in (".exe", ".dll"):
                shutil.copy(f, sign_bin)

        rehash_sboms(sign_dir, sign_bin)

        pkg = package_by_id(
            load_doc(sign_dir, "app1-1.0.0.spdx.json"), "SPDXRef-Package-app1"
        )
        assert checksums_of(pkg)["SHA256"] == sha256_of(sign_bin / "app1.exe")
        # 相互参照も整合
        refs = external_refs_of(load_doc(sign_dir, "product-app1-1.0.0.spdx.json"))
        assert refs["DocumentRef-app1"]["checksum"]["checksumValue"] == sha1_of(
            sign_dir / "app1-1.0.0.spdx.json"
        )


class TestIdempotenceAndValidity:
    def test_rehash_is_idempotent(self, generated, artifact_dir):
        sign_all_binaries(artifact_dir)
        rehash_sboms(generated, artifact_dir)
        snapshot = {
            f.name: f.read_bytes() for f in generated.glob("*.spdx.json")
        }
        rehash_sboms(generated, artifact_dir)
        for f in generated.glob("*.spdx.json"):
            assert f.read_bytes() == snapshot[f.name], f"{f.name} changed on 2nd rehash"

    def test_rehashed_documents_are_valid_spdx_2_3(self, generated, artifact_dir):
        from spdx_tools.spdx.parser.parse_anything import parse_file
        from spdx_tools.spdx.validation.document_validator import (
            validate_full_spdx_document,
        )

        sign_all_binaries(artifact_dir)
        rehash_sboms(generated, artifact_dir)
        for doc_file in sorted(generated.glob("*.spdx.json")):
            document = parse_file(str(doc_file))
            messages = validate_full_spdx_document(document)
            assert messages == [], f"{doc_file.name}: {[str(m) for m in messages]}"

    def test_verify_passes_after_signing_and_rehash(
        self, manifest, generated, artifact_dir
    ):
        # 署名 → 再ハッシュ後、verify_sbom の全整合チェック (成果物 SHA256 /
        # ローカル参照 SHA1 / Qt/vendor 参照 SHA1) が通ること
        import sys

        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from verify_sbom import Verifier

        sign_all_binaries(artifact_dir)
        rehash_sboms(generated, artifact_dir)
        assert Verifier(manifest, generated).run() == 0
