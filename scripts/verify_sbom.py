#!/usr/bin/env python3
"""生成された SBOM の相互参照整合性を機械的に検証する (標準ライブラリのみ)。

検証内容:
  1. 各 ExternalDocumentRef について、参照先ドキュメントファイルを
     DocumentNamespace で特定し、記載 SHA1 が実ファイルと一致すること
  2. "DocumentRef-x:SPDXRef-y" 形式で参照している SPDXID が、
     参照先ドキュメント内に実在すること
  3. 成果物 Package の記載チェックサム (SHA256) が実バイナリと一致すること

usage: python verify_sbom.py --manifest <build/sbom_manifest.json> --sbom-dir <build/sbom>
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


def sha1_of(path: Path) -> str:
    return hashlib.sha1(path.read_bytes()).hexdigest()


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def spdx_ids_in_tag_value(path: Path) -> set[str]:
    ids = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("SPDXID:"):
            ids.add(line.split(":", 1)[1].strip())
    return ids


def namespace_of_tag_value(path: Path) -> str:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("DocumentNamespace:"):
            return line.split(":", 1)[1].strip()
    return ""


def spdx_ids_in_json(doc: dict) -> set[str]:
    ids = {doc.get("SPDXID", "")}
    for pkg in doc.get("packages", []):
        ids.add(pkg["SPDXID"])
    for f in doc.get("files", []):
        ids.add(f["SPDXID"])
    return ids


class Verifier:
    def __init__(self, manifest: dict, sbom_dir: Path):
        self.errors: list[str] = []
        self.checked = 0
        # DocumentNamespace -> (file path, SPDXID 集合)
        self.documents: dict[str, tuple[Path, set[str]]] = {}

        # 1) 自分たちが生成したドキュメント
        self.generated = sorted(sbom_dir.glob("*.spdx.json"))
        for path in self.generated:
            doc = json.loads(path.read_text(encoding="utf-8"))
            self.documents[doc["documentNamespace"]] = (path, spdx_ids_in_json(doc))

        # 2) Qt 同梱ドキュメント (タグバリュー)
        qt_dir = manifest.get("qt_sbom_dir")
        if qt_dir and Path(qt_dir).is_dir():
            for path in Path(qt_dir).glob("*.spdx"):
                if path.name.endswith(".source.spdx"):
                    continue
                ns = namespace_of_tag_value(path)
                if ns:
                    self.documents[ns] = (path, spdx_ids_in_tag_value(path))

        # 3) 受領ドキュメント
        for info in manifest.get("externals", {}).values():
            path = Path(info["spdx_document"])
            doc = json.loads(path.read_text(encoding="utf-8"))
            self.documents[doc["documentNamespace"]] = (path, spdx_ids_in_json(doc))

        # 成果物ファイル (チェックサム照合用)
        self.artifact_files = {
            t["name"]: Path(t["file"])
            for t in manifest.get("targets", [])
            if "file" in t
        }

    def error(self, message: str) -> None:
        self.errors.append(message)

    def verify_document(self, path: Path) -> None:
        doc = json.loads(path.read_text(encoding="utf-8"))
        name = path.name

        # ExternalDocumentRef: namespace 解決 + SHA1 照合
        ref_map: dict[str, tuple[Path, set[str]]] = {}
        for ref in doc.get("externalDocumentRefs", []):
            ref_id = ref["externalDocumentId"]
            ns = ref["spdxDocument"]
            entry = self.documents.get(ns)
            if entry is None:
                self.error(f"{name}: {ref_id} -> unknown namespace {ns}")
                continue
            target_path, ids = entry
            recorded = ref["checksum"]["checksumValue"]
            actual = sha1_of(target_path)
            self.checked += 1
            if recorded != actual:
                self.error(
                    f"{name}: {ref_id} SHA1 mismatch "
                    f"(recorded {recorded[:12]}…, actual {actual[:12]}… "
                    f"for {target_path.name})"
                )
            ref_map[ref_id] = (target_path, ids)

        # DocumentRef-x:SPDXRef-y 参照先の実在確認
        for rel in doc.get("relationships", []):
            related = rel["relatedSpdxElement"]
            m = re.match(r"^(DocumentRef-[^:]+):(.+)$", related)
            if not m:
                continue
            ref_id, spdx_id = m.groups()
            if ref_id not in ref_map:
                self.error(f"{name}: relationship references undeclared {ref_id}")
                continue
            target_path, ids = ref_map[ref_id]
            self.checked += 1
            if spdx_id not in ids:
                self.error(
                    f"{name}: {spdx_id} not found in {target_path.name} ({ref_id})"
                )

        # 成果物チェックサム照合
        for pkg in doc.get("packages", []):
            artifact = self.artifact_files.get(pkg["name"])
            if artifact is None or not pkg.get("checksums"):
                continue
            recorded = {
                c["algorithm"]: c["checksumValue"] for c in pkg["checksums"]
            }
            if "SHA256" in recorded:
                self.checked += 1
                actual = sha256_of(artifact)
                if recorded["SHA256"] != actual:
                    self.error(
                        f"{name}: package {pkg['name']} SHA256 mismatch "
                        f"with {artifact.name}"
                    )

    def run(self) -> int:
        for path in self.generated:
            self.verify_document(path)
        for message in self.errors:
            print(f"[verify] ERROR {message}")
        print(
            f"[verify] {len(self.generated)} documents, "
            f"{self.checked} cross-checks, {len(self.errors)} errors"
        )
        return 1 if self.errors else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--sbom-dir", required=True)
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    return Verifier(manifest, Path(args.sbom_dir)).run()


if __name__ == "__main__":
    raise SystemExit(main())
