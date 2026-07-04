#!/usr/bin/env python3
"""CLI: ビルドマニフェスト (JSON) から SPDX 2.3 SBOM を生成する。

CMake の `ninja sbom` から呼ばれる想定。標準ライブラリのみで動作する。

usage: python generate_sbom.py --manifest <build/sbom_manifest.json> --out-dir <build/sbom>
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sbomgen.generator import generate_sboms


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="build manifest JSON path")
    parser.add_argument("--out-dir", required=True, help="output directory for SPDX docs")
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    written = generate_sboms(manifest, args.out_dir)
    for path in written:
        print(f"[sbom] wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
