#!/usr/bin/env python3
"""CLI: 署名後の SBOM 再ハッシュ (署名サーバで実行)。

生成済み SBOM 群のハッシュを署名済みバイナリのものへ更新し、相互参照の
SHA1 連鎖も維持する。Qt SBOM / vendor SBOM / ビルドマニフェストは不要。
標準ライブラリのみで動作する。

usage:
  python rehash_sbom.py --sbom-dir <dir> --artifact-dir <signed-bin-dir> [--out-dir <dir>]
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sbomgen.rehash import rehash_sboms


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom-dir", required=True,
                        help="ビルドサーバが生成した SPDX ドキュメント群のディレクトリ")
    parser.add_argument("--artifact-dir", required=True,
                        help="署名済み EXE/DLL のあるディレクトリ")
    parser.add_argument("--out-dir", default=None,
                        help="出力先 (省略時は --sbom-dir を上書き)")
    args = parser.parse_args()

    summary = rehash_sboms(args.sbom_dir, args.artifact_dir, args.out_dir)
    for path in summary["written"]:
        print(f"[rehash] wrote {path}")
    print(f"[rehash] rehashed {len(summary['rehashed_artifacts'])} artifacts, "
          f"updated {summary['updated_refs']} document refs")
    if summary["unmatched_artifacts"]:
        print(f"[rehash] WARNING: no signed binary found for: "
              f"{', '.join(sorted(set(summary['unmatched_artifacts'])))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
