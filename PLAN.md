# C/C++ (MSVC + CMake + ninja) 環境での SBOM 生成 — 実験環境構築計画

## Context(背景と目的)

Windows / MSVC2022 / CMake / ninja / Qt 6.11.1(商用)環境で、ビルド成果物(EXE/DLL)に対する SBOM を生成する方式を確立したい。要求は以下の3点:

1. 成果物 EXE/DLL 単位の SBOM 生成(それ以外の成果物は不要)
2. 外部 SBOM(Qt6・受領した独自ライブラリ)の SPDXID との Relation
3. CI での自動生成

## 調査で確定した事実(ローカル検証済み)

- **Qt 6.11.1 は SBOM を標準同梱**: `C:\Qt\6.11.1\msvc2022_64\sbom\` に Qt リポジトリ単位(qtbase 等)で SPDX 2.3(タグバリュー + JSON)と CycloneDX 1.6 を同梱。
- Qt 自身がリポジトリ間参照に **SPDX `ExternalDocumentRef`** を使用。参照先ファイルの SHA1 が実ファイルと一致することをローカルで検証済み。
- `Qt6::Core` に対応するパッケージ SPDXID: `SPDXRef-Package-qtbase-qt-module-Core-14f2e7e421b1`(qtbase-6.11.1.spdx 内。サフィックスはドキュメント固有なのでハードコード不可、パースして解決する)。
- **Qt のユーザプロジェクト向け SBOM 生成 CMake API はまだ非公開**(`_qt_internal_*` の内部 API のみ。公開 API は計画段階)。
- **既製ツールに適任なし**:
  - Microsoft sbom-tool: パッケージマネージャのマニフェスト前提で C++ 成果物の検出不可(外部SBOM参照 `-er` はあるがターゲット単位の Package 化ができない)
  - cdxgen: Conan/vcpkg 前提、CycloneDX 出力のみ
  - Syft/Trivy: Windows PE バイナリ非対応
  - DEMCON cmake-sbom: 唯一 CMake ネイティブだが手動宣言方式、Qt SPDXID 解決は自前実装が必要、メンテ状況不透明

## 決定事項

| 項目 | 決定 | 理由 |
|---|---|---|
| フォーマット | **SPDX 2.3**(JSON を正とする) | Qt が同形式で同梱、`ExternalDocumentRef` が成熟(Yocto 等で実績)、受領 SBOM も SPDX 2.x 前提 |
| 実装方式 | **自作 CMake モジュール + Python 生成スクリプト** | 必要な情報(ターゲット・出力ファイル・リンク関係)は全て CMake が保持。既製ツールでは要求を満たせない。Qt が公開 API を出したら乗り換え可能な薄い構成にする |
| 受領 SBOM 形式 | SPDX 2.x | ユーザ確認済み |
| CI | Jenkins(Jenkinsfile サンプル) | ユーザ確認済み |

## 実験環境の構成

実運用の「複数リポジトリを組み合わせてビルド」を 1 リポジトリ内のディレクトリで模擬する:

```
D:\Programs\cpp-sbom\
├── CMakeLists.txt              # スーパービルド (add_subdirectory で各 repo を統合)
├── cmake/Sbom.cmake            # 自作 SBOM CMake モジュール(再利用可能な共通部品)
├── scripts/
│   ├── generate_sbom.py        # CLI エントリポイント
│   └── sbomgen/                # Python パッケージ
│       ├── qt_sbom.py          #   Qt の .spdx(タグバリュー)パーサ / SPDXID 解決
│       └── generator.py        #   SPDX 2.3 JSON 生成・Relation 構築
├── tests/                      # pytest (TDD)。fixtures/ にミニ Qt SBOM 等の自己完結フィクスチャ
├── corelib/                     # 自社 DLL(Qt6::Core + sqlite を利用)
├── gui1lib/                     # 自社 DLL(Qt6::Core + Qt6::Widgets + Qt6::Xml を利用)
├── gui2lib/                     # 自社 DLL(Qt6::Core + Qt6::Widgets + Qt6::Core5Compat を利用)
├── app1/                        # 自社 EXE(Qt6::Core + Qt6::Widgets + corelib + gui1lib + vendorlib を利用)
├── app2/                        # 自社 EXE(Qt6::Core + Qt6::Widgets + Qt6::Network + corelib + gui2lib + vendorlib を利用)
├── service/                     # 自社 EXE(sqlite を利用。Qt使用無し)
├── vendorlib/                   # 「他社から受領した DLL/LIB + SBOM」の模擬
│   ├── include/ bin/ lib/      #   バイナリのみ(事前に別途ビルドして配置)
│   ├── cmake/                  #   VendorConfig.cmakeにて定義
│   └── sbom/vendorlib-1.2.3.spdx.json  # 手書きの受領 SBOM (SPDX 2.3 JSON)
├── sqlite/                      # SQLite を STATIC ライブラリ化する CMake プロジェクト(実環境の再現)
├── ci/Jenkinsfile              # CI 自動化サンプル
└── README.md                   # 設計判断と使い方のドキュメント
```

ツールチェーン(確認済み): VS2022 Community `vcvars64.bat` / CMake 3.30.5 (`C:\Qt\Tools\CMake_64`) / ninja 1.13.2 / Python 3.13。

## SBOM 生成の設計

### CMake 側 (`cmake/Sbom.cmake`)

| API | 役割 |
|---|---|
| `sbom_add_target(<tgt>)` | SBOM 対象の EXE/DLL を登録。種別・出力ファイル(`$<TARGET_FILE>`)・`LINK_LIBRARIES`・プロジェクト名/バージョンを収集 |
| `sbom_describe_package(<tgt> NAME SQLite VERSION ... LICENSE ... PURL ...)` | STATIC ライブラリ(SQLite)のメタデータ宣言。静的リンクのため独立成果物とせず、リンク元 SBOM に Package として埋め込む(「成果物は exe/dll のみ」の要求に合致) |
| `sbom_declare_external(<tgt> SPDX_DOCUMENT <受領SBOMパス>)` | 受領バイナリ(vendorlib)の IMPORTED ターゲットに受領 SBOM を紐付け |
| `sbom_finalize(PRODUCT <name> ...)` | 全登録情報を `file(GENERATE)` でマニフェスト JSON に出力し、`ninja sbom` で Python 生成器を実行するカスタムターゲットを定義(ビルド済みバイナリに依存) |

### Python 側 (`scripts/sbomgen/`)

1. Qt の `sbom/*.spdx` をパースし「モジュール名 → (ドキュメント名前空間, パッケージ SPDXID, ファイル SHA1)」のマップを構築。`Qt6::Core` → `DocumentRef-qtbase:SPDXRef-Package-qtbase-qt-module-Core-…` を自動解決(Qt の sbom ディレクトリは `Qt6_DIR` から導出)。
2. リポジトリ単位で SPDX 2.3 JSON ドキュメントを生成:
   - EXE/DLL ごとに Package(SHA256/SHA1 チェックサム、supplier、licenseDeclared)+ `DOCUMENT DESCRIBES` 関係
   - Qt モジュールへ `DYNAMIC_LINK`(ExternalDocumentRef 経由)
   - SQLite へ `STATIC_LINK`(埋め込み Package)
   - 受領 SBOM のルートパッケージへ `DYNAMIC_LINK`(ExternalDocumentRef 経由、受領 SBOM の DESCRIBES から SPDXID を自動取得)
   - リポジトリ間(app → corelib)も `ExternalDocumentRef` で相互参照(依存順に生成し SHA1 を確定)
3. 製品トップレベル SBOM: 組み合わせ(app + corelib + Qt + vendorlib)全体を 1 つの薄いドキュメントで束ねる(Yocto と同じパターン)。

### Relation の形(生成物のイメージ)

```
ExternalDocumentRef: DocumentRef-qtbase <qtbaseの名前空間> SHA1: <qtbase-6.11.1.spdxのSHA1>
Relationship: SPDXRef-Package-app DYNAMIC_LINK DocumentRef-qtbase:SPDXRef-Package-qtbase-qt-module-Core-14f2e7e421b1
Relationship: SPDXRef-Package-corelib STATIC_LINK SPDXRef-Package-SQLite
Relationship: SPDXRef-Package-app DYNAMIC_LINK DocumentRef-vendorlib:SPDXRef-Package-vendorlib
```

## 実行ステップ(TDD、CLAUDE.md の開発方針に従う)

1. **スケルトン作成**: 上記ディレクトリ構成、サンプル C++ ソース(corelib.dll / app.exe / SQLite 静的ライブラリ)。SQLite は公式 amalgamation をダウンロード(失敗時は最小スタブで代替し明記)。
2. **Python 環境**: `.venv` + pytest + spdx-tools(公式検証ツール `pyspdxtools`)。
3. **テスト先行**: Qt SBOM パース / SPDXID 解決 / ExternalDocumentRef の SHA1 / Package・Relationship 生成 / SPDX 2.3 JSON 組み立て のテストを書く → 失敗を確認 → **コミット**。
4. **生成器実装**: テストをパスするまで実装 → **コミット**。
5. **CMake モジュール実装**: `Sbom.cmake` + 各 repo の CMakeLists.txt 統合。
6. **vendorlib 準備**: 小さな DLL を一度ビルドして vendor/ に配置し、手書きの受領 SBOM(SPDX 2.3 JSON)を添付。ビルドシステムからはバイナリ+SBOM のみ参照。
7. **実ビルドと生成**: vcvars64 + Qt 6.11.1 msvc2022_64 + ninja で全体をビルドし `ninja sbom` を実行。
8. **検証**: `pyspdxtools` で全ドキュメントを検証。ExternalDocumentRef の SHA1 が実ファイルと一致すること、`DocumentRef-qtbase:...Core` が実際の Qt SBOM 内 SPDXID に解決できることをスクリプトで確認。テスト完了後 **コミット**。
9. **Jenkinsfile + README**: configure → build → sbom → validate → archive のパイプラインサンプルと、設計判断のドキュメント化 → **コミット**。

## 検証方法(動作確認)

- `pytest` が全パス。
- 実ビルド後、`build/sbom/` に per-repo SBOM + 製品 SBOM が生成される。
- `pyspdxtools -i <各ドキュメント>` が SPDX 2.3 として妥当と判定。
- 検証スクリプトで cross-document 参照(Qt / vendorlib / repo 間)の SPDXID・SHA1 整合を機械的に確認。
- exe/dll のチェックサムが SBOM 記載値と一致。

## 制約・注意点

- Qt の SPDXID サフィックス(例 `14f2e7e421b1`)はドキュメント固有 → ハードコードせず必ず実ファイルからパースして解決する。
- Qt を再インストール/更新すると Qt SBOM の SHA1 が変わる → 生成時に毎回計算(CI でも同様)。
- 将来 Qt がユーザプロジェクト向け公開 API を出したら乗り換えられるよう、CMake API は薄く保つ。
- 生成した SBOM の作成日時は生成のたびに変わる(再現性が必要なら `SOURCE_DATE_EPOCH` 対応を後日検討)。
