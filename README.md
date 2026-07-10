# cpp-sbom — C/C++ (MSVC + CMake + ninja) 環境での SBOM 生成実験

Windows / MSVC2022 / CMake / ninja / Qt 6.11.1(商用)環境で、ビルド成果物 (EXE/DLL) に対する
**SPDX 2.3** SBOM を生成し、外部 SBOM(Qt6 同梱 SBOM・他社から受領したライブラリの SBOM)と
`ExternalDocumentRef` で Relation を張る実験プロジェクト。

**実験結果: 全要求を達成。** 成果物単位の SBOM 生成、Qt6/受領 SBOM の SPDXID への
Relation、CI 自動化(Jenkinsfile)のすべてを検証済み。

## 設計判断

| 項目 | 決定 | 理由 |
|---|---|---|
| フォーマット | SPDX 2.3(JSON) | Qt 6.8+ が SPDX 2.3 の SBOM を標準同梱し、Qt 自身がモジュール間参照に `ExternalDocumentRef` を使用している。相互参照の仕組みが成熟(Yocto 等で実績) |
| 生成方式 | 自作 CMake モジュール + Python(標準ライブラリのみ) | パッケージマネージャ不使用の C++ ビルドで成果物 SBOM を生成できる既製ツールが存在しない(sbom-tool/cdxgen/Syft いずれも不適)。必要な情報はすべて CMake が保持している |
| Qt との Relation | Qt 同梱のタグバリュー `.spdx` をパースし、`Qt6::Core` 等を PackageName 照合で SPDXID に解決 | SPDXID の命名規則(`qt-module-`)は Qt 内部実装のため主キーにしない。SHA1 は生成のたびに実ファイルから計算 |
| 受領 SBOM | IMPORTED ターゲットの `SBOM_SPDX_DOCUMENT` プロパティで紐付け | ライブラリの Config.cmake が受領 SBOM の場所を知っている、が自然なモデル |

## 生成される SBOM

```
build/sbom/
├── corelib-1.2.0.spdx.json      # リポジトリ単位 (EXE/DLL ごとに Package + チェックサム)
├── gui1lib-2.0.1.spdx.json
├── gui2lib-2.1.0.spdx.json      #   Core5Compat → qt5compat ドキュメントを参照
├── app1-1.0.0.spdx.json         #   Qt / corelib / gui1lib / vendorlib を参照
├── app2-2.0.0.spdx.json
├── service-0.9.0.spdx.json      #   Qt 非依存 (SQLite 静的リンクのみ)
├── product-app1-1.0.0.spdx.json # 製品 (用途による組み合わせ) 単位のバンドル
├── product-app2-1.0.0.spdx.json
└── product-service-1.0.0.spdx.json
```

Relation の実例(app1-1.0.0.spdx.json、実際の Qt インストールの SPDXID に解決される):

```
SPDXRef-Package-app1 DYNAMIC_LINK DocumentRef-qtbase:SPDXRef-Package-qtbase-qt-module-Core-14f2e7e421b1
SPDXRef-Package-app1 DYNAMIC_LINK DocumentRef-corelib:SPDXRef-Package-corelib
SPDXRef-Package-app1 DYNAMIC_LINK DocumentRef-vendorlib:SPDXRef-Package-vendorlib
SPDXRef-Package-corelib STATIC_LINK SPDXRef-Package-SQLite      (corelib 側ドキュメント)
```

- 動的リンク = `DYNAMIC_LINK` + `ExternalDocumentRef`(参照先ドキュメントの SHA1 付き)
- 静的リンク (SQLite) = 成果物ではないため、リンク元ドキュメントへの Package 埋め込み + `STATIC_LINK`
- 記録するのは各ターゲットの**直接依存のみ**。推移的依存は SBOM の連鎖で辿る

## 使い方

### 各リポジトリの CMakeLists.txt

```cmake
add_library(corelib SHARED src/corelib.cpp)
target_link_libraries(corelib PUBLIC Qt6::Core PRIVATE sqlite)

if(COMMAND sbom_add_target)   # SBOM 環境なしでも単独ビルド可能
    sbom_add_target(corelib
        LICENSE_DECLARED  "LicenseRef-MyCompany-Proprietary"   # 省略時 NOASSERTION
        LICENSE_CONCLUDED "LicenseRef-MyCompany-Proprietary"
        COPYRIGHT         "Copyright (c) 2026 Example Corp"
    )
endif()
```

静的リンクされる OSS には `sbom_describe_package(sqlite NAME "SQLite" VERSION "3.53.3" LICENSE "blessing" ...)`。
`PURL` (パッケージ識別子) に加え `CPE` (脆弱性照合用の CPE 2.3、例
`cpe:2.3:a:sqlite:sqlite:3.53.3:*:*:*:*:*:*:*`) も指定でき、SPDX の
`externalRefs` (それぞれ `purl` / `cpe23Type`) として埋め込まれる。
受領バイナリには Config.cmake で `SBOM_SPDX_DOCUMENT` プロパティを設定
([vendorlib/cmake/VendorlibConfig.cmake](vendorlib/cmake/VendorlibConfig.cmake) 参照)。

### トップレベル(スーパービルド)

```cmake
include(Sbom)

# 独自 (プロプライエタリ) ライセンス定義 — 参照する SBOM ドキュメントに
# hasExtractedLicensingInfos として本文ごと埋め込まれる (TEXT_FILE も可)
sbom_define_license(
    ID   LicenseRef-MyCompany-Proprietary
    NAME "Example Corp Proprietary License"
    TEXT "Proprietary software of Example Corp.\n..."
)

add_subdirectory(...)
sbom_add_product(NAME product-app1 VERSION 1.0.0 ROOT_TARGETS app1)
sbom_finalize(SUPPLIER "Organization: Example Corp" SUPPLIER_URL "https://sbom.example.com")
```

### ビルドと生成

```bat
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release ^
      -DCMAKE_PREFIX_PATH=C:/Qt/6.11.1/msvc2022_64 -DSBOM_BUILD_ID=<ビルド識別子>
cmake --build build
cmake --build build --target sbom      :: 開発時 (未署名バイナリに対して生成)
```

### コード署名する場合(ビルドサーバ / 署名サーバ分離)

Authenticode 署名は PE ファイル末尾に署名情報を追記するため、成果物のハッシュが
**署名前後で変わる**(実測: app1.exe が 12,288B→13,704B、SHA256 も別値)。SBOM は
出荷する実成果物を記述すべきなので、署名後のハッシュに揃える必要がある。

署名は USB トークンの都合で別サーバで行うため、バイナリを往復させず
**「SBOM を署名サーバへ渡してハッシュだけ更新」**する運用とする(動かすのはテキスト
ファイルのみで事故が起きにくい)。

```bat
:: [ビルドサーバ] Qt/vendor 等との Relation を張った SBOM を生成 (ハッシュは未署名時のもの)
cmake --build build
cmake --build build --target sbom
:: → build\bin\ と build\sbom\*.spdx.json を署名サーバへ受け渡す

:: [署名サーバ] 自社成果物にのみ署名 (受領 vendorlib.dll は署名しない)
signtool sign /fd SHA256 /n "Example Corp" /tr http://timestamp... /td SHA256 ^
    build\bin\app1.exe build\bin\corelib.dll ...
:: 署名済みバイナリのハッシュへ更新 (相互参照の SHA1 連鎖も維持)
python scripts\rehash_sbom.py --sbom-dir build\sbom --artifact-dir build\bin
```

`rehash_sbom.py` が必要とする入力は **SBOM 群と署名済みバイナリだけ**。Qt SBOM・
vendor SBOM・ビルドマニフェストは署名サーバに配布しなくてよい。成果物ハッシュを
更新すると SBOM ファイル自体の SHA1 が変わるため、それを `ExternalDocumentRef` で
参照している他ドキュメントの SHA1 も依存順に連鎖更新する。Qt/vendor など署名対象外
(ローカルにないドキュメント)への参照は変更しない。

> 実測 (自社成果物6つを実署名 → rehash): verify が署名前は6件のハッシュ不一致を検出
> → rehash で6成果物 + 11件のドキュメント間参照を更新 → verify 0エラー、SPDX 2.3
> 準拠を維持、Qt 参照 SHA1 は不変。

> 補足: Windows には署名前後で不変な「Authenticode ハッシュ」(証明書テーブル等を
> 除外して計算)もあるが、これはファイル全体のハッシュではなく `sha256sum` 等での
> 検証と一致しない。SPDX の標準 checksum フィールドには使わず、署名後の実ファイル
> ハッシュを記録する方針とする。

### 検証

```bash
uv sync                       # 初回のみ (pytest + spdx-tools)
uv run pytest                 # 生成器・再ハッシュの単体テスト
uv run pyspdxtools -i build/sbom/app1-1.0.0.spdx.json   # SPDX 2.3 準拠検証
python scripts/verify_sbom.py --manifest build/sbom_manifest.json --sbom-dir build/sbom
                              # 相互参照の SHA1 / SPDXID / 成果物チェックサム整合
```

CI は [ci/Jenkinsfile](ci/Jenkinsfile) 参照(ビルドサーバ: configure → build → sbom → 受け渡し /
署名サーバ: sign → rehash → validate → archive)。

## 構成

```
cmake/Sbom.cmake         SBOM 収集 CMake モジュール (再利用可能な共通部品)
scripts/sbomgen/         SPDX 2.3 生成器 + 再ハッシュ (Python 標準ライブラリのみ)
scripts/generate_sbom.py `ninja sbom` から呼ばれる生成 CLI (ビルドサーバ)
scripts/rehash_sbom.py   署名後のハッシュ更新 CLI (署名サーバ)
scripts/verify_sbom.py   相互参照整合性の検証 CLI
tests/                   pytest (実機 Qt インストールへの統合テスト含む)
corelib, gui1lib, ...    「別リポジトリ」を模したサンプルプロジェクト群
vendorlib/               受領バイナリ + 受領 SBOM の模擬
```

## 制約・今後の課題

- Qt の Private モジュール・プラグイン (platforms 等)・MSVC ランタイム・OS DLL は対象外
- `LINK_LIBRARIES` のジェネレータ式は解決しない(通常のターゲット名リンクのみ)
- ninja 単一コンフィグ前提(Multi-Config を使う場合はマニフェストの per-config 化が必要)
- コード署名する場合は署名後に SBOM のハッシュを更新すること(`rehash_sbom.py`。上記「コード署名する場合」参照)
- 再ハッシュはファイル名で署名済みバイナリを照合する(同一ビルド内で成果物ファイル名が一意である前提)
- SBOM の作成日時は生成のたびに変わる(完全な再現性が必要なら `SOURCE_DATE_EPOCH` 対応を検討)
- Qt がユーザプロジェクト向け SBOM 公開 API を提供したら移行を検討
  (現状は `_qt_internal_*` の内部 API のみ。本実験の CMake API は薄く保っている)
