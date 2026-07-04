# スーパービルド: 各リポジトリ (実運用では別 git リポジトリ) をまとめてビルドする
cmake_minimum_required(VERSION 3.21)
project(cpp-sbom-superbuild VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/utf-8)
endif()

# EXE/DLL を build/bin に集約 (app1.exe が corelib.dll 等を見つけられるように)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# 受領ライブラリ (vendorlib) の Config パッケージ
set(Vendorlib_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendorlib/cmake)

# SBOM 生成モジュール
include(Sbom)

# 自社プロプライエタリライセンスの定義 (参照する SBOM ドキュメントに
# hasExtractedLicensingInfos として埋め込まれる)
sbom_define_license(
    ID   LicenseRef-MyCompany-Proprietary
    NAME "Example Corp Proprietary License"
    TEXT "Proprietary software of Example Corp.\nAll rights reserved. Unauthorized reproduction or redistribution is prohibited."
)

add_subdirectory(sqlite)
add_subdirectory(corelib)
add_subdirectory(gui1lib)
add_subdirectory(gui2lib)
add_subdirectory(app1)
add_subdirectory(app2)
add_subdirectory(service)

# 「用途による組み合わせ」ごとの製品 SBOM
sbom_add_product(NAME product-app1    VERSION 1.0.0 ROOT_TARGETS app1)
sbom_add_product(NAME product-app2    VERSION 1.0.0 ROOT_TARGETS app2)
sbom_add_product(NAME product-service VERSION 1.0.0 ROOT_TARGETS service)

sbom_finalize(
    SUPPLIER      "Organization: Example Corp"
    SUPPLIER_URL  "https://sbom.example.com"
)
