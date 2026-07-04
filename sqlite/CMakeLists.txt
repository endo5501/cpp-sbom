# SQLite amalgamation を STATIC ライブラリ化するリポジトリ (実環境の再現)
cmake_minimum_required(VERSION 3.21)
project(sqlite VERSION 3.53.3 LANGUAGES C)

add_library(sqlite STATIC sqlite3.c)
target_include_directories(sqlite PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# 静的リンクされる OSS のメタデータを SBOM 用に宣言する。
# このターゲットをリンクした EXE/DLL の SBOM に Package として埋め込まれ、
# STATIC_LINK の Relationship が張られる。
if(COMMAND sbom_describe_package)
    sbom_describe_package(sqlite
        NAME        "SQLite"
        VERSION     "3.53.3"
        LICENSE     "blessing"
        SUPPLIER    "Organization: SQLite Consortium"
        PURL        "pkg:generic/sqlite@3.53.3"
        DOWNLOAD    "https://www.sqlite.org/2026/sqlite-amalgamation-3530300.zip"
    )
endif()
