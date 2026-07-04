# Sbom.cmake — ビルド成果物 (EXE/DLL) の SPDX 2.3 SBOM 生成モジュール
#
# 使い方 (各リポジトリの CMakeLists.txt):
#   sbom_add_target(<tgt>
#       [LICENSE_DECLARED <SPDX式>]    宣言ライセンス (LicenseRef-* 可)
#       [LICENSE_CONCLUDED <SPDX式>]   結論ライセンス
#       [COPYRIGHT <text>])            著作権表記
#                                      EXE/DLL を SBOM 対象として登録
#   sbom_describe_package(<tgt> ...)   静的リンクされる OSS のメタデータ宣言
#   sbom_declare_external(<tgt> SPDX_DOCUMENT <path>)
#                                      受領バイナリに受領 SBOM を紐付け
#                                      (Config.cmake 側で SBOM_SPDX_DOCUMENT
#                                       プロパティを設定してもよい)
# 使い方 (トップレベル):
#   sbom_define_license(ID LicenseRef-MyCompany-Proprietary
#       [NAME <表示名>] TEXT <本文> | TEXT_FILE <パス>)
#                                      独自ライセンス定義。参照するドキュメントに
#                                      hasExtractedLicensingInfos として埋め込まれる
#   sbom_add_product(NAME <n> VERSION <v> ROOT_TARGETS <tgts...>)
#   sbom_finalize(SUPPLIER <org> SUPPLIER_URL <url> [OUTPUT_DIR <dir>]
#                 [NAMESPACE_BASE <uri>] [QT_SBOM_DIR <dir>])
#
# `ninja sbom` (または cmake --build . --target sbom) で全成果物のビルド後に
# Python 生成器 (scripts/generate_sbom.py, 標準ライブラリのみ) を実行する。
#
# CI からはビルド識別子を -DSBOM_BUILD_ID=<id> で渡す (DocumentNamespace の
# 一意性に使われる。未指定時は "local")。

include_guard(GLOBAL)

set(SBOM_BUILD_ID "local" CACHE STRING "Build identifier used for SBOM document namespaces")

set(_SBOM_MODULE_DIR "${CMAKE_CURRENT_LIST_DIR}")

define_property(GLOBAL PROPERTY SBOM_TARGETS
    BRIEF_DOCS "Targets registered for SBOM generation")
define_property(GLOBAL PROPERTY SBOM_PRODUCTS
    BRIEF_DOCS "Product definitions: name|version|root;targets")
define_property(GLOBAL PROPERTY SBOM_EXTERNALS
    BRIEF_DOCS "Received-SBOM targets: name|spdx-document-path")
define_property(GLOBAL PROPERTY SBOM_LICENSES
    BRIEF_DOCS "Custom license definition ids (LicenseRef-*)")

# JSON 文字列値のエスケープ (ライセンス本文の改行・引用符等)
function(_sbom_json_escape out_var input)
    string(REPLACE "\\" "\\\\" _escaped "${input}")
    string(REPLACE "\"" "\\\"" _escaped "${_escaped}")
    string(REPLACE "\t" "\\t" _escaped "${_escaped}")
    string(REPLACE "\r" "" _escaped "${_escaped}")
    string(REPLACE "\n" "\\n" _escaped "${_escaped}")
    set(${out_var} "${_escaped}" PARENT_SCOPE)
endfunction()

# EXE/DLL を SBOM 対象として登録する。
# リポジトリ名 = 呼び出し元の PROJECT_NAME、バージョン = PROJECT_VERSION。
# 受領 SBOM 付きの IMPORTED ターゲット (Vendorlib 等) はディレクトリスコープの
# ため sbom_finalize からは見えないことがある — ここ (リンク元と同じスコープ)
# で externals として収集する。
function(sbom_add_target target)
    cmake_parse_arguments(PARSE_ARGV 1 ARG
        "" "LICENSE_DECLARED;LICENSE_CONCLUDED;COPYRIGHT" "")
    set_target_properties(${target} PROPERTIES
        SBOM_REPO               "${PROJECT_NAME}"
        SBOM_VERSION            "${PROJECT_VERSION}"
        SBOM_LICENSE_DECLARED   "${ARG_LICENSE_DECLARED}"
        SBOM_LICENSE_CONCLUDED  "${ARG_LICENSE_CONCLUDED}"
        SBOM_COPYRIGHT          "${ARG_COPYRIGHT}"
    )
    set_property(GLOBAL APPEND PROPERTY SBOM_TARGETS ${target})

    get_target_property(_links ${target} LINK_LIBRARIES)
    if(_links)
        foreach(_link IN LISTS _links)
            if(TARGET ${_link})
                get_target_property(_ext_doc ${_link} SBOM_SPDX_DOCUMENT)
                if(_ext_doc)
                    set_property(GLOBAL APPEND PROPERTY SBOM_EXTERNALS
                        "${_link}|${_ext_doc}")
                endif()
            endif()
        endforeach()
    endif()
endfunction()

# 静的ライブラリターゲットに OSS メタデータを宣言する。
# このターゲットをリンクする成果物の SBOM に Package として埋め込まれ、
# STATIC_LINK Relationship が張られる。
function(sbom_describe_package target)
    cmake_parse_arguments(PARSE_ARGV 1 ARG
        "" "NAME;VERSION;LICENSE;SUPPLIER;PURL;DOWNLOAD" "")
    if(NOT ARG_NAME)
        message(FATAL_ERROR "sbom_describe_package: NAME is required")
    endif()
    set_target_properties(${target} PROPERTIES
        SBOM_REPO              "${PROJECT_NAME}"
        SBOM_VERSION           "${PROJECT_VERSION}"
        SBOM_DESCRIBE_NAME     "${ARG_NAME}"
        SBOM_DESCRIBE_VERSION  "${ARG_VERSION}"
        SBOM_DESCRIBE_LICENSE  "${ARG_LICENSE}"
        SBOM_DESCRIBE_SUPPLIER "${ARG_SUPPLIER}"
        SBOM_DESCRIBE_PURL     "${ARG_PURL}"
        SBOM_DESCRIBE_DOWNLOAD "${ARG_DOWNLOAD}"
    )
    set_property(GLOBAL APPEND PROPERTY SBOM_TARGETS ${target})
endfunction()

# 受領バイナリの IMPORTED ターゲットに受領 SBOM (SPDX 2.x) を紐付ける。
function(sbom_declare_external target)
    cmake_parse_arguments(PARSE_ARGV 1 ARG "" "SPDX_DOCUMENT" "")
    if(NOT ARG_SPDX_DOCUMENT)
        message(FATAL_ERROR "sbom_declare_external: SPDX_DOCUMENT is required")
    endif()
    set_target_properties(${target} PROPERTIES
        SBOM_SPDX_DOCUMENT "${ARG_SPDX_DOCUMENT}")
endfunction()

# 独自ライセンス (LicenseRef-*) を定義する。プロプライエタリライセンス等、
# SPDX License List に無いライセンスに使う。参照するドキュメントに
# hasExtractedLicensingInfos として本文ごと埋め込まれる。
function(sbom_define_license)
    cmake_parse_arguments(PARSE_ARGV 0 ARG "" "ID;NAME;TEXT;TEXT_FILE" "")
    if(NOT ARG_ID)
        message(FATAL_ERROR "sbom_define_license: ID is required")
    endif()
    if(NOT ARG_ID MATCHES "^LicenseRef-[A-Za-z0-9.\\-]+$")
        message(FATAL_ERROR
            "sbom_define_license: ID must match 'LicenseRef-[A-Za-z0-9.-]+' (got '${ARG_ID}')")
    endif()
    if(ARG_TEXT_FILE)
        file(READ "${ARG_TEXT_FILE}" ARG_TEXT)
    endif()
    if(NOT ARG_TEXT)
        message(FATAL_ERROR "sbom_define_license: TEXT or TEXT_FILE is required")
    endif()
    set_property(GLOBAL APPEND PROPERTY SBOM_LICENSES "${ARG_ID}")
    set_property(GLOBAL PROPERTY "SBOM_LICENSE_NAME_${ARG_ID}" "${ARG_NAME}")
    set_property(GLOBAL PROPERTY "SBOM_LICENSE_TEXT_${ARG_ID}" "${ARG_TEXT}")
endfunction()

# 「用途による組み合わせ」= 製品を定義する。製品ごとに、構成リポジトリの
# SBOM を ExternalDocumentRef で束ねる製品 SBOM が生成される。
function(sbom_add_product)
    cmake_parse_arguments(PARSE_ARGV 0 ARG "" "NAME;VERSION" "ROOT_TARGETS")
    if(NOT ARG_NAME OR NOT ARG_ROOT_TARGETS)
        message(FATAL_ERROR "sbom_add_product: NAME and ROOT_TARGETS are required")
    endif()
    if(NOT ARG_VERSION)
        set(ARG_VERSION "0")
    endif()
    string(REPLACE ";" "," _roots "${ARG_ROOT_TARGETS}")
    set_property(GLOBAL APPEND PROPERTY SBOM_PRODUCTS
        "${ARG_NAME}|${ARG_VERSION}|${_roots}")
endfunction()

# Qt インストールの sbom ディレクトリを探す (Qt6_DIR から導出 + フォールバック)
function(_sbom_find_qt_sbom_dir out_var)
    set(_candidates "")
    if(Qt6_DIR)
        # <prefix>/lib/cmake/Qt6 -> <prefix>/sbom
        get_filename_component(_qt_prefix "${Qt6_DIR}/../../.." ABSOLUTE)
        list(APPEND _candidates "${_qt_prefix}/sbom")
    endif()
    foreach(_prefix IN LISTS CMAKE_PREFIX_PATH)
        list(APPEND _candidates "${_prefix}/sbom")
    endforeach()
    foreach(_dir IN LISTS _candidates)
        if(IS_DIRECTORY "${_dir}")
            set(${out_var} "${_dir}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
    set(${out_var} "" PARENT_SCOPE)
endfunction()

# JSON 文字列リストを組み立てるヘルパ: "a","b","c"
function(_sbom_json_string_list out_var)
    set(_items "")
    foreach(_item IN LISTS ARGN)
        list(APPEND _items "\"${_item}\"")
    endforeach()
    list(JOIN _items ", " _joined)
    set(${out_var} "${_joined}" PARENT_SCOPE)
endfunction()

# 全登録情報からマニフェスト JSON を生成し、`sbom` カスタムターゲットを定義する
function(sbom_finalize)
    cmake_parse_arguments(PARSE_ARGV 0 ARG
        "" "SUPPLIER;SUPPLIER_URL;NAMESPACE_BASE;OUTPUT_DIR;QT_SBOM_DIR" "")

    if(NOT ARG_SUPPLIER)
        message(FATAL_ERROR "sbom_finalize: SUPPLIER is required")
    endif()
    if(NOT ARG_NAMESPACE_BASE)
        if(NOT ARG_SUPPLIER_URL)
            message(FATAL_ERROR "sbom_finalize: SUPPLIER_URL or NAMESPACE_BASE is required")
        endif()
        set(ARG_NAMESPACE_BASE "${ARG_SUPPLIER_URL}/spdxdocs")
    endif()
    if(NOT ARG_OUTPUT_DIR)
        set(ARG_OUTPUT_DIR "${CMAKE_BINARY_DIR}/sbom")
    endif()
    if(NOT ARG_QT_SBOM_DIR)
        _sbom_find_qt_sbom_dir(ARG_QT_SBOM_DIR)
    endif()

    get_property(_targets GLOBAL PROPERTY SBOM_TARGETS)
    if(NOT _targets)
        message(WARNING "sbom_finalize: no targets registered — skipping SBOM setup")
        return()
    endif()

    # ---- externals (sbom_add_target で収集済み) --------------------------
    set(_external_entries "")
    set(_seen_externals "")
    get_property(_externals GLOBAL PROPERTY SBOM_EXTERNALS)
    foreach(_external IN LISTS _externals)
        string(REPLACE "|" ";" _parts "${_external}")
        list(GET _parts 0 _ext_name)
        list(GET _parts 1 _ext_doc)
        if(NOT "${_ext_name}" IN_LIST _seen_externals)
            list(APPEND _seen_externals "${_ext_name}")
            string(APPEND _external_entries
                "    \"${_ext_name}\": { \"spdx_document\": \"${_ext_doc}\" },\n")
        endif()
    endforeach()

    # ---- targets ---------------------------------------------------------
    set(_target_entries "")
    set(_artifact_targets "")

    foreach(_tgt IN LISTS _targets)
        get_target_property(_type ${_tgt} TYPE)
        get_target_property(_repo ${_tgt} SBOM_REPO)
        get_target_property(_version ${_tgt} SBOM_VERSION)

        # 直接リンクのみを記録する (推移的依存は SBOM の連鎖で辿れる)
        get_target_property(_links ${_tgt} LINK_LIBRARIES)
        if(NOT _links)
            set(_links "")
        endif()

        _sbom_json_string_list(_links_json ${_links})

        if(_type STREQUAL "STATIC_LIBRARY")
            get_target_property(_d_name ${_tgt} SBOM_DESCRIBE_NAME)
            set(_describe "")
            if(_d_name)
                get_target_property(_d_version  ${_tgt} SBOM_DESCRIBE_VERSION)
                get_target_property(_d_license  ${_tgt} SBOM_DESCRIBE_LICENSE)
                get_target_property(_d_supplier ${_tgt} SBOM_DESCRIBE_SUPPLIER)
                get_target_property(_d_purl     ${_tgt} SBOM_DESCRIBE_PURL)
                get_target_property(_d_download ${_tgt} SBOM_DESCRIBE_DOWNLOAD)
                set(_describe ",\n      \"describe\": {\n")
                string(APPEND _describe "        \"name\": \"${_d_name}\"")
                foreach(_pair
                        "version|${_d_version}" "license|${_d_license}"
                        "supplier|${_d_supplier}" "purl|${_d_purl}"
                        "download|${_d_download}")
                    string(REPLACE "|" ";" _pair "${_pair}")
                    list(GET _pair 0 _key)
                    list(GET _pair 1 _value)
                    if(_value)
                        string(APPEND _describe ",\n        \"${_key}\": \"${_value}\"")
                    endif()
                endforeach()
                string(APPEND _describe "\n      }")
            endif()
            string(APPEND _target_entries
                "    {\n"
                "      \"name\": \"${_tgt}\",\n"
                "      \"type\": \"${_type}\",\n"
                "      \"repo\": \"${_repo}\",\n"
                "      \"version\": \"${_version}\",\n"
                "      \"links\": [${_links_json}]${_describe}\n"
                "    },\n")
        else()
            # ライセンス / 著作権 (指定時のみ出力。省略時は NOASSERTION になる)
            set(_license_fields "")
            get_target_property(_lic_declared  ${_tgt} SBOM_LICENSE_DECLARED)
            get_target_property(_lic_concluded ${_tgt} SBOM_LICENSE_CONCLUDED)
            get_target_property(_copyright     ${_tgt} SBOM_COPYRIGHT)
            if(_lic_declared)
                _sbom_json_escape(_value "${_lic_declared}")
                string(APPEND _license_fields
                    "      \"license_declared\": \"${_value}\",\n")
            endif()
            if(_lic_concluded)
                _sbom_json_escape(_value "${_lic_concluded}")
                string(APPEND _license_fields
                    "      \"license_concluded\": \"${_value}\",\n")
            endif()
            if(_copyright)
                _sbom_json_escape(_value "${_copyright}")
                string(APPEND _license_fields
                    "      \"copyright\": \"${_value}\",\n")
            endif()

            # EXE / DLL: 出力ファイルは generate 段階のジェネレータ式で解決
            string(APPEND _target_entries
                "    {\n"
                "      \"name\": \"${_tgt}\",\n"
                "      \"type\": \"${_type}\",\n"
                "      \"repo\": \"${_repo}\",\n"
                "      \"version\": \"${_version}\",\n"
                "${_license_fields}"
                "      \"file\": \"$<TARGET_FILE:${_tgt}>\",\n"
                "      \"links\": [${_links_json}]\n"
                "    },\n")
            list(APPEND _artifact_targets ${_tgt})
        endif()
    endforeach()

    # ---- licenses (独自ライセンス定義) ------------------------------------
    set(_license_entries "")
    get_property(_license_ids GLOBAL PROPERTY SBOM_LICENSES)
    if(_license_ids)
        list(REMOVE_DUPLICATES _license_ids)
    endif()
    foreach(_lic_id IN LISTS _license_ids)
        get_property(_lic_name GLOBAL PROPERTY "SBOM_LICENSE_NAME_${_lic_id}")
        get_property(_lic_text GLOBAL PROPERTY "SBOM_LICENSE_TEXT_${_lic_id}")
        _sbom_json_escape(_lic_text "${_lic_text}")
        string(APPEND _license_entries
            "    {\n"
            "      \"id\": \"${_lic_id}\",\n")
        if(_lic_name)
            _sbom_json_escape(_lic_name "${_lic_name}")
            string(APPEND _license_entries
                "      \"name\": \"${_lic_name}\",\n")
        endif()
        string(APPEND _license_entries
            "      \"text\": \"${_lic_text}\"\n"
            "    },\n")
    endforeach()

    # ---- products --------------------------------------------------------
    set(_product_entries "")
    get_property(_products GLOBAL PROPERTY SBOM_PRODUCTS)
    foreach(_product IN LISTS _products)
        string(REPLACE "|" ";" _parts "${_product}")
        list(GET _parts 0 _p_name)
        list(GET _parts 1 _p_version)
        list(GET _parts 2 _p_roots)
        string(REPLACE "," ";" _p_roots "${_p_roots}")
        _sbom_json_string_list(_roots_json ${_p_roots})
        string(APPEND _product_entries
            "    { \"name\": \"${_p_name}\", \"version\": \"${_p_version}\","
            " \"root_targets\": [${_roots_json}] },\n")
    endforeach()

    # ---- manifest 書き出し (末尾カンマを除去して結合) ----------------------
    string(REGEX REPLACE ",\n$" "\n" _target_entries "${_target_entries}")
    string(REGEX REPLACE ",\n$" "\n" _product_entries "${_product_entries}")
    string(REGEX REPLACE ",\n$" "\n" _external_entries "${_external_entries}")
    string(REGEX REPLACE ",\n$" "\n" _license_entries "${_license_entries}")

    set(_manifest_content "")
    string(APPEND _manifest_content
        "{\n"
        "  \"qt_sbom_dir\": \"${ARG_QT_SBOM_DIR}\",\n"
        "  \"supplier\": \"${ARG_SUPPLIER}\",\n"
        "  \"supplier_url\": \"${ARG_SUPPLIER_URL}\",\n"
        "  \"namespace_base\": \"${ARG_NAMESPACE_BASE}\",\n"
        "  \"build_id\": \"${SBOM_BUILD_ID}\",\n"
        "  \"licenses\": [\n${_license_entries}  ],\n"
        "  \"targets\": [\n${_target_entries}  ],\n"
        "  \"externals\": {\n${_external_entries}  },\n"
        "  \"products\": [\n${_product_entries}  ]\n"
        "}\n")

    set(_manifest_file "${CMAKE_BINARY_DIR}/sbom_manifest.json")
    file(GENERATE OUTPUT "${_manifest_file}" CONTENT "${_manifest_content}")

    # ---- sbom カスタムターゲット -----------------------------------------
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    get_filename_component(_script
        "${_SBOM_MODULE_DIR}/../scripts/generate_sbom.py" ABSOLUTE)

    # 全成果物のビルド完了に依存させる (古いバイナリのチェックサム化を防ぐ)
    add_custom_target(sbom
        COMMAND "${Python3_EXECUTABLE}" "${_script}"
                --manifest "${_manifest_file}"
                --out-dir "${ARG_OUTPUT_DIR}"
        DEPENDS ${_artifact_targets}
        COMMENT "Generating SPDX 2.3 SBOM documents into ${ARG_OUTPUT_DIR}"
        VERBATIM
    )

    message(STATUS "SBOM: ${CMAKE_BINARY_DIR} -> ${ARG_OUTPUT_DIR} "
                   "(qt_sbom_dir='${ARG_QT_SBOM_DIR}', build_id='${SBOM_BUILD_ID}')")
endfunction()
