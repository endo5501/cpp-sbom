# 受領バイナリ (vendorlib.dll / vendorlib.lib) を IMPORTED ターゲットとして定義する。
# ライブラリと一緒に受領した SBOM (SPDX 2.3 JSON) を SBOM_SPDX_DOCUMENT
# プロパティでターゲットに紐付ける — Sbom.cmake がこれを読んで
# ExternalDocumentRef + Relationship を生成する。

if(TARGET Vendorlib::vendorlib)
    return()
endif()

get_filename_component(_vendorlib_root "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

add_library(Vendorlib::vendorlib SHARED IMPORTED)
set_target_properties(Vendorlib::vendorlib PROPERTIES
    IMPORTED_LOCATION             "${_vendorlib_root}/bin/vendorlib.dll"
    IMPORTED_IMPLIB               "${_vendorlib_root}/lib/vendorlib.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${_vendorlib_root}/include"
    SBOM_SPDX_DOCUMENT            "${_vendorlib_root}/sbom/vendorlib-1.2.3.spdx.json"
)

unset(_vendorlib_root)
