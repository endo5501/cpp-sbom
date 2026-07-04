# 自社 EXE: sqlite (STATIC) のみ利用、Qt 不使用
# (Qt 非依存ターゲットの SBOM 生成パスを検証する)
cmake_minimum_required(VERSION 3.21)
project(service VERSION 0.9.0 LANGUAGES CXX)

add_executable(service src/main.cpp)
target_link_libraries(service PRIVATE sqlite)

if(COMMAND sbom_add_target)
    sbom_add_target(service
        LICENSE_DECLARED  "LicenseRef-MyCompany-Proprietary"
        LICENSE_CONCLUDED "LicenseRef-MyCompany-Proprietary"
        COPYRIGHT         "Copyright (c) 2026 Example Corp"
    )
endif()
