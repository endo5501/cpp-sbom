# 自社 EXE: Qt6::Core + Qt6::Widgets + corelib + gui1lib + vendorlib (受領バイナリ) を利用
cmake_minimum_required(VERSION 3.21)
project(app1 VERSION 1.0.0 LANGUAGES CXX)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets)
find_package(Vendorlib REQUIRED)

add_executable(app1 src/main.cpp)
target_link_libraries(app1 PRIVATE
    Qt6::Core
    Qt6::Widgets
    corelib
    gui1lib
    Vendorlib::vendorlib
)

if(COMMAND sbom_add_target)
    sbom_add_target(app1
        LICENSE_DECLARED  "LicenseRef-MyCompany-Proprietary"
        LICENSE_CONCLUDED "LicenseRef-MyCompany-Proprietary"
        COPYRIGHT         "Copyright (c) 2026 Example Corp"
    )
endif()
