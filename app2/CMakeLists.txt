# 自社 EXE: Qt6::Core + Qt6::Widgets + Qt6::Network + corelib + gui2lib + vendorlib を利用
cmake_minimum_required(VERSION 3.21)
project(app2 VERSION 2.0.0 LANGUAGES CXX)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)
find_package(Vendorlib REQUIRED)

add_executable(app2 src/main.cpp)
target_link_libraries(app2 PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
    corelib
    gui2lib
    Vendorlib::vendorlib
)

if(COMMAND sbom_add_target)
    sbom_add_target(app2
        LICENSE_DECLARED  "LicenseRef-MyCompany-Proprietary"
        LICENSE_CONCLUDED "LicenseRef-MyCompany-Proprietary"
        COPYRIGHT         "Copyright (c) 2026 Example Corp"
    )
endif()
