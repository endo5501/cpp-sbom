# 自社 DLL: Qt6::Core + Qt6::Widgets + Qt6::Xml を利用
cmake_minimum_required(VERSION 3.21)
project(gui1lib VERSION 2.0.1 LANGUAGES CXX)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Xml)

add_library(gui1lib SHARED
    src/gui1lib.h
    src/gui1lib.cpp
)
target_compile_definitions(gui1lib PRIVATE GUI1LIB_LIBRARY)
target_include_directories(gui1lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(gui1lib
    PUBLIC  Qt6::Core Qt6::Widgets
    PRIVATE Qt6::Xml
)

if(COMMAND sbom_add_target)
    sbom_add_target(gui1lib
        LICENSE_DECLARED  "LicenseRef-MyCompany-Proprietary"
        LICENSE_CONCLUDED "LicenseRef-MyCompany-Proprietary"
        COPYRIGHT         "Copyright (c) 2026 Example Corp"
    )
endif()
