# 自社 DLL: Qt6::Core + Qt6::Widgets + Qt6::Core5Compat を利用
# (Core5Compat は qtbase ではなく qt5compat リポジトリの SBOM に属する —
#  複数の Qt SBOM ドキュメントへの参照解決を検証する)
cmake_minimum_required(VERSION 3.21)
project(gui2lib VERSION 2.1.0 LANGUAGES CXX)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Core5Compat)

add_library(gui2lib SHARED
    src/gui2lib.h
    src/gui2lib.cpp
)
target_compile_definitions(gui2lib PRIVATE GUI2LIB_LIBRARY)
target_include_directories(gui2lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(gui2lib
    PUBLIC  Qt6::Core Qt6::Widgets
    PRIVATE Qt6::Core5Compat
)

if(COMMAND sbom_add_target)
    sbom_add_target(gui2lib)
endif()
