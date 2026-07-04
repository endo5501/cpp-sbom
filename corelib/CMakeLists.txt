# 自社 DLL: Qt6::Core + sqlite (STATIC) を利用
cmake_minimum_required(VERSION 3.21)
project(corelib VERSION 1.2.0 LANGUAGES CXX)

find_package(Qt6 REQUIRED COMPONENTS Core)

add_library(corelib SHARED
    src/corelib.h
    src/corelib.cpp
)
target_compile_definitions(corelib PRIVATE CORELIB_LIBRARY)
target_include_directories(corelib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(corelib
    PUBLIC  Qt6::Core
    PRIVATE sqlite
)

if(COMMAND sbom_add_target)
    sbom_add_target(corelib)
endif()
