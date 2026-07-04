# 自社 EXE: sqlite (STATIC) のみ利用、Qt 不使用
# (Qt 非依存ターゲットの SBOM 生成パスを検証する)
cmake_minimum_required(VERSION 3.21)
project(service VERSION 0.9.0 LANGUAGES CXX)

add_executable(service src/main.cpp)
target_link_libraries(service PRIVATE sqlite)

if(COMMAND sbom_add_target)
    sbom_add_target(service)
endif()
