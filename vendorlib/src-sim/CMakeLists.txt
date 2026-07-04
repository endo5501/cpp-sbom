# vendorlib の「他社側」ビルドを模擬する独立プロジェクト。
# 本体のスーパービルドには含めない — 一度ビルドして生成物
# (vendorlib.dll / vendorlib.lib) を ../bin, ../lib に配置し、
# 以後は受領バイナリとしてのみ扱う。
cmake_minimum_required(VERSION 3.21)
project(vendorlib VERSION 1.2.3 LANGUAGES CXX)

add_library(vendorlib SHARED vendorlib.cpp)
target_compile_definitions(vendorlib PRIVATE VENDORLIB_BUILD)
target_include_directories(vendorlib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
