cmake_minimum_required(VERSION 3.22.1)
project(rasp CXX)

add_library(rasp SHARED
    android/jni_bridge.cpp
    android/common.cpp
    android/hook_bytes.cpp
    android/named_artifacts.cpp
    android/art_integrity.cpp
    android/elf_anon.cpp
    android/maps_integrity.cpp
    android/got_plt.cpp
    android/uprobe_scan.cpp
    android/opcode_scan.cpp
    android/emulator_scan.cpp
    android/emulator_hw.cpp
    android/custom_rom_scan.cpp
    android/tamper_scan.cpp
    android/root_checks.cpp)

target_include_directories(rasp PRIVATE android)
target_compile_options(rasp PRIVATE -std=c++17 -O2 -fvisibility=hidden -fvisibility-inlines-hidden)
target_link_options(rasp PRIVATE -Wl,--exclude-libs,ALL)
target_link_libraries(rasp log dl vulkan android z)
