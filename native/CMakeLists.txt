cmake_minimum_required(VERSION 3.22.1)
project(blackhex CXX)

add_library(blackhex SHARED
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

target_include_directories(blackhex PRIVATE android)
target_compile_options(blackhex PRIVATE -std=c++17 -O2 -fvisibility=hidden -fvisibility-inlines-hidden
    -ffile-prefix-map=${CMAKE_SOURCE_DIR}=native -ffile-prefix-map=${CMAKE_BINARY_DIR}=build -ffile-prefix-map=${ANDROID_NDK}=ndk)
target_link_options(blackhex PRIVATE -Wl,--exclude-libs,ALL -Wl,-z,max-page-size=16384)
target_link_libraries(blackhex log dl vulkan android z)
