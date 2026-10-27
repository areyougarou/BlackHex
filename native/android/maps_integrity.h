#pragma once
#include "common.h"
#include <cstdint>

NativeResult check_lib_from_root_path();

bool page_mapped(uintptr_t addr);

NativeResult check_maps_integrity();

NativeResult check_clone_engine_maps();
