#pragma once
#include "common.h"

NativeResult check_tamper_signing_block();
int raw_open(const char* path);
std::string own_apk_path(const std::vector<VmaEntry>& maps, const std::string& pkg);
