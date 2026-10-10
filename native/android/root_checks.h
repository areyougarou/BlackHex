#pragma once
#include "common.h"

NativeResult check_root_su_path();
NativeResult check_root_selinux_domain();
NativeResult check_root_proc_status();
NativeResult check_root_mount_tokens();
NativeResult check_root_kernel_string();
NativeResult check_root_magisk_daemon();
