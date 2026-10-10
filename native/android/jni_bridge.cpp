#include <jni.h>
#include <string>
#include <vector>
#include <ctime>
#include "common.h"
#include "hook_bytes.h"
#include "named_artifacts.h"
#include "art_integrity.h"
#include "elf_anon.h"
#include "maps_integrity.h"
#include "got_plt.h"
#include "uprobe_scan.h"
#include "opcode_scan.h"
#include "emulator_scan.h"
#include "emulator_hw.h"
#include "custom_rom_scan.h"
#include "tamper_scan.h"
#include "root_checks.h"

static long now_us() {
    timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000L + t.tv_nsec / 1000;
}

static NativeResult timed(NativeResult (*check)()) {
    long t0 = now_us();
    NativeResult r = check();
    r.us = now_us() - t0;
    return r;
}

extern "C" JNIEXPORT jstring JNICALL
Java_rasp_sdk_NativeCore_run(JNIEnv* env, jclass, jstring signer) {
    init_own_process_name();
    g_maps = read_maps();
    if (signer) {
        const char* s = env->GetStringUTFChars(signer, nullptr);
        g_signer_baseline = s ? s : "";
        if (s) env->ReleaseStringUTFChars(signer, s);
    } else {
        g_signer_baseline.clear();
    }
    std::vector<NativeResult> results = {
        timed(check_hook_bytes_direct),
        timed(check_hook_bytes_mem),
        timed(check_linker_exports),
        timed(check_lib_from_root_path),
        timed(check_maps_integrity),
        timed(check_got_plt_integrity),
        timed(check_uprobe_residue),
        timed(check_opcode_trampoline),
        timed(check_elf_in_anon),
        timed(check_emu_cpu_isa),
        timed(check_emu_translator),
        timed(check_emu_props),
        timed(check_emu_devnodes),
        timed(check_emu_mounts),
        timed(check_emu_vulkan),
        timed(check_emu_sensors),
        timed(check_crom_boot),
        timed(check_crom_sign),
        timed(check_crom_rom_props),
        timed(check_tamper_signing_block),
        timed(check_root_su_path),
        timed(check_root_selinux_domain),
        timed(check_root_proc_status),
        timed(check_root_mount_tokens),
        timed(check_root_kernel_string),
        timed(check_root_magisk_daemon),
    };
    {
        long t0 = now_us();
        NativeResult r = check_art_entrypoint_integrity(env);
        r.us = now_us() - t0;
        results.push_back(r);
    }
    return env->NewStringUTF(results_to_json(results).c_str());
}
