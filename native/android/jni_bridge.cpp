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

static NativeResult timed(NativeResult (*check)(), int certainty) {
    long t0 = now_us();
    NativeResult r = check();
    r.us = now_us() - t0;
    if (r.certainty == CERT_UNSET) r.certainty = certainty;
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
        timed(check_hook_bytes_direct, CERT_WEAK),
        timed(check_hook_bytes_mem, CERT_WEAK),
        timed(check_linker_exports, CERT_PROOF),
        timed(check_lib_from_root_path, CERT_PROOF),
        timed(check_maps_integrity, CERT_WEAK),
        timed(check_got_plt_integrity, CERT_STRONG),
        timed(check_uprobe_residue, CERT_STRONG),
        timed(check_opcode_trampoline, CERT_WEAK),
        timed(check_elf_in_anon, CERT_WEAK),
        timed(check_emu_cpu_isa, CERT_WEAK),
        timed(check_emu_translator, CERT_WEAK),
        timed(check_emu_props, CERT_WEAK),
        timed(check_emu_devnodes, CERT_STRONG),
        timed(check_emu_mounts, CERT_WEAK),
        timed(check_emu_vulkan, CERT_STRONG),
        timed(check_emu_sensors, CERT_STRONG),
        timed(check_crom_boot, CERT_STRONG),
        timed(check_crom_sign, CERT_WEAK),
        timed(check_crom_rom_props, CERT_STRONG),
        timed(check_tamper_signing_block, CERT_STRONG),
        timed(check_root_su_path, CERT_WEAK),
        timed(check_root_selinux_domain, CERT_WEAK),
        timed(check_root_proc_status, CERT_PROOF),
        timed(check_root_mount_tokens, CERT_WEAK),
        timed(check_root_kernel_string, CERT_STRONG),
        timed(check_root_magisk_daemon, CERT_STRONG),
    };
    {
        long t0 = now_us();
        NativeResult r = check_art_entrypoint_integrity(env);
        r.us = now_us() - t0;
        if (r.certainty == CERT_UNSET) r.certainty = CERT_WEAK;
        results.push_back(r);
    }
    return env->NewStringUTF(results_to_json(results).c_str());
}
