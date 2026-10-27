#include <jni.h>
#include <string>
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

namespace {

long now_us() {
    timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000L + t.tv_nsec / 1000;
}

JNIEnv* g_env = nullptr;
NativeResult check_art() { return check_art_entrypoint_integrity(g_env); }

struct Check { const char* id; NativeResult (*fn)(); const char* group; int certainty; };

const Check CHECKS[] = {
    {"HOOK_BYTES",               check_hook_bytes,           "INSTRUMENTATION", CERT_STRONG},
    {"NAMED_LINKER_EXPORTS",     check_linker_exports,       "INSTRUMENTATION", CERT_PROOF},
    {"LIB_FROM_ROOT_PATH",       check_lib_from_root_path,   "INSTRUMENTATION", CERT_PROOF},
    {"MAPS_INTEGRITY",           check_maps_integrity,       "INSTRUMENTATION", CERT_WEAK},
    {"GOT_PLT_INTEGRITY",        check_got_plt_integrity,    "INSTRUMENTATION", CERT_STRONG},
    {"UPROBE_RESIDUE",           check_uprobe_residue,       "INSTRUMENTATION", CERT_STRONG},
    {"OPCODE_TRAMPOLINE",        check_opcode_trampoline,    "INSTRUMENTATION", CERT_STRONG},
    {"ELF_IN_ANON",              check_elf_in_anon,          "INSTRUMENTATION", CERT_WEAK},
    {"EMU_CPU_ISA",              check_emu_cpu_isa,          "EMULATOR",        CERT_WEAK},
    {"EMU_TRANSLATOR",           check_emu_translator,       "EMULATOR",        CERT_WEAK},
    {"EMU_PROPS_QEMU",           check_emu_props_qemu,       "EMULATOR",        CERT_STRONG},
    {"EMU_PROPS_HINTS",          check_emu_props_hints,      "EMULATOR",        CERT_WEAK},
    {"EMU_DEVNODES",             check_emu_devnodes,         "EMULATOR",        CERT_STRONG},
    {"EMU_MOUNTS",               check_emu_mounts,           "EMULATOR",        CERT_WEAK},
    {"EMU_VULKAN",               check_emu_vulkan,           "EMULATOR",        CERT_STRONG},
    {"EMU_SENSORS",              check_emu_sensors,          "EMULATOR",        CERT_STRONG},
    {"CROM_BOOT",                check_crom_boot,            "BOOTLOADER",      CERT_STRONG},
    {"CROM_SIGN",                check_crom_sign,            "BOOTLOADER",      CERT_WEAK},
    {"CROM_ROM_PROPS",           check_crom_rom_props,       "BOOTLOADER",      CERT_STRONG},
    {"TAMPER_SIGNING_BLOCK",     check_tamper_signing_block, "APP_INTEGRITY",   CERT_STRONG},
    {"CLV_MAPS_ENGINE_STRING",   check_clone_engine_maps,    "APP_INTEGRITY",   CERT_WEAK},
    {"ROOT_SU_PATH",             check_root_su_path,         "ROOT",            CERT_STRONG},
    {"ROOT_SELINUX_DOMAIN",      check_root_selinux_domain,  "ROOT",            CERT_WEAK},
    {"ROOT_PROC_STATUS",         check_root_proc_status,     "ROOT",            CERT_PROOF},
    {"ROOT_MOUNT_TOKENS",        check_root_mount_tokens,    "ROOT",            CERT_WEAK},
    {"ROOT_KERNEL_STRING",       check_root_kernel_string,   "ROOT",            CERT_STRONG},
    {"ROOT_MAGISK_DAEMON",       check_root_magisk_daemon,   "ROOT",            CERT_STRONG},
    {"ART_ENTRYPOINT_INTEGRITY", check_art,                  "INSTRUMENTATION", CERT_WEAK},
};

}

extern "C" JNIEXPORT jstring JNICALL
Java_rasp_sdk_NativeCore_run(JNIEnv* env, jclass, jstring signer) {
    init_own_process_name();
    g_maps = read_maps();
    mem_run_begin();
    g_signer_baseline.clear();
    if (signer) {
        const char* s = env->GetStringUTFChars(signer, nullptr);
        if (s) { g_signer_baseline = s; env->ReleaseStringUTFChars(signer, s); }
    }
    g_env = env;
    std::string json = "[";
    for (const Check& c : CHECKS) {
        long t0 = now_us();
        NativeResult r = c.fn();
        long us = now_us() - t0;
        if (json.size() > 1) json += ",";
        json += std::string("{\"id\":\"") + c.id + "\",\"group\":\"" + c.group +
                "\",\"certainty\":" + std::to_string(c.certainty) + ",\"status\":" + std::to_string(r.status) +
                ",\"us\":" + std::to_string(us) + ",\"details\":\"" + json_escape(r.details) + "\"}";
    }
    json += "]";
    mem_run_end();
    return env->NewStringUTF(json.c_str());
}
