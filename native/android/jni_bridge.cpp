#include <jni.h>
#include <string>
#include <ctime>
#include "common.h"
#include "hook_bytes.h"
#include "elf_anon.h"
#include "maps_integrity.h"
#include "got_plt.h"
#include "uprobe_scan.h"
#include "opcode_scan.h"
#include "tamper_scan.h"

namespace {

long now_us() {
    timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000L + t.tv_nsec / 1000;
}

std::string jstr(JNIEnv* env, jstring s) {
    const char* c = s ? env->GetStringUTFChars(s, nullptr) : nullptr;
    std::string out = c ? c : "";
    if (c) env->ReleaseStringUTFChars(s, c);
    return out;
}

struct Check { const char* id; NativeResult (*fn)(); const char* group; };

const Check CHECKS[] = {
    {"HOOK_BYTES",               check_hook_bytes,           "INSTRUMENTATION"},
    {"LIB_FROM_ROOT_PATH",       check_lib_from_root_path,   "INSTRUMENTATION"},
    {"FRIDA_AGENT_IN_MEMORY",    check_frida_agent_in_memory, "INSTRUMENTATION"},
    {"DISGUISED_LIBRARY_IN_MEMORY", check_disguised_library, "INSTRUMENTATION"},
    {"GOT_PLT_INTEGRITY",        check_got_plt_integrity,    "INSTRUMENTATION"},
    {"UPROBE_RESIDUE",           check_uprobe_residue,       "INSTRUMENTATION"},
    {"OPCODE_TRAMPOLINE",        check_opcode_trampoline,    "INSTRUMENTATION"},
    {"TAMPER_SIGNING_BLOCK",     check_tamper_signing_block, "APP_INTEGRITY"},
};

}

extern "C" JNIEXPORT jint JNICALL
Java_io_github_areyougarou_intakto_NativeCore_open(JNIEnv* env, jclass, jstring path) {
    const char* p = env->GetStringUTFChars(path, nullptr);
    if (!p) return -1;
    int fd = raw_open(p);
    env->ReleaseStringUTFChars(path, p);
    return fd;
}

// The first check() reads the map here, to find the APK, a few milliseconds before run() would read it
// again (both on the Intakto thread). run() takes this snapshot instead of reading the map twice.
static bool g_maps_fresh = false;

extern "C" JNIEXPORT jstring JNICALL
Java_io_github_areyougarou_intakto_NativeCore_apkPath(JNIEnv* env, jclass, jstring pkg) {
    g_maps = read_maps();
    g_maps_fresh = true;
    std::string p = own_apk_path(g_maps, jstr(env, pkg));
    return p.empty() ? nullptr : env->NewStringUTF(p.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_github_areyougarou_intakto_NativeCore_run(JNIEnv* env, jclass, jstring signers, jstring pkg, jint targetSdk) {
    init_own_process_name();
    if (!g_maps_fresh) g_maps = read_maps();
    g_maps_fresh = false;
    mem_run_begin();
    g_expected_signers = jstr(env, signers);
    g_own_package = jstr(env, pkg);
    g_target_sdk = targetSdk;
    std::string json = "[";
    for (const Check& c : CHECKS) {
        long t0 = now_us();
        NativeResult r = c.fn();
        long us = now_us() - t0;
        if (json.size() > 1) json += ",";
        json += std::string("{\"id\":\"") + c.id + "\",\"group\":\"" + c.group +
                "\",\"status\":" + std::to_string(r.status) +
                ",\"us\":" + std::to_string(us) + ",\"details\":\"" + json_escape(r.details) + "\"}";
    }
    json += "]";
    mem_run_end();
    return env->NewStringUTF(json.c_str());
}
