#include "art_integrity.h"
#include "maps_integrity.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

constexpr size_t   AM_ACCESS_FLAGS_OFF   = 4;
constexpr size_t   AM_ENTRY_QUICK_OFF    = 24;
constexpr uint32_t kAccNative            = 0x00000100u;
constexpr uint32_t kAccCompileDontBother = 0x02000000u;

const VmaEntry* vma_for(uint64_t addr) {
    for (const auto& v : g_maps)
        if (addr >= v.start && addr < v.end) return &v;
    return nullptr;
}

bool region_is_legit_code(const VmaEntry* v) {
    if (!v) return false;
    const std::string& p = v->path;
    if (p.empty()) return false;
    return p.find("libart.so") != std::string::npos ||
           p.find(".oat")  != std::string::npos ||
           p.find(".odex") != std::string::npos ||
           p.find(".vdex") != std::string::npos ||
           p.find(".art")  != std::string::npos ||
           p.find(".dex")  != std::string::npos ||
           p.find("dalvik") != std::string::npos ||
           p.find("jit-cache")  != std::string::npos ||
           p.find("code-cache") != std::string::npos ||
           p.find("boot")  != std::string::npos;

}

std::string hex(uint64_t v) {
    char b[20]; snprintf(b, sizeof(b), "0x%llx", (unsigned long long)v); return b;
}

struct Target { const char* cls; const char* name; const char* sig; bool is_static; bool is_control; };

const Target TARGETS[] = {

    { "java/lang/String",      "length",       "()I",  false, true  },
    { "java/io/File",          "exists",       "()Z",  false, false },
    { "android/location/Location", "getLatitude",  "()D", false, false },
    { "android/location/Location", "getLongitude", "()D", false, false },
};

void warm_location(JNIEnv* env) {
    jclass loc = env->FindClass("android/location/Location");
    if (!loc) { env->ExceptionClear(); return; }
    jmethodID ctor = env->GetMethodID(loc, "<init>", "(Ljava/lang/String;)V");
    if (ctor) {
        jstring prov = env->NewStringUTF("gps");
        jobject o = env->NewObject(loc, ctor, prov);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (o) {
            jmethodID lat = env->GetMethodID(loc, "getLatitude", "()D");
            jmethodID lon = env->GetMethodID(loc, "getLongitude", "()D");
            if (lat) { env->CallDoubleMethod(o, lat); if (env->ExceptionCheck()) env->ExceptionClear(); }
            if (lon) { env->CallDoubleMethod(o, lon); if (env->ExceptionCheck()) env->ExceptionClear(); }
            env->DeleteLocalRef(o);
        }
        env->DeleteLocalRef(prov);
    } else env->ExceptionClear();
    env->DeleteLocalRef(loc);
}

}

NativeResult check_art_entrypoint_integrity(JNIEnv* env) {
    NativeResult r;
    int checked = 0, detected = 0, inconclusive = 0, controls_checked = 0, controls_suspect = 0;
    std::string detail;

    warm_location(env);

    jfieldID artmethod_fid = nullptr;
    if (jclass exe = env->FindClass("java/lang/reflect/Executable")) {
        artmethod_fid = env->GetFieldID(exe, "artMethod", "J");
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(exe);
    } else env->ExceptionClear();

    for (const auto& t : TARGETS) {
        jclass c = env->FindClass(t.cls);
        if (!c) { env->ExceptionClear(); inconclusive++;
            detail += std::string("  ") + t.cls + "." + t.name + " : noclass\n"; continue; }
        jmethodID m = t.is_static ? env->GetStaticMethodID(c, t.name, t.sig)
                                  : env->GetMethodID(c, t.name, t.sig);
        if (!m) { env->ExceptionClear(); env->DeleteLocalRef(c); inconclusive++;
            detail += std::string("  ") + t.cls + "." + t.name + " : nomethod\n"; continue; }
        jobject refm = artmethod_fid ? env->ToReflectedMethod(c, m, t.is_static ? JNI_TRUE : JNI_FALSE) : nullptr;
        env->DeleteLocalRef(c);
        if (!refm || env->ExceptionCheck() || !artmethod_fid) { env->ExceptionClear();
            if (refm) env->DeleteLocalRef(refm); inconclusive++;
            detail += std::string("  ") + t.name + " : no-reflect/no-field\n"; continue; }
        uint64_t am = (uint64_t)env->GetLongField(refm, artmethod_fid);
        env->DeleteLocalRef(refm);
        const VmaEntry* amv = vma_for(am);
        if (!am || !amv || !amv->readable()) { inconclusive++;
            detail += std::string("  ") + t.name + " : artmethod-unmapped=" + hex(am) + "\n"; continue; }

        uint32_t flags = 0; uint64_t entry = 0;
        if (!safe_read_mem((uintptr_t)am + AM_ACCESS_FLAGS_OFF, &flags, sizeof(flags)) ||
            !safe_read_mem((uintptr_t)am + AM_ENTRY_QUICK_OFF, &entry, sizeof(entry))) {
            inconclusive++;
            detail += std::string("  ") + t.name + " : artmethod-read-failed\n"; continue;
        }
        checked++;
        if (t.is_control) controls_checked++;
        const VmaEntry* ev = vma_for(entry);
        std::string region = ev ? (ev->path.empty() ? "[anon]" : ev->path) : "[unmapped]";
        bool legit = region_is_legit_code(ev);
        bool exec  = ev && ev->executable();

        bool hidden = false;
        bool suspect;
        if (ev) {
            suspect = exec && !legit;
        } else {
            hidden  = (entry != 0 && page_mapped(entry));
            suspect = hidden;
        }
        bool cdb = (flags & kAccCompileDontBother) != 0;
        bool nat = (flags & kAccNative) != 0;
        if (suspect) { if (t.is_control) controls_suspect++; else detected++; }

        char line[360];
        snprintf(line, sizeof(line), "  %s.%s : entry=%s in %s [%s]%s%s%s%s\n",
                 t.cls, t.name, hex(entry).c_str(), region.c_str(),
                 ev ? ev->perms : "----",
                 suspect ? " <<SUSPECT" : "",
                 hidden ? " HIDDEN(mincore:mapped,maps:absent)" : "",
                 cdb ? " CompileDontBother" : "",
                 nat ? " Native" : "");
        detail += line;
    }

    char head[128];
    snprintf(head, sizeof(head), "checked=%d detected=%d inconclusive=%d ctrl_ok=%d/%d\n",
             checked, detected, inconclusive, controls_checked - controls_suspect, controls_checked);
    std::string raw = std::string("checked=") + std::to_string(checked) +
                      " detected=" + std::to_string(detected) +
                      " inconclusive=" + std::to_string(inconclusive);

    if (controls_checked == 0 || controls_suspect > 0) r.status = STATUS_INCONCLUSIVE;
    else if (detected > 0)                              r.status = STATUS_DETECTED;
    else if (checked > 0)                               r.status = STATUS_CLEAN;
    else                                                r.status = STATUS_INCONCLUSIVE;

    r.details = std::string(head) + detail;

    return r;
}
