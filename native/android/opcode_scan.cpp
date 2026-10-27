#include "opcode_scan.h"
#include <dlfcn.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

const char* const SENSITIVE_FNS[] = {
    "open", "openat", "read", "write", "close", "mmap", "munmap", "mprotect",
    "dlopen", "dlsym", "connect", "ptrace", "kill", "sigaction",
    "pthread_create", "__system_property_get", nullptr
};

inline bool is_b(uint32_t i)      { return (i & 0xFC000000u) == 0x14000000u; }
inline bool is_br(uint32_t i)     { return (i & 0xFFFFFC1Fu) == 0xD61F0000u; }
inline bool is_brk(uint32_t i)    { return (i & 0xFFE0001Fu) == 0xD4200000u; }
inline bool is_ldr_lit(uint32_t i){ return (i & 0xFF000000u) == 0x58000000u; }
inline bool is_adrp(uint32_t i)   { return (i & 0x9F000000u) == 0x90000000u; }
inline bool is_landing_pad(uint32_t i) {
    return i == 0xD503245Fu || i == 0xD503249Fu || i == 0xD50324DFu ||
           i == 0xD503241Fu || i == 0xD503233Fu || i == 0xD503237Fu;
}

const VmaEntry* vma_for(uint64_t a) {
    for (const auto& v : g_maps)
        if (a >= v.start && a < v.end) return &v;
    return nullptr;
}

bool b_escapes_module(const uint32_t* w, uintptr_t p) {
    int32_t imm = (int32_t)(w[0] << 6) >> 6;
    uint64_t target = p + (int64_t)imm * 4;
    const VmaEntry* src = vma_for(p);
    const VmaEntry* dst = vma_for(target);
    if (!src) return false;
    return dst != src;
}

const char* classify(const uint32_t* w, uintptr_t p) {
    if (is_brk(w[0])) return "BRK/breakpoint at entry";
    if (is_br(w[0]))  return "indirect-branch (BR) trampoline at entry";
    if (is_b(w[0]) && b_escapes_module(w, p)) return "direct-branch (B) escaping module";
    if (is_ldr_lit(w[0]) && (is_br(w[1]) || is_br(w[2]))) return "literal-load + BR trampoline";
    if (is_adrp(w[0]) && is_br(w[2])) return "ADRP + BR trampoline";
    return nullptr;
}

}

NativeResult check_opcode_trampoline() {
    static const std::vector<void*> addrs = [] {
        std::vector<void*> a;
        for (const char* const* s = SENSITIVE_FNS; *s; ++s) a.push_back(dlsym(RTLD_DEFAULT, *s));
        return a;
    }();
    NativeResult r;
    int resolved = 0, readable = 0, hooked = 0;
    std::string detail;
    for (size_t i = 0; SENSITIVE_FNS[i]; ++i) {
        const char* const* s = &SENSITIVE_FNS[i];
        void* p = addrs[i];
        if (!p) continue;
        resolved++;
        uint32_t w[6];
        if (safe_read_mem_n((uintptr_t)p, w, sizeof(w)) != (ssize_t)sizeof(w)) continue;
        readable++;
        int bi = is_landing_pad(w[0]) ? 1 : 0;
        const char* why = classify(w + bi, (uintptr_t)p + (uintptr_t)bi * 4);
        if (!why) continue;
        uint32_t disk[6];
        size_t need = (size_t)(bi + 3) * 4;
        size_t dn = read_disk_bytes_for_addr((uintptr_t)p, disk, sizeof(disk));
        if (dn >= need && memcmp(w, disk, need) == 0) continue;
        hooked++;
        const VmaEntry* v = vma_for((uintptr_t)p);
        bool filebacked = v && !v->path.empty() && v->path[0] != '[' && v->path.find("memfd:") == std::string::npos;
        char line[256];
        snprintf(line, sizeof(line), "  %s @%p insn0=0x%08x: %s (%s)\n", *s, p, w[bi], why,
                 filebacked ? "differs from on-disk library" : "code not backed by a file");
        detail += line;
    }

    std::string raw = "resolved=" + std::to_string(resolved) +
                      " readable=" + std::to_string(readable) +
                      " hooked=" + std::to_string(hooked);
    if (readable == 0) {
        r.status = STATUS_INCONCLUSIVE;
        r.details = "self-memory read failed on all watched fns (" + raw + ")";
    } else if (hooked > 0) {
        r.status = STATUS_DETECTED;
        r.details = raw + "\n" + detail;
    } else {
        r.status = STATUS_CLEAN;
        r.details = "no entry-prologue trampoline differing from the on-disk library (" + raw + ")";
    }

    return r;
}
