#include "opcode_scan.h"
#include <dlfcn.h>
#include <cstdint>
#include <cstdio>
#include <string>

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
    NativeResult r;
    r.id = "OPCODE_TRAMPOLINE";

    r.category = CAT_HOOKS;
    r.severity = SEV_CRITICAL;

    int resolved = 0, readable = 0, hooked = 0;
    std::string detail;
    for (const char* const* s = SENSITIVE_FNS; *s; ++s) {
        void* p = dlsym(RTLD_DEFAULT, *s);
        if (!p) continue;
        resolved++;
        uint32_t w[4];
        if (!safe_read_mem((uintptr_t)p, w, sizeof(w))) continue;
        readable++;
        if (const char* why = classify(w, (uintptr_t)p)) {
            hooked++;
            char line[200];
            snprintf(line, sizeof(line), "  %s @%p insn0=0x%08x: %s\n", *s, p, w[0], why);
            detail += line;
        }
    }

    std::string raw = "resolved=" + std::to_string(resolved) +
                      " readable=" + std::to_string(readable) +
                      " hooked=" + std::to_string(hooked);
    if (readable == 0)   r.status = STATUS_INCONCLUSIVE;
    else if (hooked > 0) r.status = STATUS_DETECTED;
    else                 r.status = STATUS_CLEAN;
    r.details = hooked ? raw + "\n" + detail
                       : "no entry-prologue trampoline on watched fns (" + raw + ")";

    return r;
}
