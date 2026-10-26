#include "hook_bytes.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <sstream>

struct HookTarget {
    const char* sym;
    const char* lib;
};

static const HookTarget HOOK_TARGETS[] = {
    { "open",           nullptr },
    { "openat",         nullptr },
    { "read",           nullptr },
    { "write",          nullptr },
    { "mmap",           nullptr },
    { "munmap",         nullptr },
    { "mprotect",       nullptr },
    { "pthread_create", nullptr },
    { "dlopen",         nullptr },
    { "dlsym",          nullptr },
    { nullptr, nullptr }
};

struct ByteCheck {
    const char* sym;
    uint32_t insn;
    uintptr_t addr;
    bool read_ok;
    bool is_trampoline;
    bool stock;
};

static ByteCheck read_hook_bytes(const char* sym) {
    ByteCheck r{};
    r.sym = sym;
    void* ptr = dlsym(RTLD_DEFAULT, sym);
    if (!ptr) return r;
    r.addr = (uintptr_t)ptr;

    uint32_t w[4];
    if (safe_read_mem_n(r.addr, w, sizeof(w)) != (ssize_t)sizeof(w)) return r;
    r.read_ok = true;
    r.insn = w[0];
    r.is_trampoline = (w[0] == FRIDA_TRAMPOLINE_INSN);
    if (r.is_trampoline) {
        uint32_t disk[4];
        size_t dn = read_disk_bytes_for_addr(r.addr, disk, sizeof(disk));
        r.stock = (dn >= sizeof(disk) && memcmp(w, disk, sizeof(disk)) == 0);
    }
    return r;
}

static NativeResult hook_bytes_result(const char* id) {
    std::ostringstream d;
    int readable = 0, hooked = 0;
    for (const auto* t = HOOK_TARGETS; t->sym; ++t) {
        auto c = read_hook_bytes(t->sym);
        if (!c.read_ok) continue;
        readable++;
        if (c.is_trampoline && !c.stock) {
            hooked++;
            d << "  " << t->sym << "() @0x" << std::hex << c.addr
              << " insn0=0x" << c.insn << " (LDR X16,[PC,#8] trampoline, differs from on-disk library)\n";
        }
    }
    if (readable == 0)
        return { .id = id, .category = CAT_HOOKS, .severity = SEV_CRITICAL,
                 .status = STATUS_INCONCLUSIVE,
                 .details = "no watched function readable (self-memory read failed)" };
    if (hooked == 0)
        return { .id = id, .category = CAT_HOOKS, .severity = SEV_CRITICAL,
                 .status = STATUS_CLEAN,
                 .details = "no ARM64 trampoline (LDR X16,[PC,#8] = 0x58000050) differing from the on-disk library (readable=" + std::to_string(readable) + ")" };
    NativeResult r{ .id = id, .category = CAT_HOOKS, .severity = SEV_CRITICAL,
                    .status = STATUS_DETECTED,
                    .details = std::to_string(hooked) + " hooked function(s):\n" + d.str() };
    r.certainty = CERT_STRONG;
    return r;
}

NativeResult check_hook_bytes_direct() { return hook_bytes_result("HOOK_BYTES_DIRECT"); }

NativeResult check_hook_bytes_mem() { return hook_bytes_result("HOOK_BYTES_MEM"); }
