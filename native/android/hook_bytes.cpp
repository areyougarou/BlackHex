#include "hook_bytes.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <vector>

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

static const std::vector<uintptr_t>& hook_addrs() {
    static const std::vector<uintptr_t> addrs = [] {
        std::vector<uintptr_t> a;
        for (const auto* t = HOOK_TARGETS; t->sym; ++t) a.push_back((uintptr_t)dlsym(RTLD_DEFAULT, t->sym));
        return a;
    }();
    return addrs;
}

static ByteCheck read_hook_bytes(const char* sym, uintptr_t addr) {
    ByteCheck r{};
    r.sym = sym;
    if (!addr) return r;
    r.addr = addr;

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

NativeResult check_hook_bytes() {
    std::ostringstream d;
    int readable = 0, hooked = 0;
    const auto& addrs = hook_addrs();
    for (size_t i = 0; HOOK_TARGETS[i].sym; ++i) {
        auto c = read_hook_bytes(HOOK_TARGETS[i].sym, addrs[i]);
        if (!c.read_ok) continue;
        readable++;
        if (c.is_trampoline && !c.stock) {
            hooked++;
            d << "  " << c.sym << "() @0x" << std::hex << c.addr
              << " insn0=0x" << c.insn << " (LDR X16,[PC,#8] trampoline, differs from on-disk library)\n";
        }
    }
    if (readable == 0) return {STATUS_INCONCLUSIVE, "no watched function readable (self-memory read failed)"};
    if (hooked == 0)
        return {STATUS_CLEAN, "no ARM64 trampoline (LDR X16,[PC,#8] = 0x58000050) differing from the on-disk library (readable=" + std::to_string(readable) + ")"};
    return {STATUS_DETECTED, std::to_string(hooked) + " hooked function(s):\n" + d.str()};
}
