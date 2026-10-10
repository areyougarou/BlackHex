#include "hook_bytes.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
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
    uint32_t direct_insn;
    uint32_t mem_insn;
    uintptr_t addr;
    bool is_trampoline;
    bool shadow_active;
    bool mem_ok;
};

static ByteCheck read_hook_bytes(const char* sym) {
    ByteCheck r{};
    r.sym = sym;
    void* ptr = dlsym(RTLD_DEFAULT, sym);
    if (!ptr) return r;
    r.addr = (uintptr_t)ptr;

    r.direct_insn = *reinterpret_cast<volatile uint32_t*>(ptr);
    r.is_trampoline = (r.direct_insn == FRIDA_TRAMPOLINE_INSN);

    int mem_fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (mem_fd >= 0) {
        r.mem_ok = (pread(mem_fd, &r.mem_insn, 4, (off64_t)r.addr) == 4);
        close(mem_fd);
    }
    if (!r.mem_ok) r.mem_insn = r.direct_insn;
    r.shadow_active = r.mem_ok && (r.direct_insn != r.mem_insn);
    return r;
}

NativeResult check_hook_bytes_direct() {
    std::ostringstream d;
    int hooked = 0;
    for (const auto* t = HOOK_TARGETS; t->sym; ++t) {
        auto c = read_hook_bytes(t->sym);
        if (c.is_trampoline) {
            hooked++;
            d << "  " << t->sym << "() @0x" << std::hex << c.addr
              << " first_insn=0x" << c.direct_insn << " (LDR X16,[PC,#8] trampoline)\n";
        }
    }
    if (hooked == 0)
        return { .id = "HOOK_BYTES_DIRECT", .category = CAT_HOOKS, .severity = SEV_CRITICAL,
                 .status = STATUS_CLEAN,
                 .details = "No ARM64 trampoline (LDR X16,[PC,#8] = 0x58000050) found via direct pointer read" };
    return { .id = "HOOK_BYTES_DIRECT", .category = CAT_HOOKS, .severity = SEV_CRITICAL,
             .status = STATUS_DETECTED,
             .details = std::to_string(hooked) + " hooked function(s):\n" + d.str() };
}

NativeResult check_hook_bytes_mem() {
    std::ostringstream d;
    int visible_trampolines = 0;
    for (const auto* t = HOOK_TARGETS; t->sym; ++t) {
        auto c = read_hook_bytes(t->sym);
        if (c.mem_insn == FRIDA_TRAMPOLINE_INSN) {
            visible_trampolines++;
            d << "  " << t->sym << "() @0x" << std::hex << c.addr
              << " mem_insn=0x" << c.mem_insn << " (trampoline visible through /proc/self/mem)\n";
        }
    }
    if (visible_trampolines == 0)
        return { .id = "HOOK_BYTES_MEM", .category = CAT_HOOKS, .severity = SEV_CRITICAL,
                 .status = STATUS_CLEAN,
                 .details = "No trampolines visible via /proc/self/mem (no hooks present, or a read shadow hides them)" };
    return { .id = "HOOK_BYTES_MEM", .category = CAT_HOOKS, .severity = SEV_CRITICAL,
             .status = STATUS_DETECTED,
             .details = std::to_string(visible_trampolines) + " trampoline(s) visible through /proc/self/mem:\n" + d.str() };
}
