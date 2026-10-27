#include "elf_anon.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>

#if defined(__LP64__)

namespace {

bool is_candidate_region(const VmaEntry& v) {
    const std::string& p = v.path;
    if (p.empty()) return true;
    if (p.find("jit-cache")   != std::string::npos) return false;
    if (p.find("code-cache")  != std::string::npos) return false;
    if (p.find("dalvik")      != std::string::npos) return false;
    if (p.find(".art")        != std::string::npos) return false;
    if (p.find("linker_alloc")!= std::string::npos) return false;
    if (p.find("scudo")       != std::string::npos) return false;
    if (p.find("stack")       != std::string::npos) return false;
    if (p.find("vdso")        != std::string::npos) return false;
    if (p[0] == '[') return true;
    if (p.find("memfd:")      != std::string::npos) return true;
    return false;
}

bool region_is_dynamic_elf(const VmaEntry& v) {
    if (!v.readable()) return false;
    if (v.size() < sizeof(Elf64_Ehdr)) return false;

    Elf64_Ehdr eh;
    if (!safe_read_mem(v.start, &eh, sizeof(eh))) return false;
    if (!(eh.e_ident[0] == 0x7f && eh.e_ident[1] == 'E' &&
          eh.e_ident[2] == 'L'  && eh.e_ident[3] == 'F')) return false;
    if (eh.e_ident[EI_CLASS] != ELFCLASS64) return false;
    if (eh.e_phoff == 0 || eh.e_phnum == 0) return false;
    if (eh.e_phentsize < sizeof(Elf64_Phdr)) return false;
    uint64_t need = eh.e_phoff + (uint64_t)eh.e_phnum * eh.e_phentsize;
    if (need > v.size()) return false;

    unsigned n = eh.e_phnum > 128 ? 128 : eh.e_phnum;
    for (unsigned i = 0; i < n; i++) {
        Elf64_Phdr ph;
        uintptr_t at = (uintptr_t)(v.start + eh.e_phoff + (uint64_t)i * eh.e_phentsize);
        if (!safe_read_mem(at, &ph, sizeof(ph))) return false;
        if (ph.p_type == PT_DYNAMIC) return true;
    }
    return false;
}

}

NativeResult check_elf_in_anon() {
    NativeResult r;
    if (!maps_available()) return {STATUS_INCONCLUSIVE, "process memory map unavailable (empty /proc/self/maps snapshot); cannot judge"};
    uint32_t probe;
    if (!safe_read_mem((uintptr_t)&check_elf_in_anon, &probe, sizeof(probe))) {
        r.status = STATUS_INCONCLUSIVE;
        r.details = "self-memory read unavailable";
        return r;
    }

    int hits = 0;
    std::string detail;
    for (const auto& v : g_maps) {
        if (!is_candidate_region(v)) continue;
        if (is_own_vma(v.path)) continue;
        if (!region_is_dynamic_elf(v)) continue;
        hits++;
        char line[256];
        snprintf(line, sizeof(line), "  %llx-%llx %s %s <<ELF+PT_DYNAMIC\n",
                 (unsigned long long)v.start, (unsigned long long)v.end,
                 v.perms, v.path.empty() ? "[anon]" : v.path.c_str());
        detail += line;
        if (hits >= 32) break;
    }

    r.status = hits > 0 ? STATUS_DETECTED : STATUS_CLEAN;
    r.details = hits > 0
        ? std::string("injected ELF(s) in anon/memfd:\n") + detail
        : "no dynamic ELF in anon/memfd/unnamed regions";

    return r;
}

#else

NativeResult check_elf_in_anon() { return not_built_for_abi(); }

#endif
