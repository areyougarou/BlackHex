#include "hook_dest.h"
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <vector>

#if defined(__aarch64__)

namespace {

const size_t MAX_HOPS = 16;
const size_t HOP_INSNS = 128;

const VmaEntry* vma_for(uint64_t a) {
    for (const auto& v : g_maps)
        if (a >= v.start && a < v.end) return &v;
    return nullptr;
}

int64_t sext(uint64_t v, int bits) { return (int64_t)(v << (64 - bits)) >> (64 - bits); }

std::string lower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

// The kernel's page-size compat (pgsize_migration.c, init_pad_vma) prints the padding at the end of a
// library segment as its own "[page size compat]" line, always "---p" whatever its real access. It is
// still memory of the segment printed before it, and a hooker can write an island there (ShadowHook
// does, in libc's padding on the Nothing Phone 2a). Returns that segment, or nullptr.
const char* const PAD_NAME = "[page size compat]";

const VmaEntry* padded_segment(const VmaEntry* pad) {
    for (int i = 0; i < 4 && pad && pad->path == PAD_NAME; i++) {
        const VmaEntry* prev = nullptr;
        for (const auto& v : g_maps)
            if (v.end == pad->start) { prev = &v; break; }
        pad = prev;
    }
    return pad && pad->path != PAD_NAME ? pad : nullptr;
}

bool is_system(const std::string& p) {
    for (const char* r : {"/system/", "/apex/", "/vendor/", "/product/", "/system_ext/", "/odm/"})
        if (p.rfind(r, 0) == 0) return true;
    return false;
}

// Code of this app: its APK files and the native libraries unpacked from them, which live under the
// install folder /data/app/.../<package>-<id>/ (or /mnt/expand/.../<package>-<id>/). These are exactly
// the files TAMPER_APK_CONTENT matches against the developer's signature, so a hook that lands in them
// is the developer's own code. The private data folder (/data/data/<package>/,
// /data/user[_de]/<n>/<package>/) is NOT trusted: the app can write there while it runs, so a library
// there is not proven to come from the signed APK. An abuser with root could drop a renamed Frida agent
// into it and pass every hook check, so a hook landing there must still read foreign.
bool is_app_own(const std::string& p) {
    if (g_own_package.empty()) return false;
    return (p.rfind("/data/app/", 0) == 0 || p.rfind("/mnt/expand/", 0) == 0)
        && p.find("/" + g_own_package + "-") != std::string::npos;
}

// DT_SONAME of the library whose ELF header is mapped at `base`, read from memory.
std::string soname_at(uintptr_t base) {
    ElfW(Ehdr) eh;
    if (!safe_read_mem(base, &eh, sizeof(eh)) || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) return "";
    uintptr_t bias = 0, dyn = 0;
    bool first = true;
    for (int i = 0; i < eh.e_phnum && i < 64; i++) {
        ElfW(Phdr) ph;
        if (!safe_read_mem(base + eh.e_phoff + i * sizeof(ph), &ph, sizeof(ph))) return "";
        if (ph.p_type == PT_LOAD && first) { bias = base - (ph.p_vaddr & ~(uintptr_t)0xFFF); first = false; }
        if (ph.p_type == PT_DYNAMIC) dyn = ph.p_vaddr;
    }
    if (!dyn) return "";
    uintptr_t strtab = 0, name = 0;
    bool named = false;
    for (int i = 0; i < 512; i++) {
        ElfW(Dyn) d;
        if (!safe_read_mem(bias + dyn + i * sizeof(d), &d, sizeof(d)) || d.d_tag == DT_NULL) break;
        if (d.d_tag == DT_STRTAB) strtab = d.d_un.d_ptr;
        if (d.d_tag == DT_SONAME) { name = d.d_un.d_val; named = true; }
    }
    char buf[96] = {};
    if (!strtab || !named || safe_read_mem_n(bias + strtab + name, buf, sizeof(buf) - 1) <= 0) return "";
    return buf;
}

// Names the library holding `addr`; true when its file name or SONAME says Frida (Frida Gadget
// packed into the app keeps the SONAME libfrida-gadget-raw.so even when the file is renamed).
bool frida_lib(uintptr_t addr, std::string& name) {
    Dl_info di;
    if (!dladdr((void*)addr, &di) || !di.dli_fbase) return false;
    std::string so = soname_at((uintptr_t)di.dli_fbase);
    std::string file = di.dli_fname ? di.dli_fname : "";
    name = so.empty() ? file.substr(file.rfind('/') + 1) : so;
    return lower(so).find("frida") != std::string::npos || lower(file).find("frida") != std::string::npos;
}

// Code addresses the instructions at `pc` branch to or load (B/BL, LDR literal, ADRP+ADD/LDR/BR),
// up to the first B, BR or RET.
void next_hops(uintptr_t pc, std::vector<uintptr_t>& out) {
    uint32_t w[HOP_INSNS];
    ssize_t n = safe_read_mem_n(pc, w, sizeof(w)) / 4;
    for (ssize_t i = 0; i < n; i++) {
        uint32_t x = w[i];
        uintptr_t p = pc + (uintptr_t)i * 4;
        uint64_t v;
        if ((x & 0x7C000000u) == 0x14000000u) {
            out.push_back(p + sext(x & 0x3FFFFFFu, 26) * 4);
            if (!(x & 0x80000000u)) return;
        } else if ((x & 0xFF000000u) == 0x58000000u) {
            if (safe_read_mem(p + sext((x >> 5) & 0x7FFFFu, 19) * 4, &v, sizeof(v))) out.push_back(v);
        } else if ((x & 0x9F000000u) == 0x90000000u && i + 1 < n) {
            uint64_t page = (p & ~(uintptr_t)0xFFF) + sext((((x >> 5) & 0x7FFFFu) << 2) | ((x >> 29) & 3), 21) * 4096;
            uint32_t y = w[i + 1], rd = x & 31;
            if (((y >> 5) & 31) != rd) continue;
            if ((y & 0xFFC00000u) == 0x91000000u) out.push_back(page + ((y >> 10) & 0xFFF));
            else if ((y & 0xFFC00000u) == 0xF9400000u && safe_read_mem(page + ((y >> 10) & 0xFFF) * 8, &v, sizeof(v))) out.push_back(v);
            else if ((y & 0xFFFFFC1Fu) == 0xD61F0000u) out.push_back(page);
        } else if ((x & 0xFFFFFC1Fu) == 0xD61F0000u || (x & 0xFFFFFC1Fu) == 0xD65F0000u) {
            return;
        }
    }
}

}

HookOwner hook_owner(uintptr_t addr, std::string& where) {
    std::vector<uintptr_t> todo{addr}, seen;
    std::string own, trace;
    for (size_t k = 0; k < todo.size() && seen.size() < MAX_HOPS; k++) {
        uintptr_t a = todo[k];
        if (std::find(seen.begin(), seen.end(), a) != seen.end()) continue;
        seen.push_back(a);
        const VmaEntry* v = vma_for(a);
        if (seen.size() <= 6) {
            uint32_t w[4] = {};
            safe_read_mem_n(a, w, sizeof(w));
            char t[160];
            snprintf(t, sizeof(t), " %llx[%s %s]%08x.%08x.%08x.%08x", (unsigned long long)a, v ? v->perms : "-",
                     v ? v->path.substr(0, 40).c_str() : "unmapped", w[0], w[1], w[2], w[3]);
            trace += t;
        }
        // A padding line's real access is not shown; a branch only lands there if it runs.
        bool pad = v && v->path == PAD_NAME;
        if (pad) v = padded_segment(v);
        if (!v || (!pad && !v->executable())) continue;
        if (k > 0 && !v->anonymous()) {
            if (is_system(v->path)) {
                // Code that differs from the library file was written there by a hooker (an island in
                // the library's own pages or its padding): follow it like generated code. Unchanged
                // code is a landing.
                uint32_t mem[4], disk[4];
                if (!pad && safe_read_mem(a, mem, sizeof(mem)) && read_disk_bytes_for_addr(a, disk, sizeof(disk)) == sizeof(disk) &&
                    memcmp(mem, disk, sizeof(mem)) == 0) continue;
            } else {
                std::string name;
                bool frida = frida_lib(a, name);
                if (is_app_own(v->path) && !frida) { if (own.empty()) own = name; continue; }
                where = frida ? "Frida library " + name + " (" + v->path + ")" : v->path;
                return HOOK_FOREIGN;
            }
        }
        next_hops(a, todo);
    }
    if (!own.empty()) { where = own; return HOOK_APP_OWN; }
    where = "no library code reached; hops:" + trace;
    return HOOK_UNRESOLVED;
}

#else

HookOwner hook_owner(uintptr_t, std::string& where) { where = "not built for this chip type"; return HOOK_UNRESOLVED; }

#endif
