#include "got_plt.h"
#include "hook_dest.h"
#include <link.h>
#include <elf.h>
#include <dlfcn.h>
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#if defined(__aarch64__)

namespace {

const VmaEntry* vma_for(uint64_t a) {
    for (const auto& v : g_maps)
        if (a >= v.start && a < v.end) return &v;
    return nullptr;
}

uint64_t g_vdso_s = 0, g_vdso_e = 0;
void find_vdso() {
    g_vdso_s = g_vdso_e = 0;
    for (const auto& v : g_maps)
        if (v.path.find("vdso") != std::string::npos || v.path.find("vvar") != std::string::npos) {
            if (!g_vdso_s || v.start < g_vdso_s) g_vdso_s = v.start;
            if (v.end > g_vdso_e) g_vdso_e = v.end;
        }
}

bool want_module(const char* name) {
    if (!name || !name[0]) return false;
    if (strstr(name, "libintakto")) return true;
    const char* b = strrchr(name, '/'); b = b ? b + 1 : name;
    return strcmp(b, "libc.so") == 0 || strcmp(b, "libart.so") == 0;
}

// Every loaded library's segments, from one dl_iterate_phdr walk, sorted by start. The library holding
// an address is found here the way dladdr() finds it (a PT_LOAD segment of a loaded library contains
// it; the name is the same realpath), without dladdr's per-call search for the nearest symbol, which
// was half of this check's time (about 1,950 slots per run).
struct Range { uintptr_t lo, hi; size_t name; };

// The call table of one scanned library, located from its dynamic section under the loader's lock.
struct Mod { uintptr_t base, jmprel, strtab, symtab; size_t n; std::string name; };

struct Walk {
    std::vector<Range> ranges;
    std::vector<std::string> names;
    std::vector<Mod> mods;
    int modules = 0;
};

const std::string* library_at(const Walk& w, uintptr_t a) {
    auto it = std::upper_bound(w.ranges.begin(), w.ranges.end(), a, [](uintptr_t x, const Range& r) { return x < r.lo; });
    if (it == w.ranges.begin()) return nullptr;
    --it;
    return a < it->hi ? &w.names[it->name] : nullptr;
}

enum { TARGET_FINE, TARGET_SUSPECT, TARGET_APP_HOOK, TARGET_UNTRACED };

int target_kind(const Walk& w, uintptr_t target, std::string& where) {
    if (g_vdso_s && target >= g_vdso_s && target < g_vdso_e) return TARGET_FINE;
    const std::string* lib = library_at(w, target);
    if (lib && !lib->empty()) {
        const char* f = lib->c_str();
        if (strncmp(f, "/data/adb/", 10) == 0 || strstr(f, "/data/local/tmp/")) { where = f; return TARGET_SUSPECT; }
        return TARGET_FINE;
    }

    const VmaEntry* v = vma_for(target);
    if (v) {
        const std::string& p = v->path;
        if (p.rfind("/data/adb/", 0) == 0 || p.find("/data/local/tmp/") != std::string::npos) { where = p; return TARGET_SUSPECT; }
        if (!p.empty() && p[0] != '[') {
            if (p.find("memfd:") == std::string::npos) return TARGET_FINE;
            if (p.find("jit-cache") != std::string::npos || p.find("code-cache") != std::string::npos) return TARGET_FINE;
        }
        where = p.empty() ? "[anon]" : p;
        if (v->anonymous()) {
            std::string to;
            HookOwner owner = hook_owner(target, to);
            if (owner == HOOK_APP_OWN) { where = to; return TARGET_APP_HOOK; }
            where += ", lands in " + to;
            // Not traced to any library: a hook, but not proof of who placed it.
            if (owner == HOOK_UNRESOLVED) return TARGET_UNTRACED;
        }
        return TARGET_SUSPECT;
    }
    where = "[unmapped]";
    return TARGET_SUSPECT;
}

// Runs under the loader's lock: only copies what the scan needs, so the lock is held for microseconds
// (the scan used to run inside this callback and held the lock for its whole 9-80 ms, blocking every
// other thread's dlopen/dlsym meanwhile).
int walk_cb(struct dl_phdr_info* info, size_t, void* data) {
    Walk* w = static_cast<Walk*>(data);
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    size_t name = w->names.size();
    w->names.emplace_back(info->dlpi_name ? info->dlpi_name : "");
    const ElfW(Dyn)* dyn = nullptr;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD) w->ranges.push_back({base + (uintptr_t)ph.p_vaddr, base + (uintptr_t)ph.p_vaddr + (uintptr_t)ph.p_memsz, name});
        if (ph.p_type == PT_DYNAMIC) dyn = (const ElfW(Dyn)*)(base + ph.p_vaddr);
    }
    if (!want_module(info->dlpi_name)) return 0;
    w->modules++;
    if (!dyn) return 0;

    uintptr_t jmprel = 0, strtab = 0, symtab = 0;
    size_t pltrelsz = 0; long pltrel = 0;
    for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_JMPREL:   jmprel   = base + d->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrelsz = d->d_un.d_val;        break;
            case DT_PLTREL:   pltrel   = d->d_un.d_val;        break;
            case DT_STRTAB:   strtab   = base + d->d_un.d_ptr; break;
            case DT_SYMTAB:   symtab   = base + d->d_un.d_ptr; break;
            default: break;
        }
    }
    if (!jmprel || !pltrelsz || pltrel != DT_RELA) return 0;

    size_t n = pltrelsz / sizeof(ElfW(Rela));
    if (n > 8192) n = 8192;
    w->mods.push_back({base, jmprel, strtab, symtab, n, info->dlpi_name});
    return 0;
}

struct Ctx { int checked = 0, hits = 0, modules = 0, untraced = 0; std::string detail, own, untraced_detail; };

// One library's call table. The relocation table and the table of slots are each read in one go
// rather than about 4,000 reads of 8 or 24 bytes; a slot outside what that read returned is read alone.
void scan(const Walk& w, const Mod& m, Ctx* c) {
    const char* mod = !m.name.empty() ? m.name.c_str() : "[self]";
    const char* modb = strrchr(mod, '/'); modb = modb ? modb + 1 : mod;

    std::vector<ElfW(Rela)> rel(m.n);
    ssize_t got = safe_read_mem_n(m.jmprel, rel.data(), m.n * sizeof(ElfW(Rela)));
    size_t nrel = got > 0 ? (size_t)got / sizeof(ElfW(Rela)) : 0;  // stops at the first unreadable entry, as before
    uintptr_t lo = UINTPTR_MAX, hi = 0;
    for (size_t i = 0; i < nrel; i++) {
        if (ELF64_R_TYPE(rel[i].r_info) != R_AARCH64_JUMP_SLOT) continue;
        lo = std::min(lo, (uintptr_t)rel[i].r_offset);
        hi = std::max(hi, (uintptr_t)rel[i].r_offset + sizeof(uintptr_t));
    }
    std::vector<uintptr_t> slots;
    ssize_t sgot = 0;
    if (lo < hi && hi - lo <= 1u << 20) {
        slots.resize((hi - lo + sizeof(uintptr_t) - 1) / sizeof(uintptr_t));
        sgot = safe_read_mem_n(m.base + lo, slots.data(), hi - lo);
    }

    for (size_t i = 0; i < nrel; i++) {
        const ElfW(Rela)& rr = rel[i];
        if (ELF64_R_TYPE(rr.r_info) != R_AARCH64_JUMP_SLOT) continue;

        uintptr_t target = 0;
        size_t at = (size_t)rr.r_offset - lo;
        if (sgot > 0 && at + sizeof(target) <= (size_t)sgot) memcpy(&target, (const char*)slots.data() + at, sizeof(target));
        else if (!safe_read_mem(m.base + rr.r_offset, &target, sizeof(target))) continue;
        if (target == 0) continue;
        c->checked++;

        std::string where;
        int kind = target_kind(w, target, where);
        if (kind == TARGET_FINE) continue;

        std::string sym = "?";
        if (m.symtab && m.strtab) {
            ElfW(Sym) s;
            uint32_t si = (uint32_t)ELF64_R_SYM(rr.r_info);
            if (safe_read_mem(m.symtab + (size_t)si * sizeof(ElfW(Sym)), &s, sizeof(s))) {
                char nbuf[96] = {0};
                if (safe_read_mem_n(m.strtab + s.st_name, nbuf, sizeof(nbuf) - 1) > 0) sym = nbuf;
            }
        }
        if (kind == TARGET_APP_HOOK) { c->own += std::string(" ") + modb + ":" + sym + "->" + where; continue; }
        char line[256];
        snprintf(line, sizeof(line), "  %s: %s -> %llx ", modb, sym.c_str(), (unsigned long long)target);
        if (kind == TARGET_UNTRACED) { if (c->untraced++ < 64) c->untraced_detail += line + where + "\n"; continue; }
        c->hits++;
        c->detail += line + where + "\n";
        if (c->hits >= 64) break;
    }
}

}

NativeResult check_got_plt_integrity() {
    NativeResult r;
    if (!maps_available()) return {STATUS_INCONCLUSIVE, "process memory map unavailable (empty /proc/self/maps snapshot); cannot judge"};
    find_vdso();
    Ctx c;
    uint32_t probe;
    if (!safe_read_mem((uintptr_t)&check_got_plt_integrity, &probe, sizeof(probe))) {
        r.status = STATUS_INCONCLUSIVE; r.details = "self-memory read unavailable";
        return r;
    }
    Walk w;
    dl_iterate_phdr(walk_cb, &w);
    std::sort(w.ranges.begin(), w.ranges.end(), [](const Range& a, const Range& b) { return a.lo < b.lo; });
    c.modules = w.modules;
    for (const Mod& m : w.mods) {
        if (c.hits >= 64) break;
        scan(w, m, &c);
    }
    if (c.checked == 0) {
        r.status = STATUS_INCONCLUSIVE;
        char h[96]; snprintf(h, sizeof(h), "no GOT/PLT slot could be read (modules=%d)", c.modules);
        r.details = h;
        return r;
    }

    char head[96];
    snprintf(head, sizeof(head), "checked=%d hits=%d\n", c.checked, c.hits);
    if (c.hits == 0 && c.untraced > 0) {
        r.status = STATUS_INCONCLUSIVE;
        r.details = std::string("could not verify: ") + head + "untraced=" + std::to_string(c.untraced) +
                    ", GOT/PLT target(s) in unnamed code not traced to the code that placed them:\n" + c.untraced_detail;
        return r;
    }
    r.status = c.hits > 0 ? STATUS_DETECTED : STATUS_CLEAN;
    r.details = std::string(head) + (c.hits ? c.detail + c.untraced_detail : "no GOT/PLT target outside a file-backed module (own lib+libc+libart)" +
                (c.own.empty() ? std::string() : "; hooked by the app's own library:" + c.own));

    return r;
}

#else

NativeResult check_got_plt_integrity() { return not_built_for_abi(); }

#endif
