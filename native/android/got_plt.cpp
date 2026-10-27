#include "got_plt.h"
#include <link.h>
#include <elf.h>
#include <dlfcn.h>
#include <string>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

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
    if (strstr(name, "libblackhex")) return true;
    const char* b = strrchr(name, '/'); b = b ? b + 1 : name;
    return strcmp(b, "libc.so") == 0 || strcmp(b, "libart.so") == 0;
}

bool target_suspect(uintptr_t target, std::string& where) {
    if (g_vdso_s && target >= g_vdso_s && target < g_vdso_e) return false;
    Dl_info di;
    if (dladdr((void*)target, &di) != 0 && di.dli_fname && di.dli_fname[0]) {
        const char* f = di.dli_fname;
        if (strncmp(f, "/data/adb/", 10) == 0 || strstr(f, "/data/local/tmp/")) { where = f; return true; }
        return false;
    }

    const VmaEntry* v = vma_for(target);
    if (v) {
        const std::string& p = v->path;
        if (p.rfind("/data/adb/", 0) == 0 || p.find("/data/local/tmp/") != std::string::npos) { where = p; return true; }
        if (!p.empty() && p[0] != '[') {
            if (p.find("memfd:") == std::string::npos) return false;
            if (p.find("jit-cache") != std::string::npos || p.find("code-cache") != std::string::npos) return false;
        }
        where = p.empty() ? "[anon]" : p;
        return true;
    }
    where = "[unmapped]";
    return true;
}

struct Ctx { int checked; int hits; int modules; std::string detail; };

int phdr_cb(struct dl_phdr_info* info, size_t, void* data) {
    Ctx* c = static_cast<Ctx*>(data);
    if (c->hits >= 64 || !want_module(info->dlpi_name)) return 0;
    c->modules++;
    uintptr_t base = (uintptr_t)info->dlpi_addr;

    const ElfW(Dyn)* dyn = nullptr;
    for (int i = 0; i < info->dlpi_phnum; i++)
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC)
            dyn = (const ElfW(Dyn)*)(base + info->dlpi_phdr[i].p_vaddr);
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
    const char* mod = (info->dlpi_name && info->dlpi_name[0]) ? info->dlpi_name : "[self]";
    const char* modb = strrchr(mod, '/'); modb = modb ? modb + 1 : mod;

    for (size_t i = 0; i < n; i++) {
        ElfW(Rela) rr;
        if (!safe_read_mem(jmprel + i * sizeof(ElfW(Rela)), &rr, sizeof(rr))) break;
        if (ELF64_R_TYPE(rr.r_info) != R_AARCH64_JUMP_SLOT) continue;

        uintptr_t target = 0;
        if (!safe_read_mem(base + rr.r_offset, &target, sizeof(target))) continue;
        if (target == 0) continue;
        c->checked++;

        std::string where;
        if (!target_suspect(target, where)) continue;
        c->hits++;

        std::string sym = "?";
        if (symtab && strtab) {
            ElfW(Sym) s;
            uint32_t si = (uint32_t)ELF64_R_SYM(rr.r_info);
            if (safe_read_mem(symtab + (size_t)si * sizeof(ElfW(Sym)), &s, sizeof(s))) {
                char nbuf[96] = {0};
                if (safe_read_mem_n(strtab + s.st_name, nbuf, sizeof(nbuf) - 1) > 0) sym = nbuf;
            }
        }
        char line[256];
        snprintf(line, sizeof(line), "  %s: %s -> %llx %s\n", modb, sym.c_str(),
                 (unsigned long long)target, where.c_str());
        c->detail += line;
        if (c->hits >= 64) break;
    }
    return 0;
}

}

NativeResult check_got_plt_integrity() {
    NativeResult r;
    find_vdso();
    Ctx c; c.checked = 0; c.hits = 0; c.modules = 0;
    uint32_t probe;
    if (!safe_read_mem((uintptr_t)&check_got_plt_integrity, &probe, sizeof(probe))) {
        r.status = STATUS_INCONCLUSIVE; r.details = "self-memory read unavailable";
        return r;
    }
    dl_iterate_phdr(phdr_cb, &c);
    if (c.checked == 0) {
        r.status = STATUS_INCONCLUSIVE;
        char h[96]; snprintf(h, sizeof(h), "no GOT/PLT slot could be read (modules=%d)", c.modules);
        r.details = h;
        return r;
    }

    char head[96];
    snprintf(head, sizeof(head), "checked=%d hits=%d\n", c.checked, c.hits);
    r.status = c.hits > 0 ? STATUS_DETECTED : STATUS_CLEAN;
    r.details = std::string(head) + (c.hits ? c.detail : "no GOT/PLT target outside a file-backed module (own lib+libc+libart)");

    return r;
}
