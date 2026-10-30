#include "elf_anon.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <elf.h>
#include <link.h>
#include <unistd.h>

namespace {

// Frida's agent library (libfrida-agent-raw.so, which frida-server loads into the
// app from a memfd) exports this entry point, and Frida's loader finds the agent by it. Only
// Frida's agent exports it. frida-server 17.9.8 and 17.23.3 carry an agent exporting exactly
// frida_agent_main and JNI_OnLoad. A build that renames it (Florida 17.9.1 exports `main`) or a
// gadget (it exports nothing) gets past this check: a miss is allowed, a false alarm is not.
const char kAgentEntry[] = "frida_agent_main";

#if defined(__LP64__)
const unsigned char kOwnClass = ELFCLASS64;
#else
const unsigned char kOwnClass = ELFCLASS32;
#endif

enum Lookup { NOT_FOUND, FOUND, UNREADABLE };

// Names the system gives its own memory: ART's JIT cache and heaps, the linker's and the allocator's
// memory, thread stacks. None of these regions holds a library image. Florida 17.9.1 and its builds,
// Rusda 17.23.1, strongR-frida 16.5.6 and FreeDaah 17.19.0 load their agent from a memfd named jit-cache,
// phantom-frida 17.16.4 from one named jit-code-cache.
// [vdso] is not in the list: it is the kernel's own library.
const char* const kSystemNames[] = {"jit-cache", "code-cache", "dalvik", ".art", "linker_alloc", "scudo", "stack"};

const char* system_name(const std::string& p) {
    for (const char* n : kSystemNames)
        if (p.find(n) != std::string::npos) return n;
    return nullptr;
}

// Memory with no file behind it: anonymous, [anon:<name>], or a memfd (a file that lives only in memory).
bool memory_only(const std::string& p) {
    return p.empty() || p[0] == '[' || p.find("memfd:") != std::string::npos;
}

bool is_candidate_region(const VmaEntry& v) {
    return memory_only(v.path) && !system_name(v.path) && v.path.find("vdso") == std::string::npos;
}

template <typename T> bool rd(uintptr_t a, T& out) { return safe_read_mem(a, &out, sizeof(out)); }

// One library image in memory, located from its own ELF header. Every address the lookup reads
// must fall inside the image, so the name can only come from this library's own tables.
struct Image {
    uintptr_t bias = 0, lo = 0, hi = 0;
    uintptr_t strtab = 0, symtab = 0, gnu_hash = 0, hash = 0;
    uint64_t strsz = 0;
    bool inside(uintptr_t a, uint64_t len) const { return a >= lo && a < hi && len <= hi - a; }
    uintptr_t at(ElfW(Addr) p) const { return p < bias ? bias + p : p; }
};

Lookup check_sym(const Image& im, uint32_t idx) {
    ElfW(Sym) s;
    uintptr_t a = im.symtab + (uintptr_t)idx * sizeof(s);
    if (!im.inside(a, sizeof(s)) || !rd(a, s)) return UNREADABLE;
    if (s.st_name >= im.strsz) return UNREADABLE;
    char name[sizeof(kAgentEntry)];
    ssize_t n = safe_read_mem_n(im.strtab + s.st_name, name, sizeof(name));
    if (n <= 0) return UNREADABLE;
    if (memcmp(name, kAgentEntry, (size_t)n) != 0) return NOT_FOUND;
    if ((size_t)n < sizeof(name)) return UNREADABLE;
    unsigned bind = s.st_info >> 4;
    bool exported = s.st_shndx != SHN_UNDEF && (bind == STB_GLOBAL || bind == STB_WEAK);
    return exported ? FOUND : NOT_FOUND;
}

// The same lookup the dynamic linker runs for dlsym(): a name the linker can export is found here.
Lookup gnu_lookup(const Image& im) {
    uint32_t hdr[4];
    if (!im.inside(im.gnu_hash, sizeof(hdr)) || !safe_read_mem(im.gnu_hash, hdr, sizeof(hdr))) return UNREADABLE;
    uint32_t nbuckets = hdr[0], symoffset = hdr[1];
    if (nbuckets == 0) return NOT_FOUND;
    uint32_t h = 5381;
    for (const char* c = kAgentEntry; *c; c++) h = h * 33 + (uint8_t)*c;
    uintptr_t buckets = im.gnu_hash + sizeof(hdr) + (uintptr_t)hdr[2] * sizeof(ElfW(Addr));
    uintptr_t chain = buckets + (uintptr_t)nbuckets * 4;
    uint32_t idx;
    uintptr_t b = buckets + (uintptr_t)(h % nbuckets) * 4;
    if (!im.inside(b, 4) || !rd(b, idx)) return UNREADABLE;
    if (idx < symoffset) return NOT_FOUND;
    for (int guard = 0; guard < 65536; guard++, idx++) {
        uint32_t ch;
        uintptr_t c = chain + (uintptr_t)(idx - symoffset) * 4;
        if (!im.inside(c, 4) || !rd(c, ch)) return UNREADABLE;
        if ((ch | 1) == (h | 1)) {
            Lookup r = check_sym(im, idx);
            if (r != NOT_FOUND) return r;
        }
        if (ch & 1) return NOT_FOUND;
    }
    return UNREADABLE;
}

Lookup sysv_lookup(const Image& im) {
    uint32_t hdr[2];
    if (!im.inside(im.hash, sizeof(hdr)) || !safe_read_mem(im.hash, hdr, sizeof(hdr))) return UNREADABLE;
    uint32_t nbucket = hdr[0], nchain = hdr[1];
    if (nbucket == 0) return NOT_FOUND;
    uint32_t h = 0;
    for (const char* c = kAgentEntry; *c; c++) {
        h = (h << 4) + (uint8_t)*c;
        uint32_t g = h & 0xf0000000u;
        if (g) h ^= g >> 24;
        h &= ~g;
    }
    uintptr_t bucket = im.hash + sizeof(hdr), chain = bucket + (uintptr_t)nbucket * 4;
    uint32_t idx;
    uintptr_t b = bucket + (uintptr_t)(h % nbucket) * 4;
    if (!im.inside(b, 4) || !rd(b, idx)) return UNREADABLE;
    for (int guard = 0; idx != 0 && guard < 65536; guard++) {
        if (idx >= nchain) return UNREADABLE;
        Lookup r = check_sym(im, idx);
        if (r != NOT_FOUND) return r;
        uintptr_t c = chain + (uintptr_t)idx * 4;
        if (!im.inside(c, 4) || !rd(c, idx)) return UNREADABLE;
    }
    return idx == 0 ? NOT_FOUND : UNREADABLE;
}

// Called for a region that starts with an ELF header of this process's class. FOUND means it is a
// library image laid out the way the linker loads one; `im` then holds its bounds and `dyn` its
// dynamic table's program header.
Lookup library_image(const VmaEntry& v, const ElfW(Ehdr)& eh, Image& im, ElfW(Phdr)& dyn) {
    if (eh.e_phentsize != sizeof(ElfW(Phdr)) || eh.e_phnum == 0 || eh.e_phnum > 128) return NOT_FOUND;
    if (eh.e_phoff + (uint64_t)eh.e_phnum * sizeof(ElfW(Phdr)) > v.size()) return NOT_FOUND;
    ElfW(Phdr) ph[128];
    if (!safe_read_mem((uintptr_t)(v.start + eh.e_phoff), ph, eh.e_phnum * sizeof(ElfW(Phdr)))) return UNREADABLE;

    const ElfW(Phdr)* first = nullptr;
    const ElfW(Phdr)* d = nullptr;
    uint64_t end = 0;
    for (unsigned i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) d = &ph[i];
        if (ph[i].p_type != PT_LOAD) continue;
        if (!first) first = &ph[i];
        if ((uint64_t)ph[i].p_vaddr + ph[i].p_memsz > end) end = (uint64_t)ph[i].p_vaddr + ph[i].p_memsz;
    }
    // No dynamic table means no exports. The header must sit at the start of the first loaded
    // segment, as it does in every library the linker loads.
    if (!d || !first || first->p_offset != 0) return NOT_FOUND;

    uintptr_t page = (uintptr_t)getpagesize();
    uintptr_t base = (uintptr_t)first->p_vaddr & ~(page - 1);
    if (v.start < base) return NOT_FOUND;
    im.bias = (uintptr_t)v.start - base;
    im.lo = (uintptr_t)v.start;
    im.hi = im.bias + (uintptr_t)end;
    if (im.hi <= im.lo) return NOT_FOUND;
    dyn = *d;
    return FOUND;
}

Lookup agent_exported(Image& im, const ElfW(Phdr)& dyn) {
    ElfW(Dyn) d[256];
    uintptr_t da = im.bias + (uintptr_t)dyn.p_vaddr;
    size_t want = dyn.p_memsz < sizeof(d) ? (size_t)dyn.p_memsz : sizeof(d);
    if (!im.inside(da, want)) return UNREADABLE;
    ssize_t got = safe_read_mem_n(da, d, want);
    if (got < (ssize_t)sizeof(ElfW(Dyn))) return UNREADABLE;
    for (size_t i = 0; i < (size_t)got / sizeof(ElfW(Dyn)) && d[i].d_tag != DT_NULL; i++) {
        switch (d[i].d_tag) {
            case DT_STRTAB:   im.strtab   = im.at(d[i].d_un.d_ptr); break;
            case DT_SYMTAB:   im.symtab   = im.at(d[i].d_un.d_ptr); break;
            case DT_STRSZ:    im.strsz    = d[i].d_un.d_val; break;
            case DT_GNU_HASH: im.gnu_hash = im.at(d[i].d_un.d_ptr); break;
            case DT_HASH:     im.hash     = im.at(d[i].d_un.d_ptr); break;
        }
    }
    if (!im.strtab || !im.symtab || (!im.gnu_hash && !im.hash)) return NOT_FOUND;
    if (!im.inside(im.strtab, im.strsz)) return UNREADABLE;
    return im.gnu_hash ? gnu_lookup(im) : sysv_lookup(im);
}

std::string region_line(const VmaEntry& v) {
    char line[320];
    snprintf(line, sizeof(line), "  %llx-%llx %s %s\n", (unsigned long long)v.start,
             (unsigned long long)v.end, v.perms, v.path.empty() ? "[anon]" : v.path.c_str());
    return line;
}

// An empty map or a failed read of our own code means the walk would see nothing: never CLEAN.
const char* cannot_judge(const void* own_code) {
    if (!maps_available()) return "process memory map unavailable (empty /proc/self/maps snapshot); cannot judge";
    uint32_t probe;
    if (!safe_read_mem((uintptr_t)own_code, &probe, sizeof(probe))) return "self-memory read unavailable";
    return nullptr;
}

}

NativeResult check_frida_agent_in_memory() {
    if (const char* why = cannot_judge((const void*)&check_frida_agent_in_memory)) return {STATUS_INCONCLUSIVE, why};

    int images = 0, unreadable = 0;
    std::string unread;
    // A small library can map its first file page twice (code, then read-only data), so its header
    // shows at the start of two regions. Regions inside an image already read belong to it.
    uintptr_t image_hi = 0;
    for (const auto& v : g_maps) {
        if (v.start < image_hi) continue;
        if (!v.readable() || !is_candidate_region(v) || is_own_vma(v.path)) continue;
        ElfW(Ehdr) eh;
        if (v.size() < sizeof(eh) || !rd((uintptr_t)v.start, eh)) continue;
        if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != kOwnClass) continue;
        images++;
        Image im;
        ElfW(Phdr) dyn;
        Lookup r = library_image(v, eh, im, dyn);
        if (r == FOUND) {
            image_hi = im.hi;
            r = agent_exported(im, dyn);
        }
        switch (r) {
            case FOUND:
                return {STATUS_DETECTED, std::string("library loaded from memory exports Frida's agent entry ") +
                                         kAgentEntry + ":\n" + region_line(v)};
            case UNREADABLE:
                if (++unreadable <= 4) unread += region_line(v);
                break;
            case NOT_FOUND:
                break;
        }
    }
    if (unreadable > 0)
        return {STATUS_INCONCLUSIVE, "export table unreadable for " + std::to_string(unreadable) +
                                     " library image(s) in unnamed memory:\n" + unread};
    return {STATUS_CLEAN, std::to_string(images) + " library image(s) in unnamed memory; none exports " + kAgentEntry};
}

// Only memfds are read: a loader that goes through the linker maps the library from a file, and every
// disguised agent seen so far is a memfd. ART's own anonymous regions run to hundreds per process.
NativeResult check_disguised_library() {
    if (const char* why = cannot_judge((const void*)&check_disguised_library)) return {STATUS_INCONCLUSIVE, why};

    int regions = 0, unreadable = 0;
    std::string unread;
    for (const auto& v : g_maps) {
        if (v.path.find("memfd:") == std::string::npos || !v.readable()) continue;
        const char* name = system_name(v.path);
        if (!name || is_own_vma(v.path)) continue;
        regions++;
        ElfW(Ehdr) eh;
        if (v.size() < sizeof(eh) || !rd((uintptr_t)v.start, eh)) continue;
        if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != kOwnClass) continue;
        Image im;
        ElfW(Phdr) dyn;
        switch (library_image(v, eh, im, dyn)) {
            case FOUND:
                return {STATUS_DETECTED, std::string("library image in memory named as the system's own (") + name +
                                         "), which never holds a library:\n" + region_line(v)};
            case UNREADABLE:
                if (++unreadable <= 4) unread += region_line(v);
                break;
            case NOT_FOUND:
                break;
        }
    }
    if (unreadable > 0)
        return {STATUS_INCONCLUSIVE, "program headers unreadable for " + std::to_string(unreadable) +
                                     " library header(s) in memfds named as the system's own:\n" + unread};
    return {STATUS_CLEAN, std::to_string(regions) + " memfd region(s) named as the system's own memory; none holds a library image"};
}
