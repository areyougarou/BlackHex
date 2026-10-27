#include "uprobe_scan.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <fcntl.h>
#include <unistd.h>

#if defined(__aarch64__)

namespace {

constexpr uint32_t BRK_UPROBE = 0xD42000A0u;

bool ends_with(const std::string& s, const char* suf) {
    size_t n = strlen(suf);
    return s.size() >= n && s.compare(s.size() - n, n, suf) == 0;
}

bool scan_region(uint64_t start, uint64_t end, uint64_t& hit) {
    const size_t CH = 65536;
    static uint8_t buf[CH];
    uint64_t cap = start + (24u << 20);
    if (end > cap) end = cap;
    for (uint64_t off = start; off < end; ) {
        size_t want = (end - off < CH) ? (size_t)(end - off) : CH;
        ssize_t got = safe_read_mem_n(off, buf, want);
        if (got <= 0) break;
        size_t g = (size_t)got & ~3u;
        for (size_t i = 0; i + 4 <= g; i += 4) {
            uint32_t w; std::memcpy(&w, buf + i, 4);
            if (w == BRK_UPROBE) { hit = off + i; return true; }
        }
        off += want;
        if (got < (ssize_t)want) break;
    }
    return false;
}

}

NativeResult check_uprobe_residue() {
    NativeResult r;
    if (!maps_available()) return {STATUS_INCONCLUSIVE, "process memory map unavailable (empty /proc/self/maps snapshot); cannot judge"};
    int hits = 0;
    std::string detail;

    for (const auto& v : g_maps)
        if (v.path.find("[uprobes]") != std::string::npos) {
            hits++;
            char line[128];
            snprintf(line, sizeof(line), "  [uprobes] VMA @ %llx-%llx\n",
                     (unsigned long long)v.start, (unsigned long long)v.end);
            detail += line;
            break;
        }

    uint32_t probe;
    if (!safe_read_mem((uintptr_t)&check_uprobe_residue, &probe, sizeof(probe))) {
        r.status = hits ? STATUS_DETECTED : STATUS_INCONCLUSIVE;
        r.details = hits ? detail : "self-memory read unavailable";
        return r;
    }

    int scanned = 0;
    for (const auto& v : g_maps) {
        if (!v.executable()) continue;
        const std::string& p = v.path;
        if (p.empty() || p[0] == '[') continue;
        bool want = is_own_vma(p) || ends_with(p, "/libc.so") || p.find("libblackhex") != std::string::npos;
        if (!want) continue;
        scanned++;
        uint64_t hit = 0;
        if (scan_region(v.start, v.end, hit)) {
            hits++;
            char line[192];
            snprintf(line, sizeof(line), "  BRK#0x5 @ %llx in %s\n",
                     (unsigned long long)hit, p.c_str());
            detail += line;
        }
    }

    char head[96];
    snprintf(head, sizeof(head), "regions_scanned=%d hits=%d\n", scanned, hits);
    r.status = hits > 0 ? STATUS_DETECTED : STATUS_CLEAN;
    r.details = std::string(head) + (hits ? detail : "no uprobe BRK#0x5 in own/libc .text, no [uprobes] VMA");

    return r;
}

#else

NativeResult check_uprobe_residue() { return not_built_for_abi(); }

#endif
