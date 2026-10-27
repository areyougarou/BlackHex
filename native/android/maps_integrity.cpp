#include "maps_integrity.h"
#include <cstdio>
#include <string>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>

namespace {
const VmaEntry* vma_for(uint64_t addr) {
    for (const auto& v : g_maps)
        if (addr >= v.start && addr < v.end) return &v;
    return nullptr;
}
}

bool page_mapped(uintptr_t addr) {
    static long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    uintptr_t base = addr & ~((uintptr_t)ps - 1);
    unsigned char vec = 0;

    return mincore((void*)base, (size_t)ps, &vec) == 0;
}

NativeResult check_lib_from_root_path() {
    NativeResult r;
    if (!maps_available()) return {STATUS_INCONCLUSIVE, "process memory map unavailable (empty /proc/self/maps snapshot); cannot judge"};
    int hits = 0;
    std::string detail;
    for (const auto& v : g_maps) {
        if (!v.executable()) continue;
        const std::string& p = v.path;
        if (p.empty() || p[0] == '[') continue;
        if (is_own_vma(p)) continue;
        bool suspect = (p.rfind("/data/adb/", 0) == 0) ||
                       (p.find("/data/local/tmp/") != std::string::npos);
        if (!suspect) continue;
        hits++;
        char line[256];
        snprintf(line, sizeof(line), "  %llx-%llx %s %s\n",
                 (unsigned long long)v.start, (unsigned long long)v.end, v.perms, p.c_str());
        detail += line;
        if (hits >= 32) break;
    }

    r.status = hits > 0 ? STATUS_DETECTED : STATUS_CLEAN;
    r.details = hits > 0 ? std::string("exec lib(s) from root/temp path:\n") + detail
                         : "no exec lib mapped from /data/adb or /data/local/tmp";

    return r;
}

NativeResult check_maps_integrity() {
    NativeResult r;
    std::string detail;

    int order_viol = 0;
    for (size_t i = 1; i < g_maps.size(); i++) {
        if (g_maps[i].start < g_maps[i - 1].start ||
            g_maps[i].start < g_maps[i - 1].end) {
            order_viol++;
            if (order_viol <= 4) {
                char line[192];
                snprintf(line, sizeof(line), "  order/overlap @ %llx (prev end %llx)\n",
                         (unsigned long long)g_maps[i].start,
                         (unsigned long long)g_maps[i - 1].end);
                detail += line;
            }
        }
    }

    struct GT { const char* name; uintptr_t addr; };
    GT gt[5];
    int n = 0;
    gt[n++] = { "own_code", (uintptr_t)&check_lib_from_root_path };
    if (void* p = dlsym(RTLD_DEFAULT, "malloc")) gt[n++] = { "libc:malloc", (uintptr_t)p };
    if (void* p = dlsym(RTLD_DEFAULT, "open"))   gt[n++] = { "libc:open",   (uintptr_t)p };
    if (void* p = dlsym(RTLD_DEFAULT, "read"))   gt[n++] = { "libc:read",   (uintptr_t)p };

    int hidden = 0, nonexec = 0, checked = 0;
    for (int i = 0; i < n; i++) {
        if (!gt[i].addr) continue;
        checked++;
        const VmaEntry* ev = vma_for(gt[i].addr);
        if (ev) {
            if (!ev->executable()) {
                nonexec++;
                char line[160];
                snprintf(line, sizeof(line), "  %s @ %llx in NON-EXEC %s\n",
                         gt[i].name, (unsigned long long)gt[i].addr,
                         ev->path.empty() ? "[anon]" : ev->path.c_str());
                detail += line;
            }
        } else if (page_mapped(gt[i].addr)) {
            hidden++;
            char line[160];
            snprintf(line, sizeof(line), "  %s @ %llx HIDDEN (maps:absent, mincore:mapped)\n",
                     gt[i].name, (unsigned long long)gt[i].addr);
            detail += line;
        }
    }

    bool bad = (order_viol > 0) || (hidden > 0) || (nonexec > 0);
    r.status = bad ? STATUS_DETECTED : STATUS_CLEAN;
    char head[160];
    snprintf(head, sizeof(head), "order_viol=%d gt_checked=%d hidden=%d nonexec=%d\n",
             order_viol, checked, hidden, nonexec);
    r.details = std::string(head) + detail;

    return r;
}

NativeResult check_clone_engine_maps() {
    static const char* const kEngines[] = {
        "com.lody.virtual", "io.busniess.va", "com.by.chaos", "com.bly.dkplat", "com.qihoo.magic",
        "com.lbe.parallel", "com.parallel.space", "com.ludashi.dualspace", "com.excelliance.dualaid",
        "com.excelliance.multiaccount", "com.cloneapp", "multi.parallel.dualspace", "com.applisto.appclone",
        "com.vmos", "blackbox", "top.niunaijun", "com.catchingnow.icebox", nullptr };
    if (g_maps.empty()) return {STATUS_INCONCLUSIVE, "maps empty/blocked"};
    for (const auto& v : g_maps)
        for (const char* const* t = kEngines; *t; ++t)
            if (v.path.find(*t) != std::string::npos) return {STATUS_DETECTED, std::string("engine=") + *t + " in " + v.path};
    return {STATUS_CLEAN, "no engine token"};
}
