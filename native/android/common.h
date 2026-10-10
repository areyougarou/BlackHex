#pragma once
#include <string>
#include <vector>
#include <cstdint>

#define STATUS_CLEAN          0
#define STATUS_DETECTED       1
#define STATUS_INCONCLUSIVE   2
#define STATUS_NOT_APPLICABLE 3

#define CAT_HOOKS         "HOOK_DETECTION"
#define CAT_LINKER        "DYNAMIC_LINKER"
#define CAT_MAPS          "MAPS_ANALYSIS"
#define CAT_INTEGRITY     "INTEGRITY"
#define CAT_EMULATOR      "EMULATOR"
#define CAT_CUSTOM_ROM    "CUSTOM_ROM"
#define CAT_SUBSTRATE     "SUBSTRATE"

#define SEV_CRITICAL "CRITICAL"
#define SEV_HIGH     "HIGH"
#define SEV_MEDIUM   "MEDIUM"
#define SEV_LOW      "LOW"

struct NativeResult {
    std::string id;
    std::string category;
    std::string severity;
    int status;
    std::string details;
    long us = 0;
};

struct VmaEntry {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    unsigned dev_major;
    unsigned dev_minor;
    uint64_t inode;
    char perms[8];
    std::string path;

    bool readable()    const { return perms[0] == 'r'; }
    bool writable()    const { return perms[1] == 'w'; }
    bool executable()  const { return perms[2] == 'x'; }
    bool anonymous()   const { return path.empty() || path[0] == '['; }
    uint64_t size()    const { return end - start; }
};

std::vector<VmaEntry> read_maps();
extern std::vector<VmaEntry> g_maps;

std::string read_proc_file(const char* path);

bool safe_read_mem(uintptr_t addr, void* out, size_t len);

std::string json_escape(const std::string& s);

std::string results_to_json(const std::vector<NativeResult>& results);

extern std::string g_own_process_name;
void  init_own_process_name();
bool  is_own_vma(const std::string& path);

extern std::string g_signer_baseline;

#define FRIDA_TRAMPOLINE_INSN 0x58000050u

static const char* const FRIDA_EXPORTS[] = {
    "frida_agent_main",
    "gum_init",
    "gum_deinit",
    "gum_interceptor_obtain",
    "frida_init",
    nullptr
};
