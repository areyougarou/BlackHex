#include "named_artifacts.h"
#include <dlfcn.h>
#include <string>

namespace {

NativeResult make(const char* id, const char* name, const char* cat, const char* sev,
                  int status, const std::string& details, const std::string& raw,
                  int sig, int adopt, int diff) {
    NativeResult r;
    r.id = id;  r.category = cat; r.severity = sev;
    r.status = status; r.details = details;

    return r;
}

}

NativeResult check_linker_exports() {
    std::string hits; int n = 0;
    for (const char* const* s = FRIDA_EXPORTS; *s; ++s)
        if (dlsym(RTLD_DEFAULT, *s)) { hits += std::string("  ") + *s + "\n"; n++; }
    if (n == 0)
        return make("NAMED_LINKER_EXPORTS", "Frida ELF exports resolvable via dlsym", CAT_LINKER, SEV_HIGH,
                    STATUS_CLEAN, "No Frida exports resolve", "exports=0", 80, 70, 20);
    return make("NAMED_LINKER_EXPORTS", "Frida ELF exports resolvable via dlsym", CAT_LINKER, SEV_HIGH,
                STATUS_DETECTED, std::to_string(n) + " Frida export(s) resolve:\n" + hits, "exports=" + std::to_string(n), 80, 70, 20);
}
