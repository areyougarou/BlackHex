#include "named_artifacts.h"
#include <dlfcn.h>
#include <string>

NativeResult check_linker_exports() {
    std::string hits; int n = 0;
    for (const char* const* s = FRIDA_EXPORTS; *s; ++s)
        if (dlsym(RTLD_DEFAULT, *s)) { hits += std::string("  ") + *s + "\n"; n++; }
    if (n == 0) return {STATUS_CLEAN, "No Frida exports resolve"};
    return {STATUS_DETECTED, std::to_string(n) + " Frida export(s) resolve:\n" + hits};
}
