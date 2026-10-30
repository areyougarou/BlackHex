#pragma once
#include "common.h"

enum HookOwner { HOOK_UNRESOLVED, HOOK_FOREIGN, HOOK_APP_OWN };

// Follows a hook from `addr` (a hooked function's entry, or a code pointer found in a function
// table) through the jumps and code pointers of generated code, to the first code that belongs to
// a file other than a system library. HOOK_APP_OWN: that code is a library installed with this app
// (the developer's own hooking SDK), and not Frida. HOOK_FOREIGN: it is anywhere else, or Frida
// packed into the app. HOOK_UNRESOLVED: no such code within a few hops. `where` names the code.
HookOwner hook_owner(uintptr_t addr, std::string& where);
