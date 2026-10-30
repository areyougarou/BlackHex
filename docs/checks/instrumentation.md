# Instrumentation checks

[Back to the README](../../README.md)

**Instrumentation**: someone is hooking or injecting code into your running app.

| Id | DETECTED means |
|---|---|
| `FRIDA_AGENT_IN_MEMORY` | A library loaded from memory, not from a file, exports `frida_agent_main`, the entry point of Frida's agent. |
| `DISGUISED_LIBRARY_IN_MEMORY` | A library is loaded from a memfd (a file that lives only in memory) named like the system's own memory, such as ART's `jit-cache`, which never holds a library. |
| `LIB_FROM_ROOT_PATH` | Code runs from a file in `/data/local/tmp` (where files pushed over ADB live) or `/data/adb` (where root modules live). A root module counts only if it is LSPosed (Vector) or ZygiskFrida: they load only into the apps they hook. Other modules load into every app, so they say nothing about yours. |
| `HOOK_BYTES` | A watched system function (`open`, `read`, `mmap`, `dlopen`, `dlsym` and others) begins with Frida's default trampoline instruction in memory, not the real code on disk. arm64 only. |
| `OPCODE_TRAMPOLINE` | A wider list of sensitive functions (adding `connect`, `ptrace`, `kill` and others) is checked for a jump or a breakpoint that the library file on disk does not have. arm64 only. |
| `GOT_PLT_INTEGRITY` | A function address table (GOT/PLT) in this library, libc or the Android runtime points outside any library file. arm64 only. |
| `UPROBE_RESIDUE` | Kernel tracing breakpoints (uprobes) sit in this library's code or in libc's code. arm64 only. |

`HOOK_BYTES`, `OPCODE_TRAMPOLINE` and `GOT_PLT_INTEGRITY` follow each hook to the code it jumps to. A hook that lands in a library shipped inside your APK is your own and reads CLEAN. A hook they cannot follow to any library reads INCONCLUSIVE: it proves a hook, not who placed it.

One case is flagged on purpose: a hooking library your app downloads into its data folder and loads at run time, instead of shipping it inside the APK. Nothing signs that folder, so a hook that lands there could be anyone's.
