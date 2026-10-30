# Changelog

All notable changes to the free tier. The public interface is still settling, so this
tracks it as it moves. Dates are ISO (year-month-day).

## 0.2.0 (2026-10-31)

### Breaking
- The library is renamed from BlackHex to Intakto. The entry object `BlackHex` is now `Intakto`,
  and the native library file is `libintakto.so`. The GitHub repository is now
  `areyougarou/IntaktoFT`; the old addresses redirect. Install through JitPack:
  `com.github.areyougarou:IntaktoFT:v0.2.0`.
- The code package is renamed from `rasp.sdk` to `io.github.areyougarou.intakto`. Update your imports.
- `Signal.category` and `Signal.severity` (free-text strings) are removed. Use `Signal.group`
  (`APP_INTEGRITY`, `INSTRUMENTATION`).
- The free tier now answers two questions only: were the app files changed, and is running code
  hooked. Every `ROOT_*`, `EMU_*` and `CROM_*` check is removed with its group: honest users have
  rooted phones, emulators and custom systems, so these are not grounds to stop an app.
- `Policy` and its per-group toggles are removed. One setting replaces them: `Mode.BLOCK` (the
  default: Intakto stops the app on any DETECTED signal) or `Mode.REPORT` (Intakto never stops
  the app and hands the report to the callback).
- `check(context, mode, onResult)` returns at once and delivers the report on the main thread. The
  mode and the callback are optional, so the whole setup is `Intakto.check(this)`. The blocking
  `val report = BlackHex.check(context, policy)` is removed.
- `BlackHex.baseline { }` is removed with every value in it (`packageName`, `resources`,
  `nativeLib`, `dexCrc`, `signers`). There is nothing to paste or configure.
- `Signal.certainty` is removed. A check that cannot get an answer reads INCONCLUSIVE, with details
  starting `could not verify`, and never closes the app. Only a DETECTED signal makes the verdict BLOCK.
- Checks removed: `TAMPER_NATIVELIB`, `TAMPER_RESOURCES`, `CLV_DEX_CRC` (they needed pasted
  build-time values and could not match a Play install); `TAMPER_SIGNER` and
  `CLV_SIGCERT_MISMATCH` (they needed a pasted signer); `CLV_CGROUP_UID_MISMATCH`,
  `CLV_AM_SINGLETON_PROXY`, `CLV_MAPS_ENGINE_STRING`, `ELF_IN_ANON`, `MAPS_INTEGRITY` and
  `ART_ENTRYPOINT_INTEGRITY` (honest phones can show them); `NAMED_LINKER_EXPORTS` (it matched only
  five fixed Frida function names).
- `HOOK_BYTES_DIRECT` and `HOOK_BYTES_MEM` are merged into `HOOK_BYTES`.

### Added
- `FRIDA_AGENT_IN_MEMORY`: flags a library loaded from memory (anonymous memory or a memfd) whose own
  export table holds `frida_agent_main`, the entry point of Frida's agent, which is how frida-server
  loads it. It replaces the removed `ELF_IN_ANON`, which flagged any library in that memory and
  so could fire on honest apps that unpack their own libraries there (packers, anti-cheat).
- `DISGUISED_LIBRARY_IN_MEMORY`: flags a library loaded from a memfd named as the system's own memory
  (ART's `jit-cache`, `dalvik`, and the like), which never holds a library. Frida builds that rename the
  agent's entry, so `FRIDA_AGENT_IN_MEMORY` misses them, hide their agent this way (Florida and its
  builds, Rusda, strongR-frida, phantom-frida, FreeDaah).
- Zero-paste setup. The package name is read from a manifest value Android fills in at build
  time, and the signer from Android, so the developer configures nothing.
- `Mode.BLOCK` stops the app by closing its tasks (which removes them from the recent-apps list)
  and ending its process. No message is shown.
- `TAMPER_APK_CONTENT`: verifies each installed APK file (base and every split) against the
  signature block inside that file, and against the signer Android reports. It finds the real
  base.apk from the process memory map and reads it below the Java layer, so a tool that points
  the app at a clean copy does not fool it.
- `TAMPER_PUBLIC_KEY`: flags an app signed with a key anyone can download, the public AOSP test
  keys and the keys that ship inside common re-signing tools, matched by exact SHA-256.
- One package carries native code for all four chip types: arm64-v8a as a normal library, the
  other three loaded at run time from assets. A check built for one chip type is left out of the
  report on the others.
- `CHECK_STALLED` and `CHECK_FAILED`: a run that made no progress for 5 s, or that could not run,
  blocks instead of passing.
- An app that Google Play installs while it downloads (Android 12 and later) is checked once the
  download finishes. The 5 s stall limit does not count while it waits.

### Changed
- One run happens at a time. Calls made during a run share it, and each keeps its own mode.
- `TAMPER_SIGNING_BLOCK` and `TAMPER_APK_CONTENT` accept the file when any of its v2, v3 or v3.1
  signing entries carries a signer Android reports, so a key-rotated app is not flagged after an
  Android upgrade. Both are left out for an app that ships inside the system image.
- `TAMPER_PUBLIC_KEY` is reported on debuggable builds too.
- `CLV_PKGNAME_MISMATCH` reads DETECTED, instead of disappearing, when the build-time package name
  is missing from the manifest.
- The APK files are hashed again in every new app process; nothing is cached across app starts.
- Fixed APK and device facts are read once per process and reused.
- Repackaging-tool markers are matched by file name inside any folder, and read from the real APK
  below the Java layer, so App Cloner and LSPatch are caught where the old match missed them.
- `LIB_FROM_ROOT_PATH` no longer counts every root module loaded into the app, because Zygisk loaders
  such as ReZygisk load every enabled module into every app. A module counts only if it is LSPosed,
  Vector or ZygiskFrida, which unload themselves from every app they do not hook. Code from
  `/data/local/tmp`, or from `/data/adb` outside the modules folder, still reads DETECTED.
- `HOOK_BYTES`, `OPCODE_TRAMPOLINE` and `GOT_PLT_INTEGRITY` read INCONCLUSIVE, not DETECTED, for a
  hook they cannot follow to any library: it proves a hook, not who placed it. A hook that lands in
  a library outside the app's install folder still reads DETECTED.

### Fixed
- The hook checks follow a jump into a library's padding. The kernel's page-size compat shows that
  padding as its own `---p [page size compat]` line whatever its real access, and ShadowHook writes
  its jump there in libc on the Nothing Phone 2a, so an honest ShadowHook app was closed there.
- A crafted signing block could crash the native parser on 32-bit ARM or make it loop forever.
- The ZIP end record is found the way Android finds it, so a fake one inside the ZIP comment is
  ignored.
- The APK file checks read only files in the folders Android installs apps into, so an
  app-writable copy is never used.
- Memory checks now work in release builds. They read the app's own memory through a pipe, so a
  whole family of checks that silently read nothing on shipped builds now runs.
- A native check that cannot read the process memory map reports `could not verify`, instead of a
  false CLEAN.
- `HOOK_BYTES` and `OPCODE_TRAMPOLINE` compare a suspected jump against the same bytes in the
  library file on disk, so a jump that ships in the original library is not reported.
- Memory-map paths are kept in full.
- The native library is linked for 16 KB memory pages. A failed native load reports `NATIVE_CORE`
  instead of crashing the app, and the next call tries the load, and the APK file check, again.

### Security of the build
- Reproducible native build: build-machine paths are mapped out of the build id, so the same source
  produces a byte-identical library (on a Linux x86-64 host).
