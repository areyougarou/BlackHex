# Changelog

All notable changes to the free tier. The public interface is still settling, so this
tracks it as it moves. Dates are ISO (year-month-day).

## Unreleased

### Breaking
- The code package is renamed from `rasp.sdk` to `io.github.areyougarou.blackhex`. Update your imports.
- `Signal.category` and `Signal.severity` (free-text strings) are removed. Use `Signal.group`
  (`APP_INTEGRITY`, `INSTRUMENTATION`, `ROOT`, `EMULATOR`, `BOOTLOADER`) and `Signal.certainty`
  (`PROOF`, `STRONG`, `WEAK`).
- The app no longer pastes identity values into `BlackHex.baseline { }`. `packageName`,
  `resources`, `nativeLib` and `dexCrc` are gone; the only value left is an optional `signers` pin.
- Checks removed: `TAMPER_NATIVELIB`, `TAMPER_RESOURCES`, `CLV_DEX_CRC` (they needed pasted
  build-time values and could not match a Play install); `CLV_SIGCERT_MISMATCH` (it repeated
  `TAMPER_SIGNER`).
- Checks merged or split: `HOOK_BYTES_DIRECT` + `HOOK_BYTES_MEM` become `HOOK_BYTES`;
  `EMU_PROPS` splits into `EMU_PROPS_QEMU` (STRONG) and `EMU_PROPS_HINTS` (WEAK).

### Added
- Zero-paste setup. The package name is read from a manifest value Android fills in at build
  time, so the developer configures nothing.
- `TAMPER_APK_CONTENT` (STRONG): verifies each installed APK file (base and every split) against
  the signature block inside that file, and against the signer Android reports. It finds the real
  base.apk from the process memory map and reads it below the Java layer, so a tool that points
  the app at a clean copy does not fool it.
- `TAMPER_PUBLIC_KEY` (WEAK): flags a release build signed with the Android debug certificate or a
  public AOSP test key (matched by exact SHA-256).
- One package carries native code for all four chip types: arm64-v8a as a normal library, the
  other three loaded at run time from assets. A check built for one chip type is reported
  `NOT_APPLICABLE` on the others.
- `CHECK_IN_PROGRESS` (INCONCLUSIVE, WEAK): returned to a main-thread caller when the first check
  is still running on another thread.

### Changed
- A DETECTED signal causes BLOCK only when its certainty is PROOF or STRONG. WEAK signals are
  reported and never block.
- One run happens at a time. A background caller waits for the running check and gets its result;
  the main thread never waits behind a running check.
- `TAMPER_SIGNER` accepts a set of pinned signing keys and key rotation (v3 lineage). With no pin
  it reports INCONCLUSIVE.
- `CLV_MAPS_ENGINE_STRING` is now computed in native code (same id and group).
- `ROOT_SU_PATH` no longer counts `/system/xbin/busybox`; it looks only for `su`.
- Fixed APK and device facts are read once per process and reused.
- Repackaging-tool markers are matched by file name inside any folder, and read from the real APK
  below the Java layer, so App Cloner, Xpatch and LSPatch are caught where the old match missed them.

### Fixed
- Memory checks now work in release builds. They read the app's own memory through a pipe, so a
  whole family of checks that silently read nothing on shipped builds now runs.
- A native check that reads the process memory map reports INCONCLUSIVE when the map cannot be read,
  instead of a false CLEAN.
- `HOOK_BYTES` and `OPCODE_TRAMPOLINE` compare a suspected jump against the same bytes in the
  library file on disk, so a jump that ships in the original library is not reported.
- `ROOT_MOUNT_TOKENS` parses each mount field separately, so an unrelated word no longer counts as a
  root trace.
- Memory-map paths are kept in full.
- `EMU_CPU_ISA` no longer treats a `model name` line in `/proc/cpuinfo` as an x86 sign.
- The native library is linked for 16 KB memory pages, and a failed native load no longer stops the
  host app from opening (`NATIVE_CORE` reports INCONCLUSIVE instead).

### Security of the build
- Reproducible native build: build-machine paths are mapped out of the build id, so the same source
  produces a byte-identical library (on a Linux x86-64 host).
