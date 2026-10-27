> [!IMPORTANT]
> **Why BlackHex?**
>
> Because the major RASP competitors are run by marketing and sales teams, not security researchers.
>
> App owners are being sold high-ticket placebos, while attackers are 3 prompts away from running fraud operations on your app.
>
> **We plan to do better, and to do it for free.**

~ BlackHex (free tier)

Free Android RASP (runtime app self-protection) library. It actively checks on-device 
integrity and returns signals plus a verdict. It does not send data back to our servers.

> [!NOTE]
> This is the free tier, in active development. It is not on a package repository yet, so
> build it from source (see [Build](#build)). The public interface is still settling; a
> changelog records each change ([CHANGELOG.md](CHANGELOG.md)).

~ What it checks for

| Group | Toggle | What it looks for |
|-------|--------|-------------------|
| App integrity | always on | The installed app files are intact and signed by the key Android reports for the app (each installed APK file checked against its own signature, the signer Android reports, package name, publicly known signing keys, repackager/cloner artifacts). Catching a copy re-signed with a different key needs the optional signer pin (see [Usage](#usage)). |
| Instrumentation | ALLOW \| BLOCK | Runtime hooking / code injection (ART method hooks, inline-hook residue, injected libraries) |
| Emulator | ALLOW \| BLOCK | Signs the app is running on an emulator / virtual device rather than real hardware (CPU/ISA, GPU, sensors, device nodes, build props) |
| Root | ALLOW \| BLOCK | Signs of an unhidden rooted device (world-visible su, live Magisk/Zygisk/APatch daemon socket, module mount residue, a known root-manager app, kernel root token, privileged/non-zygote launch context) |
| Custom ROM / unlocked Bootloader | ALLOW \| BLOCK | Unlocked bootloader / custom ROM indicators (verified-boot state, ROM system features, ROM signing, ROM build props) |

<details>
<summary>Every check, with its certainty and what DETECTED means</summary>

**App integrity**

| Id | Certainty | DETECTED means |
|---|---|---|
| `TAMPER_SIGNER` | PROOF | The app is signed by a key that is not in your optional signer pin, and not a rotation from a pinned key. Without a pin it is left out of the report. |
| `TAMPER_SIGNING_BLOCK` | STRONG | No signing entry inside base.apk, read by native code with direct system calls, carries a signer Android reports for this app. So Android's answer, or the file, was faked or swapped. Left out for an app that ships inside the system image. |
| `TAMPER_APK_CONTENT` | STRONG | An installed APK file (the base or any split) no longer matches its own signature, or no signing entry in it carries a signer Android reports for the app. A file with no v2/v3 signature reads DETECTED when the app targets Android 11 or later, and INCONCLUSIVE below that. Left out for an app that ships inside the system image. |
| `TAMPER_PUBLIC_KEY` | WEAK | The app is signed with the Android debug certificate or a public AOSP test key, which anyone can use. |
| `TAMPER_REPACKAGER` | PROOF | The APK holds files left by LSPatch, Xpatch or App Cloner. |
| `CLV_PKGNAME_MISMATCH` | PROOF | The running package name differs from the application id written into the manifest when the app was built, so the app was renamed or cloned. INCONCLUSIVE when that manifest value is missing. |
| `CLV_CGROUP_UID_MISMATCH` | WEAK | The user id in the process's cgroup entry differs from the app's own user id, a sign that the app may run inside another app. |
| `CLV_AM_SINGLETON_PROXY` | WEAK | The app's link to Android's activity manager was swapped for a Java proxy object, a trick used by app-cloning engines. |
| `CLV_MAPS_ENGINE_STRING` | WEAK | The process memory map names a known app-cloning or virtual-phone engine (VirtualApp, Parallel Space, Dual Space, VMOS and others). |
| `NATIVE_CORE` | WEAK | Never DETECTED. It appears, as INCONCLUSIVE, only when the native library did not run. |
| `CHECK_STALLED` | STRONG | No check made progress for 5 s, or an earlier run is stuck. The report holds only the checks that finished, so it is treated as a block. |
| `CHECK_FAILED` | STRONG | The run could not start, or it stopped with an error. |

**Instrumentation**

| Id | Certainty | DETECTED means |
|---|---|---|
| `NAMED_LINKER_EXPORTS` | PROOF | Frida's own function names (`frida_agent_main`, `gum_init` and others) resolve inside your process. |
| `LIB_FROM_ROOT_PATH` | PROOF | Code runs from a file in `/data/adb` or `/data/local/tmp`, the folders where root modules and files pushed over ADB live. |
| `HOOK_BYTES` | STRONG | A watched system function (`open`, `read`, `mmap`, `dlopen`, `dlsym` and others) starts with a jump that the library file on disk does not have. arm64-v8a only. |
| `OPCODE_TRAMPOLINE` | STRONG | A wider list of sensitive functions (adding `connect`, `ptrace`, `kill` and others) is checked for a jump or a breakpoint that the library file on disk does not have. arm64-v8a only. |
| `GOT_PLT_INTEGRITY` | STRONG | A function address table (GOT/PLT) in this library, libc or the Android runtime points outside any library file. arm64-v8a only. |
| `UPROBE_RESIDUE` | STRONG | Kernel tracing breakpoints (uprobes) sit in this library's code or in libc's code. arm64-v8a only. |
| `ELF_IN_ANON` | WEAK | A loadable library sits in memory with no file behind it. 64-bit chips only. |
| `MAPS_INTEGRITY` | WEAK | The process memory map is out of order, or it hides or mislabels the memory of core functions. |
| `ART_ENTRYPOINT_INTEGRITY` | WEAK | A watched Java method (`File.exists`, `Location.getLatitude`, `Location.getLongitude`) now starts in code outside the normal Android runtime. 64-bit chips only. |

**Root**

| Id | Certainty | DETECTED means |
|---|---|---|
| `ROOT_PROC_STATUS` | PROOF | The app process runs without the seccomp filter (the kernel rules Android puts on every normal app), so it was not started the normal way. |
| `ROOT_SU_PATH` | STRONG | An `su` file exists in a standard place (`/system/bin/su`, `/system/xbin/su`, `/sbin/su` and others). |
| `ROOT_KERNEL_STRING` | STRONG | The kernel version string names KernelSU, APatch or Magisk. |
| `ROOT_MAGISK_DAEMON` | STRONG | A local socket named after a root daemon (Magisk, Zygisk, APatch) is listening. CLEAN only when every name reports that nothing listens; any other error reads INCONCLUSIVE. |
| `ROOT_SELINUX_DOMAIN` | WEAK | The process runs in a SELinux security domain other than the normal app domain, `untrusted_app`. |
| `ROOT_MOUNT_TOKENS` | WEAK | The mount table shows system folders covered or replaced, or names Magisk, KernelSU, APatch or `/data/adb`. |
| `ROOT_MANAGER_PKG` | WEAK | A known root manager app is installed (Magisk, KernelSU, APatch, SuperSU, KingRoot and others), found by its package name. |

**Emulator**

| Id | Certainty | DETECTED means |
|---|---|---|
| `EMU_PROPS_QEMU` | STRONG | System properties that emulators set: `ro.kernel.qemu`, a hardware name of `goldfish`, `ranchu` or `vbox86`, or emulated graphics. |
| `EMU_DEVNODES` | STRONG | Emulator device files exist (`/dev/qemu_pipe`, goldfish, Genymotion and VirtualBox nodes). |
| `EMU_VULKAN` | STRONG | The Vulkan graphics driver reports a software GPU, one that runs on the CPU. |
| `EMU_SENSORS` | STRONG | A sensor's vendor name belongs to an emulator (Genymotion, goldfish, ranchu and others). |
| `EMU_PROPS_HINTS` | WEAK | The hardware name looks like an emulator's (Nox and others), the main ABI is x86, or an ARM translation bridge is set. |
| `EMU_CPU_ISA` | WEAK | `/proc/cpuinfo` names an emulator or, on an ARM build, shows Intel, AMD or hypervisor markers. |
| `EMU_TRANSLATOR` | WEAK | An ARM translation library (Houdini, ndk_translation) is loaded in your app. These libraries run ARM apps on x86 machines. |
| `EMU_MOUNTS` | WEAK | Shared-folder file systems of virtual machines are mounted (9p, vboxsf, virtiofs). |
| `EMU_GL` | WEAK | OpenGL draws in software (SwiftShader, llvmpipe and others). |

**Custom ROM / unlocked Bootloader**

| Id | Certainty | DETECTED means |
|---|---|---|
| `CROM_FEATURE` | PROOF | The system declares a feature of a custom Android system (GrapheneOS, LineageOS, CalyxOS, microG). |
| `CROM_BOOT` | STRONG | The bootloader is unlocked, or verified boot did not end in its fully checked "green" state. |
| `CROM_ROM_PROPS` | STRONG | A version property of a known custom system is set (LineageOS, crDroid, EvolutionX, PixelOS, /e/OS and others). |
| `CROM_SIGN` | WEAK | The system was built with test keys, or as a debug build (`userdebug`, `eng`). |
| `CROM_PKG_CLUSTER` | WEAK | Apps that come with a custom system are installed, or neither Google Play services nor the Play Store is installed. |

</details>

BlackHex actively hunts only for values that can be confirmed without server verdicts. Device fingerprint, promo abuse and coordinated actions are not included in the free tier because they would violate this exact principle.

Every check reports CLEAN, DETECTED or INCONCLUSIVE (it could not get an answer). A check is left
out of the report in two cases, both known before anything is read. It does not apply to this app
(the signer check with no pin, or the APK file checks for an app that ships inside the system
image). Or it is not built for this phone's chip type: 6 instrumentation checks are built only for
64-bit chips and 4 of them only for arm64, so 32-bit ARM and x86 phones miss 6 and x86_64 phones
miss 4. The second case means less coverage, not a clean result. Each signal also has a certainty:
- **PROOF**: it does not show up unless the thing it names is really there.
- **STRONG**: it almost never shows up without it.
- **WEAK**: honest phones can show it too. A WEAK signal is reported but never blocks.

Four groups are policy toggles you set to `ALLOW` or `BLOCK`; app integrity is always
enforced. The verdict is BLOCK when a DETECTED signal with certainty PROOF or STRONG sits
in app integrity or in a group your policy sets to BLOCK.

Unless yours is a Fintech app or similar, we discourage blocking access to Root / Custom ROM / unlocked Bootloader / Emulators. While their presence has a strong correlation with fraud, it also represents a portion of real traffic. Using them only as signals is advised.
On the other side, App Integrity and Instrumentation are always and unambiguously a sign of fraud. Someone is trying to change how your app behaves and not for benign purposes.

### Keep in mind

- **Root detection catches UNHIDDEN root only**, including unhidden modern Magisk, caught via
  its mount residue and manager app. It does NOT catch hidden root (Magisk DenyList /
  Zygisk-hidden, KernelSU / SUSFS), which conceals these tells from an app by design.
  Absence of these signals means "no unhidden root," not "no root." Some of the root signals
  (world-visible su, the daemon socket) target legacy Magisk / SuperSU and read CLEAN against
  a modern Magisk that no longer exposes them.
- **No check is final, and none is meant to be.** Every signal, on the phone or on a server,
  comes from a device the attacker holds. So BlackHex is not one wall: it is many independent
  checks, built so that getting past all of them costs time, skill and custom tooling, and
  every new way of hiding becomes the next thing we look for.
- A check that cannot read what it needs returns **INCONCLUSIVE**, never a false CLEAN and
  never an enforce. Unknown is unknown.
- If the native library cannot load on a phone, your app still opens. The report then carries
  a `NATIVE_CORE` signal (INCONCLUSIVE) and most checks are missing: treat it as incomplete,
  not as clean.
- An app signed only with the old v1 scheme and targeting Android 10 or lower gets INCONCLUSIVE
  from the two APK file checks, because they read only v2/v3 signatures.

## Usage

```kotlin
import io.github.areyougarou.blackhex.BlackHex
import io.github.areyougarou.blackhex.Policy
import io.github.areyougarou.blackhex.Mode
import io.github.areyougarou.blackhex.Verdict

val policy = Policy(
    emulator = Mode.BLOCK,
    instrumentation = Mode.BLOCK,
    root = Mode.ALLOW,
    bootloader = Mode.ALLOW,
)

// Call at startup and at sensitive moments (login, payment), from any thread. check() returns
// at once: the checks run on a BlackHex thread, and the callback runs on the main thread.
BlackHex.check(context, policy) { report ->
    when (report.verdict) {
        Verdict.PASS  -> proceed()
        Verdict.BLOCK -> handleFailure(report.enforced)   // PROOF or STRONG DETECTED signals in app integrity or a BLOCK group
    }
}
```

Nothing to paste: BlackHex learns your app's identity on its own. Optionally, to also catch
copies re-signed with someone else's key, pin your signing certificate before the first
`check()`. For Play, copy the SHA-256 of the **app signing key certificate** from Play Console,
App integrity page, App signing section. Do not use the upload key certificate shown on the
same page: Google re-signs your app with the app signing key, so a pin holding only the upload
key flags every user. If you also ship outside Play, add that signing certificate's SHA-256 to
the same set:

```kotlin
BlackHex.baseline { signers = setOf("<SHA-256 of the Play app signing key certificate>") }
```

- `report.signals`: every signal with its id, group, certainty, status, details and run time (micros).
- `report.enforced`: the DETECTED signals that drove a BLOCK verdict (empty on PASS).
- An INCONCLUSIVE signal never contributes to a BLOCK verdict.
- Never block the main thread waiting for the callback: the callback runs on the main thread,
  so it would never arrive.
- Calls made while a check is running share that run, and each callback gets a report built with
  its own policy. A run uses the signer pin that was set when the run started.
- If `context` is an Activity, or a context wrapped around one, and that Activity is finishing or
  destroyed when the result is ready, the callback is not called. After a screen rotation, call
  `check()` again from the new screen; it joins the run already going. Pass the application
  context to always get the callback.
- If no check makes progress for 5 s, the callback gets the signals finished so far plus
  `CHECK_STALLED`, so the verdict is BLOCK. A check missing from that report did not finish; it
  was not left out. Hashing the APK files counts as progress, so a large app is not cut off for
  its size. If an earlier run has made no progress for 5 s, a new call gets `CHECK_STALLED`
  alone at once, never that run's old results.
- Cost, from the call to the callback, first call in an app process: 50 to 380 ms for a 5 MB app
  on six test phones (Android 12 to 17). On our slowest phone (Pixel 3a, Android 12) a 284 MB app
  takes 206 to 339 ms, and about 0.95 s right after a reboot, when the whole APK is read from
  storage. Later calls in the same process take about 100 ms.

## Build

Android library module (`:sdk`), `minSdk 26`, `compileSdk 35`. One AAR carries the native
library for all four chip types: arm64-v8a in `lib/`, and armeabi-v7a, x86 and x86_64 as
assets loaded at run time. Requires the Android NDK (see `sdk/build.gradle.kts` for the pinned version).

```
./gradlew :sdk:assembleRelease
```
