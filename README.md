# BlackHex (free tier)

A lightweight Android RASP (runtime app self-protection) library. It runs a battery of
on-device integrity checks and returns signals plus a verdict. The host app decides what
to do with the verdict — the library reports, it does not kill your process for you.

It is a **sensor, not a judge**: every check reports CLEAN, DETECTED, or INCONCLUSIVE, and
only the checks you opt into blocking can raise an enforce verdict.

## What it checks

Five groups. Four are policy toggles you set to `ALLOW` or `BLOCK`; app-integrity is always
enforced.

| Group | Toggle | What it looks for |
|-------|--------|-------------------|
| App integrity | always on | The running app is the original signed build (signing cert, native-lib and resource digests, repackager/cloner artifacts, signing-block parse) |
| Emulator | ALLOW \| BLOCK | Signs the app is running on an emulator / virtual device rather than real hardware (CPU/ISA, GPU, sensors, device nodes, build props) |
| Instrumentation | ALLOW \| BLOCK | Runtime hooking / code injection (ART method hooks, inline-hook residue, injected libraries) |
| Root | ALLOW \| BLOCK | Signs of an unhidden rooted device (world-visible su, live Magisk/Zygisk/APatch daemon socket, module mount residue, a known root-manager app, kernel root token, privileged/non-zygote launch context) |
| Bootloader / custom ROM | ALLOW \| BLOCK | Unlocked bootloader / custom ROM indicators (verified-boot state, ROM system features, ROM signing, ROM build props) |

### Honest limits

- **Root detection catches UNHIDDEN root only** — including unhidden modern Magisk, caught via
  its mount residue and manager app. It does NOT catch hidden root (Magisk DenyList /
  Zygisk-hidden, KernelSU / SUSFS), which conceals these tells from an app by design — that
  needs the paid / server-verified tier. Absence of these signals means "no unhidden root," not
  "no root." Some of the root signals (world-visible su, the daemon socket) target legacy
  Magisk / SuperSU and read CLEAN against a modern Magisk that no longer exposes them.
- Any on-device check can, in principle, be defeated by an attacker with enough control of
  the device. These checks catch the common, un-hidden cases cheaply. They are not an
  unforgeable verdict; that requires server-side attestation.
- A check that cannot read what it needs returns **INCONCLUSIVE**, never a false CLEAN and
  never an enforce. Unknown is unknown.

## Usage

```kotlin
import rasp.sdk.Rasp
import rasp.sdk.Policy
import rasp.sdk.Mode

val policy = Policy(
    emulator = Mode.BLOCK,
    instrumentation = Mode.BLOCK,
    root = Mode.ALLOW,
    bootloader = Mode.ALLOW,
)

// Call off the main thread, at startup and at sensitive moments (login, payment).
val report = Rasp.check(context, policy)

when (report.verdict) {
    Verdict.PASS  -> proceed()
    Verdict.BLOCK -> handleFailure(report.enforced)   // DETECTED signals in a BLOCK group / app-integrity
}
```

- `report.signals` — every signal with its status, group, severity, and detail.
- `report.enforced` — the DETECTED signals that drove a BLOCK verdict (empty on PASS).
- An INCONCLUSIVE signal never contributes to a BLOCK verdict.

## Build

Android library module (`:sdk`), `minSdk 26`, `compileSdk 35`, arm64-v8a native library.
Requires the Android NDK (see `sdk/build.gradle.kts` for the pinned version).

```
./gradlew :sdk:assembleRelease
```
