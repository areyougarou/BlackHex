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

~ What it checks for

| Group | Toggle | What it looks for |
|-------|--------|-------------------|
| App integrity | always on | The running app is the original signed build (signing cert, native-lib and resource digests, repackager/cloner artifacts, signing-block parse) |
| Instrumentation | ALLOW \| BLOCK | Runtime hooking / code injection (ART method hooks, inline-hook residue, injected libraries) |
| Emulator | ALLOW \| BLOCK | Signs the app is running on an emulator / virtual device rather than real hardware (CPU/ISA, GPU, sensors, device nodes, build props) |
| Root | ALLOW \| BLOCK | Signs of an unhidden rooted device (world-visible su, live Magisk/Zygisk/APatch daemon socket, module mount residue, a known root-manager app, kernel root token, privileged/non-zygote launch context) |
| Custom ROM / unlocked Bootloader | ALLOW \| BLOCK | Unlocked bootloader / custom ROM indicators (verified-boot state, ROM system features, ROM signing, ROM build props) |

BlackHex actively hunts only for values that can be confirmed without server verdicts. Device fingerprint, promo abuse and coordinated actions are not included in the free tier because they would violate this exact principle.

Every check reports either CLEAN, DETECTED, or INCONCLUSIVE.
Four are policy toggles you set to `ALLOW` or `BLOCK`; app-integrity is always
enforced.

Unless yours is a Fintech app or similar, we discourage to block access to Root / Custom ROM / unlocked Bootloader / Emulators. While their presence has a strong correlation with fraud, it also represents a portion of real traffic. Using them only as signals is adviced.
On the other side, App Integrity and Instrumentation are always and unambiguously a sign of fraud. Someone is trying to change how your app behaves and not for benign purposes.

### Keep in mind

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

// Call off the main thread, at startup and at sensitive moments (login, payment).
val report = BlackHex.check(context, policy)

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
