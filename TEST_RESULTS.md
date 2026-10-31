# Test results

Every test below names the phone, the Android version, and what each check did. You can see for
yourself that IntaktoFT blocks real abuse and leaves honest users alone, and you can see what it does
not catch. A protection tool that hides its misses is not one you can trust with your paying users.

Tested on release 0.2.1. The results come from three places: Google's device farm (Firebase Test
Lab), our own phones, and a first-hour adopter run. Last updated 2026-10-31.

## Honest apps stayed clean on nine Firebase Test Lab devices

Firebase Test Lab runs an app on real phones we do not own, plus Google's virtual devices. We ran two
apps on each device in one pass: the honest app, and a copy of it repackaged with LSPatch, a free tool
that modifies and re-signs an APK. One pass shows both, so a clean result and a real block come from
the same phone.

The nine devices are five physical phones from five makers (Samsung, Motorola, OnePlus, Xiaomi and
Google) and four of Google's virtual devices. Together they cover Android 10, 11, 12, 12L, 13, 14, 15,
16 and 17.

| Maker | Type | Android | Honest app | Repackaged copy |
|---|---|---|---|---|
| Samsung | physical | 10 | clean, 10 of 10 reports, nothing flagged | blocked |
| Motorola | physical | 12 | clean, 10 of 10 | blocked |
| OnePlus | physical | 13 | clean, 10 of 10 | blocked |
| Xiaomi | physical | 15 | clean, 10 of 10 | blocked |
| Google | physical | 17 | clean, 10 of 10 | blocked |
| Google | virtual | 11 | clean, 10 of 10 | blocked |
| Google | virtual | 12L | clean, 10 of 10 | blocked |
| Google | virtual | 14 | clean, 10 of 10 | blocked |
| Google | virtual | 16 | clean, 10 of 10 | blocked |

Across all nine devices the honest app was flagged zero times and never crashed. The repackaged copy
was blocked on every device, every time, by three checks that read the installed files:
`TAMPER_APK_CONTENT`, `TAMPER_SIGNING_BLOCK` and `TAMPER_REPACKAGER`. These file checks run on every
chip, so the x86 virtual devices caught the repackaging too.

Firebase Test Lab device ids, for traceability: starlte, caprip, OP4F39L1, houji, cubs, and the
MediumPhone virtual device at API 30, 32, 34 and 36. Google's free plan allows 5 physical and 10
virtual device runs a day. Firebase Test Lab is scheduled to shut down on 2027-09-30.

## Our own phones caught Frida and left an honest hooking library alone

We run harder abuses on phones we control, including rooted ones: a Nothing Phone 2a (Android 16), a
Pixel 6a (Android 17) and a Pixel 3a (Android 12).

| Test | Result |
|---|---|
| Honest app, 54 report calls across the three phones | clean, 0 flagged |
| Frida server hooking a system function in memory (a native hook) | caught every time, by `FRIDA_AGENT_IN_MEMORY` and `OPCODE_TRAMPOLINE` |
| Frida replacing a Java method (a Java-only hook) | caught once Frida's agent was in memory, by `FRIDA_AGENT_IN_MEMORY` |
| Honest app that ships ShadowHook and hooks its own code for monitoring | clean, 0 flagged |

That last row is the one a worried developer should read. ShadowHook is an honest hooking library that
some apps ship to watch their own code. An earlier build wrongly flagged it. This release leaves it
alone.

## An adopter's first hour showed no false alarm and no crash

A developer adding IntaktoFT spends the first hour running the app from Android Studio, on emulators,
inside their own tests, and in their kind of build. We ran all four.

| Adopter step | Result |
|---|---|
| Android Studio dev loop: debugger with breakpoints, Apply Changes, the profilers, Layout Inspector | clean, the app never closed. Pixel 6 Pro (Android 16) and an x86 emulator |
| Emulators: x86_64, and an arm64-only build run through ARM translation | clean, no false alarm |
| The adopter's own JVM unit test (Robolectric) and instrumented test | both pass, no crash. On the JVM the checks report "could not confirm", never a false flag |
| Build variants: Groovy build file, an older toolchain (AGP 8.1), R8 full mode, and Android 8.0 | all build and run clean |

## What the free tier does not catch

- A copy rebuilt by hand and signed with a fresh key passes the file checks. Telling a fresh key from
  the developer's own key needs either a signing-key setting or a server check, which the paid tier
  adds.
- A hook placed only inside the app's own native code, with no outside agent in memory, is not caught.
- On x86 and x86_64 emulators, 8 of the 12 checks run. The four hook checks are written for arm64 phone
  chips, so they do nothing on an emulator's x86 chip. Run on a real arm64 phone for the full set.

## The full tool-by-tool table is coming

A table of every tool we test, its version, and which check caught it is being re-run on this release.
It will be added here.
