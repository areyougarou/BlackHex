# Test results

If IntaktoFT flags an honest user, you lose that user. So here is every test we ran: the phone, the Android version, and what happened. What it doesn't catch is listed too, at the end.

The checks tested here are the ones in v0.2.1. They're the same as in v0.2.0: v0.2.1 changed only how Java calls the library, and the docs. Last updated 2026-10-31.

## Nine Google lab phones: honest app clean, modified copy blocked

Firebase Test Lab is Google's service that runs your app on real phones in Google's own lab. On each phone we ran two apps, one after the other: our honest test app, and a copy of it modified with LSPatch, a free tool that rewrites and re-signs an APK.

| Maker | Phone | Android | Honest app | Modified copy |
|---|---|---|---|---|
| Samsung | real | 10 | clean, 10 of 10 runs | blocked, 5 of 5 |
| Motorola | real | 12 | clean, 10 of 10 | blocked, 5 of 5 |
| OPPO | real | 13 | clean, 10 of 10 | blocked, 5 of 5 |
| Xiaomi | real | 15 | clean, 10 of 10 | blocked, 5 of 5 |
| Google | real | 17 | clean, 10 of 10 | blocked, 5 of 5 |
| Google | virtual | 11 | clean, 10 of 10 | blocked, 5 of 5 |
| Google | virtual | 12L | clean, 10 of 10 | blocked, 5 of 5 |
| Google | virtual | 14 | clean, 10 of 10 | blocked, 5 of 5 |
| Google | virtual | 16 | clean, 10 of 10 | blocked, 5 of 5 |

Zero false flags, zero crashes. Three checks that read the installed files caught every modified copy: `TAMPER_APK_CONTENT`, `TAMPER_SIGNING_BLOCK` and `TAMPER_REPACKAGER`.

## Apps installed from Google Play read clean

Google Play changes every app it delivers. It signs the app with Google's key, splits it into pieces, and adds a stamp. If our checks took that for tampering, every honest user would be blocked.
- We installed our test app the way Play does: split into pieces, re-signed with a second key, with a stamp added. Clean, 3 of 3 runs on two phones.
- We took 58 files from 13 real apps installed from Play on our phones, and ran our file checks on each one. All 58 read clean.
- The native library meets Play's 16 KB page rule, so Play won't block your update. It also ran clean on a 16 KB emulator.
- Updating the app over an older version, and archiving then restoring it on Android 16: clean.

## Popular SDKs in the same app cause no false alarm

Crash reporters and performance tools hook native code, much like an attacker does. We put these in one app, on a Nothing Phone 2a (Android 16) and a Pixel 6a (Android 17): Firebase Crashlytics with NDK, Firebase Performance, Sentry with NDK, Google Mobile Ads, AppsFlyer and the Facebook SDK. All clean, 20 runs per phone.
- ShadowHook and ByteHook, two hooking libraries that apps ship to watch their own code: clean. The checks see their hooks and mark them as the app's own.
- A Flutter app and a React Native app: clean, and the app stayed open.
- Work profile, Private Space, a clone profile and a second user, on the Pixel 6a: clean.

## Frida gets caught on our own phones

| Test | Result |
|---|---|
| Honest app, 54 runs on three phones (Nothing Phone 2a, Pixel 6a, Pixel 3a) | clean |
| Frida hooking a native system function | caught every time (`FRIDA_AGENT_IN_MEMORY`, `OPCODE_TRAMPOLINE`) |
| Frida replacing a Java method | caught once Frida's agent was in memory (`FRIDA_AGENT_IN_MEMORY`) |

## A developer's first hour brings no false alarm and no crash

| What the developer does | Result |
|---|---|
| Runs the app with a debugger attached | clean |
| Uses Android Studio's live tools (Apply Changes, the profilers, Layout Inspector), which load an agent into the app. We loaded the same kind of agent (JVMTI) and had it watch every method | clean, the app never closed |
| Runs it on emulators, including an arm64-only app on an x86 emulator through ARM translation | clean |
| Runs their own unit tests (Robolectric) and device tests | pass. In unit tests there's no phone, so the checks report "could not confirm", never a false flag |
| Builds with Groovy files, an older toolchain (AGP 8.1), R8 full mode, or for an Android 8.0 phone | builds and runs clean |

## It doesn't crash your app

We ran every check 1,000 times in a row with a memory-error detector on (HWASan), from 8 threads at once, and from 2 processes at once. Then 3,000 times while measuring memory: it didn't grow. Then with the phone almost out of memory. No crash.

## It doesn't slow your app down

IntaktoFT adds about 540 KB to your app on arm64 phones. The checks run on their own background thread, so your app's start time doesn't change: on a Pixel 6, the median cold start was 95 ms without IntaktoFT and 90 ms with it. Android's StrictMode, which reports slow work on the main thread, found nothing.

## What the free tier doesn't catch

- A copy rebuilt by hand and signed with a new key passes the file checks. So does anything the attacker packs into that copy, such as a renamed Frida Gadget that hooks Java code. We tested this with standard tools (apktool, apksigner). Telling a new key from yours needs a server check, which the paid tier adds.
- A hook placed only inside your app's own native code, with no Frida agent in memory, isn't caught.
- On x86 emulators, 8 of the 12 checks run. The four hook checks are written for the arm64 chips in real phones. Test on a real phone for the full set.

## Every tool in the README's table was caught again on this release

We re-ran the attack tools from the README's table against these checks. 15 of the 16 were caught live, each by the check the README names:
- 11 Frida builds, including ones that rename or hide Frida's agent, such as StealthFrida, ReShift and strongR-frida: caught by `FRIDA_AGENT_IN_MEMORY` or `DISGUISED_LIBRARY_IN_MEMORY`.
- The Frida Gadget in its standard setup (its own file name, hooking native code): caught by `OPCODE_TRAMPOLINE` and the file checks.
- LSPatch: caught by the three file checks.
- ZygiskFrida and LSPosed (Vector): caught by `LIB_FROM_ROOT_PATH`.

The honest app read clean on all three test phones. One row wasn't a live catch. FreeDaah's agent crashes the app it attaches to, so the attack ends there; it hides the same way as the Frida builds above, which were caught.
