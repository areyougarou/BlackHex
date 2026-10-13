# BlackHex

**Open source & free-tier of BlackHex, Android SDK for app protection against repackaging and hooking.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![JitPack](https://jitpack.io/v/areyougarou/BlackHex.svg)](https://jitpack.io/#areyougarou/BlackHex)
![Android 10.0+](https://img.shields.io/badge/Android-10.0%2B-green)

## What is it?

This is the free tier of BlackHex, RASP library for Android. This lite version answers three questions:

1. **Is the app being repackaged?** (Detects App Cloner, LSPatch and similar tools used to inject their own code into the APK and re-sign it)
   Repackaging helps unlocking paid features, remove ads or carry malware that steals your users' passwords.
2. **Is the app being hooked?** (Detects LSPosed, Zygisk and Frida-like tools)
   Injection can be used to bypass paywalls, spoof device identity, reverse engineer/steal intellectual property or change app values.
3. **Is the app running in a tampered environment?** (Root with Magisk, APatch or KernelSU, custom ROMs, unlocked bootloaders, emulators)
   The usual home of bot farms and fake accounts.

BlackHex is specifically optimized to be fast and accurate. Measured: about 300 ms on average to run every check, and no false positives in our testing. Run the verdict in sensitive processes (login, payment, app startup). You decide what happens: block, close the app, or send the signal back to your server.

## Who is it for?

- Mobile games
- Subscription and freemium apps
- Web3 and crypto apps
- Any Android team that wants real app protection without an enterprise contract

## Who is it not for?

- Banks and regulated payment apps. In most countries they need certified, audited protection. BlackHex is not certified.
- Apps facing skilled, determined attackers.  Any check that runs on the phone can be beaten by someone with full control of it. You'll need server-side checks too.

## What's on by default

### Repackaging and hooking: on

If this flag fires, your app is being attacked or manipulated.
We suggest Block+Flag regardless of what you're defending against.

### Tampered environments: off

Tampered environments (emulators, root, custom ROMs, unlocked bootloaders) are disabled by default. We suggest treating them only as a signal to feed into your backend: tampered environment enable dangerous attack classes that are not available on stock android, but only a small percentage of all emulators/rom/rooted use those capabilities to attack you. Unless  you're defending a Web3 or crypto app, we suggest ignoring this value.

To get the signal, set them to `REPORT`. BlackHex checks and tells you, but blocks no one:

```kotlin
val report = BlackHex.check(applicationContext, Policy(
    rootedDevices = Mode.REPORT,
    emulators = Mode.REPORT,
    customRoms = Mode.REPORT,  // also covers unlocked bootloaders
))
// send report.signals to your backend as a risk signal
```

You can also set any of them to `Mode.BLOCK`, but expect to turn away some honest users.

## Quick start

**1. Add the library**

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        maven("https://jitpack.io")
    }
}

// app/build.gradle.kts
dependencies {
    implementation("com.github.areyougarou:BlackHex:v0.1.0")
}
```

**2. Tell BlackHex what your real app looks like**

BlackHex recognizes your app by the fingerprint of the certificate it's signed with. Add it once, when your app starts:

```kotlin
BlackHex.baseline {
    signers = listOf("your SHA-256 fingerprint here")
}
```

Where to find the fingerprint:

- **Published on Google Play?** Google re-signs your app with its own key. Open Play Console, find *App integrity*, and copy the SHA-256 of the *App signing key certificate*. If you use your own key here instead, BlackHex will reject every copy downloaded from Play.
- **Signing the app yourself?** Run `./gradlew signingReport` and copy the SHA-256 of your release key.
- **Not sure?** Run your app once. BlackHex prints the fingerprint it sees in the report.

You can list more than one fingerprint, for example Google's key for Play and your own key for test builds.

Until you add a fingerprint, the repackaging check answers "not sure" and never blocks anyone.

**3. Run the check**

```kotlin
lifecycleScope.launch {
    val report = withContext(Dispatchers.Default) {
        BlackHex.check(applicationContext)
    }
    if (report.verdict == Verdict.BLOCK) {
        // Your call: show a message, ask for extra verification, or stop the payment.
    }
}
```

Run it at the moments that matter: app start, login, payment.

Testing your own app with Frida? Use `Policy(hookingTools = Mode.IGNORE)` in your debug builds.

## Questions you probably have

**Will it slow down my app?**
It only runs when you call it. Nothing runs in the background. A check takes about 0.3 seconds on a Pixel 6, up to 1 second the very first time. That's why the example above runs it in the background.

**Can it crash my app?**
It's built not to. If something can't be read, or a part of BlackHex can't run on a phone, that check simply answers "not sure".

**Will it flag honest users / produce false positives?**
Every check answers one of three things: clean, detected, or not sure. "Not sure" never blocks anyone. By default, BlackHex only blocks on exact signs: things a normal, untouched app never has. Checks that rely on an educated guess only report. The checks that do catch honest people (root, emulators, custom ROMs) stay off unless you turn them on.

**Does it send data anywhere?**
No. No internet permission, no servers, no analytics, no account. The report goes to your code and nowhere else.

**Does it need permissions?**
No. It asks Android about a short, fixed list of known root and custom ROM apps, which Google Play allows.

**How much does it add to my app?**
About 0.5 MB.

**Which phones does it support?**
Android 10 and newer.

**Can a hacker get around it?**
Root is the hardest thing for any Android RASP to detect reliably, and BlackHex is no exception: it sits on the higher end, but a determined attacker can still hide root from it. Hooking and repackaging are a different story. BlackHex is proven to detect Zygisk, Frida Gadget, App Cloner, LSPosed and their common forks, and as far as we know no public, off-the-shelf injection or repackaging tool gets past it. A tool custom-built to evade BlackHex is another matter.

**Is it really free?**
Yes. Apache 2.0 license: use it in commercial apps, change it, ship it. No fees, no usage limits. If you build on it, keep the NOTICE file, which credits BlackHex.

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
