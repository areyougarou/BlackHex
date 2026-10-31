# Integration guide

[Back to the README](../../README.md)

The call that protects your app is one line. The setup around it is the few steps on this page.

**Requirements.** IntaktoFT needs `minSdk 26` (Android 8.0) or higher. It is built for Java 11, so it
works in projects set to Java 11 or higher, which includes Android Studio's default new-project
settings. It needs the Kotlin Gradle plugin 1.9 or higher.

## Step 1: add JitPack and the dependency

The exact coordinate is `com.github.areyougarou:IntaktoFT:v0.2.1`. Keep the `v`.

Kotlin DSL:

```kotlin
// settings.gradle.kts, inside dependencyResolutionManagement { repositories { ... } }
maven { url = uri("https://jitpack.io") }

// app/build.gradle.kts, inside dependencies { ... }
implementation("com.github.areyougarou:IntaktoFT:v0.2.1")
```

Version catalog (`gradle/libs.versions.toml`), the style new Android Studio projects use:

```toml
[libraries]
intaktoft = { module = "com.github.areyougarou:IntaktoFT", version = "v0.2.1" }
```

```kotlin
// app/build.gradle.kts
implementation(libs.intaktoft)
```

Groovy DSL. Write the JitPack line with `url =`, not `url '...'`, which Gradle 8.13 warns it will
remove in Gradle 10:

```groovy
// settings.gradle, inside dependencyResolutionManagement { repositories { ... } }
maven { url = 'https://jitpack.io' }

// app/build.gradle, inside dependencies { ... }
implementation 'com.github.areyougarou:IntaktoFT:v0.2.1'
```

## Step 2: make an Application class and register it

A new project has no `Application` class. Make one, put the call in `onCreate()`, and register it in
the manifest with `android:name`. `onCreate()` is best, because it runs however the app is opened.

```kotlin
// App.kt
import android.app.Application
import io.github.areyougarou.intakto.Intakto

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        Intakto.check(this)
    }
}
```

```xml
<!-- AndroidManifest.xml, on the <application> tag -->
<application
    android:name=".App"
    ... >
```

Without the `android:name` line, Android never uses your class, so `onCreate()` never runs and the
check silently does nothing. No error appears. If a check never seems to run, this line is the first
thing to look at.

## Step 3: the call

```kotlin
Intakto.check(this)
```

The same call in Java:

```java
Intakto.check(this);
```

That is the whole setup. The checks run on an IntaktoFT thread. Only a DETECTED signal closes the
app; an INCONCLUSIVE ("could not confirm") result never does. On a DETECTED signal IntaktoFT shows a
short "Security check" notice naming what was detected, then closes the app when the user dismisses
it: its screens close, it leaves the recent-apps list, and the phone shows what was on screen before
the app was opened. Call `check()` again at sensitive moments (login, payment).

On an x86 or x86_64 emulator, 8 of the 12 checks run. The 4 hook checks are written for arm64 phone
chips and do nothing on an emulator's x86 chip, so an emulator cannot show a hook, but it also never
raises a false alarm there. For the full set of checks, run on a real arm64 phone.

## Read the result without turning protection off

The callback runs on every result, in both modes: on PASS and on a DETECTED signal. In the default
mode it runs just before the app closes, so protection stays on while you still get the report:

```kotlin
Intakto.check(this) { report ->
    log(report.verdict, report.signals)   // runs on every result; the app still closes on DETECTED
}
```

The same in Java. The callback is a single-method interface, so a plain lambda works, with no
`Unit.INSTANCE` to return:

```java
Intakto.check(this, report -> log(report.getVerdict(), report.getSignals()));
```

To decide for yourself instead, for example by sending the report to your own server, use
`Mode.REPORT`. IntaktoFT then never stops the app and hands you the report on the main thread:

```kotlin
import io.github.areyougarou.intakto.Mode
import io.github.areyougarou.intakto.Verdict

Intakto.check(this, Mode.REPORT) { report ->
    when (report.verdict) {
        Verdict.PASS  -> proceed()
        Verdict.BLOCK -> handleFailure(report.enforced)   // every DETECTED signal
    }
}
```

```java
Intakto.check(this, Mode.REPORT, report -> {
    if (report.getVerdict() == Verdict.BLOCK) handleFailure(report.getEnforced());
});
```

- `report.signals`: every signal with its id, group, status, details and time in microseconds
  (`micros`). A status is CLEAN, DETECTED or INCONCLUSIVE; INCONCLUSIVE means the check could not
  confirm and is not a reason to stop the app.
- `report.enforced`: the DETECTED signals only. The verdict is BLOCK when it is not empty; an
  INCONCLUSIVE result is never enforced.
- Never block the main thread waiting for the callback: the callback runs on the main thread,
  so it would never arrive.
- Calls made while a check is running share that run, and each keeps its own mode. So a report
  can hold results from checks that finished before the call that receives it.
- If `context` is an Activity, or a context wrapped around one, and that Activity is finishing or
  destroyed when the result is ready, the callback is not called (in the default mode the app
  still stops on a DETECTED signal). After a screen rotation, call `check()` again from the new
  screen; it joins the run already going. Pass the application context to always get the callback.
- If no check makes progress for 5 s, the report holds the signals finished so far plus
  `CHECK_STALLED` (status INCONCLUSIVE). On its own that does not make the verdict BLOCK, so a slow
  run does not close the app. A check missing from that report did not finish; it was not left out.
  Hashing the APK files counts as progress, so a large app is not cut off for its size. If an
  earlier run has made no progress for 5 s, a new call gets `CHECK_STALLED` alone at once, never
  that run's old results.
- Cost, from the call to the callback (`Report.elapsedMs`), on our test phones (Android 12 to 17).
  A 1.5 MB app: 26 to 221 ms for the first call in an app process and 26 to 162 ms for later calls.
  A 159 MB app: 112 to 284 ms for the first call and 40 to 161 ms for later calls. With the phone's
  file cache emptied, as on the first launch after a reboot, the first call took 546 to 559 ms on a
  Pixel 3a (Android 12) and 355 to 379 ms on a Pixel 7a (Android 16).

## API reference

| Name | Shape | Notes |
|---|---|---|
| `Intakto.check` | `check(context: Context, mode: Mode = Mode.BLOCK, onResult: ReportCallback = {})` | `mode` and `onResult` are optional. Callable from Java as `Intakto.check(...)`. |
| `ReportCallback` | `fun onReport(report: Report)` | A single-method interface, so a Kotlin or Java lambda works. |
| `Report` | `signals: List<Signal>`, `verdict: Verdict`, `enforced: List<Signal>`, `elapsedMs: Long` | `enforced` is the DETECTED signals. |
| `Signal` | `id: String`, `group: Group`, `status: Status`, `details: String`, `micros: Long` | One check's result. |
| `Verdict` | `PASS`, `BLOCK` | `BLOCK` when any signal is DETECTED. |
| `Status` | `CLEAN`, `DETECTED`, `INCONCLUSIVE` | Only DETECTED closes the app. |
| `Mode` | `BLOCK`, `REPORT` | Default `BLOCK` closes the app on DETECTED; `REPORT` never closes it. |
| `Group` | `APP_INTEGRITY`, `INSTRUMENTATION` | Which family a signal belongs to. |

Every result, with the phone and Android build it ran on: [test results](../../TEST_RESULTS.md).

## Google Play Data safety

IntaktoFT collects and shares no data, so it adds nothing to your app's Data safety form.
Every check runs on the device and reads only your own app's files and memory. Nothing leaves
the phone, so the library adds no data type for you to declare.
