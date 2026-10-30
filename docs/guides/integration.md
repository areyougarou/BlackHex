# Integration guide

[Back to the README](../../README.md)

IntaktoFT needs `minSdk 26` (Android 8.0) or higher. Add JitPack to your repositories and the
library to your app module:

```kotlin
// settings.gradle.kts, inside dependencyResolutionManagement { repositories { ... } }
maven { url = uri("https://jitpack.io") }

// app/build.gradle.kts, inside dependencies { ... }
implementation("com.github.areyougarou:Intakto:v0.2.0")
```

Then add one line where your app starts. `Application.onCreate()` is best, because it runs however the
app is opened:

```kotlin
Intakto.check(this)
```

That is the whole setup. The checks run on an IntaktoFT thread. Only a DETECTED signal closes the
app; an INCONCLUSIVE ("could not confirm") result never does. On a DETECTED signal IntaktoFT shows a
short "Security check" notice naming what was detected, then closes the app when the user dismisses
it: its screens close, it leaves the recent-apps list, and the phone shows what was on screen before
the app was opened. Call `check()` again at sensitive moments (login, payment).

To decide yourself, for example by sending the report to your own server, use `Mode.REPORT`.
IntaktoFT then never stops the app and hands you the report on the main thread:

```kotlin
import io.github.areyougarou.intakto.Intakto
import io.github.areyougarou.intakto.Mode
import io.github.areyougarou.intakto.Verdict

Intakto.check(context, Mode.REPORT) { report ->
    when (report.verdict) {
        Verdict.PASS  -> proceed()
        Verdict.BLOCK -> handleFailure(report.enforced)   // every DETECTED signal
    }
}
```

- `report.signals`: every signal with its id, group, status, details and run time (micros). A
  status is CLEAN, DETECTED or INCONCLUSIVE; INCONCLUSIVE means the check could not confirm and is
  not a reason to stop the app.
- `report.enforced`: the DETECTED signals only. The verdict is BLOCK when it is not empty; an
  INCONCLUSIVE result is never enforced.
- In the default mode you may pass a callback too. It runs before the app stops, so work it starts
  (a network call, for example) does not finish. Use `Mode.REPORT` to send reports.
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
  Pixel 3a (Android 12) and 355 to 379 ms on a Pixel 7a (Android 16). [TEST RESULTS LINK]
