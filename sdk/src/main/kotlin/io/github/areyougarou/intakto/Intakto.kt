package io.github.areyougarou.intakto

import android.app.Activity
import android.app.ActivityManager
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.Process
import org.json.JSONArray
import java.lang.ref.WeakReference
import java.util.concurrent.Executors

enum class Status {
    /** The check looked and found nothing wrong. */
    CLEAN,

    /** The check looked and found a real problem. This is the only status that closes the app. */
    DETECTED,

    /**
     * The check could not get an answer (a read failed, an empty read, an error, the native core did
     * not load, or the run did not finish). The app is NOT closed on this: we cannot test every phone,
     * so an honest phone quirk must never force-close an honest user's app. The accepted cost is that
     * an abuser with root who blocks our reads is not stopped by that check. In Mode.REPORT this lets
     * the host tell "could not confirm" apart from CLEAN and decide for itself.
     */
    INCONCLUSIVE,
}

enum class Group { APP_INTEGRITY, INSTRUMENTATION }

enum class Verdict { PASS, BLOCK }

enum class Mode { BLOCK, REPORT }

data class Signal(
    val id: String,
    val group: Group,
    val status: Status,
    val details: String,
    val micros: Long,
)

data class Report(
    val signals: List<Signal>,
    val verdict: Verdict,
    val enforced: List<Signal>,
    val elapsedMs: Long,
)

/**
 * The result callback. A `fun interface` (single-abstract-method), so a Kotlin trailing lambda and a
 * plain Java lambda both work: `Intakto.check(this) { report -> ... }` in Kotlin, and
 * `Intakto.check(this, report -> { ... })` in Java with no `Unit.INSTANCE` to return.
 */
fun interface ReportCallback {
    fun onReport(report: Report)
}

object Intakto {

    private const val STALL_MS = 5000L
    private const val NOTICE_TIMEOUT_MS = 2500L
    private val main = Handler(Looper.getMainLooper())
    private val lock = Any()
    private var running: Run? = null

    // One long-lived thread runs every check, instead of a new thread per call (0.8-3 ms of each
    // check went to starting it). A new run is only queued when none is running, so a stuck run never
    // has later runs waiting behind it: those calls report CHECK_STALLED, as before.
    private val worker = Executors.newSingleThreadExecutor { r -> Thread(r, "Intakto").apply { isDaemon = true } }

    private class Run {
        private val signals = ArrayList<Signal>()
        val waiting = ArrayList<Waiter>()
        fun add(s: List<Signal>) = synchronized(this) { signals += s; progress() }
        fun snapshot(): List<Signal> = synchronized(this) { signals.toList() }
    }

    private class Waiter(
        val run: Run, val t0: Long, val app: Context, val screen: WeakReference<Activity>?, val mode: Mode,
        var onResult: ReportCallback?,
    ) : Runnable {
        override fun run() {
            val idle = (System.nanoTime() - lastProgress) / 1_000_000
            val waiting = synchronized(lock) { if (idle >= STALL_MS) run.waiting.remove(this) else this in run.waiting }
            when {
                !waiting -> deliver(this, run.snapshot())
                idle < STALL_MS -> main.postDelayed(this, STALL_MS - idle)
                else -> deliver(this, run.snapshot() +
                    stalled("no check made progress for $STALL_MS ms; only the signals that finished are listed"))
            }
        }
    }

    // @JvmStatic + @JvmOverloads so Java callers can write Intakto.check(this), Intakto.check(this, mode),
    // or the full form, matching the one-line call the README shows. Without them, Kotlin's default
    // arguments are not visible to Java and the object method is only reachable as Intakto.INSTANCE.check(...).
    @JvmStatic
    @JvmOverloads
    fun check(context: Context, mode: Mode = Mode.BLOCK, onResult: ReportCallback = ReportCallback {}) {
        val app = context.applicationContext ?: context
        val screen = activity(context)?.let { WeakReference(it) }
        val t0 = System.nanoTime()
        var start = false
        var idleMs = 0L
        val w = synchronized(lock) {
            val current = running
            if (current != null) idleMs = (t0 - lastProgress) / 1_000_000
            val run = current ?: Run().also { running = it; start = true; progress() }
            Waiter(run, t0, app, screen, mode, onResult).also { if (idleMs < STALL_MS) run.waiting += it }
        }
        if (idleMs >= STALL_MS) {
            main.post { deliver(w, listOf(stalled("an earlier run has made no progress for $idleMs ms; no checks ran for this call"))) }
            return
        }
        main.postDelayed(w, STALL_MS)
        if (!start) return
        val run = w.run
        try {
            worker.execute {
                try { collect(app, run) } catch (t: Throwable) { run.add(listOf(failed(t))) }
                finish(run)
            }
        } catch (t: Throwable) {
            run.add(listOf(failed(t)))
            finish(run)
        }
    }

    private fun finish(run: Run) {
        val done = synchronized(lock) { if (running === run) running = null; run.waiting.toList().also { run.waiting.clear() } }
        val signals = run.snapshot()
        main.post { done.forEach { deliver(it, signals) } }
    }

    private fun failed(t: Throwable) = Signal("CHECK_FAILED", Group.APP_INTEGRITY, Status.INCONCLUSIVE,
        "could not verify: the run stopped early: ${t.javaClass.simpleName}: ${t.message}", 0)

    private fun stalled(detail: String) = Signal("CHECK_STALLED", Group.APP_INTEGRITY, Status.INCONCLUSIVE, "could not verify: $detail", 0)

    private tailrec fun activity(c: Context?): Activity? = when (c) {
        is Activity -> c
        is ContextWrapper -> activity(c.baseContext)
        else -> null
    }

    private fun deliver(w: Waiter, signals: List<Signal>) {
        main.removeCallbacks(w)
        val onResult = w.onResult ?: return
        w.onResult = null
        val enforced = signals.filter { it.status == Status.DETECTED }
        val verdict = if (enforced.isNotEmpty()) Verdict.BLOCK else Verdict.PASS
        try {
            if (w.screen == null || w.screen.get().let { it != null && !it.isFinishing && !it.isDestroyed })
                onResult.onReport(Report(signals, verdict, enforced, (System.nanoTime() - w.t0) / 1_000_000))
        } finally {
            if (w.mode == Mode.BLOCK && verdict == Verdict.BLOCK) block(w, enforced)
        }
    }

    @Volatile private var blocking = false
    @Volatile internal var noticeShown = false

    // On a proven catch in Mode.BLOCK (verdict BLOCK, so enforced holds only DETECTED signals): show
    // the notice naming what was caught, then close when the user acts (NoticeActivity calls closeNow).
    // If the screen cannot be shown, close now as before. An INCONCLUSIVE result never reaches here,
    // so a "could not confirm" outcome never closes the app. Guarded so concurrent blocking waiters
    // launch the screen (and close) exactly once.
    private fun block(w: Waiter, enforced: List<Signal>) {
        synchronized(lock) { if (blocking) return; blocking = true }
        val app = w.app
        try {
            NoticeActivity.show(app, w.screen?.get(), noticeLines(enforced), noticeIds(enforced))
            // The notice can only appear if this process has a foreground screen. When the process was
            // started with none (check() in Application.onCreate after an FCM push, a background job or a
            // broadcast), the activity launch is dropped and the notice never shows, yet a proven catch
            // must still end with the app closed, as the old silent close always did. So if the notice
            // has not reached the foreground within NOTICE_TIMEOUT_MS, close as before. NoticeActivity
            // sets noticeShown in onResume; both that and this callback run on the main thread, so no race.
            main.postDelayed({ if (!noticeShown) closeNow(app) }, NOTICE_TIMEOUT_MS)
        } catch (_: Throwable) {
            closeNow(app)
        }
    }

    // One plain sentence per group of results. `enforced` holds only DETECTED signals (a proven catch),
    // so every line here names a real problem; a "could not confirm" result is INCONCLUSIVE, never
    // enforced, and never shows a notice.
    private fun noticeLines(enforced: List<Signal>): List<String> {
        val lines = ArrayList<String>(2)
        if (enforced.any { it.group == Group.APP_INTEGRITY })
            lines += "This copy of the app has been modified."
        if (enforced.any { it.group == Group.INSTRUMENTATION })
            lines += "Another program is tampering with this app while it runs."
        return lines
    }

    private fun noticeIds(enforced: List<Signal>): String =
        enforced.map { it.id }.distinct().joinToString(", ")

    internal fun closeNow(app: Context) {
        try { app.getSystemService(ActivityManager::class.java).appTasks.forEach { it.finishAndRemoveTask() } } catch (_: Throwable) {}
        Process.killProcess(Process.myPid())
    }

    private fun collect(context: Context, run: Run) {
        TamperProbe.awaitPlayDownload(context)
        val loadError = NativeCore.load(context)
        TamperProbe.startContentCheck(context)
        run.add(nativeSignals(context, loadError))
        run.add(CloneProbe.collect(context))
        run.add(TamperProbe.collect(context))
    }

    private const val NOT_APPLICABLE = 3

    private fun nativeSignals(context: Context, loadError: Throwable?): List<Signal> {
        val t0 = System.nanoTime()
        val failure = loadError ?: try {
            val arr = JSONArray(NativeCore.run(
                TamperProbe.androidSigners(context).joinToString(",").ifEmpty { null },
                context.packageName, context.applicationInfo.targetSdkVersion))
            val systemImage = TamperProbe.systemImage(context)
            return (0 until arr.length()).mapNotNull { i ->
                val o = arr.getJSONObject(i)
                val code = o.getInt("status")
                if (code == NOT_APPLICABLE || systemImage && o.getString("id") == "TAMPER_SIGNING_BLOCK") return@mapNotNull null
                require(code in 0..2) { "unknown native status $code" }
                Signal(
                    id = o.getString("id"),
                    group = Group.valueOf(o.getString("group")),
                    // native status: 0 = clean, 1 = a real catch, 2 = could not get an answer.
                    status = when (code) { 0 -> Status.CLEAN; 1 -> Status.DETECTED; else -> Status.INCONCLUSIVE },
                    details = (if (code == 2) "could not verify: " else "") + o.getString("details"),
                    micros = o.getLong("us"),
                )
            }
        } catch (t: Throwable) { t }
        val details = "could not verify: native checks did not run: ${failure.javaClass.simpleName}: ${failure.message}" +
            " abis=${Build.SUPPORTED_ABIS.joinToString(",")} is64=${Process.is64Bit()}"
        return listOf(Signal("NATIVE_CORE", Group.APP_INTEGRITY, Status.INCONCLUSIVE, details, (System.nanoTime() - t0) / 1000))
    }
}
