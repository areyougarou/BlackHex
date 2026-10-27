package io.github.areyougarou.blackhex

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.util.Log
import org.json.JSONArray
import java.lang.ref.WeakReference

enum class Status { CLEAN, DETECTED, INCONCLUSIVE }

enum class Certainty { PROOF, STRONG, WEAK }

enum class Group { APP_INTEGRITY, INSTRUMENTATION, ROOT, EMULATOR, BOOTLOADER }

enum class Mode { ALLOW, BLOCK }

enum class Verdict { PASS, BLOCK }

data class Policy(
    val emulator: Mode = Mode.ALLOW,
    val instrumentation: Mode = Mode.ALLOW,
    val root: Mode = Mode.ALLOW,
    val bootloader: Mode = Mode.ALLOW,
)

data class Signal(
    val id: String,
    val group: Group,
    val certainty: Certainty,
    val status: Status,
    val details: String,
    val micros: Long,
)

data class Report(
    val signals: List<Signal>,
    val verdict: Verdict,
    val enforced: List<Signal>,
    val elapsedMs: Long,
) {
    val detected: List<Signal> get() = signals.filter { it.status == Status.DETECTED }
}

class BaselineBuilder {
    var signer: String? = null
    var signers: Set<String> = emptySet()
}

internal object Baselines {
    @Volatile var signers: Set<String> = emptySet()
}

object BlackHex {

    private const val STALL_MS = 5000L
    private val main = Handler(Looper.getMainLooper())
    private val lock = Any()
    private var running: Run? = null

    private class Run(val pins: Set<String>) {
        private val signals = ArrayList<Signal>()
        val waiting = ArrayList<Waiter>()
        fun add(s: List<Signal>) = synchronized(this) { signals += s; progress() }
        fun snapshot(): List<Signal> = synchronized(this) { signals.toList() }
    }

    private class Waiter(
        val run: Run, val policy: Policy, val t0: Long, val screen: WeakReference<Activity>?, var onResult: ((Report) -> Unit)?,
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

    fun baseline(block: BaselineBuilder.() -> Unit) {
        val b = BaselineBuilder().apply(block)
        Baselines.signers = (b.signers + listOfNotNull(b.signer))
            .map { pin -> pin.filterNot { it == ':' || it.isWhitespace() }.lowercase() }
            .filter { it.isNotEmpty() }
            .toSet()
    }

    fun check(context: Context, policy: Policy = Policy(), onResult: (Report) -> Unit) {
        val app = context.applicationContext ?: context
        val screen = activity(context)?.let { WeakReference(it) }
        val t0 = System.nanoTime()
        var start = false
        var idleMs = 0L
        val w = synchronized(lock) {
            val current = running
            if (current != null) idleMs = (t0 - lastProgress) / 1_000_000
            val run = current ?: Run(Baselines.signers).also { running = it; start = true; progress() }
            Waiter(run, policy, t0, screen, onResult).also { if (idleMs < STALL_MS) run.waiting += it }
        }
        if (idleMs >= STALL_MS) {
            main.post { deliver(w, listOf(stalled("an earlier run has made no progress for $idleMs ms; no checks ran for this call"))) }
            return
        }
        main.postDelayed(w, STALL_MS)
        if (!start) return
        val run = w.run
        try {
            Thread({
                try { collect(app, run) } catch (t: Throwable) { run.add(listOf(failed(t))) }
                finish(run)
            }, "BlackHex").apply { isDaemon = true }.start()
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

    private fun failed(t: Throwable) = Signal("CHECK_FAILED", Group.APP_INTEGRITY, Certainty.STRONG, Status.DETECTED,
        "the run stopped early: ${t.javaClass.simpleName}: ${t.message}", 0)

    private fun stalled(detail: String) = Signal("CHECK_STALLED", Group.APP_INTEGRITY, Certainty.STRONG, Status.DETECTED, detail, 0)

    private tailrec fun activity(c: Context?): Activity? = when (c) {
        is Activity -> c
        is ContextWrapper -> activity(c.baseContext)
        else -> null
    }

    private fun deliver(w: Waiter, signals: List<Signal>) {
        main.removeCallbacks(w)
        val onResult = w.onResult ?: return
        w.onResult = null
        if (w.screen != null && w.screen.get().let { it == null || it.isFinishing || it.isDestroyed }) return
        val enforced = signals.filter {
            it.status == Status.DETECTED && it.certainty != Certainty.WEAK && blocks(it.group, w.policy)
        }
        val verdict = if (enforced.isNotEmpty()) Verdict.BLOCK else Verdict.PASS
        onResult(Report(signals, verdict, enforced, (System.nanoTime() - w.t0) / 1_000_000))
    }

    private fun collect(context: Context, run: Run) {
        val deadline = System.nanoTime() + 2_000_000_000L
        val loadError = NativeCore.load(context)
        TamperProbe.startContentCheck(context)
        run.add(nativeSignals(context, loadError))
        run.add(AppProbe.collect(deadline))
        run.add(CustomRomProbe.collect(context))
        run.add(CloneProbe.collect(context))
        run.add(RootManagerProbe.collect(context))
        val tamper = TamperProbe.collect(context, run.pins)
        run.add(tamper)
        if (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            tamper.filter { it.status == Status.DETECTED && it.id == "TAMPER_SIGNER" }.forEach {
                Log.w("BlackHex", "${it.id}: the installed signer is not in your optional signer pin (${it.details}). " +
                    "No pin is needed. If you keep one, it must list every signing key users install from, " +
                    "including the Play app signing key; otherwise remove BlackHex.baseline { signers = ... }")
            }
        }
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
                val status = o.getInt("status")
                if (status == NOT_APPLICABLE || systemImage && o.getString("id") == "TAMPER_SIGNING_BLOCK") return@mapNotNull null
                Signal(
                    id = o.getString("id"),
                    group = Group.valueOf(o.getString("group")),
                    certainty = Certainty.entries[o.getInt("certainty")],
                    status = Status.entries[status],
                    details = o.getString("details"),
                    micros = o.getLong("us"),
                )
            }
        } catch (t: Throwable) { t }
        val details = "native checks did not run: ${failure.javaClass.simpleName}: ${failure.message}" +
            " abis=${Build.SUPPORTED_ABIS.joinToString(",")} is64=${Process.is64Bit()}"
        return listOf(Signal("NATIVE_CORE", Group.APP_INTEGRITY, Certainty.WEAK, Status.INCONCLUSIVE, details,
            (System.nanoTime() - t0) / 1000))
    }

    private fun blocks(group: Group, policy: Policy): Boolean = when (group) {
        Group.APP_INTEGRITY -> true
        Group.INSTRUMENTATION -> policy.instrumentation == Mode.BLOCK
        Group.ROOT -> policy.root == Mode.BLOCK
        Group.EMULATOR -> policy.emulator == Mode.BLOCK
        Group.BOOTLOADER -> policy.bootloader == Mode.BLOCK
    }
}
