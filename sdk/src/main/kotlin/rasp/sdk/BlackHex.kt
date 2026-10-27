package rasp.sdk

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Looper
import android.os.Process
import android.util.Log
import org.json.JSONArray
import java.util.concurrent.CompletableFuture

enum class Status { CLEAN, DETECTED, INCONCLUSIVE, NOT_APPLICABLE }

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
    var packageName: String? = null
    var resources: String? = null
    var nativeLib: String? = null
    var dexCrc: Long? = null
}

internal object Baselines {
    @Volatile var signers: Set<String> = emptySet()
    @Volatile var packageName: String? = null
    @Volatile var resources: String? = null
    @Volatile var nativeLib: String? = null
    @Volatile var dexCrc: Long? = null
}

object BlackHex {

    private val lock = Any()
    private var running: CompletableFuture<List<Signal>>? = null
    private var last: List<Signal>? = null

    fun baseline(block: BaselineBuilder.() -> Unit) {
        val b = BaselineBuilder().apply(block)
        Baselines.signers = (b.signers + listOfNotNull(b.signer))
            .map { pin -> pin.filterNot { it == ':' || it.isWhitespace() }.lowercase() }
            .filter { it.isNotEmpty() }
            .toSet()
        Baselines.packageName = b.packageName
        Baselines.resources = b.resources
        Baselines.nativeLib = b.nativeLib
        Baselines.dexCrc = b.dexCrc
    }

    fun check(context: Context, policy: Policy = Policy()): Report {
        val t0 = System.nanoTime()
        val signals = signals(context)
        val enforced = signals.filter {
            it.status == Status.DETECTED && it.certainty != Certainty.WEAK && blocks(it.group, policy)
        }
        val verdict = if (enforced.isNotEmpty()) Verdict.BLOCK else Verdict.PASS
        return Report(signals, verdict, enforced, (System.nanoTime() - t0) / 1_000_000)
    }

    private fun signals(context: Context): List<Signal> {
        val mine = CompletableFuture<List<Signal>>()
        val (current, previous) = synchronized(lock) {
            Pair(running, last).also { if (running == null) running = mine }
        }
        if (current != null) {
            if (Looper.myLooper() != Looper.getMainLooper()) return current.join()
            Log.w("BlackHex", "check() on the main thread while another thread runs it: " +
                if (previous != null) "returning the previous result" else "no previous result yet")
            return previous ?: listOf(Signal("CHECK_IN_PROGRESS", Group.APP_INTEGRITY, Certainty.WEAK,
                Status.INCONCLUSIVE, "another thread is running check(); no previous result yet", 0))
        }
        try {
            val s = collect(context)
            synchronized(lock) { last = s; running = null }
            mine.complete(s)
            return s
        } catch (t: Throwable) {
            synchronized(lock) { running = null }
            mine.completeExceptionally(t)
            throw t
        }
    }

    private fun collect(context: Context): List<Signal> {
        val signals = ArrayList(nativeSignals())
        signals += AppProbe.collect()
        signals += TamperProbe.collect(context)
        signals += CustomRomProbe.collect(context)
        signals += CloneProbe.collect(context)
        signals += RootManagerProbe.collect(context)
        if (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            signals.filter { it.status == Status.DETECTED && it.id.startsWith("TAMPER_SIGN") }.forEach {
                Log.w("BlackHex", "${it.id}: signer pin mismatch (${it.details}). Pin the SHA-256 of every " +
                    "certificate users install, including the Play app signing key: BlackHex.baseline { signers = setOf(...) }")
            }
        }
        return signals
    }

    private fun nativeSignals(): List<Signal> {
        val t0 = System.nanoTime()
        val failure = NativeCore.loadError ?: try {
            val arr = JSONArray(NativeCore.run(Baselines.signers.joinToString(",").ifEmpty { null }))
            return (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                Signal(
                    id = o.getString("id"),
                    group = Group.valueOf(o.getString("group")),
                    certainty = Certainty.entries[o.getInt("certainty")],
                    status = Status.entries[o.getInt("status")],
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
