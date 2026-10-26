package rasp.sdk

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Process
import android.util.Log
import org.json.JSONArray

enum class Status { CLEAN, DETECTED, INCONCLUSIVE, NOT_APPLICABLE }

enum class Certainty { PROOF, STRONG, WEAK }

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
    val category: String,
    val severity: String,
    val status: Status,
    val details: String,
    val micros: Long,
    val certainty: Certainty = Certainty.WEAK,
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

    @Synchronized
    fun check(context: Context, policy: Policy = Policy()): Report {
        val t0 = System.nanoTime()
        val signals = ArrayList(nativeSignals())
        signals += AppProbe.collect(context)
        signals += TamperProbe.collect(context)
        signals += CustomRomProbe.collect(context)
        signals += CloneProbe.collect(context)
        signals += RootManagerProbe.collect(context)

        if (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            signals.filter { it.status == Status.DETECTED && it.id in signerIds }.forEach {
                Log.w("BlackHex", "${it.id}: signer pin mismatch (${it.details}). Pin the SHA-256 of every " +
                    "certificate users install, including the Play app signing key: BlackHex.baseline { signers = setOf(...) }")
            }
        }

        val enforced = signals.filter {
            it.status == Status.DETECTED && it.certainty != Certainty.WEAK && enforces(groupOf(it.category), policy)
        }
        val verdict = if (enforced.isNotEmpty()) Verdict.BLOCK else Verdict.PASS
        return Report(signals, verdict, enforced, (System.nanoTime() - t0) / 1_000_000)
    }

    private fun nativeSignals(): List<Signal> {
        val t0 = System.nanoTime()
        val failure = NativeCore.loadError ?: try {
            val arr = JSONArray(NativeCore.run(Baselines.signers.joinToString(",").ifEmpty { null }))
            return (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                Signal(
                    id = o.getString("id"),
                    category = o.getString("category"),
                    severity = o.getString("severity"),
                    status = Status.entries[o.getInt("status")],
                    details = o.getString("details"),
                    micros = o.getLong("us"),
                    certainty = Certainty.entries.getOrElse(o.optInt("certainty", 2)) { Certainty.WEAK },
                )
            }
        } catch (t: Throwable) { t }
        val details = "native checks did not run: ${failure.javaClass.simpleName}: ${failure.message}" +
            " abis=${Build.SUPPORTED_ABIS.joinToString(",")} is64=${Process.is64Bit()}"
        return listOf(Signal("NATIVE_CORE", "INTEGRITY", "HIGH", Status.INCONCLUSIVE, details,
            (System.nanoTime() - t0) / 1000))
    }

    private val signerIds = setOf("TAMPER_SIGNER", "TAMPER_SIGNING_BLOCK", "CLV_SIGCERT_MISMATCH")

    private enum class Group { EMULATOR, INSTRUMENTATION, BOOTLOADER, APP_INTEGRITY, ROOT, NONE }

    private fun groupOf(category: String): Group = when (category) {
        "EMULATOR" -> Group.EMULATOR
        "HOOK_DETECTION", "DYNAMIC_LINKER", "MAPS_ANALYSIS" -> Group.INSTRUMENTATION
        "CUSTOM_ROM" -> Group.BOOTLOADER
        "INTEGRITY", "TAMPER", "CLONE" -> Group.APP_INTEGRITY
        "SUBSTRATE" -> Group.ROOT
        else -> Group.NONE
    }

    private fun enforces(group: Group, policy: Policy): Boolean = when (group) {
        Group.APP_INTEGRITY -> true
        Group.EMULATOR -> policy.emulator == Mode.BLOCK
        Group.INSTRUMENTATION -> policy.instrumentation == Mode.BLOCK
        Group.BOOTLOADER -> policy.bootloader == Mode.BLOCK
        Group.ROOT -> policy.root == Mode.BLOCK
        Group.NONE -> false
    }
}
