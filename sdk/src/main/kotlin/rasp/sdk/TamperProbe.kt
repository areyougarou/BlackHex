package rasp.sdk

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest
import java.util.TreeMap
import java.util.zip.ZipFile

internal object TamperProbe {

    private var signerCerts: Pair<List<String>, List<String>>? = null
    private val digests = HashMap<String, Pair<String, Int>>()
    private var repackaged: List<String>? = null

    fun collect(ctx: Context): List<Signal> = listOf(
        timedSignal("TAMPER_SIGNER", Group.APP_INTEGRITY, Certainty.PROOF) { signer(ctx) },
        timedSignal("TAMPER_RESOURCES", Group.APP_INTEGRITY, Certainty.WEAK) { apkDigest(ctx, "res", Baselines.resources) { it == "resources.arsc" || it == "AndroidManifest.xml" } },
        timedSignal("TAMPER_NATIVELIB", Group.APP_INTEGRITY, Certainty.STRONG) { apkDigest(ctx, "lib", Baselines.nativeLib) { it.startsWith("lib/") && it.endsWith(".so") } },
        timedSignal("TAMPER_REPACKAGER", Group.APP_INTEGRITY, Certainty.PROOF) { repackager(ctx) },
    )

    private fun signer(ctx: Context): Pair<Status, String> {
        val (current, history) = signerCerts ?: readSigner(ctx).also { if (it.first.isNotEmpty()) signerCerts = it }
        val live = current.firstOrNull() ?: return Status.INCONCLUSIVE to "no signer cert"
        val pins = Baselines.signers
        if (pins.isEmpty()) return Status.INCONCLUSIVE to "signer baseline unset - pin this: $live"
        if (current.all { it in pins }) return Status.CLEAN to "signer matches pin: ${live.take(16)}"
        val anchor = history.firstOrNull { it in pins }
        if (current.size == 1 && anchor != null)
            return Status.CLEAN to "signer ${live.take(16)} rotated from pinned ${anchor.take(16)}"
        return Status.DETECTED to "signer mismatch: live=${current.joinToString(",") { it.take(16) }} " +
            "pinned=${pins.joinToString(",") { it.take(16) }}"
    }

    private fun readSigner(ctx: Context): Pair<List<String>, List<String>> {
        val pm = ctx.packageManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
                ?: return emptyList<String>() to emptyList()
            val history = if (info.hasMultipleSigners()) emptyList() else info.signingCertificateHistory.orEmpty().map { certHex(it) }
            return info.apkContentsSigners.orEmpty().map { certHex(it) } to history
        }
        @Suppress("DEPRECATION")
        return pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES).signatures.orEmpty().map { certHex(it) } to emptyList()
    }

    private fun certHex(sig: android.content.pm.Signature): String =
        sha256Hex(MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()))

    private fun apkDigest(ctx: Context, key: String, baseline: String?, want: (String) -> Boolean): Pair<Status, String> {
        val src = ctx.applicationInfo.sourceDir
        val (hex, n) = digests.getOrPut(key) { digest(src, want) }
        if (n == 0) return Status.INCONCLUSIVE to "no matching entries in $src"
        return verdict(hex, baseline, "entries=$n")
    }

    private fun digest(src: String, want: (String) -> Boolean): Pair<String, Int> {
        val perEntry = TreeMap<String, String>()
        ZipFile(src).use { zf ->
            val e = zf.entries()
            while (e.hasMoreElements()) {
                val entry = e.nextElement()
                if (entry.isDirectory || !want(entry.name)) continue
                val md = MessageDigest.getInstance("SHA-256")
                zf.getInputStream(entry).use { ins ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = ins.read(buf); if (n < 0) break; md.update(buf, 0, n)
                    }
                }
                perEntry[entry.name] = sha256Hex(md.digest())
            }
        }
        val fold = MessageDigest.getInstance("SHA-256")
        for ((name, dig) in perEntry) { fold.update(name.toByteArray()); fold.update(dig.toByteArray()) }
        return sha256Hex(fold.digest()) to perEntry.size
    }

    private fun repackager(ctx: Context): Pair<Status, String> {
        val hits = repackaged ?: repackagerHits(ctx.applicationInfo.sourceDir).also { repackaged = it }
        return if (hits.isNotEmpty()) Status.DETECTED to "repackager artifacts: $hits"
        else Status.CLEAN to "no repackager artifacts"
    }

    private fun repackagerHits(src: String): List<String> {
        val markers = listOf(
            "assets/lspatch/", "origin.apk", "liblspatch.so", "assets/lspatch/origin.apk",
            "assets/xpatch/", "AppClonerCodeClasses.jar", "assets/libAppCloner.zip", "libappcloner.so",
        )
        val hits = ArrayList<String>()
        ZipFile(src).use { zf ->
            val e = zf.entries()
            while (e.hasMoreElements()) {
                val name = e.nextElement().name
                for (m in markers) if (name == m || name.startsWith(m)) { hits += name; break }
            }
        }
        return hits
    }

    private fun verdict(live: String, baseline: String?, label: String): Pair<Status, String> =
        when (baseline) {
            null -> Status.INCONCLUSIVE to "$label baseline unset - pin this: $live"
            live -> Status.CLEAN to "$label matches pin: ${live.take(16)}"
            else -> Status.DETECTED to "$label mismatch: live=${live.take(16)} pinned=${baseline.take(16)}"
        }

    private fun sha256Hex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) { val v = x.toInt() and 0xff; sb.append("0123456789abcdef"[v ushr 4]); sb.append("0123456789abcdef"[v and 0xf]) }
        return sb.toString()
    }
}
