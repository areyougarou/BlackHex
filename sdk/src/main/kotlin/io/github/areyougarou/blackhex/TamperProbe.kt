package io.github.areyougarou.blackhex

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

internal object TamperProbe {

    private class Signers(val current: List<String>, val history: List<String>, val subjects: List<Set<String>>)

    private var signerCerts: Signers? = null
    private var contentWorker: Thread? = null
    private var contentWaited = false
    @Volatile private var contentResults: List<Pair<String, ApkVerdict>>? = null
    private var repackaged: List<String>? = null

    private val debugSubject = setOf("CN=Android Debug", "O=Android", "C=US")
    private val aospTestKeys = setOf(
        "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc",
        "c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8",
        "28bbfe4a7b97e74681dc55c2fbb6ccb8d6c74963733f6af6ae74d8c3a6e879fd",
        "465983f7791f2abeb43ea2cbdc7f21a8260b72bc08a55c839fc1a43bc741a81e",
        "e1dbadce60dc080d15b58a014b0dcf9400e24de23fa00b287a5a982bfebda2ee",
        "abf21f9e2af1d881cc673fddcefa6ed9c269a437bd64b279cf45844cfd589126",
        "a6ccc500ff0e7421200eb66a7fe174ef1b00e52ca91727070cbedf061ff76c35",
        "fae9122a8721d6e2a196d2224dffcf773c9127e2bb956cbddb40b009192ffdfd",
        "ce7b2b47ae2b7552c8f92cc29124279883041fb623a5f194a82c9bf15d492aa0",
    )

    fun collect(ctx: Context, deadline: Long): List<Signal> = listOf(
        timedSignal("TAMPER_SIGNER", Group.APP_INTEGRITY, Certainty.PROOF) { signer(ctx) },
        timedSignal("TAMPER_PUBLIC_KEY", Group.APP_INTEGRITY, Certainty.WEAK) { publicKey(ctx) },
        timedSignal("TAMPER_REPACKAGER", Group.APP_INTEGRITY, Certainty.PROOF) { repackager(ctx) },
        timedSignal("TAMPER_APK_CONTENT", Group.APP_INTEGRITY, Certainty.STRONG) { apkContent(ctx, deadline) },
    )

    fun startContentCheck(ctx: Context) {
        if (contentWorker != null) return
        val files = listOf(ctx.applicationInfo.sourceDir) + ctx.applicationInfo.splitSourceDirs.orEmpty()
        contentWorker = Thread { contentResults = files.map { File(it).name to verify(it) } }.apply { isDaemon = true; start() }
    }

    fun androidSigners(ctx: Context): List<String> = try {
        signers(ctx).run { current + history }.distinct()
    } catch (_: Throwable) { emptyList() }

    private fun signers(ctx: Context): Signers =
        signerCerts ?: readSigner(ctx).also { if (it.current.isNotEmpty()) signerCerts = it }

    private fun signer(ctx: Context): Pair<Status, String> {
        val s = signers(ctx)
        val current = s.current
        val live = current.firstOrNull() ?: return Status.INCONCLUSIVE to "no signer cert"
        val pins = Baselines.signers
        if (pins.isEmpty()) return Status.INCONCLUSIVE to "no signer pin set (optional): $live"
        if (current.all { it in pins }) return Status.CLEAN to "signer matches pin: ${live.take(16)}"
        val anchor = s.history.firstOrNull { it in pins }
        if (current.size == 1 && anchor != null)
            return Status.CLEAN to "signer ${live.take(16)} rotated from pinned ${anchor.take(16)}"
        return Status.DETECTED to "signer mismatch: live=${current.joinToString(",") { it.take(16) }} " +
            "pinned=${pins.joinToString(",") { it.take(16) }}"
    }

    private fun apkContent(ctx: Context, deadline: Long): Pair<Status, String> {
        val s = signers(ctx)
        if (s.current.isEmpty()) return Status.INCONCLUSIVE to "no signer cert from Android"
        if (!contentWaited) { contentWaited = true; contentWorker?.join(msLeft(deadline)) }
        val results = contentResults
            ?: return Status.INCONCLUSIVE to "still hashing the APK files at the first-run limit (2s); a later check() reports the result"
        val known = (s.current + s.history).toSet()
        results.firstOrNull { it.second.status == Status.DETECTED }?.let { (n, v) -> return Status.DETECTED to "$n: ${v.detail}" }
        results.firstOrNull { it.second.signer != null && it.second.signer !in known }?.let { (n, v) ->
            return Status.DETECTED to "$n: signed by ${v.signer!!.take(16)}, Android reports ${s.current.joinToString(",") { it.take(16) }}"
        }
        results.firstOrNull { it.second.status != Status.CLEAN }?.let { (n, v) -> return Status.INCONCLUSIVE to "$n: ${v.detail}" }
        return Status.CLEAN to "files=${results.size} match their signatures; ${results.first().second.detail}"
    }

    private fun verify(path: String): ApkVerdict = try { ApkSignature.verify(path) } catch (t: Throwable) {
        ApkVerdict(Status.INCONCLUSIVE, null, "cannot verify: ${t.javaClass.simpleName}: ${t.message}")
    }

    private fun publicKey(ctx: Context): Pair<Status, String> {
        if (ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
            return Status.NOT_APPLICABLE to "debuggable build"
        val s = signers(ctx)
        if (s.subjects.isEmpty()) return Status.INCONCLUSIVE to "no signer cert"
        return when {
            s.subjects.any { it == debugSubject } -> Status.DETECTED to "release build signed with the Android debug certificate"
            s.current.any { it in aospTestKeys } -> Status.DETECTED to "release build signed with a public AOSP test key"
            else -> Status.CLEAN to "signer is not a publicly known key"
        }
    }

    private fun readSigner(ctx: Context): Signers {
        val pm = ctx.packageManager
        val (current, history) = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
                ?: return Signers(emptyList(), emptyList(), emptyList())
            val history = if (info.hasMultipleSigners()) emptyList() else info.signingCertificateHistory.orEmpty().toList()
            info.apkContentsSigners.orEmpty().toList() to history
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES).signatures.orEmpty().toList() to emptyList()
        }
        return Signers(current.map { certHex(it) }, history.map { certHex(it) }, current.map { subject(it) })
    }

    private fun certHex(sig: android.content.pm.Signature): String =
        hex(MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()))

    private fun subject(sig: android.content.pm.Signature): Set<String> =
        (CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(sig.toByteArray())) as X509Certificate)
            .subjectX500Principal.name.split(',').map { it.trim() }.toSet()

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
}
