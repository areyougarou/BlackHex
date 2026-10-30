package io.github.areyougarou.intakto

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.LauncherApps
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import java.io.File
import java.security.MessageDigest

internal object TamperProbe {

    private class Signers(val current: List<String>, val history: List<String>)

    private var signerCerts: Signers? = null
    private var contentWorker: Thread? = null
    @Volatile private var contentResults: List<Pair<String, ApkVerdict>>? = null
    private var repackaged: List<String>? = null
    private var baseApk: String? = null

    private val installerDir = Regex("/data/app/.+|/mnt/expand/[^/]+/app/.+")
    private val publicKeys = setOf(
        "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc",
        "c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8",
        "28bbfe4a7b97e74681dc55c2fbb6ccb8d6c74963733f6af6ae74d8c3a6e879fd",
        "465983f7791f2abeb43ea2cbdc7f21a8260b72bc08a55c839fc1a43bc741a81e",
        "e1dbadce60dc080d15b58a014b0dcf9400e24de23fa00b287a5a982bfebda2ee",
        "abf21f9e2af1d881cc673fddcefa6ed9c269a437bd64b279cf45844cfd589126",
        "a6ccc500ff0e7421200eb66a7fe174ef1b00e52ca91727070cbedf061ff76c35",
        "fae9122a8721d6e2a196d2224dffcf773c9127e2bb956cbddb40b009192ffdfd",
        "ce7b2b47ae2b7552c8f92cc29124279883041fb623a5f194a82c9bf15d492aa0",
        "1e08a903aef9c3a721510b64ec764d01d3d094eb954161b62544ea8f187b5953",
        "c081890cf2a1adf13e56d7b50a4f3d8edb35b7c46d6ccc732dd997b7e433be1d",
        "f67430285c020c72fbeaa81870b42c79bcc159b08be2ddd83789d0eae68215fd",
        "698cabd10a4f3bfe6073a4dc8435fe7538cee01d234d13a3070aa42a6dbf6013",
        "6215f00baa4bf18bab5792fc796bfc5555917240f14f7c7e672d956888d75c96",
        "7b19ed7f0a76ce4898a0b439b84a0df0585efed1fbc970c828f525e94254f67d",
        "492682f877607ee99df2ddd2bd5953fd727bdf6e19d397de9dbbafd582bcad75",
    )

    fun collect(ctx: Context): List<Signal> {
        // An app built into the system image is served from /system, a path the installer-folder rule
        // rejects, so TAMPER_REPACKAGER's APK read throws and reads "could not verify", closing the
        // app at every start on OEM and ROM builds. "Built into the system image" is a fixed fact from
        // ApplicationInfo flags, known before any file is read, so it is allowed to switch the check
        // off (OVERVIEW rule: a check is never switched off by a failed read). TAMPER_APK_CONTENT
        // already skips here for the same reason; TAMPER_REPACKAGER must too.
        val systemImage = systemImage(ctx)
        return listOfNotNull(
            timedSignal("TAMPER_PUBLIC_KEY", Group.APP_INTEGRITY) { publicKey(ctx) },
            if (systemImage) null
            else timedSignal("TAMPER_REPACKAGER", Group.APP_INTEGRITY) { repackager(ctx) },
            if (systemImage) null
            else timedSignal("TAMPER_APK_CONTENT", Group.APP_INTEGRITY) { apkContent(ctx) },
        )
    }

    // Set once the install is known to be complete. Neither fact can change while this process lives
    // (an update restarts it), so later checks skip the two system calls (0.4-1.7 ms per check).
    @Volatile private var downloadComplete = false

    fun awaitPlayDownload(ctx: Context) {
        if (downloadComplete || Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
        try {
            if (ctx.packageManager.getInstallSourceInfo(ctx.packageName).initiatingPackageName != "com.android.vending") {
                downloadComplete = true
                return
            }
            val apps = ctx.getSystemService(LauncherApps::class.java)
            while ((apps.getActivityList(ctx.packageName, Process.myUserHandle()).firstOrNull()?.loadingProgress ?: 1f) < 1f) {
                progress()
                Thread.sleep(500)
            }
            downloadComplete = true
        } catch (_: Exception) {}
    }

    fun startContentCheck(ctx: Context) {
        if (contentWorker != null || systemImage(ctx)) return
        try {
            val files = listOf(baseApk(ctx)) + ctx.applicationInfo.splitSourceDirs.orEmpty()
            val known = androidSigners(ctx).toSet()
            val targetSdk = ctx.applicationInfo.targetSdkVersion
            contentWorker = Thread {
                contentResults = try { verifyAll(files, known, targetSdk) } catch (t: Throwable) {
                    listOf("apk" to ApkVerdict(Status.INCONCLUSIVE, null, "could not verify: ${t.javaClass.simpleName}: ${t.message}"))
                }
            }.apply { isDaemon = true; start() }
        } catch (t: Throwable) {
            contentResults = listOf("apk" to ApkVerdict(Status.INCONCLUSIVE, null, "could not verify: the APK file check could not start: ${t.javaClass.simpleName}: ${t.message}"))
        }
    }

    private fun baseApk(ctx: Context): String = baseApk
        ?: (NativeCore.apkPath(ctx.packageName) ?: ctx.applicationInfo.sourceDir).also { baseApk = it }

    private fun installed(path: String): String = path.also {
        require(installerDir.matches(it) && "/../" !in it) { "$it is not in a folder Android installs apps into" }
    }

    fun systemImage(ctx: Context): Boolean = ctx.applicationInfo.flags.let {
        it and ApplicationInfo.FLAG_SYSTEM != 0 && it and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP == 0
    }

    fun androidSigners(ctx: Context): List<String> = try {
        signers(ctx).run { current + history }.distinct()
    } catch (_: Throwable) { emptyList() }

    private fun signers(ctx: Context): Signers =
        signerCerts ?: readSigner(ctx).also { if (it.current.isNotEmpty()) signerCerts = it }

    private fun apkContent(ctx: Context): Pair<Status, String> {
        val s = signers(ctx)
        if (s.current.isEmpty()) return Status.INCONCLUSIVE to "could not verify: no signer cert from Android"
        contentWorker?.join()
        val results = contentResults ?: return Status.INCONCLUSIVE to "could not verify: the APK file check did not start"
        // A proven mismatch closes the app, so report DETECTED first. Otherwise, if any file could not
        // be checked, report INCONCLUSIVE (not CLEAN): a file we could not read is not a file that matched.
        results.firstOrNull { it.second.status == Status.DETECTED }?.let { (n, v) -> return Status.DETECTED to "$n: ${v.detail}" }
        results.firstOrNull { it.second.status == Status.INCONCLUSIVE }?.let { (n, v) -> return Status.INCONCLUSIVE to "$n: ${v.detail}" }
        return Status.CLEAN to "files=${results.size} match their signatures; ${results.first().second.detail}"
    }

    private fun verifyAll(files: List<String>, signers: Set<String>, targetSdk: Int): List<Pair<String, ApkVerdict>> = files.map { path ->
        File(path).name to ParcelFileDescriptor.AutoCloseInputStream(ParcelFileDescriptor.adoptFd(NativeCore.open(installed(path))))
            .use { ApkSignature.verify(it.channel, signers, targetSdk) }
    }

    private fun publicKey(ctx: Context): Pair<Status, String> {
        val s = signers(ctx)
        if (s.current.isEmpty()) return Status.INCONCLUSIVE to "could not verify: no signer cert"
        val known = s.current.firstOrNull { it in publicKeys }
            ?: return Status.CLEAN to "signer is not a publicly known key"
        return Status.DETECTED to "signed with a publicly known key: ${known.take(16)}"
    }

    private fun readSigner(ctx: Context): Signers {
        val pm = ctx.packageManager
        val (current, history) = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
                ?: return Signers(emptyList(), emptyList())
            val history = if (info.hasMultipleSigners()) emptyList() else info.signingCertificateHistory.orEmpty().toList()
            info.apkContentsSigners.orEmpty().toList() to history
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES).signatures.orEmpty().toList() to emptyList()
        }
        return Signers(current.map { certHex(it) }, history.map { certHex(it) })
    }

    private fun certHex(sig: android.content.pm.Signature): String =
        hex(MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()))

    private fun repackager(ctx: Context): Pair<Status, String> {
        val hits = repackaged ?: repackagerHits(baseApk(ctx)).also { repackaged = it }
        return if (hits.isNotEmpty()) Status.DETECTED to "repackager artifacts: $hits"
        else Status.CLEAN to "no repackager artifacts"
    }

    private fun repackagerHits(src: String): List<String> {
        val markers = listOf(
            "assets/lspatch/", "liblspatch.so",
            "libfrida-gadget.so", "libfrida-gadget.config.so",
            "libappcloner.so",
        )
        return ParcelFileDescriptor.AutoCloseInputStream(ParcelFileDescriptor.adoptFd(NativeCore.open(installed(src))))
            .use { ApkSignature.entryNames(it.channel) }
            .filter { n -> markers.any { n.startsWith(it) || n.endsWith("/$it") } }
    }
}
