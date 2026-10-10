package rasp.sdk

import android.content.pm.PackageManager
import android.content.Context
import android.os.Process
import java.io.File

internal object CloneProbe {

    private val ENGINE_TOKENS = listOf(
        "com.lody.virtual", "io.busniess.va", "com.by.chaos", "com.bly.dkplat", "com.qihoo.magic",
        "com.lbe.parallel", "com.parallel.space", "com.ludashi.dualspace", "com.excelliance.dualaid",
        "com.excelliance.multiaccount", "com.cloneapp", "multi.parallel.dualspace", "com.applisto.appclone",
        "com.vmos", "blackbox", "top.niunaijun", "com.catchingnow.icebox"
    )

    fun collect(ctx: Context): List<Signal> {
        val maps = try { File("/proc/self/maps").readText() } catch (_: Throwable) { "" }
        return listOf(
            timedSignal("CLV_MAPS_FOREIGN_APK", "CLONE", "MEDIUM") { mapsForeignApk(ctx, maps) },
            timedSignal("CLV_MAPS_ENGINE_STRING", "CLONE", "MEDIUM") { mapsEngineString(maps) },
            timedSignal("CLV_CGROUP_UID_MISMATCH", "CLONE", "MEDIUM") { cgroupUid() },
            timedSignal("CLV_SIGCERT_MISMATCH", "CLONE", "MEDIUM") { sigcert(ctx) },
            timedSignal("CLV_DEX_CRC", "CLONE", "MEDIUM") { dexCrc(ctx) },
            timedSignal("CLV_PKGNAME_MISMATCH", "CLONE", "MEDIUM") { pkgName(ctx) },
            timedSignal("CLV_AM_SINGLETON_PROXY", "CLONE", "MEDIUM") { amSingletonProxy() },
        )
    }

    private fun mapsForeignApk(ctx: Context, maps: String): Pair<Status, String> {
        if (maps.isBlank()) return Status.INCONCLUSIVE to "maps empty/blocked"
        val pkg = ctx.packageName
        val userApks = maps.lineSequence().map { it.substringAfterLast(' ') }
            .filter { it.endsWith(".apk") && it.startsWith("/data/") }.toSet()
        val foreign = userApks.filter { !it.contains(pkg) }
        return (if (foreign.isNotEmpty()) Status.DETECTED else Status.CLEAN) to
            "userApks=${userApks.size} foreign=${foreign.take(3)}"
    }

    private fun mapsEngineString(maps: String): Pair<Status, String> {
        if (maps.isBlank()) return Status.INCONCLUSIVE to "maps empty/blocked"
        val hit = ENGINE_TOKENS.firstOrNull { maps.contains(it) }
        return (if (hit != null) Status.DETECTED else Status.CLEAN) to (hit?.let { "engine=$it" } ?: "no engine token")
    }

    private fun cgroupUid(): Pair<Status, String> {
        val cg = File("/proc/self/cgroup").readText()
        val m = Regex("uid_(\\d+)").find(cg)?.groupValues?.get(1)?.toIntOrNull()
        val myUid = Process.myUid()
        return when {
            m == null -> Status.INCONCLUSIVE to "no uid token in cgroup"
            m != myUid -> Status.DETECTED to "cgroup uid=$m myUid=$myUid"
            else -> Status.CLEAN to "cgroup uid=$m"
        }
    }

    private fun sigcert(ctx: Context): Pair<Status, String> {
        val baseline = Baselines.signer
            ?: return Status.INCONCLUSIVE to "signer baseline unset - set BlackHex.baseline { signer=... }"
        val pi = ctx.packageManager.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val sig = pi.signingInfo?.apkContentsSigners?.firstOrNull()
            ?: return Status.INCONCLUSIVE to "no signer"
        val h = java.security.MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())
            .joinToString("") { b -> "%02x".format(b) }
        return (if (h != baseline) Status.DETECTED else Status.CLEAN) to "signer=${h.take(16)} matchesPin=${h == baseline}"
    }

    private fun dexCrc(ctx: Context): Pair<Status, String> {
        val zf = java.util.zip.ZipFile(ctx.applicationInfo.sourceDir)
        val crc = try { zf.getEntry("classes.dex")?.crc ?: -1L } finally { zf.close() }
        val baseline = Baselines.dexCrc
            ?: return Status.INCONCLUSIVE to "dex-crc baseline unset - pin this: ${java.lang.Long.toHexString(crc)}"
        return (if (crc != baseline) Status.DETECTED else Status.CLEAN) to
            "classes.dex crc=${java.lang.Long.toHexString(crc)} pinned=${java.lang.Long.toHexString(baseline)}"
    }

    private fun pkgName(ctx: Context): Pair<Status, String> {
        val expected = Baselines.packageName
            ?: return Status.INCONCLUSIVE to "packageName baseline unset - set BlackHex.baseline { packageName=... }"
        val pkg = ctx.packageName
        return (if (pkg != expected) Status.DETECTED else Status.CLEAN) to "pkg=$pkg expected=$expected"
    }

    private fun amSingletonProxy(): Pair<Status, String> {
        val amClass = Class.forName("android.app.ActivityManager")
        val f = try { amClass.getDeclaredField("IActivityManagerSingleton") }
            catch (_: Throwable) { amClass.getDeclaredField("gDefault") }
        f.isAccessible = true
        val singleton = f.get(null)
        val getM = Class.forName("android.util.Singleton").getMethod("get").apply { isAccessible = true }
        val iam = getM.invoke(singleton)
        val isProxy = java.lang.reflect.Proxy.isProxyClass(iam.javaClass)
        return (if (isProxy) Status.DETECTED else Status.CLEAN) to "iam=${iam.javaClass.name} proxy=$isProxy"
    }
}
