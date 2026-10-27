package rasp.sdk

import android.content.Context
import android.os.Process
import java.io.File

internal object CloneProbe {

    private var dexCrcCache: Long? = null

    fun collect(ctx: Context): List<Signal> = listOf(
        timedSignal("CLV_CGROUP_UID_MISMATCH", Group.APP_INTEGRITY, Certainty.WEAK) { cgroupUid() },
        timedSignal("CLV_DEX_CRC", Group.APP_INTEGRITY, Certainty.WEAK) { dexCrc(ctx) },
        timedSignal("CLV_PKGNAME_MISMATCH", Group.APP_INTEGRITY, Certainty.PROOF) { pkgName(ctx) },
        timedSignal("CLV_AM_SINGLETON_PROXY", Group.APP_INTEGRITY, Certainty.WEAK) { amSingletonProxy() },
    )

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

    private fun dexCrc(ctx: Context): Pair<Status, String> {
        val crc = dexCrcCache ?: java.util.zip.ZipFile(ctx.applicationInfo.sourceDir).use { it.getEntry("classes.dex")?.crc ?: -1L }
            .also { dexCrcCache = it }
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
