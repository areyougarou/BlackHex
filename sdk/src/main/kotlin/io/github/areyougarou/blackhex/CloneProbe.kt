package io.github.areyougarou.blackhex

import android.content.Context
import android.content.pm.PackageManager
import android.os.Process
import java.io.File

internal object CloneProbe {

    fun collect(ctx: Context): List<Signal> = listOf(
        timedSignal("CLV_CGROUP_UID_MISMATCH", Group.APP_INTEGRITY, Certainty.WEAK) { cgroupUid() },
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

    private fun buildTimeId(ctx: Context): String? = try {
        @Suppress("DEPRECATION")
        ctx.packageManager.getApplicationInfo(ctx.packageName, PackageManager.GET_META_DATA)
            .metaData?.getString("io.github.areyougarou.blackhex.applicationId")?.takeIf { '$' !in it && '{' !in it }
    } catch (_: Throwable) { null }

    private fun pkgName(ctx: Context): Pair<Status, String> {
        val expected = buildTimeId(ctx) ?: return Status.INCONCLUSIVE to "no build-time package name in the app manifest"
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
