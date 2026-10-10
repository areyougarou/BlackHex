package rasp.sdk

import android.content.Context
import android.content.pm.PackageManager

internal object RootManagerProbe {

    private val MANAGERS = listOf(
        "com.topjohnwu.magisk",
        "io.github.huskydg.magisk",
        "io.github.vvb2060.magisk",
        "me.weishu.kernelsu",
        "com.rifsxd.ksunext",
        "me.bmax.apatch",
        "me.garfieldhan.apatch.next",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "com.kingroot.kinguser",
        "com.kingo.root",
    )

    fun collect(ctx: Context): List<Signal> = listOf(
        timedSignal("ROOT_MANAGER_PKG", "SUBSTRATE", "MEDIUM") { managerPkg(ctx) },
    )

    private fun isInstalled(pm: PackageManager, pkg: String): Boolean =
        try { pm.getPackageInfo(pkg, 0); true } catch (_: Throwable) { false }

    private fun managerPkg(ctx: Context): Pair<Status, String> {
        val pm = ctx.packageManager
        val hits = MANAGERS.filter { isInstalled(pm, it) }
        return if (hits.isNotEmpty())
            Status.DETECTED to "root-manager package(s) present: $hits"
        else
            Status.CLEAN to "no known root-manager package (name-based; a renamed/hidden manager evades by design)"
    }
}
