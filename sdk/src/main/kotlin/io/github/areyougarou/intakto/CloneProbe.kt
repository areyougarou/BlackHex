package io.github.areyougarou.intakto

import android.content.Context
import android.content.pm.PackageManager

internal object CloneProbe {

    fun collect(ctx: Context): List<Signal> = listOf(
        timedSignal("CLV_PKGNAME_MISMATCH", Group.APP_INTEGRITY) { pkgName(ctx) },
    )

    private fun buildTimeId(ctx: Context): String? = try {
        @Suppress("DEPRECATION")
        ctx.packageManager.getApplicationInfo(ctx.packageName, PackageManager.GET_META_DATA)
            .metaData?.getString("io.github.areyougarou.intakto.applicationId")?.takeIf { '$' !in it && '{' !in it }
    } catch (_: Throwable) { null }

    private fun pkgName(ctx: Context): Pair<Status, String> {
        val expected = buildTimeId(ctx) ?: return Status.INCONCLUSIVE to "could not verify: no build-time package name in the app manifest"
        val pkg = ctx.packageName
        return (if (pkg != expected) Status.DETECTED else Status.CLEAN) to "pkg=$pkg expected=$expected"
    }
}
