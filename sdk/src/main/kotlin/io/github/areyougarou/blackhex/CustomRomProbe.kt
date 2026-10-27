package io.github.areyougarou.blackhex

import android.content.Context
import android.content.pm.PackageManager

internal object CustomRomProbe {

    fun collect(ctx: Context): List<Signal> = listOf(
        timedSignal("CROM_FEATURE", Group.BOOTLOADER, Certainty.PROOF) { feature(ctx) },
        timedSignal("CROM_PKG_CLUSTER", Group.BOOTLOADER, Certainty.WEAK) { pkgCluster(ctx) },
    )

    private const val POLICY = " [policy WEIGHT, not malicious]"

    private fun feature(ctx: Context): Pair<Status, String> {
        val pm = ctx.packageManager
        val gos = try { pm.hasSystemFeature("grapheneos.version") } catch (_: Throwable) { false }
        val feats = try { pm.systemAvailableFeatures.mapNotNull { it.name } } catch (_: Throwable) { emptyList() }
        val romFeats = feats.filter {
            val l = it.lowercase()
            l.startsWith("grapheneos.") || l.startsWith("org.microg.") ||
                l.contains("lineage") || l.contains("calyx")
        }
        val raw = "grapheneos.version=$gos romFeatures=$romFeats total=${feats.size}"
        return when {
            gos || romFeats.any { it.lowercase().startsWith("grapheneos.") } ->
                Status.DETECTED to "GrapheneOS system feature present$POLICY: $raw"
            romFeats.isNotEmpty() -> Status.DETECTED to "ROM-declared system feature(s)$POLICY: $raw"
            feats.isEmpty() -> Status.INCONCLUSIVE to "no system features enumerable - cannot judge"
            else -> Status.CLEAN to "no ROM-declared system feature (total=${feats.size})"
        }
    }

    private fun isInstalled(pm: PackageManager, pkg: String): Boolean =
        try { pm.getPackageInfo(pkg, 0); true } catch (_: Throwable) { false }

    private fun pkgCluster(ctx: Context): Pair<Status, String> {
        val pm = ctx.packageManager
        val clusters = linkedMapOf(
            "GrapheneOS" to listOf("app.grapheneos.camera", "app.attestation.auditor",
                                   "app.vanadium.browser", "app.grapheneos.gmscompat"),
            "LineageOS"  to listOf("org.lineageos.updater", "org.lineageos.jelly", "org.lineageos.trebuchet"),
            "CalyxOS"    to listOf("org.calyxos.datura", "com.stevesoltys.seedvault"),
            "/e/OS"      to listOf("foundation.e.blisslauncher", "foundation.e.apps"),
            "microG"     to listOf("org.microg.gms.droidguard", "com.google.android.gsf.microg"),
        )
        val found = StringBuilder()
        var rom: String? = null
        for ((name, pkgs) in clusters) {
            val hit = pkgs.filter { isInstalled(pm, it) }
            if (hit.isNotEmpty()) { found.append("$name$hit "); if (rom == null) rom = name }
        }
        val gms = isInstalled(pm, "com.google.android.gms")
        val play = isInstalled(pm, "com.android.vending")
        val raw = "clusters=[$found] gms=$gms play=$play"
        return when {
            rom != null -> Status.DETECTED to "ROM package cluster ($rom)$POLICY: $raw"
            !gms && !play -> Status.DETECTED to "no GMS and no Play Store (de-Googled indicator)$POLICY: $raw"
            else -> Status.CLEAN to "no ROM package cluster; GMS/Play present: $raw"
        }
    }
}
