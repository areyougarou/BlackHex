package io.github.areyougarou.blackhex

import android.content.Context
import java.io.File

internal object NativeCore {
    @Volatile private var loaded = false

    @JvmStatic external fun run(signers: String?, pkg: String, targetSdk: Int): String

    @JvmStatic external fun open(path: String): Int

    @JvmStatic external fun apkPath(pkg: String): String?

    @Synchronized
    fun load(ctx: Context): Throwable? {
        if (loaded) return null
        val first = try { System.loadLibrary("blackhex"); loaded = true; return null } catch (t: Throwable) { t }
        return try { loadFromAssets(ctx); loaded = true; null } catch (t: Throwable) {
            UnsatisfiedLinkError("${first.message}; from assets: $t").apply { initCause(t) }
        }
    }

    private fun loadFromAssets(ctx: Context) {
        val abi = when (val isa = File(ctx.applicationInfo.nativeLibraryDir).name) {
            "arm64" -> "arm64-v8a"
            "arm" -> "armeabi-v7a"
            "x86_64", "x86" -> isa
            else -> throw IllegalStateException("unknown instruction set $isa")
        }
        val out = File(ctx.codeCacheDir, "libblackhex.$abi.so")
        if (!out.exists()) {
            val tmp = File.createTempFile("libblackhex", ".so", ctx.codeCacheDir)
            try {
                ctx.assets.open("blackhex/$abi/libblackhex.so").use { input ->
                    tmp.outputStream().use { output -> input.copyTo(output) }
                }
                if (!tmp.renameTo(out)) throw IllegalStateException("stage failed")
            } finally {
                tmp.delete()
            }
        }
        System.load(out.absolutePath)
    }
}
