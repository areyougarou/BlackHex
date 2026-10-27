package rasp.sdk

import android.content.Context
import java.io.File

internal object NativeCore {
    val loadError: Throwable? = load()

    @JvmStatic external fun run(signer: String?): String

    private fun load(): Throwable? {
        val first = try { System.loadLibrary("blackhex"); return null } catch (t: Throwable) { t }
        return try { loadFromAssets(); null } catch (t: Throwable) {
            UnsatisfiedLinkError("${first.message}; from assets: $t").apply { initCause(t) }
        }
    }

    private fun loadFromAssets() {
        val ctx = appContext() ?: throw IllegalStateException("no application context")
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

    private fun appContext(): Context? = try {
        val at = Class.forName("android.app.ActivityThread")
        at.getMethod("currentApplication").invoke(null) as? Context
    } catch (_: Throwable) { null }
}
