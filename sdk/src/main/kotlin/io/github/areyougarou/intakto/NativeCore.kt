package io.github.areyougarou.intakto

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
        val first = try { System.loadLibrary("intakto"); loaded = true; return null } catch (t: Throwable) { t }
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
        val out = File(ctx.codeCacheDir, "libintakto.$abi.so")
        if (!out.exists()) {
            val tmp = File.createTempFile("libintakto", ".so", ctx.codeCacheDir)
            try {
                ctx.assets.open("intakto/$abi/libintakto.so").use { input ->
                    tmp.outputStream().use { output -> input.copyTo(output) }
                }
                if (!tmp.renameTo(out)) throw IllegalStateException("stage failed")
            } finally {
                tmp.delete()
            }
        }
        // Mark the staged file read-only before loading it. For an app that targets API 37 (Android
        // 17) or higher, System.load() refuses a file that is still writable and throws
        // UnsatisfiedLinkError ("Attempt to load writable file"), as the "Safer Dynamic Code Loading"
        // rule that covered DEX/JAR since Android 14 now also covers native libraries. Without this,
        // every x86, x86_64 and 32-bit process (which reach the native core only through this assets
        // fallback) would fail to load it and read NATIVE_CORE once hosts target API 37. The call is
        // idempotent, and we never write the file again after staging it, so it is safe to load.
        out.setReadOnly()
        System.load(out.absolutePath)
    }
}
