package rasp.sdk

import android.content.Context
import android.opengl.EGL14
import android.opengl.EGLConfig
import android.opengl.GLES20

internal object AppProbe {

    @Suppress("UNUSED_PARAMETER")
    fun collect(ctx: Context): List<Signal> = listOf(
        timed("EMU_GL", "HIGH", Certainty.WEAK) { glRenderer() },
    )

    private fun timed(id: String, sev: String, certainty: Certainty, block: () -> Pair<Status, String>): Signal {
        val t0 = System.nanoTime()
        var result: Pair<Status, String>? = null
        val worker = Thread {
            result = try { block() } catch (t: Throwable) { Status.INCONCLUSIVE to "probe error: ${t.message}" }
        }.apply { isDaemon = true; start() }
        worker.join(2000)
        val (st, det) = result ?: (Status.INCONCLUSIVE to "probe timed out (>2s) - stalled HAL (emulator-like)")
        return Signal(id, "EMULATOR", sev, st, det, (System.nanoTime() - t0) / 1000, certainty)
    }

    private fun glRenderer(): Pair<Status, String> {
        val dpy = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY)
        if (dpy == EGL14.EGL_NO_DISPLAY) return Status.INCONCLUSIVE to "no EGL display"
        val ver = IntArray(2)
        if (!EGL14.eglInitialize(dpy, ver, 0, ver, 1)) return Status.INCONCLUSIVE to "eglInitialize failed"
        try {
            val cfg = arrayOfNulls<EGLConfig>(1); val n = IntArray(1)
            val attr = intArrayOf(
                EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT, EGL14.EGL_NONE,
            )
            if (!EGL14.eglChooseConfig(dpy, attr, 0, cfg, 0, 1, n, 0) || n[0] == 0)
                return Status.INCONCLUSIVE to "no EGL config"
            val ctx = EGL14.eglCreateContext(dpy, cfg[0], EGL14.EGL_NO_CONTEXT,
                intArrayOf(EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE), 0)
            val surf = EGL14.eglCreatePbufferSurface(dpy, cfg[0],
                intArrayOf(EGL14.EGL_WIDTH, 1, EGL14.EGL_HEIGHT, 1, EGL14.EGL_NONE), 0)
            EGL14.eglMakeCurrent(dpy, surf, surf, ctx)
            val renderer = GLES20.glGetString(GLES20.GL_RENDERER) ?: ""
            val vendor = GLES20.glGetString(GLES20.GL_VENDOR) ?: ""
            EGL14.eglMakeCurrent(dpy, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT)
            if (surf != EGL14.EGL_NO_SURFACE) EGL14.eglDestroySurface(dpy, surf)
            if (ctx != EGL14.EGL_NO_CONTEXT) EGL14.eglDestroyContext(dpy, ctx)
            val r = renderer.lowercase()
            val soft = listOf("swiftshader", "llvmpipe", "softpipe", "virgl", "android emulator", "emulation")
            val raw = "renderer='$renderer' vendor='$vendor'"
            return if (soft.any { r.contains(it) }) Status.DETECTED to "software GL renderer (emulator): $raw"
            else if (renderer.isBlank()) Status.INCONCLUSIVE to "no GL renderer string"
            else Status.CLEAN to "hardware GL renderer: $raw"
        } finally {
            EGL14.eglTerminate(dpy)
        }
    }
}
