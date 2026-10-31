package io.github.areyougarou.intakto

import android.os.Looper
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

// An adopter's unit tests run on a JVM with no phone and no native library. There, check() must not
// throw, must report the native checks as "could not confirm" (INCONCLUSIVE), and must never report
// a catch, so it never fails or closes an adopter's test run.
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class JvmCheckTest {

    @Test
    fun checkOnTheJvmIsInconclusiveAndNeverBlocks() {
        var report: Report? = null
        Intakto.check(RuntimeEnvironment.getApplication(), Mode.REPORT) { report = it }

        // The checks run on IntaktoFT's own thread and post the result to the main looper, which
        // Robolectric runs only when asked.
        val deadline = System.nanoTime() + 10_000_000_000
        while (report == null && System.nanoTime() < deadline) {
            Thread.sleep(50)
            shadowOf(Looper.getMainLooper()).idle()
        }

        val r = report ?: throw AssertionError("no report within 10 s")
        println("JVM report: verdict=${r.verdict} " + r.signals.joinToString(" ") { "${it.id}=${it.status}" })
        assertEquals(Status.INCONCLUSIVE, r.signals.single { it.id == "NATIVE_CORE" }.status)
        assertTrue("a check reported DETECTED: ${r.enforced}", r.enforced.isEmpty())
        assertEquals(Verdict.PASS, r.verdict)
    }
}
