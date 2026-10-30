package io.github.areyougarou.intakto

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Shown on DETECTED in Mode.BLOCK: one short sentence per group of results, plus the
 * check id(s) in small text so the user can send them to the developer. Closes the app
 * when the user taps OK or dismisses the screen (back / tap outside). Started only by
 * [Intakto]; if it cannot be shown, Intakto closes the app silently as before.
 */
internal class NoticeActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val lines = intent?.getStringArrayListExtra(EXTRA_LINES)
            ?: arrayListOf("This app failed a security check.")
        val ids = intent?.getStringExtra(EXTRA_IDS).orEmpty()
        val density = resources.displayMetrics.density
        fun dp(v: Int) = (v * density).toInt()

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(20), dp(24), dp(4))
        }
        lines.forEach { line ->
            content.addView(TextView(this).apply {
                text = line
                textSize = 16f
                setPadding(0, 0, 0, dp(10))
            })
        }
        if (ids.isNotEmpty()) content.addView(TextView(this).apply {
            text = ids
            textSize = 12f
            alpha = 0.6f
        })

        var closed = false
        fun close() {
            if (closed) return
            closed = true
            Intakto.closeNow(applicationContext)
        }

        try {
            AlertDialog.Builder(this)
                .setTitle("Security check")
                .setView(content)
                .setCancelable(true)
                .setPositiveButton(android.R.string.ok, null)
                .setOnDismissListener { close() }
                .create()
                .show()
        } catch (_: Throwable) {
            // Cannot show the dialog on this device → close as before, don't crash the host.
            close()
        }
    }

    // The notice is actually in front of the user now: cancel Intakto's close-anyway watchdog.
    override fun onResume() {
        super.onResume()
        Intakto.noticeShown = true
    }

    companion object {
        private const val EXTRA_LINES = "io.github.areyougarou.intakto.LINES"
        private const val EXTRA_IDS = "io.github.areyougarou.intakto.IDS"

        /** Called on the main thread from [Intakto]. May throw if the activity cannot be started. */
        fun show(app: Context, from: Activity?, lines: List<String>, ids: String) {
            val intent = Intent(app, NoticeActivity::class.java)
                .putStringArrayListExtra(EXTRA_LINES, ArrayList(lines))
                .putExtra(EXTRA_IDS, ids)
            if (from != null && !from.isFinishing && !from.isDestroyed) {
                from.startActivity(intent)
            } else {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                app.startActivity(intent)
            }
        }
    }
}
