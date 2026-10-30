package io.github.areyougarou.intakto

internal inline fun timedSignal(
    id: String,
    group: Group,
    block: () -> Pair<Status, String>,
): Signal {
    val t0 = System.nanoTime()
    val (st, det) = try { block() } catch (t: Throwable) {
        Status.INCONCLUSIVE to "could not verify: probe error: ${t.message}"
    }
    return Signal(id, group, st, det, (System.nanoTime() - t0) / 1000)
}

@Volatile internal var lastProgress = 0L

internal fun progress() { lastProgress = System.nanoTime() }

internal fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
