package io.github.areyougarou.blackhex

internal inline fun timedSignal(
    id: String,
    group: Group,
    certainty: Certainty,
    block: () -> Pair<Status, String>,
): Signal {
    val t0 = System.nanoTime()
    val (st, det) = try { block() } catch (t: Throwable) {
        Status.INCONCLUSIVE to "probe error: ${t.message}"
    }
    return Signal(id, group, certainty, st, det, (System.nanoTime() - t0) / 1000)
}

internal fun msLeft(deadline: Long): Long = maxOf(1L, (deadline - System.nanoTime()) / 1_000_000)

internal fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
