package rasp.sdk

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
