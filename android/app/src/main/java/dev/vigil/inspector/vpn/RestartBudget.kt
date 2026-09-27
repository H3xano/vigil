package dev.vigil.inspector.vpn

/**
 * Bounded automatic restarts after engine failures: at most [maxRestarts]
 * within [windowMs], with exponential backoff. Not thread-safe; used from
 * the service's command loop only.
 */
class RestartBudget(
    private val maxRestarts: Int = 3,
    private val windowMs: Long = 5 * 60_000L,
    private val baseDelayMs: Long = 1_000L,
) {
    private val failures = ArrayDeque<Long>()

    /** Records a failure at [now]; returns the delay before restarting, or null to give up. */
    fun onFailure(now: Long): Long? {
        while (failures.isNotEmpty() && now - failures.first() > windowMs) failures.removeFirst()
        failures.addLast(now)
        if (failures.size > maxRestarts) return null
        return baseDelayMs shl (failures.size - 1)
    }

    /** A user-initiated start gets a fresh budget. */
    fun reset() = failures.clear()
}
