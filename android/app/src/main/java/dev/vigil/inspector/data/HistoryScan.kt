package dev.vigil.inspector.data

/**
 * Streams the network history to the health check in bounded windows of
 * row ids, each aggregated per (name, app) in SQL. With a long retention the
 * history holds millions of rows; loading every (name, app) group at once
 * could exhaust the heap of the process that also runs the VPN.
 */
object HistoryScan {
    /** Rows per window: at most this many groups are in memory at a time. */
    const val WINDOW = 10_000L

    /**
     * Every (name, app) observation of the history, read lazily on the
     * calling thread (blocking database calls: iterate off the main thread).
     * [checkActive] runs before each window, to stop a cancelled check.
     */
    fun observed(db: VigilDatabase, checkActive: () -> Unit = {}): Sequence<ObservedName> = sequence {
        val dns = db.dns()
        val flows = db.flows()
        val destinations = db.destinations()
        for (w in windows(dns.idRange())) {
            checkActive()
            yieldAll(dns.observedNames(w.first, w.last))
        }
        for (w in windows(flows.idRange())) {
            checkActive()
            yieldAll(flows.observedDomains(w.first, w.last))
            yieldAll(flows.observedIps(w.first, w.last))
        }
        for (w in windows(destinations.idRange())) {
            checkActive()
            yieldAll(destinations.observed(w.first, w.last))
        }
    }

    /** Consecutive id windows of at most [size] ids covering [range] (none if the table is empty). */
    fun windows(range: IdRange, size: Long = WINDOW): Sequence<LongRange> {
        require(size > 0)
        val first = range.firstId ?: return emptySequence()
        val last = range.lastId ?: return emptySequence()
        if (last < first) return emptySequence()
        return generateSequence(first) { start -> if (last - start >= size) start + size else null }
            .map { start -> start..(if (last - start >= size) start + size - 1 else last) }
    }
}
