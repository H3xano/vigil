package dev.vigil.inspector.data

/**
 * Size cap of the history database, on top of the age-based retention: a
 * busy device with a long retention could otherwise fill the storage. When
 * the data in the database exceeds [MAX_BYTES], the oldest connections and
 * DNS lookups are deleted in chunks until it is below [TARGET_BYTES] (the
 * margin avoids trimming again after every batch). Alerts and the learned
 * destinations are not trimmed: they are small and kept longer.
 *
 * Deleting rows does not shrink the file (SQLite reuses the freed pages;
 * VACUUM returns them), so the size measured is the pages in use.
 */
object HistoryCap {
    const val MAX_BYTES = 300L * 1024 * 1024
    const val TARGET_BYTES = MAX_BYTES / 10 * 9

    /** Rows deleted per step. */
    const val CHUNK = 5_000

    /** Upper bound on steps per run, so a run always ends (each step deletes [CHUNK] rows). */
    const val MAX_STEPS = 2_000

    /** What to trim next. */
    enum class Table { FLOWS, DNS }

    /** Bytes of data in a database: pages in use (free pages excluded) times the page size. */
    fun usedBytes(pageCount: Long, freePages: Long, pageSize: Long): Long = (pageCount - freePages).coerceAtLeast(0) * pageSize

    /**
     * The table to delete the oldest [CHUNK] rows from, or null to stop.
     * [trimming] is false for the first decision of a run (trim only above
     * [max]) and true afterwards (go on down to [target]). The table whose
     * oldest row is older goes first, so the history keeps one time span;
     * null oldest means the table is empty.
     */
    fun next(
        usedBytes: Long,
        trimming: Boolean,
        oldestFlow: Long?,
        oldestDns: Long?,
        max: Long = MAX_BYTES,
        target: Long = TARGET_BYTES,
    ): Table? {
        if (usedBytes <= if (trimming) target else max) return null
        return when {
            oldestFlow == null && oldestDns == null -> null
            oldestFlow == null -> Table.DNS
            oldestDns == null -> Table.FLOWS
            oldestDns < oldestFlow -> Table.DNS
            else -> Table.FLOWS
        }
    }
}
