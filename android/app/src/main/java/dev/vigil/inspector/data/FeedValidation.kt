package dev.vigil.inspector.data

import dev.vigil.inspector.engine.FeedSummary

/**
 * Sanity checks for a freshly downloaded feed before it replaces the last
 * good copy. They catch captive-portal pages, error pages served with HTTP
 * 200 and truncated downloads.
 */
object FeedValidation {
    /** Reject when more than this share of the non-comment lines is unparseable. */
    const val MAX_REJECTED_RATIO = 0.5

    /** Reject when the entry count falls below this share of the previous download. */
    const val MIN_SHRINK_RATIO = 0.1

    /**
     * Returns null if [summary] is acceptable, otherwise the reason.
     * [previousEntries] is the entry count of the copy currently in use
     * (null when there is none).
     */
    fun check(summary: FeedSummary, previousEntries: Int?): String? {
        val entries = summary.domains.toLong() + summary.ipRanges
        if (entries == 0L) return "feed contained no usable entries"
        val lines = entries + summary.rejectedLines
        if (summary.rejectedLines > lines * MAX_REJECTED_RATIO) {
            return "${summary.rejectedLines} of $lines lines unreadable; not a feed?"
        }
        if (previousEntries != null && previousEntries > 0 && entries < previousEntries * MIN_SHRINK_RATIO) {
            return "only $entries entries (previously $previousEntries); keeping the previous copy"
        }
        return null
    }
}
