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
     * Spyware packs are stricter: they are small, curated and only grow, and
     * a copy stripped of one stalkerware app's indicators is exactly what an
     * attacker would serve. Reject a pack that keeps fewer than this share
     * of the previous copy's indicators.
     */
    const val SPYWARE_MIN_SHRINK_RATIO = 0.5

    /**
     * Returns null if [summary] is acceptable, otherwise the reason.
     * [previousEntries] is the entry count of the copy currently in use
     * (null when there is none).
     */
    fun check(summary: FeedSummary, previousEntries: Int?, kind: String = FeedKinds.LIST): String? {
        // The summary comes from a parse that recognises every entry type; a
        // JA4 feed's domain/IP lines are rejected by the engine's `ja4` category.
        val ja4Only = kind == FeedKinds.JA4
        val entries = if (ja4Only) summary.ja4.toLong() else summary.domains.toLong() + summary.ipRanges + summary.ja4
        val rejected = summary.rejectedLines.toLong() + if (ja4Only) summary.domains.toLong() + summary.ipRanges else 0L
        if (entries == 0L) return if (ja4Only) "feed contained no JA4 fingerprints" else "feed contained no usable entries"
        val lines = entries + rejected
        if (rejected > lines * MAX_REJECTED_RATIO) {
            return "$rejected of $lines lines unreadable; not a feed?"
        }
        if (previousEntries != null && previousEntries > 0 && entries < previousEntries * MIN_SHRINK_RATIO) {
            return "only $entries entries (previously $previousEntries); keeping the previous copy"
        }
        return null
    }

    /**
     * A full TAXII re-sync replaces the indicator state; reject it when it
     * collapses a sizeable collection (lost read permission, a server
     * returning an empty page on error). Incremental polls pass null for
     * [previousEntries]: they only add, replace or revoke.
     */
    fun checkTaxiiResync(entries: Int, previousEntries: Int?): String? {
        if (previousEntries == null || previousEntries <= 100) return null
        if (entries < previousEntries * MIN_SHRINK_RATIO) {
            return "full sync returned only $entries indicators (previously $previousEntries); keeping the previous copy"
        }
        return null
    }

    /**
     * Returns null if a spyware pack with [total] indicators may replace the
     * copy in use ([previousTotal], null when there is none), otherwise the reason.
     */
    fun checkSpywarePack(total: Int, previousTotal: Int?): String? {
        if (total == 0) return "the pack contained no indicators vigil can use"
        if (previousTotal != null && previousTotal > 0 && total < previousTotal * SPYWARE_MIN_SHRINK_RATIO) {
            return "only $total indicators (previously $previousTotal); keeping the previous copy"
        }
        return null
    }
}
