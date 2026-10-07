package dev.vigil.inspector.ui

import dev.vigil.inspector.data.AlertMute
import dev.vigil.inspector.data.AlertMutes

/**
 * What adding one alert mute changed: the mute itself and the narrower
 * mutes it replaced (see [AlertMutes.add]). Undo reverts exactly this, so
 * mutes added or removed in the meantime are kept.
 */
data class MuteChange(val added: AlertMute, val replaced: List<AlertMute>) {
    /** [current] without [added] and with the [replaced] mutes back (unless something else covers them now). */
    fun undo(current: List<AlertMute>): List<AlertMute> =
        replaced.fold(current.filterNot { it == added }) { acc, m -> AlertMutes.add(acc, m) }

    companion object {
        /** The change adding [mute] makes to [mutes], or null when it changes nothing (already covered). */
        fun of(mutes: List<AlertMute>, mute: AlertMute): MuteChange? {
            val after = AlertMutes.add(mutes, mute)
            if (after == mutes) return null
            return MuteChange(mute, mutes.filter { it !in after })
        }
    }
}
