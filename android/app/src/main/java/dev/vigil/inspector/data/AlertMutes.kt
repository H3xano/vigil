package dev.vigil.inspector.data

import kotlinx.serialization.Serializable

/**
 * An alert the user silenced, stored in [Settings.alertMutes]. Without a
 * [target] it mutes every alert of [kind] for the app [pkg] ("Mute this kind
 * for this app"); with one, only alerts about that target ("Mark as
 * expected"). Muted alerts are still recorded and exported, but hidden from
 * the default Alerts view and not notified.
 */
@Serializable
data class AlertMute(
    val kind: String,
    val pkg: String,
    val target: String? = null,
    /** When the mute was added (ms), for display. */
    val since: Long = 0,
)

object AlertMutes {
    /** Whether [mutes] silence an alert of [kind] for [pkg] about [target]. */
    fun isMuted(mutes: Collection<AlertMute>, kind: String, pkg: String, target: String): Boolean =
        mutes.any { it.kind == kind && it.pkg == pkg && (it.target == null || it.target == target) }

    fun isMuted(mutes: Collection<AlertMute>, alert: AlertEntity): Boolean = isMuted(mutes, alert.kind, alert.pkg, alert.target)

    /** [mutes] plus [mute], replacing narrower mutes it covers. */
    fun add(mutes: List<AlertMute>, mute: AlertMute): List<AlertMute> {
        val covered = mutes.any { it.kind == mute.kind && it.pkg == mute.pkg && (it.target == null || it.target == mute.target) }
        if (covered) return mutes
        val rest = if (mute.target == null) mutes.filterNot { it.kind == mute.kind && it.pkg == mute.pkg } else mutes
        return rest + mute
    }

    /** [mutes] without whatever silences this alert. */
    fun remove(mutes: List<AlertMute>, kind: String, pkg: String, target: String): List<AlertMute> =
        mutes.filterNot { it.kind == kind && it.pkg == pkg && (it.target == null || it.target == target) }
}
