package dev.vigil.inspector.processing

import dev.vigil.inspector.data.AppInfo
import dev.vigil.inspector.data.AppResolver
import dev.vigil.inspector.engine.AlertEvent
import dev.vigil.inspector.engine.EngineEvent
import dev.vigil.inspector.engine.EngineJson
import dev.vigil.inspector.engine.FlowEndEvent
import dev.vigil.inspector.engine.FlowEvent
import dev.vigil.inspector.engine.FlowUpdateEvent
import dev.vigil.inspector.ui.formatBytes
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.File

/** User settings of the upload-volume ("exfiltration") alert. */
@Serializable
data class ExfilSettings(
    val enabled: Boolean = true,
    /**
     * Absolute floor: an app must upload at least this much in one hour (or
     * half of it within five minutes) before anything is considered.
     */
    val floorMbPerHour: Int = 50,
    /** How far above the app's own usual busiest hour (7-day p95) the upload must be. */
    val baselineFactor: Double = 3.0,
)

/**
 * Sums of values in fixed time slots (a ring of `slots` × `slotMs`). Slots
 * carry their slot number, so stale slots are ignored without a sweep and
 * events older than the ring are dropped. Not thread-safe.
 */
class SlotRing(val slots: Int, val slotMs: Long) {
    private val ids = LongArray(slots) { Long.MIN_VALUE }
    private val values = LongArray(slots)

    fun add(ts: Long, v: Long) {
        if (v <= 0 || ts < 0) return
        val slot = ts / slotMs
        val i = (slot % slots).toInt()
        if (ids[i] != slot) {
            if (ids[i] > slot) return // older than the ring
            ids[i] = slot
            values[i] = 0
        }
        values[i] += v
    }

    /** Sum of the slots overlapping the last [windowMs] up to [now] (current slot included). */
    fun sum(now: Long, windowMs: Long): Long {
        val cur = now / slotMs
        val n = ((windowMs + slotMs - 1) / slotMs).coerceIn(1, slots.toLong())
        var total = 0L
        for (i in 0 until slots) if (ids[i] in (cur - n + 1)..cur) total += values[i]
        return total
    }

    /** Non-zero values of the completed slots in (now − slots, now), i.e. excluding the current slot. */
    fun completed(now: Long): List<Long> {
        val cur = now / slotMs
        return (0 until slots).filter { ids[it] in (cur - slots + 1) until cur && values[it] > 0 }.map { values[it] }
    }

    /** (slot number, value) pairs, for persistence. */
    fun entries(): List<List<Long>> = (0 until slots).filter { ids[it] != Long.MIN_VALUE && values[it] > 0 }
        .map { listOf(ids[it], values[it]) }

    fun restore(entries: List<List<Long>>) {
        for (e in entries) if (e.size == 2) add(e[0] * slotMs, e[1])
    }

    fun lastSlot(): Long = ids.max()
}

/**
 * Pure decision rules of the upload-volume alert, kept apart from the
 * bookkeeping so they can be unit-tested.
 */
object ExfilRules {
    const val MB = 1024L * 1024
    const val HOUR_MS = 3_600_000L
    const val SHORT_WINDOW_MS = 5 * 60_000L

    /** Upload must be at least this many times the download for the same destination. */
    const val MIN_TX_RX_RATIO = 4.0

    /** Active hours needed before the app's baseline is trusted (otherwise: floor only). */
    const val MIN_BASELINE_HOURS = 3

    /** Hours of history kept per app (7 days). */
    const val BASELINE_HOURS = 168

    /** One alert per app at most this often. */
    const val REALERT_MS = 6 * HOUR_MS

    /**
     * Apps whose job is to upload the user's files. Package names cannot be
     * taken over by other apps (signatures), so this cannot be abused by
     * malware; other backup tools are covered by their own baseline.
     */
    val TRUSTED_UPLOADERS = setOf(
        "com.google.android.apps.photos",
        "com.google.android.apps.docs",
        "com.dropbox.android",
        "com.microsoft.skydrive",
        "com.nextcloud.client",
        "com.owncloud.android",
        "com.synology.dsphoto",
        "com.synology.projectkailash",
        "com.amazon.clouddrive.photos",
        "com.mega.android",
        "com.github.catfriend1.syncthingandroid",
        "com.nutomic.syncthingandroid",
    )

    data class Window(val label: String, val lengthMs: Long, val floorBytes: Long)

    /** The two windows: one hour at the full floor, five minutes at half of it. */
    fun windows(s: ExfilSettings): List<Window> {
        val floor = s.floorMbPerHour.coerceAtLeast(1) * MB
        return listOf(Window("5 min", SHORT_WINDOW_MS, floor / 2), Window("1 h", HOUR_MS, floor))
    }

    /** 95th percentile (nearest rank) of the app's active hours, or null with too little history. */
    fun p95(hours: List<Long>): Long? {
        if (hours.size < MIN_BASELINE_HOURS) return null
        val sorted = hours.sorted()
        val rank = kotlin.math.ceil(0.95 * sorted.size).toInt().coerceIn(1, sorted.size)
        return sorted[rank - 1]
    }

    /**
     * Whether [uploaded] bytes (sent while the app was not in the
     * foreground) within a window are unusual: at least [floor], at least
     * [factor] times the app's baseline (when known), and dominated by
     * upload towards the top destination ([destTx] ≥ 4 × [destRx]).
     */
    fun isUnusual(uploaded: Long, floor: Long, baseline: Long?, factor: Double, destTx: Long, destRx: Long): Boolean {
        if (uploaded < floor) return false
        if (baseline != null && uploaded < factor * baseline) return false
        return destTx > 0 && destTx >= MIN_TX_RX_RATIO * destRx
    }
}

/**
 * Upload-volume ("exfiltration") alerts, computed in the app from the byte
 * counters of `flow_update` / `flow_end` events.
 *
 * Why here and not in the engine: whether an upload is unusual depends on
 * whether the app is in the foreground (only the app knows, via usage
 * access) and on the app's own history over days, which outlives engine
 * sessions. The engine's running totals, delivered every couple of seconds,
 * are precise enough for windows of minutes to an hour.
 *
 * For every app it keeps the bytes uploaded while not in the foreground in
 * one-minute slots (last hour), per (app, destination) upload and download
 * in five-minute slots, and per app the total upload per hour over seven
 * days. The hourly history is the baseline and is persisted to a small JSON
 * file (not Room, whose schema is being changed elsewhere; it can move there
 * later). Every structure is bounded.
 *
 * Thread-safe: consecutive sessions may overlap while the old one drains.
 */
class ExfilDetector(private val store: File?) {
    private data class FlowKey(val session: Long, val id: Long)
    private class FlowState(val uid: Int?, val pkg: String, val dest: String, var tx: Long = 0, var rx: Long = 0)

    private class AppState {
        val background = SlotRing(60, 60_000)
        /** Uploads while the foreground state was unknown (no usage access). */
        val unknown = SlotRing(60, 60_000)
        var lastAlert = Long.MIN_VALUE
    }

    private class DestState {
        val tx = SlotRing(12, 5 * 60_000)
        val rx = SlotRing(12, 5 * 60_000)
    }

    private val flows = lru<FlowKey, FlowState>(MAX_FLOWS)
    private val apps = lru<String, AppState>(MAX_APPS)
    private val dests = lru<Pair<String, String>, DestState>(MAX_DESTS)
    private val hourly = lru<String, SlotRing>(MAX_BASELINE_APPS)
    private var loaded = false
    private var dirty = false
    private var lastSave = 0L

    /**
     * Folds a batch of engine events into the windows and returns the alerts
     * to raise (engine-shaped, so they are stored, exported and notified
     * like engine alerts).
     */
    @Synchronized
    fun process(
        session: Long,
        batch: List<EngineEvent>,
        settings: ExfilSettings,
        resolve: (Int?) -> AppInfo,
        isBackground: (String) -> Boolean?,
        now: Long = System.currentTimeMillis(),
    ): List<AlertEvent> {
        load()
        val touched = LinkedHashMap<String, Int?>()
        for (e in batch) {
            when (e) {
                is FlowEvent -> {
                    val app = resolve(e.uid)
                    if (app.key == AppResolver.UNKNOWN.key || e.verdict == "block") continue
                    flows[FlowKey(session, e.id)] = FlowState(e.uid, app.key, e.domain ?: e.dstIp)
                }
                is FlowUpdateEvent -> account(session, e.id, e.ts, e.tx, e.rx, false, isBackground, touched)
                is FlowEndEvent -> account(session, e.id, e.ts, e.tx, e.rx, true, isBackground, touched)
                else -> {}
            }
        }
        val out = ArrayList<AlertEvent>()
        if (settings.enabled) {
            for ((pkg, uid) in touched) evaluate(pkg, uid, settings, resolve, now)?.let(out::add)
        }
        if (dirty && now - lastSave >= SAVE_EVERY_MS) save(now)
        return out
    }

    /** Forgets the session's flows and saves the baseline. */
    @Synchronized
    fun endSession(session: Long, now: Long = System.currentTimeMillis()) {
        flows.keys.removeAll { it.session == session }
        if (dirty) save(now)
    }

    /** The app's baseline: 95th percentile of its hourly uploads over the last 7 days (null: not enough history). */
    @Synchronized
    fun baseline(pkg: String, now: Long = System.currentTimeMillis()): Long? {
        load()
        return hourly[pkg]?.let { ExfilRules.p95(it.completed(now)) }
    }

    private fun account(
        session: Long, id: Long, ts: Long, tx: Long, rx: Long, end: Boolean,
        isBackground: (String) -> Boolean?, touched: MutableMap<String, Int?>,
    ) {
        val key = FlowKey(session, id)
        val f = (if (end) flows.remove(key) else flows[key]) ?: return
        val dTx = (tx - f.tx).coerceAtLeast(0)
        val dRx = (rx - f.rx).coerceAtLeast(0)
        f.tx = maxOf(f.tx, tx)
        f.rx = maxOf(f.rx, rx)
        if (dTx == 0L && dRx == 0L) return
        val d = dests.getOrPut(f.pkg to f.dest) { DestState() }
        d.tx.add(ts, dTx)
        d.rx.add(ts, dRx)
        if (dTx == 0L) return
        hourly.getOrPut(f.pkg) { SlotRing(ExfilRules.BASELINE_HOURS, ExfilRules.HOUR_MS) }.add(ts, dTx)
        dirty = true
        val a = apps.getOrPut(f.pkg) { AppState() }
        when (isBackground(f.pkg)) {
            false -> return // user-driven: foreground uploads never count
            true -> a.background.add(ts, dTx)
            null -> a.unknown.add(ts, dTx)
        }
        touched.putIfAbsent(f.pkg, f.uid)
    }

    private fun evaluate(pkg: String, uid: Int?, s: ExfilSettings, resolve: (Int?) -> AppInfo, now: Long): AlertEvent? {
        if (pkg in ExfilRules.TRUSTED_UPLOADERS) return null
        val a = apps[pkg] ?: return null
        if (a.lastAlert != Long.MIN_VALUE && now - a.lastAlert < ExfilRules.REALERT_MS) return null
        // The baseline excludes the current hour, so a running upload does not raise its own bar.
        val base = hourly[pkg]?.let { ExfilRules.p95(it.completed(now)) }
        for (w in ExfilRules.windows(s)) {
            val bg = a.background.sum(now, w.lengthMs)
            val unk = a.unknown.sum(now, w.lengthMs)
            val uploaded = bg + unk
            if (uploaded < w.floorBytes) continue
            val (dest, dTx, dRx) = topDestination(pkg, now, w.lengthMs) ?: continue
            if (!ExfilRules.isUnusual(uploaded, w.floorBytes, base, s.baselineFactor, dTx, dRx)) continue
            a.lastAlert = now
            return alert(now, uid, pkg, resolve(uid).label, w, uploaded, bg >= unk, base, s, dest, dTx, dRx)
        }
        return null
    }

    private fun topDestination(pkg: String, now: Long, windowMs: Long): Triple<String, Long, Long>? {
        var best: Triple<String, Long, Long>? = null
        for ((k, d) in dests) {
            if (k.first != pkg) continue
            val tx = d.tx.sum(now, windowMs)
            if (tx > (best?.second ?: 0L)) best = Triple(k.second, tx, d.rx.sum(now, windowMs))
        }
        return best
    }

    private fun alert(
        now: Long, uid: Int?, pkg: String, label: String, w: ExfilRules.Window, uploaded: Long, knownBackground: Boolean,
        base: Long?, s: ExfilSettings, dest: String, dTx: Long, dRx: Long,
    ): AlertEvent {
        val period = if (w.lengthMs == ExfilRules.HOUR_MS) "the last hour" else "the last 5 minutes"
        val state = if (knownBackground) "while in the background" else "(vigil cannot tell whether it was on screen: usage access is not granted)"
        val usual = base?.let { " Its usual busiest hour is ${formatBytes(it)}." } ?: " There is no upload history for it yet."
        val message = "$label uploaded ${formatBytes(uploaded)} in $period $state, mostly to $dest " +
            "(${formatBytes(dTx)} sent, ${formatBytes(dRx)} received).$usual"
        val detail = JsonObject(
            mapOf(
                "window" to JsonPrimitive(w.label),
                "window_s" to JsonPrimitive(w.lengthMs / 1000),
                "uploaded_bytes" to JsonPrimitive(uploaded),
                "baseline_bytes_per_hour" to (base?.let(::JsonPrimitive) ?: JsonNull),
                "floor_bytes" to JsonPrimitive(w.floorBytes),
                "factor" to JsonPrimitive(s.baselineFactor),
                "destination" to JsonPrimitive(dest),
                "dest_tx_bytes" to JsonPrimitive(dTx),
                "dest_rx_bytes" to JsonPrimitive(dRx),
                "background" to JsonPrimitive(if (knownBackground) "yes" else "unknown"),
                "package" to JsonPrimitive(pkg),
            ),
        )
        return AlertEvent(
            ts = now, kind = KIND, severity = if (knownBackground) "medium" else "low", uid = uid, target = dest,
            message = message, detail = detail,
        )
    }

    @Serializable
    private class Stored(val version: Int = 1, val apps: Map<String, List<List<Long>>> = emptyMap())

    private fun load() {
        if (loaded) return
        loaded = true
        val f = store ?: return
        val text = runCatching { f.takeIf { it.exists() }?.readText() }.getOrNull() ?: return
        val s = runCatching { EngineJson.json.decodeFromString(Stored.serializer(), text) }.getOrNull() ?: return
        for ((pkg, entries) in s.apps) {
            hourly[pkg] = SlotRing(ExfilRules.BASELINE_HOURS, ExfilRules.HOUR_MS).apply { restore(entries) }
        }
    }

    private fun save(now: Long) {
        lastSave = now
        dirty = false
        val f = store ?: return
        val horizon = now / ExfilRules.HOUR_MS - ExfilRules.BASELINE_HOURS
        val data = Stored(apps = hourly.filterValues { it.lastSlot() > horizon }.mapValues { it.value.entries() })
        runCatching {
            val tmp = File(f.parentFile, f.name + ".tmp")
            tmp.writeText(EngineJson.json.encodeToString(Stored.serializer(), data))
            if (!tmp.renameTo(f)) error("rename failed")
        }.onFailure { System.err.println("vigil: saving upload baseline failed: $it") }
    }

    companion object {
        const val KIND = "exfil_volume"
        private const val MAX_FLOWS = 20_000
        private const val MAX_APPS = 1_000
        private const val MAX_DESTS = 4_096
        private const val MAX_BASELINE_APPS = 500
        private const val SAVE_EVERY_MS = 15 * 60_000L

        private fun <K, V> lru(max: Int) = object : LinkedHashMap<K, V>(64, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<K, V>?) = size > max
        }
    }
}
