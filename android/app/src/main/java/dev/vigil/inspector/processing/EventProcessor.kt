package dev.vigil.inspector.processing

import android.util.Log
import androidx.room.withTransaction
import dev.vigil.inspector.data.AlertEntity
import dev.vigil.inspector.data.AppInfo
import dev.vigil.inspector.data.AppResolver
import dev.vigil.inspector.data.DestinationEntity
import dev.vigil.inspector.data.DnsEntity
import dev.vigil.inspector.data.FlowEntity
import dev.vigil.inspector.data.SettingsStore
import dev.vigil.inspector.data.VigilDatabase
import dev.vigil.inspector.engine.AlertEvent
import dev.vigil.inspector.engine.DnsEvent
import dev.vigil.inspector.engine.EngineEvent
import dev.vigil.inspector.engine.EngineJson
import dev.vigil.inspector.engine.EngineStateEvent
import dev.vigil.inspector.engine.FlowEndEvent
import dev.vigil.inspector.engine.FlowEvent
import dev.vigil.inspector.engine.FlowUpdateEvent
import dev.vigil.inspector.engine.StatsEvent
import dev.vigil.inspector.export.ExportRecords
import dev.vigil.inspector.export.SiemExporter
import dev.vigil.inspector.vpn.ServiceState
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Turns engine event batches into database rows, live state, notifications
 * and SIEM records. One instance per engine session.
 *
 * The engine's event queue is bounded and may drop events, so a `flow` can
 * arrive without its `flow_end` or the reverse; both orphans are tolerated.
 * Flows that never end are exported (with the last known byte counts) when
 * they are evicted from [open] or when the session finishes.
 */
class EventProcessor(
    private val db: VigilDatabase,
    private val apps: AppResolver,
    private val settings: SettingsStore,
    private val foreground: ForegroundTracker,
    private val exporter: SiemExporter,
    private val notifier: AlertNotifier,
    private val session: Long,
    /** Upload-volume alerts; fed from each batch (see [ExfilDetector]). */
    private val exfil: ExfilDetector? = null,
    /** Called (on the processing coroutine) when the engine reports a fatal error. */
    private val onEngineError: (String) -> Unit = {},
) {
    private class OpenFlow(val flow: FlowEvent, val app: AppInfo, var tx: Long = 0, var rx: Long = 0)

    /** Open flows kept so exported flow records carry final byte counts. */
    private val open = object : LinkedHashMap<Long, OpenFlow>(256, 0.75f, false) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, OpenFlow>?): Boolean {
            if (size <= MAX_OPEN) return false
            eldest?.value?.let { exportUnfinished(it, System.currentTimeMillis(), "not tracked to completion") }
            return true
        }
    }

    /** (pkg|destination) keys known to be stored in `destinations`. */
    private val knownDestinations = object : LinkedHashMap<String, Boolean>(1024, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Boolean>?) = size > 20_000
    }

    private val newAsn = NewAsnDetector(db.appAsns()) { apps.byKey(it).label }

    suspend fun process(json: String) =process(EngineJson.parseBatch(json))

    suspend fun process(batch: List<EngineEvent>) {
        if (batch.isEmpty()) return
        foreground.refresh()
        val events = exfil?.let { batch + it.process(session, batch, settings.value.exfil, apps::resolve, foreground::isBackgroundForExfil) } ?: batch
        val flows = ArrayList<FlowEntity>()
        val dns = ArrayList<DnsEntity>()
        val alerts = ArrayList<AlertEntity>()
        val ends = ArrayList<FlowEndEvent>()
        val updates = LinkedHashMap<Long, FlowUpdateEvent>()
        var engineError: String? = null
        for (e in events) {
            when (e) {
                is FlowEvent -> {
                    val app = apps.resolve(e.uid)
                    flows += e.toEntity(app)
                    open[e.id] = OpenFlow(e, app)
                }
                is FlowEndEvent -> {
                    ends += e
                    updates.remove(e.id)
                    // No entry: the flow event was dropped (or evicted); the DB update is a no-op then.
                    open.remove(e.id)?.let { o -> exporter.offer("flow", ExportRecords.flow(o.flow, e, o.app)) }
                }
                is FlowUpdateEvent -> {
                    updates[e.id] = e
                    open[e.id]?.let { it.tx = e.tx; it.rx = e.rx }
                }
                is DnsEvent -> {
                    val app = apps.resolve(e.uid)
                    dns += EntityMapping.dns(e, app.key)
                    exporter.offer("dns", ExportRecords.dns(e, app))
                }
                is AlertEvent -> {
                    val app = apps.resolve(e.uid)
                    alerts += AlertEntity(
                        ts = e.ts, kind = e.kind, severity = e.severity, uid = e.uid, pkg = app.key, target = e.target,
                        message = e.message, detail = e.detail?.toString() ?: "{}",
                    )
                    exporter.offer("alert", ExportRecords.alert(e, app))
                }
                is StatsEvent -> ServiceState.stats.value = e
                is EngineStateEvent -> {
                    Log.i(TAG, "engine ${e.state} ${e.message}")
                    if (e.state == "error") engineError = e.message
                }
            }
        }
        db.withTransaction {
            alerts += noveltyAlerts(flows)
            val s = settings.value
            alerts += newAsn.process(flows, s.newAsnAlerts, NewAsnDetector.learningMs(s.asnLearningDays))
            if (flows.isNotEmpty()) db.flows().insert(flows)
            if (dns.isNotEmpty()) db.dns().insert(dns)
            if (alerts.isNotEmpty()) db.alerts().insert(alerts)
            for (u in updates.values) db.flows().progress(session, u.id, u.tx, u.rx)
            for (e in ends) db.flows().finish(session, e.id, e.ts, e.tx, e.rx, e.durationMs, e.error)
        }
        if (settings.value.notifyAlerts) alerts.filter { it.severity == "high" || it.severity == "medium" }.forEach(notifier::notify)
        engineError?.let(onEngineError)
    }

    /**
     * Called once after the engine was shut down and its queue drained:
     * exports and closes the flows whose `flow_end` never arrived.
     */
    suspend fun finishSession() {
        val now = System.currentTimeMillis()
        open.values.toList().forEach { exportUnfinished(it, now, "session ended") }
        open.clear()
        exfil?.endSession(session)
        db.flows().closeSession(session, now)
    }

    private fun exportUnfinished(o: OpenFlow, now: Long, reason: String) {
        val end = FlowEndEvent(id = o.flow.id, ts = now, tx = o.tx, rx = o.rx, durationMs = (now - o.flow.ts).coerceAtLeast(0), error = reason)
        exporter.offer("flow", ExportRecords.flow(o.flow, end, o.app))
    }

    private fun FlowEvent.toEntity(app: AppInfo) = EntityMapping.flow(this, session, app.key, foreground.isBackground(app.key))

    private class Seen(val first: FlowEntity, var count: Long = 0, var minTs: Long = Long.MAX_VALUE, var maxTs: Long = Long.MIN_VALUE)

    /**
     * Records (app, destination) pairs (connection count and last seen) and,
     * if enabled, raises an alert the first time an app that has been
     * observed for over a day contacts a new domain. Runs inside the batch
     * transaction.
     */
    private suspend fun noveltyAlerts(flows: List<FlowEntity>): List<AlertEntity> {
        val seen = LinkedHashMap<String, Seen>()
        for (f in flows) {
            val dest = f.domain ?: continue
            if (f.pkg == AppResolver.UNKNOWN.key) continue
            val s = seen.getOrPut("${f.pkg}|$dest") { Seen(f) }
            s.count++
            s.minTs = minOf(s.minTs, f.ts)
            s.maxTs = maxOf(s.maxTs, f.ts)
        }
        if (seen.isEmpty()) return emptyList()
        val out = ArrayList<AlertEntity>()
        val inserts = ArrayList<DestinationEntity>()
        val alertsOn = settings.value.noveltyAlerts
        val dao = db.destinations()
        for ((key, s) in seen) {
            val pkg = s.first.pkg
            val dest = s.first.domain ?: continue
            // A cached key can be stale after pruning or "clear history": touch() then changes no row.
            if (knownDestinations[key] == true && dao.touch(pkg, dest, s.maxTs, s.count) > 0) continue
            if (dao.get(pkg, dest) != null) {
                dao.touch(pkg, dest, s.maxTs, s.count)
                knownDestinations[key] = true
                continue
            }
            if (alertsOn) {
                val appFirstSeen = dao.firstSeenApp(pkg)
                if (appFirstSeen != null && s.first.ts - appFirstSeen > LEARNING_PERIOD_MS) {
                    val app = apps.byKey(pkg)
                    val detail = JsonObject(mapOf("destination" to JsonPrimitive(dest)))
                    out += AlertEntity(
                        ts = s.first.ts, kind = "new_destination", severity = "info", uid = s.first.uid, pkg = pkg, target = dest,
                        message = "${app.label} contacted a destination it has never used before: $dest", detail = detail.toString(),
                    )
                }
            }
            inserts += DestinationEntity(pkg = pkg, destination = dest, firstSeen = s.minTs, lastSeen = s.maxTs, flows = s.count)
            knownDestinations[key] = true
        }
        if (inserts.isNotEmpty()) dao.insertIfAbsent(inserts)
        return out
    }

    private companion object {
        const val TAG = "vigil.events"
        const val LEARNING_PERIOD_MS = 24L * 3600 * 1000
        const val MAX_OPEN = 20_000
    }
}
