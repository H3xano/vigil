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

/**
 * Turns engine event batches into database rows, live state, notifications
 * and SIEM records. One instance per engine session.
 */
class EventProcessor(
    private val db: VigilDatabase,
    private val apps: AppResolver,
    private val settings: SettingsStore,
    private val foreground: ForegroundTracker,
    private val exporter: SiemExporter,
    private val notifier: AlertNotifier,
    private val session: Long,
) {
    /** Open flows kept so exported flow records carry final byte counts. */
    private val open = object : LinkedHashMap<Long, Pair<FlowEvent, AppInfo>>(256, 0.75f, false) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, Pair<FlowEvent, AppInfo>>?) = size > 20_000
    }
    private val knownDestinations = object : LinkedHashMap<String, Boolean>(1024, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Boolean>?) = size > 20_000
    }

    suspend fun process(json: String) = process(EngineJson.parseBatch(json))

    suspend fun process(batch: List<EngineEvent>) {
        if (batch.isEmpty()) return
        foreground.refresh()
        val flows = ArrayList<FlowEntity>()
        val dns = ArrayList<DnsEntity>()
        val alerts = ArrayList<AlertEntity>()
        val ends = ArrayList<FlowEndEvent>()
        val updates = LinkedHashMap<Long, FlowUpdateEvent>()
        for (e in batch) {
            when (e) {
                is FlowEvent -> {
                    val app = apps.resolve(e.uid)
                    flows += e.toEntity(app)
                    open[e.id] = e to app
                }
                is FlowEndEvent -> {
                    ends += e
                    updates.remove(e.id)
                    open.remove(e.id)?.let { (f, app) -> exporter.offer("flow", ExportRecords.flow(f, e, app)) }
                }
                is FlowUpdateEvent -> updates[e.id] = e
                is DnsEvent -> {
                    val app = apps.resolve(e.uid)
                    dns += DnsEntity(
                        ts = e.ts, uid = e.uid, pkg = app.key, qname = e.qname, qtype = e.qtype, rcode = e.rcode,
                        answers = e.answers.joinToString(", "), verdict = e.verdict, reason = e.reason,
                        latencyMs = e.latencyMs, server = e.server, transport = e.transport,
                    )
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
                    if (e.state == "error") ServiceState.reportEngineError(e.message)
                }
            }
        }
        alerts += noveltyAlerts(flows)
        db.withTransaction {
            if (flows.isNotEmpty()) db.flows().insert(flows)
            if (dns.isNotEmpty()) db.dns().insert(dns)
            if (alerts.isNotEmpty()) db.alerts().insert(alerts)
            for (u in updates.values) db.flows().progress(session, u.id, u.tx, u.rx)
            for (e in ends) db.flows().finish(session, e.id, e.ts, e.tx, e.rx, e.durationMs, e.error)
        }
        if (settings.value.notifyAlerts) alerts.filter { it.severity == "high" || it.severity == "medium" }.forEach(notifier::notify)
    }

    private fun FlowEvent.toEntity(app: AppInfo) = FlowEntity(
        session = session, engineId = id, ts = ts, proto = proto, uid = uid, pkg = app.key, src = src, dstIp = dstIp,
        dstPort = dstPort, domain = domain, domainSource = domainSource, appProto = appProto, alpn = alpn,
        tlsVersion = tlsVersion, ja4 = ja4, ech = ech, httpMethod = httpMethod, verdict = verdict ?: "allow",
        reason = reason, tags = tags.joinToString(","), background = foreground.isBackground(app.key),
    )

    /**
     * Records (app, destination) pairs and, if enabled, raises an alert the
     * first time an app that has been observed for over a day contacts a
     * new domain.
     */
    private suspend fun noveltyAlerts(flows: List<FlowEntity>): List<AlertEntity> {
        val out = ArrayList<AlertEntity>()
        val upserts = LinkedHashMap<String, DestinationEntity>()
        val alertsOn = settings.value.noveltyAlerts
        for (f in flows) {
            val dest = f.domain ?: continue
            if (f.pkg == AppResolver.UNKNOWN.key) continue
            val key = "${f.pkg}|$dest"
            if (knownDestinations[key] == true) continue
            val existing = db.destinations().get(f.pkg, dest)
            if (existing == null && alertsOn) {
                val appFirstSeen = db.destinations().firstSeenApp(f.pkg)
                if (appFirstSeen != null && f.ts - appFirstSeen > LEARNING_PERIOD_MS) {
                    val app = apps.byKey(f.pkg)
                    val detail = JsonObject(mapOf("destination" to kotlinx.serialization.json.JsonPrimitive(dest)))
                    out += AlertEntity(
                        ts = f.ts, kind = "new_destination", severity = "info", uid = f.uid, pkg = f.pkg, target = dest,
                        message = "${app.label} contacted a destination it has never used before: $dest", detail = detail.toString(),
                    )
                }
            }
            upserts[key] = DestinationEntity(
                pkg = f.pkg, destination = dest, firstSeen = existing?.firstSeen ?: f.ts, lastSeen = f.ts,
                flows = (existing?.flows ?: 0) + 1,
            )
            knownDestinations[key] = true
        }
        if (upserts.isNotEmpty()) db.destinations().upsert(upserts.values.toList())
        return out
    }

    private companion object {
        const val TAG = "vigil.events"
        const val LEARNING_PERIOD_MS = 24L * 3600 * 1000
    }
}
