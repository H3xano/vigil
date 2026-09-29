package dev.vigil.inspector.processing

import dev.vigil.inspector.data.AlertEntity
import dev.vigil.inspector.engine.AlertEvent
import kotlinx.serialization.json.Json

/** Alerts raised by the app itself (`new_destination`, `new_asn`) rather than by the engine. */
object AppAlerts {
    /** The engine-event form of a stored app-side alert, so it exports with the same record shape. */
    fun toEvent(a: AlertEntity): AlertEvent = AlertEvent(
        ts = a.ts, kind = a.kind, severity = a.severity, uid = a.uid, target = a.target, message = a.message,
        detail = runCatching { Json.parseToJsonElement(a.detail) }.getOrNull(),
    )
}
