package dev.vigil.inspector.data

import android.content.Context
import dev.vigil.inspector.engine.EngineJson
import dev.vigil.inspector.processing.ExfilSettings
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
data class ExportSettings(
    val enabled: Boolean = false,
    /** "syslog" or "http". */
    val mode: String = "syslog",
    val host: String = "",
    val port: Int = 6514,
    /** Syslog transport: "udp", "tcp" or "tls". */
    val transport: String = "tls",
    val url: String = "",
    /** HTTP body format: "ndjson", "splunk_hec" or "elastic_bulk". */
    val httpFormat: String = "ndjson",
    val authHeader: String = "",
    /** Android KeyChain alias of a client certificate for mutual TLS. */
    val clientCertAlias: String? = null,
    /** "alerts", "alerts_dns" or "all". */
    val level: String = "alerts",
)

@Serializable
data class Settings(
    val sinkhole: String = "null_ip",
    val blockEncryptedDns: Boolean = false,
    /** Block connections whose TLS/QUIC JA4 fingerprint is on a feed (default: alert only). */
    val blockJa4Matches: Boolean = false,
    /** Keep private/LAN destinations out of the tunnel (casting, printers...). */
    val excludeLan: Boolean = true,
    /** "network" (resolvers of the underlying network) or "custom". */
    val upstreamMode: String = "network",
    val customUpstreams: List<String> = listOf("1.1.1.1", "9.9.9.9"),
    /** DNS over TLS / HTTPS to the upstream resolver (off: plain DNS to the resolvers above). */
    val encryptedDns: EncryptedDnsSettings = EncryptedDnsSettings(),
    val blockedPackages: Set<String> = emptySet(),
    val allowDomains: Set<String> = emptySet(),
    val denyDomains: Set<String> = emptySet(),
    val beaconEnabled: Boolean = true,
    /** "low", "normal" or "high" sensitivity. */
    val beaconSensitivity: String = "normal",
    val noveltyAlerts: Boolean = false,
    /** Alerts for unusually large uploads while an app is in the background. */
    val exfil: ExfilSettings = ExfilSettings(),
    val notifyAlerts: Boolean = true,
    val retentionDays: Int = 7,
    val export: ExportSettings = ExportSettings(),
    /** Route relayed traffic through a WireGuard peer or SOCKS5 proxy. */
    val upstream: UpstreamSettings = UpstreamSettings(),
    val deviceId: String = "",
    val onboarded: Boolean = false,
)

/**
 * Settings persisted as one JSON document, so updates are atomic and the
 * whole state is observable as a single [StateFlow].
 */
class SettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences("vigil", Context.MODE_PRIVATE)
    private val state = MutableStateFlow(load())
    val flow: StateFlow<Settings> = state.asStateFlow()
    val value: Settings get() = state.value

    private fun load(): Settings {
        val raw = prefs.getString(KEY, null)
        val s = raw?.let {
            runCatching { EngineJson.json.decodeFromString(Settings.serializer(), it) }
                .onFailure { e -> android.util.Log.e("vigil.settings", "unreadable settings, using defaults", e) }
                .getOrNull()
        } ?: Settings()
        return if (s.deviceId.isEmpty()) s.copy(deviceId = UUID.randomUUID().toString()).also { save(it) } else s
    }

    private fun save(s: Settings) {
        prefs.edit().putString(KEY, EngineJson.json.encodeToString(Settings.serializer(), s)).apply()
    }

    fun update(transform: (Settings) -> Settings) {
        state.update { old -> transform(old).also { if (it != old) save(it) } }
    }

    private companion object {
        const val KEY = "settings_v1"
    }
}
