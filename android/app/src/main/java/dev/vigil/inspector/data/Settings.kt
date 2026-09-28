package dev.vigil.inspector.data

import android.content.Context
import androidx.core.content.edit
import dev.vigil.inspector.engine.EngineJson
import dev.vigil.inspector.processing.ExfilSettings
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
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
    /**
     * Two engine worker threads instead of one: higher peak throughput (for
     * links above roughly 500 Mbit/s) at the cost of more CPU and battery.
     * Read when inspection starts; changing it restarts the session.
     */
    val maxThroughput: Boolean = false,
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
    /** Alert when an app contacts an autonomous system (network) it never used before (needs the ASN database). */
    val newAsnAlerts: Boolean = false,
    /** Days after vigil first records an app's networks before new-network alerts start. */
    val asnLearningDays: Int = 7,
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
    private val problem = MutableStateFlow<String?>(null)
    private val state = MutableStateFlow(load())
    val flow: StateFlow<Settings> = state.asStateFlow()
    val value: Settings get() = state.value

    /**
     * Set when the stored settings could not be read and they configured a
     * WireGuard or SOCKS5 upstream that could not be recovered. The VPN
     * service refuses to start while this is set (fail closed: traffic must
     * not silently leave directly). Cleared when the upstream settings are
     * changed, or by [acknowledgeLoadProblem]. The unreadable document is
     * kept under a backup key.
     */
    val loadProblem: StateFlow<String?> = problem.asStateFlow()

    private fun load(): Settings {
        val raw = prefs.getString(KEY, null)
        val loaded = SettingsCodec.decode(raw)
        if (loaded.unreadable && raw != null) {
            // Never lose the unreadable document (it may hold WireGuard keys);
            // the exception text may contain the JSON, so it is not logged.
            prefs.edit { putString(KEY_UNREADABLE_BACKUP, raw) }
            android.util.Log.e(TAG, "unreadable settings (${loaded.errorType}); kept a backup, using defaults")
        }
        problem.value = loaded.problem
        val s = loaded.settings
        if (s.deviceId.isNotEmpty()) return s
        val withId = s.copy(deviceId = UUID.randomUUID().toString())
        if (!loaded.unreadable) save(withId)
        return withId
    }

    private fun save(s: Settings) {
        prefs.edit { putString(KEY, SettingsCodec.encode(s)) }
    }

    fun update(transform: (Settings) -> Settings) {
        state.update { old ->
            transform(old).also {
                if (it != old) {
                    save(it)
                    if (it.upstream != old.upstream) problem.value = null
                }
            }
        }
    }

    /** The user accepts the recovered settings as they are (see [loadProblem]). */
    fun acknowledgeLoadProblem() {
        problem.value = null
    }

    private companion object {
        const val TAG = "vigil.settings"
        const val KEY = "settings_v1"
        const val KEY_UNREADABLE_BACKUP = "settings_v1_unreadable_backup"
    }
}

/** Decoding of the stored settings document, separate from SharedPreferences so it is testable. */
object SettingsCodec {
    /**
     * [unreadable]: the document existed but did not decode; [problem]: why
     * the VPN must not start (see [SettingsStore.loadProblem]); [errorType]:
     * the exception class, safe to log.
     */
    class Loaded(val settings: Settings, val unreadable: Boolean = false, val problem: String? = null, val errorType: String? = null)

    fun encode(s: Settings): String = EngineJson.json.encodeToString(Settings.serializer(), s)

    fun decode(raw: String?): Loaded {
        if (raw == null) return Loaded(Settings())
        val error = try {
            return Loaded(EngineJson.json.decodeFromString(Settings.serializer(), raw))
        } catch (e: kotlinx.serialization.SerializationException) {
            e
        } catch (e: IllegalArgumentException) {
            e
        }
        val obj = runCatching { EngineJson.json.parseToJsonElement(raw) as? JsonObject }.getOrNull()
        // Recover what can be recovered: the upstream section (it holds the
        // WireGuard keys) and the device id (SIEM records are keyed by it).
        val upstream = (obj?.get("upstream") as? JsonObject)?.let {
            runCatching { EngineJson.json.decodeFromJsonElement(UpstreamSettings.serializer(), it) }.getOrNull()
        }
        val deviceId = (obj?.get("deviceId") as? JsonPrimitive)?.takeIf { it.isString }?.content.orEmpty()
        val mode = upstream?.mode ?: storedUpstreamMode(obj, raw)
        val lost = upstream == null && mode != UpstreamSettings.MODE_DIRECT
        val settings = Settings(
            // Keep the configured mode visible (the upstream screen then asks
            // for the missing details) rather than silently showing "direct".
            upstream = upstream ?: UpstreamSettings(mode = if (mode in RECOVERABLE_MODES) mode else UpstreamSettings.MODE_DIRECT),
            deviceId = deviceId,
            onboarded = true,
        )
        val problem = if (lost) {
            "vigil's saved settings could not be read, and they route traffic through a " +
                (if (mode == UpstreamSettings.MODE_WIREGUARD) "WireGuard tunnel" else if (mode == UpstreamSettings.MODE_SOCKS5) "SOCKS5 proxy" else "tunnel or proxy") +
                ". Inspection will not start, so traffic does not go out directly. Set up the upstream again in Settings."
        } else {
            null
        }
        return Loaded(settings, unreadable = true, problem = problem, errorType = error.javaClass.simpleName)
    }

    /**
     * The upstream mode an unreadable document mentions: from its JSON
     * structure when it still parses, else by a textual search (only the
     * upstream section uses the values "wireguard" and "socks5").
     */
    private fun storedUpstreamMode(obj: JsonObject?, raw: String): String {
        if (obj != null) {
            val up = obj["upstream"] as? JsonObject ?: return UpstreamSettings.MODE_DIRECT
            return (up["mode"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: UpstreamSettings.MODE_DIRECT
        }
        return MODE_PATTERN.find(raw)?.groupValues?.get(1) ?: UpstreamSettings.MODE_DIRECT
    }

    private val RECOVERABLE_MODES = setOf(UpstreamSettings.MODE_WIREGUARD, UpstreamSettings.MODE_SOCKS5)
    private val MODE_PATTERN = Regex("\"mode\"\\s*:\\s*\"(wireguard|socks5)\"")
}
