package dev.vigil.inspector.export

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.security.KeyChain
import android.util.Log
import dev.vigil.inspector.BuildConfig
import dev.vigil.inspector.data.ExportSettings
import dev.vigil.inspector.data.SettingsStore
import dev.vigil.inspector.data.TrackerMatch
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.Closeable
import java.io.IOException
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.time.Instant
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager

/**
 * Streams records to a SIEM. Queueing and retries live in [ExportPipeline];
 * this class owns the Android side: settings, connectivity and the syslog
 * and HTTP transports. vigil's own sockets bypass the tunnel (the app is
 * excluded from its VPN).
 */
class SiemExporter(
    private val context: Context,
    private val settings: SettingsStore,
    private val scope: CoroutineScope,
    /** Tracker label of a destination name, added to flow and DNS records as `vigil.tracker`. */
    private val trackerLabel: (String?) -> TrackerMatch? = { null },
) {
    private val config: StateFlow<ExportSettings> = settings.flow.map { it.export }
        .stateIn(scope, SharingStarted.Eagerly, settings.value.export)
    private val online = MutableStateFlow(true)
    private val pipeline = ExportPipeline(config, online, ::send, onFailure = ::closeSinkQuietly)
    val status: StateFlow<ExportStatus> = pipeline.status

    /** Guards [sink]: the export loop and [sendTest] must not interleave writes. */
    private val sinkLock = Mutex()
    private var sink: Sink? = null
    private var sinkConfig: ExportSettings? = null

    fun offer(kind: String, record: JsonObject) {
        val s = settings.value.export
        if (!s.enabled) return
        val wanted = when (s.level) {
            "all" -> true
            "alerts_dns" -> kind == "alert" || kind == "dns"
            else -> kind == "alert"
        }
        if (wanted) pipeline.offer(ExportRecords.withTracker(record, trackerLabel))
    }

    fun start() {
        watchConnectivity()
        scope.launch(Dispatchers.IO) { pipeline.run() }
    }

    /** Tracks whether this app's default network (never the tunnel) is usable. */
    private fun watchConnectivity() {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return
        online.value = cm.activeNetwork != null
        runCatching {
            cm.registerDefaultNetworkCallback(object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    online.value = true
                }

                // The default-network callback reports onLost only when no default network is left.
                override fun onLost(network: Network) {
                    online.value = false
                }
            })
        }.onFailure { Log.w(TAG, "no connectivity callback: ${it.message}") }
    }

    /** Sends one synthetic record with [cfg] (by default the saved settings). */
    suspend fun sendTest(cfg: ExportSettings = settings.value.export): Result<Unit> = withContext(Dispatchers.IO) {
        val record = JsonObject(
            mapOf(
                "@timestamp" to JsonPrimitive(Instant.now().toString()),
                "message" to JsonPrimitive("vigil export test"),
                "event" to JsonObject(mapOf("kind" to JsonPrimitive("event"), "dataset" to JsonPrimitive("vigil.test"))),
                "vigil" to JsonObject(mapOf("type" to JsonPrimitive("test"), "severity" to JsonPrimitive("info"))),
            ),
        )
        runCatching {
            val out = send(cfg, listOf(record))
            if (out.delivered == 0) throw IOException(out.detail ?: "the collector did not accept the test event")
        }.onFailure { closeSinkQuietly() }.map { }
    }

    private fun decorate(r: JsonObject): JsonObject {
        val deviceId = settings.value.deviceId
        val withId = ExportRecords.withEventId(r, ExportRecords.recordId(deviceId, r))
        return ExportRecords.withDevice(
            withId, deviceId, "${Build.MANUFACTURER} ${Build.MODEL}", Build.VERSION.RELEASE, Build.VERSION.SDK_INT, BuildConfig.VERSION_NAME,
        )
    }

    private suspend fun send(cfg: ExportSettings, batch: List<JsonObject>): SendOutcome {
        val records = batch.map(::decorate)
        if (cfg.mode == "http") return sendHttp(cfg, batch, records)
        return sinkLock.withLock {
            val current = sink?.takeIf { sinkConfig == cfg } ?: run {
                closeSink()
                openSyslog(cfg).also {
                    sink = it
                    sinkConfig = cfg
                }
            }
            val host = Build.MODEL.replace(' ', '_')
            val maxBytes = if (cfg.transport == "udp") WireFormats.UDP_MAX_BYTES else Int.MAX_VALUE
            // The header carries the event's own time, not the (possibly much later) send time.
            val messages = records.map { WireFormats.syslogFitted(it, host, WireFormats.recordSyslogTimestamp(it), maxBytes) }
            current.write(messages.filterNotNull())
            val tooLarge = messages.count { it == null }
            SendOutcome(
                delivered = messages.size - tooLarge,
                rejected = tooLarge,
                detail = if (tooLarge > 0) "$tooLarge record(s) too large for a UDP datagram, skipped" else null,
            )
        }
    }

    private fun closeSink() {
        runCatching { sink?.close() }
        sink = null
        sinkConfig = null
    }

    /** Closes the syslog connection unless a send is in progress (it will be reopened as needed). */
    private fun closeSinkQuietly() {
        if (sinkLock.tryLock()) {
            try {
                closeSink()
            } finally {
                sinkLock.unlock()
            }
        }
    }

    private fun sslContext(alias: String?): SSLContext = SSLContext.getInstance("TLS").apply {
        val km: Array<KeyManager>? = alias?.let { arrayOf(KeyChainKeyManager(context, it)) }
        init(km, null, null)
    }

    private fun openSyslog(cfg: ExportSettings): Sink {
        require(cfg.host.isNotBlank()) { "no syslog host configured" }
        require(cfg.port in 1..65535) { "invalid syslog port" }
        return when (cfg.transport) {
            "udp" -> UdpSink(cfg.host, cfg.port)
            "tcp" -> StreamSink(Socket().apply { connect(InetSocketAddress(cfg.host, cfg.port), 10_000); soTimeout = 15_000 })
            else -> {
                // Connect first (with a timeout), then layer TLS over the
                // connected socket; passing the host name enables SNI.
                val plain = Socket()
                try {
                    plain.connect(InetSocketAddress(cfg.host, cfg.port), 10_000)
                    plain.soTimeout = 15_000
                    val socket = sslContext(cfg.clientCertAlias).socketFactory.createSocket(plain, cfg.host, cfg.port, true) as SSLSocket
                    socket.sslParameters = socket.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                    socket.startHandshake()
                    // SSLSocket does not always verify the host name: check it explicitly.
                    if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(cfg.host, socket.session)) {
                        socket.close()
                        throw SSLPeerUnverifiedException("certificate does not match ${cfg.host}")
                    }
                    StreamSink(socket)
                } catch (e: Exception) {
                    runCatching { plain.close() }
                    throw e
                }
            }
        }
    }

    private fun sendHttp(cfg: ExportSettings, originals: List<JsonObject>, records: List<JsonObject>): SendOutcome {
        require(cfg.url.startsWith("https://") || cfg.url.startsWith("http://")) { "no HTTP endpoint configured" }
        val conn = URL(cfg.url).openConnection() as HttpURLConnection
        if (conn is HttpsURLConnection) conn.sslSocketFactory = sslContext(cfg.clientCertAlias).socketFactory
        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = 10_000
            conn.readTimeout = 20_000
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", WireFormats.contentType(cfg.httpFormat))
            conn.setRequestProperty("User-Agent", "vigil/${BuildConfig.VERSION_NAME}")
            if (cfg.authHeader.isNotBlank()) conn.setRequestProperty("Authorization", cfg.authHeader)
            conn.outputStream.use { it.write(WireFormats.httpBody(records, cfg.httpFormat).toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            if (code !in 200..299) {
                val detail = runCatching { conn.errorStream?.bufferedReader()?.use { it.readText() } }.getOrNull()
                throw HttpStatusException(code, detail)
            }
            if (cfg.httpFormat != "elastic_bulk") return SendOutcome(delivered = records.size)
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            // Unreadable response: retry everything; document ids make that idempotent.
            val result = ElasticBulk.parse(body, records.size)
                ?: return SendOutcome(delivered = 0, retry = originals, detail = "unreadable Elasticsearch response")
            return SendOutcome(
                delivered = result.delivered,
                rejected = result.rejected,
                retry = result.retry.map { originals[it] },
                detail = result.firstError?.let { "Elasticsearch: $it" },
            )
        } finally {
            conn.disconnect()
        }
    }

    private interface Sink : Closeable {
        fun write(messages: List<String>)
    }

    /**
     * UDP has no connection to notice a server move, so the collector's name
     * is resolved again every few minutes (keeping the last address if that
     * lookup fails), and after any send error: the pipeline then closes the
     * sink and the next one resolves afresh.
     */
    private class UdpSink(private val host: String, private val port: Int) : Sink {
        private val socket = DatagramSocket()
        private var addr: InetAddress = InetAddress.getByName(host)
        private var resolvedAt = System.nanoTime()

        override fun write(messages: List<String>) {
            if (System.nanoTime() - resolvedAt > RESOLVE_INTERVAL_NS) {
                runCatching { InetAddress.getByName(host) }.onSuccess { addr = it }
                resolvedAt = System.nanoTime()
            }
            for (m in messages) {
                val bytes = m.toByteArray(Charsets.UTF_8)
                socket.send(DatagramPacket(bytes, bytes.size, addr, port))
            }
        }
        override fun close() = socket.close()

        private companion object {
            const val RESOLVE_INTERVAL_NS = 5 * 60 * 1_000_000_000L
        }
    }

    private class StreamSink(private val socket: Socket) : Sink {
        private val out: OutputStream = socket.getOutputStream().buffered()
        override fun write(messages: List<String>) {
            for (m in messages) out.write(WireFormats.octetCounted(m))
            out.flush()
        }
        override fun close() = socket.close()
    }

    private companion object {
        const val TAG = "vigil.export"
    }
}

/** Presents a KeyChain-held client certificate for mutual TLS. */
private class KeyChainKeyManager(private val context: Context, private val alias: String) : X509ExtendedKeyManager() {
    override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?) = alias
    override fun getCertificateChain(alias: String?): Array<X509Certificate>? = KeyChain.getCertificateChain(context, this.alias)
    override fun getPrivateKey(alias: String?): PrivateKey? = KeyChain.getPrivateKey(context, this.alias)
    override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) = arrayOf(alias)
    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null
    override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null
}
