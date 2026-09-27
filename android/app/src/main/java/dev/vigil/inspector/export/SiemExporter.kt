package dev.vigil.inspector.export

import android.content.Context
import android.os.Build
import android.security.KeyChain
import android.util.Log
import dev.vigil.inspector.BuildConfig
import dev.vigil.inspector.data.ExportSettings
import dev.vigil.inspector.data.SettingsStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
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
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager

data class ExportStatus(val sent: Long = 0, val dropped: Long = 0, val lastError: String? = null, val lastSuccess: Long? = null)

/**
 * Streams records to a SIEM. Records are queued in a bounded buffer (oldest
 * dropped under back-pressure), sent in batches, and retried with backoff.
 * vigil's own sockets bypass the tunnel (the app is excluded from its VPN).
 */
class SiemExporter(private val context: Context, private val settings: SettingsStore, private val scope: CoroutineScope) {
    private val queue = Channel<JsonObject>(10_000, BufferOverflow.DROP_OLDEST)
    private val _status = MutableStateFlow(ExportStatus())
    val status: StateFlow<ExportStatus> = _status
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
        if (wanted && !queue.trySend(record).isSuccess) {
            _status.value = _status.value.copy(dropped = _status.value.dropped + 1)
        }
    }

    fun start() {
        scope.launch(Dispatchers.IO) {
            var backoff = 1_000L
            while (isActive) {
                val first = queue.receive()
                val batch = mutableListOf(first)
                while (batch.size < 200) batch += queue.tryReceive().getOrNull() ?: break
                var attempts = 0
                while (isActive) {
                    val cfg = settings.value.export
                    if (!cfg.enabled) break
                    val result = runCatching { send(cfg, batch) }
                    if (result.isSuccess) {
                        _status.value = _status.value.copy(sent = _status.value.sent + batch.size, lastError = null, lastSuccess = System.currentTimeMillis())
                        backoff = 1_000L
                        break
                    }
                    closeSink()
                    val msg = result.exceptionOrNull()?.let { it.message ?: it.javaClass.simpleName }
                    Log.w(TAG, "export failed: $msg")
                    _status.value = _status.value.copy(lastError = msg)
                    if (++attempts >= 5) {
                        _status.value = _status.value.copy(dropped = _status.value.dropped + batch.size)
                        break
                    }
                    delay(backoff)
                    backoff = (backoff * 2).coerceAtMost(60_000L)
                }
            }
        }
    }

    /** Sends one synthetic record with the current settings. */
    suspend fun sendTest(): Result<Unit> = withContext(Dispatchers.IO) {
        val record = JsonObject(
            mapOf(
                "@timestamp" to kotlinx.serialization.json.JsonPrimitive(Instant.now().toString()),
                "message" to kotlinx.serialization.json.JsonPrimitive("vigil export test"),
                "vigil" to JsonObject(mapOf("type" to kotlinx.serialization.json.JsonPrimitive("test"), "severity" to kotlinx.serialization.json.JsonPrimitive("info"))),
            ),
        )
        runCatching { send(settings.value.export, listOf(record)) }.onFailure { closeSink() }
    }

    private fun decorate(r: JsonObject) =
        ExportRecords.withDevice(r, settings.value.deviceId, "${Build.MANUFACTURER} ${Build.MODEL}", Build.VERSION.SDK_INT, BuildConfig.VERSION_NAME)

    private fun send(cfg: ExportSettings, batch: List<JsonObject>) {
        val records = batch.map(::decorate)
        if (cfg.mode == "http") {
            sendHttp(cfg, records)
            return
        }
        if (sink == null || sinkConfig != cfg) {
            closeSink()
            sink = openSyslog(cfg)
            sinkConfig = cfg
        }
        val host = Build.MODEL.replace(' ', '_')
        sink!!.write(records.map { WireFormats.syslog(it, host, Instant.now().toString()) })
    }

    private fun closeSink() {
        runCatching { sink?.close() }
        sink = null
        sinkConfig = null
    }

    private fun sslContext(alias: String?): SSLContext = SSLContext.getInstance("TLS").apply {
        val km: Array<KeyManager>? = alias?.let { arrayOf(KeyChainKeyManager(context, it)) }
        init(km, null, null)
    }

    private fun openSyslog(cfg: ExportSettings): Sink {
        require(cfg.host.isNotBlank()) { "no syslog host configured" }
        return when (cfg.transport) {
            "udp" -> UdpSink(InetAddress.getByName(cfg.host), cfg.port)
            "tcp" -> StreamSink(Socket().apply { connect(InetSocketAddress(cfg.host, cfg.port), 10_000); soTimeout = 15_000 })
            else -> {
                val socket = sslContext(cfg.clientCertAlias).socketFactory.createSocket() as SSLSocket
                socket.connect(InetSocketAddress(cfg.host, cfg.port), 10_000)
                socket.soTimeout = 15_000
                // SSLSocket does not verify the hostname unless asked to.
                socket.sslParameters = socket.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                socket.startHandshake()
                StreamSink(socket)
            }
        }
    }

    private fun sendHttp(cfg: ExportSettings, records: List<JsonObject>) {
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
            if (code !in 200..299) throw IOException("HTTP $code")
            if (cfg.httpFormat == "elastic_bulk") {
                val body = conn.inputStream.bufferedReader().use { it.readText() }
                if (body.contains("\"errors\":true")) throw IOException("Elasticsearch rejected some documents")
            }
        } finally {
            conn.disconnect()
        }
    }

    private interface Sink : Closeable {
        fun write(messages: List<String>)
    }

    private class UdpSink(private val addr: InetAddress, private val port: Int) : Sink {
        private val socket = DatagramSocket()
        override fun write(messages: List<String>) {
            for (m in messages) {
                val bytes = m.toByteArray(Charsets.UTF_8)
                socket.send(DatagramPacket(bytes, minOf(bytes.size, 65_000), addr, port))
            }
        }
        override fun close() = socket.close()
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
