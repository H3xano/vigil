package dev.vigil.inspector.export

import dev.vigil.inspector.BuildConfig
import dev.vigil.inspector.R
import dev.vigil.inspector.data.ExportSettings
import dev.vigil.inspector.ui.UiText
import kotlinx.serialization.json.JsonObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocketFactory

/**
 * The collector's settings (not the records) prevent delivery, e.g. the URL
 * redirects elsewhere or does not name an Elasticsearch index. Records stay
 * queued and are retried slowly (see [FailureKind.CONFIG]). [problem] is
 * shown on the Export screen.
 */
class ExportConfigException(val problem: UiText) : IOException("export configuration problem: $problem")

/** HTTP transport: one POST per batch in the configured body format. */
internal object HttpSender {
    /**
     * A problem with [cfg]'s endpoint URL that makes every delivery fail,
     * or null. Meant for the settings screen's save-time validation too.
     */
    fun urlProblem(cfg: ExportSettings): UiText? {
        if (cfg.mode != "http") return null
        if (!(cfg.url.startsWith("https://") || cfg.url.startsWith("http://"))) return UiText.of(R.string.export_error_url_scheme)
        if (cfg.httpFormat == "elastic_bulk") return elasticBulkUrlProblem(cfg.url)
        return null
    }

    /**
     * Elasticsearch `_bulk` URLs must name the index (`/<index>/_bulk`):
     * vigil's action lines carry no `_index`, so a bare `/_bulk` makes
     * Elasticsearch refuse every request.
     */
    fun elasticBulkUrlProblem(url: String): UiText? {
        val path = runCatching { URI(url).path }.getOrNull() ?: return UiText.of(R.string.export_error_url_invalid)
        val segments = path.trimEnd('/').split('/').filter { it.isNotEmpty() }
        val ok = segments.size >= 2 && segments.last() == "_bulk" && !segments[segments.size - 2].startsWith("_")
        return if (ok) null else UiText.of(R.string.export_error_bulk_index)
    }

    fun send(cfg: ExportSettings, originals: List<JsonObject>, records: List<JsonObject>, sslSocketFactory: () -> SSLSocketFactory?): SendOutcome {
        require(cfg.url.startsWith("https://") || cfg.url.startsWith("http://")) { "no HTTP endpoint configured" }
        urlProblem(cfg)?.let { throw ExportConfigException(it) }
        val conn = URL(cfg.url).openConnection() as HttpURLConnection
        if (conn is HttpsURLConnection) sslSocketFactory()?.let { conn.sslSocketFactory = it }
        try {
            // A redirected POST becomes a GET that may well answer 200 (a
            // login page, a trailing-slash redirect): nothing would be ingested.
            conn.instanceFollowRedirects = false
            conn.requestMethod = "POST"
            conn.connectTimeout = 10_000
            conn.readTimeout = 20_000
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", WireFormats.contentType(cfg.httpFormat))
            conn.setRequestProperty("User-Agent", "vigil/${BuildConfig.VERSION_NAME}")
            if (cfg.authHeader.isNotBlank()) conn.setRequestProperty("Authorization", cfg.authHeader)
            conn.outputStream.use { it.write(WireFormats.httpBody(records, cfg.httpFormat).toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            if (code in 300..399) {
                val location = conn.getHeaderField("Location")?.takeIf { it.isNotBlank() }
                throw ExportConfigException(
                    location?.let { UiText.of(R.string.export_error_redirected, it, code) }
                        ?: UiText.of(R.string.export_error_redirect, code),
                )
            }
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
}
