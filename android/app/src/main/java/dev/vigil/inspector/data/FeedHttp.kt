package dev.vigil.inspector.data

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.MalformedURLException
import java.net.URL

/**
 * A feed or TAXII credential: the header ([name], e.g. `Authorization` or
 * `X-Api-Key`) and its [value], bound to the URL the user entered
 * ([origin]). It is only ever sent to that host (see [FeedHttp.mayCarryCredential]).
 */
class FeedCredential(val name: String, val value: String, origin: String) {
    val origin: URL = URL(origin)

    override fun toString() = "FeedCredential($name for ${origin.host})"
}

/**
 * HTTP GET for feed downloads and TAXII: redirects are followed here, not by
 * HttpURLConnection, which would forward a custom credential header (such as
 * `X-Api-Key`) to whatever host a redirect points at.
 */
object FeedHttp {
    const val MAX_REDIRECTS = 5

    /**
     * Whether a credential for [origin] may be sent to [target]: same host,
     * and not over plain HTTP unless the user entered a plain-HTTP URL for
     * that host.
     */
    fun mayCarryCredential(origin: URL, target: URL): Boolean =
        target.host.equals(origin.host, ignoreCase = true) &&
            (target.protocol.equals("https", ignoreCase = true) || target.protocol.equals(origin.protocol, ignoreCase = true))

    /**
     * The URL a redirect from [from] to [location] leads to. Throws for a
     * missing or unusable Location, for a scheme other than HTTP(S), and for
     * a downgrade from HTTPS to plain HTTP.
     */
    fun redirectTarget(from: URL, location: String?): URL {
        if (location.isNullOrBlank()) throw IOException("redirect without a Location")
        val to = try {
            URL(from, location.trim())
        } catch (e: MalformedURLException) {
            throw IOException("redirect to an invalid URL")
        }
        val scheme = to.protocol.lowercase()
        if (scheme != "https" && scheme != "http") throw IOException("redirect to an unsupported URL scheme ($scheme)")
        if (from.protocol.equals("https", ignoreCase = true) && scheme == "http") {
            throw IOException("refusing a redirect from HTTPS to plain HTTP (${to.host})")
        }
        return to
    }

    private fun isRedirect(code: Int) = code == 301 || code == 302 || code == 303 || code == 307 || code == 308

    /**
     * Sends a GET for [url] and follows up to [MAX_REDIRECTS] redirects. The
     * [credential] is attached only where [mayCarryCredential] allows it;
     * across hosts the redirect is followed without it. [configure] sets
     * timeouts and headers on each connection; [onConnection] sees each one
     * before it connects (e.g. to disconnect it on cancellation). Returns the
     * final connection with its response code read; the caller disconnects it.
     */
    fun get(
        url: String,
        credential: FeedCredential?,
        configure: (HttpURLConnection) -> Unit,
        onConnection: (HttpURLConnection) -> Unit = {},
    ): HttpURLConnection {
        var target = URL(url)
        var redirects = 0
        while (true) {
            val conn = target.openConnection() as HttpURLConnection
            conn.instanceFollowRedirects = false
            configure(conn)
            if (credential != null && mayCarryCredential(credential.origin, target)) {
                conn.setRequestProperty(credential.name, credential.value)
            }
            onConnection(conn)
            val code = try {
                conn.responseCode
            } catch (e: IOException) {
                conn.disconnect()
                throw e
            }
            if (!isRedirect(code)) return conn
            val location = conn.getHeaderField("Location")
            conn.disconnect()
            if (++redirects > MAX_REDIRECTS) throw IOException("more than $MAX_REDIRECTS redirects")
            target = redirectTarget(target, location)
        }
    }

    /** Reads at most [max] bytes of [input]; more throws before it is buffered. */
    fun readCapped(input: InputStream, max: Long, what: String): ByteArray {
        val buf = ByteArrayOutputStream()
        val chunk = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(chunk)
            if (n < 0) break
            if (buf.size().toLong() + n > max) throw IOException("$what larger than ${max / 1_000_000} MB")
            buf.write(chunk, 0, n)
        }
        return buf.toByteArray()
    }
}
