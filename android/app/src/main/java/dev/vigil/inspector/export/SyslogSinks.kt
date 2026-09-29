package dev.vigil.inspector.export

import java.io.Closeable
import java.io.IOException
import java.io.OutputStream
import java.net.Socket
import java.net.SocketTimeoutException

/** A syslog transport: one connection or socket, reused across batches. */
internal interface SyslogSink : Closeable {
    fun write(messages: List<String>)
}

/**
 * Syslog over TCP or TLS with octet-counting framing (RFC 6587).
 *
 * A collector (or a NAT or load balancer in between) may close an idle
 * connection. A write to such a socket still succeeds, into the kernel's
 * send buffer, and the batch would be counted as delivered although it is
 * lost. So before each batch the connection is replaced if it sat idle for
 * longer than [IDLE_REOPEN_NS], or if the peer has closed it (checked with a
 * 1 ms read: end of stream or an error means closed, a timeout means open).
 */
internal class StreamSink(
    /** Opens a connected socket (for TLS, after the handshake). */
    private val connect: () -> Socket,
    private val nanoTime: () -> Long = System::nanoTime,
) : SyslogSink {
    private var socket: Socket? = null
    private var out: OutputStream? = null
    private var lastUsed = 0L

    /** Connections opened so far (for tests). */
    var connects = 0
        private set

    override fun write(messages: List<String>) {
        val o = usableStream()
        for (m in messages) o.write(WireFormats.octetCounted(m))
        o.flush()
        lastUsed = nanoTime()
    }

    private fun usableStream(): OutputStream {
        val s = socket
        val o = out
        if (s != null && o != null && nanoTime() - lastUsed <= IDLE_REOPEN_NS && peerStillOpen(s)) return o
        closeSocket()
        val fresh = connect()
        connects++
        socket = fresh
        lastUsed = nanoTime()
        return fresh.getOutputStream().buffered().also { out = it }
    }

    private fun closeSocket() {
        runCatching { socket?.close() }
        socket = null
        out = null
    }

    override fun close() = closeSocket()

    companion object {
        const val IDLE_REOPEN_NS = 30 * 1_000_000_000L

        /**
         * False if the peer closed (or reset) [s]. Syslog collectors send
         * nothing, so a read either times out (open) or sees the end of the
         * stream; a stray byte is discarded and taken as a sign of life.
         */
        fun peerStillOpen(s: Socket): Boolean {
            if (s.isClosed || s.isInputShutdown) return false
            val timeout = runCatching { s.soTimeout }.getOrElse { return false }
            return try {
                s.soTimeout = 1
                s.getInputStream().read() != -1
            } catch (_: SocketTimeoutException) {
                true
            } catch (_: IOException) {
                false
            } finally {
                runCatching { s.soTimeout = timeout }
            }
        }
    }
}
