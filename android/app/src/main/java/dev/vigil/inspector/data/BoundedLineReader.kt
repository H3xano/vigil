package dev.vigil.inspector.data

import java.io.Closeable
import java.io.IOException
import java.io.InputStream

/**
 * Reads UTF-8 lines from [input] with hard limits, for untrusted (possibly
 * decompressed) downloads: a line longer than [maxLineBytes] or a stream
 * longer than [maxTotalBytes] throws [IOException] before the data is
 * buffered. `BufferedReader.readLine` builds the whole line first, so a
 * gzip bomb without a newline would exhaust the heap.
 *
 * Lines end at `\n`; a trailing `\r` is removed, like `readLine`.
 */
class BoundedLineReader(
    private val input: InputStream,
    private val maxLineBytes: Int,
    private val maxTotalBytes: Long,
    private val what: String = "file",
) : Closeable {
    private val buf = ByteArray(64 * 1024)
    private var pos = 0
    private var end = 0
    private var line = ByteArray(minOf(maxLineBytes, 1024))
    private var lineLen = 0

    /** Bytes consumed from [input] so far (the decompressed size, for a decompressing stream). */
    var totalBytes = 0L
        private set

    /** The next line without its terminator, or null at the end of the stream. */
    fun readLine(): String? {
        lineLen = 0
        var sawAny = false
        while (true) {
            if (pos == end) {
                val n = input.read(buf)
                if (n < 0) return if (sawAny) finish() else null
                totalBytes += n
                if (totalBytes > maxTotalBytes) throw IOException("$what larger than ${maxTotalBytes / 1_000_000} MB")
                pos = 0
                end = n
                if (n == 0) continue
            }
            sawAny = true
            var i = pos
            while (i < end && buf[i] != NL) i++
            append(pos, i - pos)
            if (i < end) {
                pos = i + 1
                return finish()
            }
            pos = end
        }
    }

    private fun append(from: Int, len: Int) {
        if (len == 0) return
        if (lineLen + len > maxLineBytes) throw IOException("$what has a line longer than $maxLineBytes bytes")
        if (lineLen + len > line.size) line = line.copyOf(minOf(maxLineBytes, maxOf(line.size * 2, lineLen + len)))
        System.arraycopy(buf, from, line, lineLen, len)
        lineLen += len
    }

    private fun finish(): String {
        val n = if (lineLen > 0 && line[lineLen - 1] == CR) lineLen - 1 else lineLen
        return String(line, 0, n, Charsets.UTF_8)
    }

    override fun close() = input.close()

    private companion object {
        const val NL = '\n'.code.toByte()
        const val CR = '\r'.code.toByte()
    }
}
