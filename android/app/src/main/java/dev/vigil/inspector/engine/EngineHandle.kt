package dev.vigil.inspector.engine

import androidx.annotation.WorkerThread
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * Owns a native engine handle. Calls take the read lock; [close] takes the
 * write lock, so the native object can never be freed while a call (e.g. a
 * blocking event poll) is still using it.
 */
class EngineHandle(private var handle: Long) {
    private val lock = ReentrantReadWriteLock()

    val isOpen: Boolean get() = lock.read { handle != 0L }

    fun <T> use(block: (Long) -> T): T? = lock.read {
        if (handle == 0L) null else block(handle)
    }

    /**
     * Stops the engine but keeps the handle, so the final `flow_end` events
     * can still be polled before [close]. False if already closed, or if the
     * native library predates `nativeShutdown`.
     */
    @WorkerThread // blocks up to about 2 s while the engine winds down
    fun shutdown(): Boolean = lock.read {
        if (handle == 0L) return@read false
        try {
            VigilNative.nativeShutdown(handle)
        } catch (e: UnsatisfiedLinkError) {
            false
        }
    }

    /**
     * Exports the captured packets matching [filter] to [path] (PCAPng).
     * Null if the handle is closed, the export failed, or the native library
     * predates packet capture.
     */
    @WorkerThread // writes up to the ring size (128 MiB at most) to disk
    fun exportPcap(filter: PcapFilter, path: String): PcapExportSummary? = lock.read {
        if (handle == 0L) return@read null
        val json = try {
            VigilNative.nativeExportPcap(handle, filter.toJson(), path)
        } catch (e: UnsatisfiedLinkError) {
            null
        } ?: return@read null
        runCatching { EngineJson.json.decodeFromString(PcapExportSummary.serializer(), json) }.getOrNull()
    }

    /** Waits for a blocking poll to return (write lock) and frees the engine. */
    @WorkerThread
    fun close() = lock.write {
        if (handle != 0L) {
            VigilNative.nativeStop(handle)
            handle = 0L
        }
    }
}
