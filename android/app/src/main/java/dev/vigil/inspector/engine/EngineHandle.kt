package dev.vigil.inspector.engine

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
    fun shutdown(): Boolean = lock.read {
        if (handle == 0L) return@read false
        try {
            VigilNative.nativeShutdown(handle)
        } catch (e: UnsatisfiedLinkError) {
            false
        }
    }

    fun close() = lock.write {
        if (handle != 0L) {
            VigilNative.nativeStop(handle)
            handle = 0L
        }
    }
}
