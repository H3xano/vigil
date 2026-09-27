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

    fun close() = lock.write {
        if (handle != 0L) {
            VigilNative.nativeStop(handle)
            handle = 0L
        }
    }
}
