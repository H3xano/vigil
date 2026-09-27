package dev.vigil.inspector.engine

/**
 * JNI surface of the Rust engine (core/vigil-jni). Signatures must match the
 * `Java_dev_vigil_inspector_engine_VigilNative_*` symbols exactly.
 */
object VigilNative {
    init {
        System.loadLibrary("vigil")
    }

    @JvmStatic external fun nativeVersion(): String

    /** Starts the engine on a duplicate of [tunFd]; returns a handle or 0. */
    @JvmStatic external fun nativeStart(tunFd: Int, configJson: String, bridge: PlatformBridge): Long

    @JvmStatic external fun nativeStop(handle: Long)

    /** Blocks up to [timeoutMs]; returns a JSON array of events or null. */
    @JvmStatic external fun nativePollEvents(handle: Long, max: Int, timeoutMs: Int): String?

    @JvmStatic external fun nativeUpdateConfig(handle: Long, configJson: String): Boolean

    /** Streams a feed file into the engine; returns a JSON summary or null. */
    @JvmStatic external fun nativeLoadFeedFile(handle: Long, id: String, category: String, path: String): String?

    @JvmStatic external fun nativeRemoveFeed(handle: Long, id: String): Boolean

    @JvmStatic external fun nativeStats(handle: Long): String?

    /** Parses a feed file without an engine; returns a JSON summary or null. */
    @JvmStatic external fun nativeInspectFeedFile(path: String): String?
}
