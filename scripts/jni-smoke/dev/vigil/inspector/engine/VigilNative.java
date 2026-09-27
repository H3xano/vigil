package dev.vigil.inspector.engine;

/** Host-side mirror of the Kotlin VigilNative object, used for JNI smoke tests. */
public final class VigilNative {
    public static native String nativeVersion();
    public static native long nativeStart(int tunFd, String configJson, Object bridge);
    public static native void nativeStop(long handle);
    public static native String nativePollEvents(long handle, int max, int timeoutMs);
    public static native boolean nativeUpdateConfig(long handle, String configJson);
    public static native String nativeLoadFeedFile(long handle, String id, String category, String path);
    public static native boolean nativeRemoveFeed(long handle, String id);
    public static native String nativeStats(long handle);
    public static native String nativeInspectFeedFile(String path);
}
