package dev.vigil.inspector.engine

import android.net.ConnectivityManager
import android.net.VpnService
import androidx.annotation.Keep
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Upcalls made by the engine from its worker threads. Method names and
 * signatures are looked up from native code — keep them in sync with
 * core/vigil-jni/src/lib.rs.
 */
@Keep
class PlatformBridge(
    private val vpn: VpnService,
    private val connectivity: ConnectivityManager,
) {
    /** Owner UID of the socket src→dst, or -1 (Process.INVALID_UID). */
    @Keep
    fun ownerUid(proto: Int, src: ByteArray, srcPort: Int, dst: ByteArray, dstPort: Int): Int = try {
        connectivity.getConnectionOwnerUid(
            proto,
            InetSocketAddress(InetAddress.getByAddress(src), srcPort),
            InetSocketAddress(InetAddress.getByAddress(dst), dstPort),
        )
    } catch (e: SecurityException) {
        -1 // not (or no longer) the active VPN
    } catch (e: IllegalArgumentException) {
        -1
    }

    @Keep
    fun protect(fd: Int): Boolean = vpn.protect(fd)
}
