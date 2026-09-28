package dev.vigil.inspector.vpn

/** Pure decisions of [VigilVpnService], kept here so they are unit-testable. */
object ServicePolicy {
    /**
     * Whether stopping on behalf of start request [stoppingFor] may take the
     * service out of the foreground. `stopSelf(startId)` is a no-op when a
     * newer start request ([latestReceived]) arrived; that request is queued
     * and will run the VPN, so the service must stay a foreground service.
     */
    fun mayLeaveForeground(stoppingFor: Int, latestReceived: Int): Boolean = stoppingFor >= latestReceived

    /**
     * Warning when the SOCKS5 proxy app is excluded from the VPN while
     * Android's always-on lockdown ("Block connections without VPN") is on:
     * lockdown gives apps outside the VPN no network at all, so the proxy
     * (e.g. Orbot) cannot reach its upstream and every relayed connection
     * fails. Null when not affected.
     */
    fun lockdownWarning(excludedPackage: String?, lockdown: Boolean, proxyLabel: String? = null): String? {
        if (excludedPackage == null || !lockdown) return null
        val name = proxyLabel?.takeIf { it.isNotBlank() } ?: excludedPackage
        return "$name has no network: Android's “Block connections without VPN” (always-on lockdown) is on, " +
            "and $name runs outside vigil's VPN as the SOCKS5 proxy, so every connection through the proxy fails. " +
            "Turn off “Block connections without VPN” for vigil in Android's VPN settings, or use a proxy on another device."
    }

    /** One line for the ongoing notification. */
    fun lockdownShort(excludedPackage: String, proxyLabel: String? = null): String =
        "${proxyLabel?.takeIf { it.isNotBlank() } ?: excludedPackage} has no network (always-on lockdown); connections fail"
}
