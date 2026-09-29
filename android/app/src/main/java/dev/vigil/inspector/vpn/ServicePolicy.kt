package dev.vigil.inspector.vpn

import dev.vigil.inspector.R
import dev.vigil.inspector.engine.StatsEvent
import dev.vigil.inspector.ui.UiText

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
    fun lockdownWarning(excludedPackage: String?, lockdown: Boolean, proxyLabel: String? = null): UiText? {
        if (excludedPackage == null || !lockdown) return null
        val name = proxyLabel?.takeIf { it.isNotBlank() } ?: excludedPackage
        return UiText.of(R.string.vpn_lockdown_warning, name)
    }

    /** One line for the ongoing notification. */
    fun lockdownShort(excludedPackage: String, proxyLabel: String? = null): UiText =
        UiText.of(R.string.vpn_lockdown_short, proxyLabel?.takeIf { it.isNotBlank() } ?: excludedPackage)

    /** Wireshark clients connected to the PCAP-over-IP stream (0 when none or off). */
    fun streamClients(stats: StatsEvent?): Long = stats?.capture?.stream?.clients ?: 0

    /**
     * The ongoing notification's note while someone receives the packet
     * stream, so a connected client is never invisible. Null when none is.
     */
    fun streamingNotice(stats: StatsEvent?): UiText? {
        val n = streamClients(stats)
        if (n <= 0) return null
        val count = n.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        val where = stats?.capture?.stream?.listening
        return if (where == null) {
            UiText.plural(R.plurals.vpn_streaming_clients, count, n)
        } else {
            UiText.plural(R.plurals.vpn_streaming_clients_on, count, n, where)
        }
    }
}
