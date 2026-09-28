package dev.vigil.inspector.vpn

import dev.vigil.inspector.engine.StatsEvent
import kotlinx.coroutines.flow.MutableStateFlow

sealed interface VpnStatus {
    data object Stopped : VpnStatus
    data object Starting : VpnStatus
    data class Running(val since: Long) : VpnStatus
    data class Failed(val message: String) : VpnStatus
}

data class NetworkInfo(
    val upstreamDns: List<String> = emptyList(),
    /** Private DNS hostname when Private DNS is in strict mode. */
    val privateDnsStrictHost: String? = null,
    val privateDnsActive: Boolean = false,
    /** NAT64 prefixes of the underlying network (CIDR), API 30+. */
    val nat64Prefixes: List<String> = emptyList(),
    /** Handle of the underlying network; a change makes a WireGuard upstream roam. */
    val networkId: String = "",
)

/** Process-wide observable state of the inspector service. */
object ServiceState {
    val status = MutableStateFlow<VpnStatus>(VpnStatus.Stopped)
    val stats = MutableStateFlow<StatsEvent?>(null)
    val network = MutableStateFlow(NetworkInfo())
    val loadedFeeds = MutableStateFlow<Map<String, Long>>(emptyMap())

    /**
     * Set when the engine rejected a settings change (the previous
     * configuration stays active); cleared by the next accepted change or a
     * new session.
     */
    val configError = MutableStateFlow<String?>(null)
}
