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
)

/** Process-wide observable state of the inspector service. */
object ServiceState {
    val status = MutableStateFlow<VpnStatus>(VpnStatus.Stopped)
    val stats = MutableStateFlow<StatsEvent?>(null)
    val network = MutableStateFlow(NetworkInfo())
    val loadedFeeds = MutableStateFlow<Map<String, Long>>(emptyMap())

    fun reportEngineError(message: String) {
        status.value = VpnStatus.Failed("Engine error: $message")
    }
}
