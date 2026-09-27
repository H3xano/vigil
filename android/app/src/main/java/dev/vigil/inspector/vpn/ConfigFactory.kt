package dev.vigil.inspector.vpn

import dev.vigil.inspector.data.Settings
import dev.vigil.inspector.engine.BeaconConfig
import dev.vigil.inspector.engine.EngineConfig

object ConfigFactory {
    fun build(s: Settings, networkDns: List<String>, blockedUids: List<Int>): EngineConfig {
        val upstreams = when (s.upstreamMode) {
            "custom" -> s.customUpstreams.mapNotNull(::normalizeResolver)
            else -> networkDns
        }.ifEmpty { EngineConfig.FALLBACK_UPSTREAMS }
        val beacon = when (s.beaconSensitivity) {
            "low" -> BeaconConfig(enabled = s.beaconEnabled, minEvents = 8, maxJitter = 0.10)
            "high" -> BeaconConfig(enabled = s.beaconEnabled, minEvents = 5, maxJitter = 0.25)
            else -> BeaconConfig(enabled = s.beaconEnabled)
        }
        return EngineConfig(
            upstreamDns = upstreams,
            sinkhole = s.sinkhole,
            blockEncryptedDns = s.blockEncryptedDns,
            blockedUids = blockedUids,
            allowDomains = s.allowDomains.sorted(),
            denyDomains = s.denyDomains.sorted(),
            beacon = beacon,
        )
    }

    /**
     * Accepts `1.1.1.1`, `1.1.1.1:5353`, `2606:4700::1111` or
     * `[2606:4700::1111]:53`; returns `ip:port` form or null if invalid.
     */
    fun normalizeResolver(raw: String): String? {
        val s = raw.trim()
        if (s.isEmpty()) return null
        if (s.startsWith("[")) {
            val end = s.indexOf(']')
            if (end < 0) return null
            val host = s.substring(1, end)
            val port = s.substring(end + 1).removePrefix(":").ifEmpty { "53" }.toIntOrNull() ?: return null
            return if (isIpv6(host) && port in 1..65535) "[$host]:$port" else null
        }
        if (s.count { it == ':' } > 1) return if (isIpv6(s)) "[$s]:53" else null
        val parts = s.split(':')
        val host = parts[0]
        val port = parts.getOrNull(1)?.toIntOrNull() ?: if (parts.size == 1) 53 else return null
        return if (isIpv4(host) && port in 1..65535) "$host:$port" else null
    }

    fun formatResolver(ip: java.net.InetAddress): String =
        if (ip is java.net.Inet6Address) "[${ip.hostAddress?.substringBefore('%')}]:53" else "${ip.hostAddress}:53"

    private fun isIpv4(s: String) = s.split('.').let { p -> p.size == 4 && p.all { it.toIntOrNull() in 0..255 && it.isNotEmpty() } }

    private fun isIpv6(s: String) = s.contains(':') && s.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' } &&
        s.split("::").size <= 2
}
