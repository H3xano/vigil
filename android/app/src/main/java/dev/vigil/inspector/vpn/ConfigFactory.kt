package dev.vigil.inspector.vpn

import dev.vigil.inspector.data.Settings
import dev.vigil.inspector.engine.BeaconConfig
import dev.vigil.inspector.engine.EngineConfig

object ConfigFactory {
    /**
     * [nat64Prefixes] are the underlying network's NAT64 prefixes (CIDR).
     * Anything that is not a valid IPv6 /96 is dropped, because the engine
     * rejects the whole config otherwise.
     */
    fun build(s: Settings, networkDns: List<String>, blockedUids: List<Int>, nat64Prefixes: List<String> = emptyList()): EngineConfig {
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
            blockJa4Matches = s.blockJa4Matches,
            blockedUids = blockedUids,
            allowDomains = s.allowDomains.sorted(),
            denyDomains = s.denyDomains.sorted(),
            beacon = beacon,
            nat64Prefixes = nat64Prefixes.mapNotNull(::normalizeNat64Prefix).distinct(),
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
            val rest = s.substring(end + 1)
            val port = when {
                rest.isEmpty() -> 53
                rest.startsWith(":") -> parsePort(rest.substring(1)) ?: return null
                else -> return null
            }
            return if (IpLiteral.isV6(host)) "[$host]:$port" else null
        }
        if (s.count { it == ':' } > 1) return if (IpLiteral.isV6(s)) "[$s]:53" else null
        val parts = s.split(':')
        val host = parts[0]
        val port = if (parts.size == 1) 53 else parsePort(parts[1]) ?: return null
        return if (IpLiteral.isV4(host)) "$host:$port" else null
    }

    /** `64:ff9b::/96`-style prefix, or null unless it is an IPv6 /96. */
    fun normalizeNat64Prefix(raw: String): String? {
        val parts = raw.trim().split('/')
        if (parts.size != 2 || parts[1] != "96" || !IpLiteral.isV6(parts[0])) return null
        return "${parts[0]}/96"
    }

    /**
     * Resolver of the underlying network in `ip:port` form. Link-local
     * resolvers give null: the engine cannot use a scope id, and a scope-less
     * `fe80::` address is unroutable.
     */
    fun formatResolver(ip: java.net.InetAddress): String? = when {
        ip.isLinkLocalAddress -> null
        ip is java.net.Inet6Address -> ip.hostAddress?.substringBefore('%')?.let { "[$it]:53" }
        else -> ip.hostAddress?.let { "$it:53" }
    }

    private fun parsePort(s: String): Int? =
        if (s.isEmpty() || s.length > 5 || !s.all { it in '0'..'9' }) null else s.toInt().takeIf { it in 1..65535 }
}
