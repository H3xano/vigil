package dev.vigil.inspector.vpn

import dev.vigil.inspector.data.FeedEntity
import dev.vigil.inspector.data.FeedKinds
import dev.vigil.inspector.data.Settings
import dev.vigil.inspector.data.UpstreamSettings
import dev.vigil.inspector.engine.BeaconConfig
import dev.vigil.inspector.engine.EngineConfig
import dev.vigil.inspector.engine.FeedFileConfig
import dev.vigil.inspector.engine.Socks5Config
import dev.vigil.inspector.engine.UpstreamConfig
import dev.vigil.inspector.engine.WireGuardConfig

object ConfigFactory {
    /**
     * [nat64Prefixes] are the underlying network's NAT64 prefixes (CIDR).
     * Anything that is not a valid IPv6 /96 is dropped, because the engine
     * rejects the whole config otherwise.
     */
    fun build(
        s: Settings,
        networkDns: List<String>,
        blockedUids: List<Int>,
        nat64Prefixes: List<String> = emptyList(),
        networkId: String = "",
    ): EngineConfig {
        // DNS precedence when several settings apply:
        // 1. Encrypted DNS (mode dot/doh) answers the virtual resolver's lookups,
        //    whatever `upstream_dns` holds. Its servers are reached over the
        //    upstream path (through the WireGuard tunnel or the SOCKS5 proxy).
        // 2. `upstream_dns` (below) is then only used for fallback_plain,
        //    bootstrap lookups of server names and, with encrypted DNS off,
        //    all lookups: the WireGuard config's DNS servers, else the custom
        //    resolvers, else public resolvers in tunnel/proxy modes, else the
        //    network's resolvers. Also reached over the upstream path.
        val up = s.upstream
        val tunnelDns = up.wireguard?.dns.orEmpty().mapNotNull(::normalizeResolver)
        val upstreams = when {
            // DNS goes through the tunnel, to the provider's resolvers.
            up.mode == UpstreamSettings.MODE_WIREGUARD && tunnelDns.isNotEmpty() -> tunnelDns
            s.upstreamMode == "custom" -> s.customUpstreams.mapNotNull(::normalizeResolver)
            // The network's resolver is usually on the local network: not
            // reachable through a tunnel or proxy, and asking it would bypass them.
            up.mode != UpstreamSettings.MODE_DIRECT -> emptyList()
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
            // Invalid settings (which the DNS screen does not save) become "off".
            encryptedDns = s.encryptedDns.toEngine(),
            upstream = upstreamConfig(up, networkId),
            // One worker uses 17-34% less CPU per packet than two; two only
            // pay off on links faster than a phone usually has.
            workerThreads = workerThreads(s),
        )
    }

    /**
     * The feeds the engine should hold: enabled ones with a downloaded file
     * ([hasFile]), except the app-only kinds (spyware app indicators and
     * indexes, see [FeedKinds.loadsIntoEngine]). The service preloads
     * exactly these at start and keeps the engine in sync with this
     * selection afterwards.
     */
    fun loadableFeeds(feeds: List<FeedEntity>, hasFile: (String) -> Boolean): List<FeedEntity> =
        feeds.filter { it.enabled && FeedKinds.loadsIntoEngine(it.kind) && hasFile(it.id) }

    /**
     * [base] as a start config: [feeds] (already filtered by [loadableFeeds])
     * are loaded by the engine before it processes the first packet, so
     * blocking and threat alerts apply from the first connection.
     */
    fun startConfig(base: EngineConfig, feeds: List<FeedEntity>, pathFor: (String) -> String): EngineConfig = base.copy(
        feeds = feeds.map { FeedFileConfig(id = it.id, category = it.category, path = pathFor(it.id)) },
        feedsPreloadTimeoutMs = EngineConfig.FEEDS_PRELOAD_TIMEOUT_MS,
    )

    /** Engine worker threads: 1 by default (battery), 2 with "Maximum throughput". */
    fun workerThreads(s: Settings): Int = if (s.maxThroughput) 2 else 1

    /**
     * The engine's upstream section. A WireGuard mode without an imported
     * configuration is passed on as such: the engine rejects it, so inspection
     * fails to start instead of silently running direct.
     */
    fun upstreamConfig(up: UpstreamSettings, networkId: String): UpstreamConfig = when (up.mode) {
        UpstreamSettings.MODE_WIREGUARD -> UpstreamConfig(
            mode = up.mode,
            failClosed = up.failClosed,
            networkId = networkId,
            wireguard = up.wireguard?.let { w ->
                WireGuardConfig(
                    privateKey = w.privateKey,
                    peerPublicKey = w.peerPublicKey,
                    presharedKey = w.presharedKey,
                    endpoint = w.endpoint,
                    addresses = w.addresses,
                    allowedIps = w.allowedIps,
                    mtu = w.mtu ?: DEFAULT_WG_MTU,
                    persistentKeepalive = w.persistentKeepalive,
                )
            },
        )
        UpstreamSettings.MODE_SOCKS5 -> UpstreamConfig(
            mode = up.mode,
            failClosed = up.failClosed,
            networkId = networkId,
            socks5 = Socks5Config(
                server = hostPort(up.socks5.host, up.socks5.port),
                username = up.socks5.username,
                password = up.socks5.password,
                sendDomain = up.socks5.sendDomain,
                udp = up.socks5.udp,
            ),
        )
        else -> UpstreamConfig(mode = UpstreamSettings.MODE_DIRECT, failClosed = up.failClosed, networkId = networkId)
    }

    /** `host:port`, bracketing IPv6 literals. */
    fun hostPort(host: String, port: Int): String {
        val h = host.trim().removePrefix("[").removeSuffix("]")
        return if (h.contains(':')) "[$h]:$port" else "$h:$port"
    }

    /** Used when the wg-quick file sets no MTU (as the WireGuard Android app does). */
    const val DEFAULT_WG_MTU = 1280

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
