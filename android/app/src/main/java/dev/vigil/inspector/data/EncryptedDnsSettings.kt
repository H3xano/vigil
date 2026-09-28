package dev.vigil.inspector.data

import dev.vigil.inspector.engine.EncryptedDnsConfig
import dev.vigil.inspector.engine.EncryptedDnsServer
import dev.vigil.inspector.vpn.IpLiteral
import kotlinx.serialization.Serializable

/**
 * How vigil forwards the lookups it answers: plain DNS (the default), DNS over
 * TLS or DNS over HTTPS, to a preset provider or a custom server. Mirrors the
 * engine's `encrypted_dns` object (docs/EVENTS.md).
 */
@Serializable
data class EncryptedDnsSettings(
    /** "off", "dot" or "doh". */
    val mode: String = "off",
    /** A [DnsProviders] id, or [CUSTOM]. */
    val provider: String = "quad9",
    /** Custom DoH endpoint, `https://host[:port]/path`. */
    val customUrl: String = "",
    /** Custom DoT server name (as in its certificate) or IP address. */
    val customHost: String = "",
    val customPort: Int = 853,
    /** Custom server addresses (IP literals), so its name never needs a cleartext lookup. */
    val customAddrs: List<String> = emptyList(),
    /** Use the plain resolvers when the encrypted server fails, instead of failing the lookup. */
    val fallbackPlain: Boolean = false,
) {
    val enabled: Boolean get() = mode == "dot" || mode == "doh"

    /** Why these settings cannot be used, or null. Only checked when [enabled]. */
    fun problem(): String? {
        if (!enabled) return null
        if (provider != CUSTOM) return if (DnsProviders.byId(provider) == null) "Choose a provider." else null
        val badAddr = customAddrs.firstOrNull { !IpLiteral.isV4(it) && !IpLiteral.isV6(it) }
        return when {
            badAddr != null -> "“$badAddr” is not an IP address."
            customAddrs.size > MAX_ADDRS -> "At most $MAX_ADDRS addresses."
            mode == "doh" && parseDohUrl(customUrl) == null -> "Enter an https:// URL, e.g. https://dns.example/dns-query."
            mode == "dot" && !isServerName(customHost) -> "Enter the server's name (as in its certificate) or IP address."
            mode == "dot" && customPort !in 1..65535 -> "The port must be between 1 and 65535."
            customAddrs.isEmpty() && !hostIsIp() && !fallbackPlain ->
                "Enter the server's IP addresses, or allow plain DNS to look its name up."
            else -> null
        }
    }

    private fun hostIsIp(): Boolean {
        val host = if (mode == "doh") parseDohUrl(customUrl)?.host else customHost.trim()
        return host != null && (IpLiteral.isV4(host) || IpLiteral.isV6(host))
    }

    /** The engine configuration; `off` when disabled or invalid (see [problem]). */
    fun toEngine(): EncryptedDnsConfig {
        if (!enabled || problem() != null) return EncryptedDnsConfig()
        val server = if (provider == CUSTOM) {
            if (mode == "doh") {
                EncryptedDnsServer(url = customUrl.trim(), addrs = customAddrs)
            } else {
                EncryptedDnsServer(host = customHost.trim().trimEnd('.'), addrs = customAddrs, port = customPort)
            }
        } else {
            val p = DnsProviders.byId(provider)!!
            if (mode == "doh") EncryptedDnsServer(url = p.dohUrl, addrs = p.addrs) else EncryptedDnsServer(host = p.dotHost, addrs = p.addrs)
        }
        return EncryptedDnsConfig(mode = mode, servers = listOf(server), fallbackPlain = fallbackPlain)
    }

    /** Short description, e.g. "DNS over HTTPS · Quad9". */
    fun summary(): String {
        if (!enabled) return "Off"
        val transport = if (mode == "doh") "DNS over HTTPS" else "DNS over TLS"
        val who = if (provider == CUSTOM) {
            if (mode == "doh") parseDohUrl(customUrl)?.host ?: "custom" else customHost.ifBlank { "custom" }
        } else {
            DnsProviders.byId(provider)?.name ?: provider
        }
        return "$transport · $who"
    }

    companion object {
        const val CUSTOM = "custom"
        const val MAX_ADDRS = 8

        data class DohUrl(val host: String, val port: Int, val path: String)

        /** Mirrors the engine's `parse_https_url`: `https://host[:port][/path][?query]`. */
        fun parseDohUrl(raw: String): DohUrl? {
            val url = raw.trim()
            if (url.length > 512 || url.any { it.code !in 0x21..0x7e }) return null
            if (!url.startsWith("https://", ignoreCase = true)) return null
            val rest = url.substring(8)
            if ('#' in rest) return null
            val split = rest.indexOfFirst { it == '/' || it == '?' }.let { if (it < 0) rest.length else it }
            val authority = rest.substring(0, split)
            val target = rest.substring(split)
            if ('@' in authority) return null
            val host: String
            val portText: String?
            if (authority.startsWith("[")) {
                val end = authority.indexOf(']')
                if (end < 0) return null
                host = authority.substring(1, end)
                if (!IpLiteral.isV6(host)) return null
                val after = authority.substring(end + 1)
                portText = when {
                    after.isEmpty() -> null
                    after.startsWith(":") -> after.substring(1)
                    else -> return null
                }
            } else {
                val colon = authority.indexOf(':')
                host = if (colon < 0) authority else authority.substring(0, colon)
                portText = if (colon < 0) null else authority.substring(colon + 1)
                if (!isServerName(host)) return null
            }
            val port = if (portText == null) 443 else portText.takeIf { it.isNotEmpty() && it.length <= 5 && it.all(Char::isDigit) }
                ?.toInt()?.takeIf { it in 1..65535 } ?: return null
            val path = when {
                target.isEmpty() -> "/dns-query"
                target.startsWith("?") -> "/$target"
                else -> target
            }
            return DohUrl(host.lowercase(), port, path)
        }

        /** A host name with at least two LDH labels, or an IP literal (the engine's rule). */
        fun isServerName(raw: String): Boolean {
            val h = raw.trim().trimEnd('.')
            if (IpLiteral.isV4(h) || IpLiteral.isV6(h)) return true
            if (h.isEmpty() || h.length > 253 || '.' !in h) return false
            return h.split('.').all { l ->
                l.isNotEmpty() && l.length <= 63 && !l.startsWith('-') && !l.endsWith('-') &&
                    l.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' }
            }
        }

        /** Splits user input ("9.9.9.9, 2620:fe::fe") into address strings. */
        fun splitAddrs(text: String): List<String> = text.split(',', ' ', '\n', ';').map { it.trim() }.filter { it.isNotEmpty() }
    }
}

/** A public resolver with published DoT and DoH endpoints and fixed addresses. */
data class DnsProvider(
    val id: String,
    val name: String,
    val description: String,
    val dotHost: String,
    val dohUrl: String,
    /** IPv4 first: an address that cannot be reached is skipped for a while. */
    val addrs: List<String>,
)

/** Presets, checked against the providers' documentation (2026-09). */
object DnsProviders {
    val ALL = listOf(
        DnsProvider(
            "quad9", "Quad9", "Non-profit, Switzerland. Blocks known malicious domains.",
            "dns.quad9.net", "https://dns.quad9.net/dns-query",
            listOf("9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"),
        ),
        DnsProvider(
            "cloudflare", "Cloudflare", "1.1.1.1. No filtering.",
            "one.one.one.one", "https://cloudflare-dns.com/dns-query",
            listOf("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"),
        ),
        DnsProvider(
            "google", "Google", "Google Public DNS. No filtering.",
            "dns.google", "https://dns.google/dns-query",
            listOf("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"),
        ),
        DnsProvider(
            "mullvad", "Mullvad", "No filtering, no logging.",
            "dns.mullvad.net", "https://dns.mullvad.net/dns-query",
            listOf("194.242.2.2", "2a07:e340::2"),
        ),
    )

    fun byId(id: String): DnsProvider? = ALL.firstOrNull { it.id == id }
}
