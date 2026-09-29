package dev.vigil.inspector.data

import androidx.annotation.StringRes
import dev.vigil.inspector.R
import dev.vigil.inspector.engine.EncryptedDnsConfig
import dev.vigil.inspector.engine.EncryptedDnsServer
import dev.vigil.inspector.ui.UiText
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
    fun problemText(): UiText? {
        if (!enabled) return null
        if (provider != CUSTOM) return if (DnsProviders.byId(provider) == null) UiText.of(R.string.settings_dns_choose_provider) else null
        val badAddr = customAddrs.firstOrNull { !IpLiteral.isV4(it) && !IpLiteral.isV6(it) }
        return when {
            badAddr != null -> UiText.of(R.string.settings_dns_not_ip, badAddr)
            customAddrs.size > MAX_ADDRS -> UiText.plural(R.plurals.settings_dns_too_many_addrs, MAX_ADDRS, MAX_ADDRS)
            mode == "doh" && parseDohUrl(customUrl) == null -> UiText.of(R.string.settings_dns_need_https_url)
            mode == "dot" && !isServerName(customHost) -> UiText.of(R.string.settings_dns_need_server_name)
            mode == "dot" && customPort !in 1..65535 -> UiText.of(R.string.settings_port_range)
            customAddrs.isEmpty() && !hostIsIp() && !fallbackPlain -> UiText.of(R.string.settings_dns_need_addrs)
            else -> null
        }
    }

    private fun hostIsIp(): Boolean {
        val host = if (mode == "doh") parseDohUrl(customUrl)?.host else customHost.trim()
        return host != null && (IpLiteral.isV4(host) || IpLiteral.isV6(host))
    }

    /** The engine configuration; `off` when disabled or invalid (see [problemText]). */
    fun toEngine(): EncryptedDnsConfig {
        if (!enabled || problemText() != null) return EncryptedDnsConfig()
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

    /**
     * Short description, e.g. "DNS over HTTPS · Quad9" (protocol and
     * provider names are not translated); a custom server whose name is
     * unknown is called "custom".
     */
    fun summary(): UiText {
        if (!enabled) return UiText.of(R.string.common_off)
        val who: UiText = if (provider == CUSTOM) {
            val name = if (mode == "doh") parseDohUrl(customUrl)?.host else customHost.ifBlank { null }
            name?.let(UiText::Raw) ?: UiText.of(R.string.settings_encrypted_dns_custom_server)
        } else {
            UiText.Raw(DnsProviders.byId(provider)?.name ?: provider)
        }
        return UiText.of(if (mode == "doh") R.string.settings_dns_summary_doh else R.string.settings_dns_summary_dot, who)
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
    /** Shown under the name in the provider list. */
    @param:StringRes val description: Int,
    val dotHost: String,
    val dohUrl: String,
    /** IPv4 first: an address that cannot be reached is skipped for a while. */
    val addrs: List<String>,
)

/** Presets, checked against the providers' documentation (2026-09). */
object DnsProviders {
    val ALL = listOf(
        DnsProvider(
            "quad9", "Quad9", R.string.dns_provider_quad9,
            "dns.quad9.net", "https://dns.quad9.net/dns-query",
            listOf("9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"),
        ),
        DnsProvider(
            "cloudflare", "Cloudflare", R.string.dns_provider_cloudflare,
            "one.one.one.one", "https://cloudflare-dns.com/dns-query",
            listOf("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"),
        ),
        DnsProvider(
            "google", "Google", R.string.dns_provider_google,
            "dns.google", "https://dns.google/dns-query",
            listOf("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"),
        ),
        DnsProvider(
            "mullvad", "Mullvad", R.string.dns_provider_mullvad,
            "dns.mullvad.net", "https://dns.mullvad.net/dns-query",
            listOf("194.242.2.2", "2a07:e340::2"),
        ),
    )

    fun byId(id: String): DnsProvider? = ALL.firstOrNull { it.id == id }
}
