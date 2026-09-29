package dev.vigil.inspector.data

import dev.vigil.inspector.R
import dev.vigil.inspector.ui.UiText
import dev.vigil.inspector.vpn.IpLiteral
import java.util.Base64

/**
 * Parser for wg-quick configuration files (the `.conf` files VPN providers
 * hand out). Pure Kotlin, no Android dependencies.
 *
 * Reads [Interface] PrivateKey, Address, DNS and MTU and [Peer] PublicKey,
 * PresharedKey, Endpoint, AllowedIPs and PersistentKeepalive. Keys that only
 * matter to wg-quick on Linux (PostUp, Table, ListenPort...) are ignored
 * with a warning, as are extra peers and DNS search domains.
 */
object WgQuick {
    /** A configuration that cannot be used; [text] is shown to the user. */
    class ParseException(val text: UiText) : Exception("WireGuard configuration refused: $text")

    data class Parsed(val settings: WireGuardSettings, val warnings: List<UiText>)

    private const val MAX_TEXT = 64 * 1024

    fun parse(text: String, name: String = ""): Parsed {
        if (text.length > MAX_TEXT) throw ParseException(UiText.of(R.string.upstream_wg_too_large))
        val warnings = mutableListOf<UiText>()
        var section: String? = null
        var peers = 0
        val iface = mutableMapOf<String, MutableList<String>>()
        val peer = mutableMapOf<String, MutableList<String>>()
        // Key names as written, for warnings.
        val spelled = mutableMapOf<String, String>()
        text.lineSequence().forEachIndexed { i, raw ->
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) return@forEachIndexed
            if (line.startsWith("[") && line.endsWith("]")) {
                section = line.substring(1, line.length - 1).trim().lowercase()
                when (section) {
                    "interface" -> Unit
                    "peer" -> if (++peers == 2) warnings += UiText.of(R.string.upstream_wg_only_first_peer)
                    else -> warnings += UiText.of(R.string.upstream_wg_unknown_section, section.orEmpty())
                }
                return@forEachIndexed
            }
            val eq = line.indexOf('=')
            if (eq <= 0) throw ParseException(UiText.of(R.string.upstream_wg_not_key_value, i + 1))
            val key = line.substring(0, eq).trim().lowercase()
            spelled.putIfAbsent(key, line.substring(0, eq).trim())
            val value = line.substring(eq + 1).trim()
            when (section) {
                "interface" -> iface.getOrPut(key) { mutableListOf() } += value
                "peer" -> if (peers == 1) peer.getOrPut(key) { mutableListOf() } += value
                null -> throw ParseException(UiText.of(R.string.upstream_wg_outside_section, i + 1))
            }
        }
        if (iface.isEmpty()) throw ParseException(UiText.of(R.string.upstream_wg_no_interface))
        if (peers == 0) throw ParseException(UiText.of(R.string.upstream_wg_no_peer))

        for (k in iface.keys - setOf("privatekey", "address", "dns", "mtu")) warnings += UiText.of(R.string.upstream_wg_interface_key_ignored, spelled[k] ?: k)
        for (k in peer.keys - setOf("publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive")) warnings += UiText.of(R.string.upstream_wg_peer_key_ignored, spelled[k] ?: k)

        val privateKey = single(iface, "privatekey", "[Interface] PrivateKey")
        if (!isKey(privateKey)) throw ParseException(UiText.of(R.string.upstream_wg_not_a_key, "[Interface] PrivateKey"))
        val publicKey = single(peer, "publickey", "[Peer] PublicKey")
        if (!isKey(publicKey)) throw ParseException(UiText.of(R.string.upstream_wg_not_a_key, "[Peer] PublicKey"))
        val psk = peer["presharedkey"]?.lastOrNull()
        if (psk != null && !isKey(psk)) throw ParseException(UiText.of(R.string.upstream_wg_not_a_key, "[Peer] PresharedKey"))

        val endpoint = single(peer, "endpoint", "[Peer] Endpoint")
        if (!isEndpoint(endpoint)) throw ParseException(UiText.of(R.string.upstream_wg_endpoint_invalid, endpoint))

        val addresses = list(iface["address"]).map {
            normalizeCidr(it) ?: throw ParseException(UiText.of(R.string.upstream_wg_address_invalid, it))
        }
        if (addresses.isEmpty()) throw ParseException(UiText.of(R.string.upstream_wg_address_missing))
        val v4 = addresses.filter { !it.contains(':') }
        val v6 = addresses.filter { it.contains(':') }
        if (v4.size > 1 || v6.size > 1) warnings += UiText.of(R.string.upstream_wg_first_address_only)
        val usedAddresses = listOfNotNull(v4.firstOrNull(), v6.firstOrNull())

        val dnsEntries = list(iface["dns"])
        val dns = dnsEntries.filter { IpLiteral.isV4(it) || IpLiteral.isV6(it) }
        if (dns.size < dnsEntries.size) warnings += UiText.of(R.string.upstream_wg_search_domains)

        val mtu = iface["mtu"]?.lastOrNull()?.let {
            it.toIntOrNull()?.takeIf { m -> m in 576..65535 } ?: throw ParseException(UiText.of(R.string.upstream_wg_mtu_invalid, it))
        }
        val allowed = list(peer["allowedips"]).map {
            normalizeCidr(it) ?: throw ParseException(UiText.of(R.string.upstream_wg_allowed_ips_invalid, it))
        }
        allowedIpsWarning(allowed)?.let { warnings += it }
        val keepalive = peer["persistentkeepalive"]?.lastOrNull()?.let {
            if (it.equals("off", ignoreCase = true)) 0
            else it.toIntOrNull()?.takeIf { k -> k in 0..65535 } ?: throw ParseException(UiText.of(R.string.upstream_wg_keepalive_invalid, it))
        } ?: 0

        return Parsed(
            WireGuardSettings(
                privateKey = privateKey,
                addresses = usedAddresses,
                dns = dns,
                mtu = mtu,
                peerPublicKey = publicKey,
                presharedKey = psk,
                endpoint = endpoint,
                allowedIps = allowed,
                persistentKeepalive = keepalive,
                name = name,
            ),
            warnings,
        )
    }

    /**
     * The engine sends an address family that AllowedIPs does not cover at
     * all around the tunnel, or refuses it when fail-closed is on. A file
     * routing all IPv4 (`0.0.0.0/0`) but no IPv6 is the common case: warn.
     */
    fun allowedIpsWarning(allowed: List<String>): UiText? {
        val allV4 = allowed.any { !it.contains(':') && it.endsWith("/0") }
        val anyV6 = allowed.any { it.contains(':') }
        if (!allV4 || anyV6) return null
        return UiText.of(R.string.upstream_wg_ipv6_not_tunnelled)
    }

    /** A base64 WireGuard key (32 bytes). */
    fun isKey(s: String): Boolean = try {
        Base64.getDecoder().decode(s.trim()).size == 32
    } catch (e: IllegalArgumentException) {
        false
    }

    /** `host:port` or `[v6]:port`, host being an IP literal or a DNS name. */
    fun isEndpoint(s: String): Boolean {
        val (host, port) = splitHostPort(s) ?: return false
        if (port !in 1..65535) return false
        if (IpLiteral.isV4(host) || IpLiteral.isV6(host)) return true
        return host.length <= 253 && host.split('.').all { label ->
            label.isNotEmpty() && label.length <= 63 && label.all { (it.isLetterOrDigit() && it.code < 128) || it == '-' }
        }
    }

    fun splitHostPort(s: String): Pair<String, Int>? {
        val t = s.trim()
        return if (t.startsWith("[")) {
            val end = t.indexOf(']')
            if (end < 0 || end + 1 >= t.length || t[end + 1] != ':') null
            else t.substring(1, end) to (t.substring(end + 2).toIntOrNull() ?: return null)
        } else {
            val colon = t.lastIndexOf(':')
            if (colon <= 0 || t.substring(0, colon).contains(':')) null
            else t.substring(0, colon) to (t.substring(colon + 1).toIntOrNull() ?: return null)
        }
    }

    /** `addr/prefix` with a valid prefix, or a bare address as a host route. */
    fun normalizeCidr(s: String): String? {
        val parts = s.trim().split('/')
        if (parts.size > 2) return null
        val addr = parts[0].trim()
        val max = when {
            IpLiteral.isV4(addr) -> 32
            IpLiteral.isV6(addr) -> 128
            else -> return null
        }
        val prefix = if (parts.size == 2) parts[1].trim().toIntOrNull()?.takeIf { it in 0..max } ?: return null else max
        return "$addr/$prefix"
    }

    private fun list(values: List<String>?): List<String> =
        values.orEmpty().flatMap { it.split(',') }.map { it.trim() }.filter { it.isNotEmpty() }

    private fun single(map: Map<String, List<String>>, key: String, label: String): String =
        map[key]?.lastOrNull()?.takeIf { it.isNotBlank() } ?: throw ParseException(UiText.of(R.string.upstream_wg_missing, label))

}
