package dev.vigil.inspector.data

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
    class ParseException(message: String) : Exception(message)

    data class Parsed(val settings: WireGuardSettings, val warnings: List<String>)

    private const val MAX_TEXT = 64 * 1024

    fun parse(text: String, name: String = ""): Parsed {
        if (text.length > MAX_TEXT) throw ParseException("The file is too large for a WireGuard configuration.")
        val warnings = mutableListOf<String>()
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
                    "peer" -> if (++peers == 2) warnings += "Only the first [Peer] is used."
                    else -> warnings += "Unknown section [$section] ignored."
                }
                return@forEachIndexed
            }
            val eq = line.indexOf('=')
            if (eq <= 0) throw ParseException("Line ${i + 1} is not \"Key = Value\".")
            val key = line.substring(0, eq).trim().lowercase()
            spelled.putIfAbsent(key, line.substring(0, eq).trim())
            val value = line.substring(eq + 1).trim()
            when (section) {
                "interface" -> iface.getOrPut(key) { mutableListOf() } += value
                "peer" -> if (peers == 1) peer.getOrPut(key) { mutableListOf() } += value
                null -> throw ParseException("Line ${i + 1} is outside a section.")
            }
        }
        if (iface.isEmpty()) throw ParseException("No [Interface] section.")
        if (peers == 0) throw ParseException("No [Peer] section.")

        for (k in iface.keys - setOf("privatekey", "address", "dns", "mtu")) warnings += "[Interface] ${spelled[k] ?: k} ignored."
        for (k in peer.keys - setOf("publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive")) warnings += "[Peer] ${spelled[k] ?: k} ignored."

        val privateKey = single(iface, "privatekey", "[Interface] PrivateKey")
        if (!isKey(privateKey)) throw ParseException("[Interface] PrivateKey is not a WireGuard key.")
        val publicKey = single(peer, "publickey", "[Peer] PublicKey")
        if (!isKey(publicKey)) throw ParseException("[Peer] PublicKey is not a WireGuard key.")
        val psk = peer["presharedkey"]?.lastOrNull()
        if (psk != null && !isKey(psk)) throw ParseException("[Peer] PresharedKey is not a WireGuard key.")

        val endpoint = single(peer, "endpoint", "[Peer] Endpoint")
        if (!isEndpoint(endpoint)) throw ParseException("[Peer] Endpoint \"$endpoint\" is not host:port.")

        val addresses = list(iface["address"]).map {
            normalizeCidr(it) ?: throw ParseException("[Interface] Address \"$it\" is not an IP address.")
        }
        if (addresses.isEmpty()) throw ParseException("[Interface] Address is missing.")
        val v4 = addresses.filter { !it.contains(':') }
        val v6 = addresses.filter { it.contains(':') }
        if (v4.size > 1 || v6.size > 1) warnings += "Only the first IPv4 and the first IPv6 address are used."
        val usedAddresses = listOfNotNull(v4.firstOrNull(), v6.firstOrNull())

        val dnsEntries = list(iface["dns"])
        val dns = dnsEntries.filter { IpLiteral.isV4(it) || IpLiteral.isV6(it) }
        if (dns.size < dnsEntries.size) warnings += "DNS search domains ignored."

        val mtu = iface["mtu"]?.lastOrNull()?.let {
            it.toIntOrNull()?.takeIf { m -> m in 576..65535 } ?: throw ParseException("[Interface] MTU \"$it\" is not a number between 576 and 65535.")
        }
        val allowed = list(peer["allowedips"]).map {
            normalizeCidr(it) ?: throw ParseException("[Peer] AllowedIPs \"$it\" is not a CIDR range.")
        }
        val keepalive = peer["persistentkeepalive"]?.lastOrNull()?.let {
            if (it.equals("off", ignoreCase = true)) 0
            else it.toIntOrNull()?.takeIf { k -> k in 0..65535 } ?: throw ParseException("[Peer] PersistentKeepalive \"$it\" is not a number.")
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
        map[key]?.lastOrNull()?.takeIf { it.isNotBlank() } ?: throw ParseException("$label is missing.")

}
