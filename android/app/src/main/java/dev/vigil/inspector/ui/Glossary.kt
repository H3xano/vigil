package dev.vigil.inspector.ui

/** Short explanations for the technical terms shown in the UI. */
object Glossary {
    const val SNI =
        "Server Name Indication: the site name an app sends in clear text at the start of a TLS or QUIC connection. " +
            "vigil reads it to name encrypted connections without decrypting them."
    const val NAME_SOURCE =
        "Where vigil learned the destination name. SNI and the HTTP Host header come from the connection itself. " +
            "\"Earlier DNS answer\" is only a hint: the app looked this name up and got this IP, but other sites may share it."
    const val ALPN =
        "Application-Layer Protocol Negotiation: the protocols the app offers inside TLS, such as h2 (HTTP/2), " +
            "h3 (HTTP/3) or http/1.1."
    const val JA4 =
        "A fingerprint of how the app's TLS library opens connections (versions, cipher suites, extensions). " +
            "The same app usually produces the same JA4, and malware families are often recognisable by theirs."
    const val JA4_MATCH =
        "The app's TLS or QUIC handshake has a JA4 fingerprint that a threat feed lists, for example as a malware " +
            "family or attack framework (Sliver, Cobalt Strike…). vigil compares the fingerprint of every connection's " +
            "ClientHello with the enabled JA4 feeds, without decrypting anything.\n\n" +
            "A match is a lead, not proof. JA4 describes the TLS library and its settings, not the program: legitimate " +
            "software built on the same library can produce exactly the same fingerprint (Sliver's, for instance, is " +
            "also Go's default TLS client). Check which app made the connection and where it went. That is why matches " +
            "only raise an alert unless you turn on blocking; allowlisted domains are never blocked for their fingerprint."
    const val TAXII =
        "TAXII 2.1 is the standard API for sharing threat intelligence as STIX 2.1 objects; MISP, OpenCTI and many " +
            "commercial platforms serve it. vigil polls the chosen collection with the feed updates, only fetching objects " +
            "added since the last poll (and a full copy weekly). It uses indicators whose patterns compare a domain, IP " +
            "address or range, URL (its host) or JA4 fingerprint, plus domain and IP objects; revoked and expired " +
            "indicators are dropped. Other pattern types (file hashes, email…) are ignored."
    const val ECH =
        "Encrypted Client Hello hides the real site name from the network. Only the provider's public name is visible."
    const val SINKHOLE =
        "How vigil answers DNS lookups of blocked names. 0.0.0.0 / :: returns an address that goes nowhere, so apps fail " +
            "fast and rarely retry. NXDOMAIN says the name does not exist; some apps then retry or fall back to other resolvers."
    const val BEACONING =
        "Connections to the same destination at a near-constant interval. Malware checks in with its command-and-control " +
            "(C2) server this way, but so do many legitimate telemetry and sync services."
    const val C2 =
        "Command and control: servers that malware contacts to receive instructions or send stolen data."
    const val ASN =
        "An autonomous system (AS) is one network on the internet: a provider, cloud, company or university that " +
            "announces its own blocks of IP addresses, identified by a number (ASN), e.g. AS13335 is Cloudflare and " +
            "AS15169 Google. vigil looks up each connection's address in an offline copy of the routing table " +
            "(iptoasn.com, public domain), so no lookup leaves the device. The country is where the network is " +
            "registered, not where the server stands. A cloud or CDN network hosts many unrelated sites, so the AS says " +
            "who carries the traffic, not who runs the site."
    const val NEW_ASN =
        "The app connected to a network (autonomous system) it had never used since vigil started watching it. Most " +
            "apps talk to a small, stable set of networks: their own servers, a cloud provider, a CDN, analytics. A new " +
            "one can be an update, a new ad or CDN partner, or a user visiting a new site in a browser, but it can " +
            "also be data going somewhere unexpected. Alerts start after a learning period (7 days by default) and " +
            "are medium severity for apps that used only a few networks so far. $ASN"
    const val VIA =
        "The path vigil used for this connection: direct over the phone's network, through your WireGuard tunnel, or " +
            "through the SOCKS5 proxy (e.g. Tor). Destinations outside the WireGuard peer's AllowedIPs go direct."
    const val DNS_UPSTREAM =
        "How vigil forwarded the lookup to the resolver: UDP or TCP (plain DNS, readable by the network), DoT (DNS over " +
            "TLS) or DoH (DNS over HTTPS)."
    const val ECS =
        "Elastic Common Schema: standard field names (event.*, source.*, destination.*, dns.*) that Elastic, Splunk " +
            "and Sentinel map without custom parsing."
}
