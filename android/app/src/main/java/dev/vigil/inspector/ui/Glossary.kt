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
    const val BEACONING_IN_CONNECTION =
        "Beaconing inside a connection: the app keeps one connection open and sends a small burst of data through it at " +
            "a near-constant interval, instead of reconnecting each time. Malware does this to check in with its " +
            "command-and-control (C2) server while hiding among long-lived connections. Push services (Firebase Cloud " +
            "Messaging, Apple push) and chat apps also keep connections alive, but their keep-alive pings are tiny; vigil " +
            "skips known push services and bursts too small to carry a request."
    const val EXFILTRATION =
        "Exfiltration: sending data off the device without the user asking for it, for example stolen photos, contacts " +
            "or messages. vigil alerts when an app uploads far more than usual while it is in the background: more than " +
            "the absolute floor, several times its own busiest hour of the past week, and mostly one-way (much more sent " +
            "than received). Backups and photo sync can look like this; apps whose job is uploading are skipped, and " +
            "the baseline learns an app's regular uploads."
    const val C2 =
        "Command and control: servers that malware contacts to receive instructions or send stolen data."
    const val ECS =
        "Elastic Common Schema: standard field names (event.*, source.*, destination.*, dns.*) that Elastic, Splunk " +
            "and Sentinel map without custom parsing."
}
