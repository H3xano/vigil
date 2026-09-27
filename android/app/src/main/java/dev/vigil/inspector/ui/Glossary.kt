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
    const val ECS =
        "Elastic Common Schema: standard field names (event.*, source.*, destination.*, dns.*) that Elastic, Splunk " +
            "and Sentinel map without custom parsing."
}
