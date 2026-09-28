package dev.vigil.inspector.data

/** Built-in feeds. URLs verified to serve formats vigil parses. */
object FeedCatalog {
    private const val HAGEZI = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main"

    val builtin: List<FeedEntity> = listOf(
        feed("hagezi-tif-medium", "HaGeZi Threat Intelligence (medium)", "$HAGEZI/wildcard/tif.medium-onlydomains.txt", "malware", true,
            "Malware, phishing, scam and C2 domains aggregated from many threat feeds (~850k domains)."),
        feed("urlhaus", "abuse.ch URLhaus", "https://urlhaus.abuse.ch/downloads/hostfile/", "malware", true,
            "Domains currently distributing malware."),
        feed("threatfox", "abuse.ch ThreatFox", "https://threatfox.abuse.ch/downloads/hostfile/", "c2", true,
            "Indicators of compromise: botnet C2 and malware infrastructure."),
        feed("feodo", "abuse.ch Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "c2", true,
            "IP addresses of active botnet command-and-control servers."),
        feed("phishing-army", "Phishing Army", "https://phishing.army/download/phishing_army_blocklist.txt", "phishing", false,
            "Phishing domains (extended list)."),
        feed("hagezi-tif-ips", "HaGeZi Threat IPs", "$HAGEZI/ips/tif.txt", "malware", false,
            "Malicious IP addresses (~29k)."),
        feed("spamhaus-drop", "Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt", "malware", false,
            "Netblocks hijacked or leased by professional spam and cyber-crime operations."),
        feed("hagezi-tif-full", "HaGeZi Threat Intelligence (full)", "$HAGEZI/wildcard/tif-onlydomains.txt", "malware", false,
            "Complete threat feed (~2.3M domains, ~60 MB RAM). Use instead of the medium list on high-memory devices."),
        feed("hagezi-pro", "HaGeZi Pro", "$HAGEZI/wildcard/pro-onlydomains.txt", "ads", false,
            "Ads, trackers, telemetry and badware (~230k domains)."),
        feed("adguard-dns", "AdGuard DNS filter", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "ads", false,
            "AdGuard's DNS-level ad and tracker filter."),
        feed("stevenblack", "StevenBlack unified hosts", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "ads", false,
            "Consolidated hosts file of ad and malware domains."),
        feed("disconnect", "Disconnect tracking", "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt", "tracking", false,
            "Disconnect's basic tracking list."),
        feed("native-samsung", "Samsung telemetry", "$HAGEZI/wildcard/native.samsung-onlydomains.txt", "tracking", false,
            "Native tracking and telemetry of Samsung devices."),
        feed("native-xiaomi", "Xiaomi telemetry", "$HAGEZI/wildcard/native.xiaomi-onlydomains.txt", "tracking", false,
            "Native tracking and telemetry of Xiaomi devices."),
        feed("native-huawei", "Huawei telemetry", "$HAGEZI/wildcard/native.huawei-onlydomains.txt", "tracking", false,
            "Native tracking and telemetry of Huawei devices."),
        feed("native-oppo", "OPPO / Realme telemetry", "$HAGEZI/wildcard/native.oppo-realme-onlydomains.txt", "tracking", false,
            "Native tracking and telemetry of OPPO and Realme devices."),
        feed("native-vivo", "Vivo telemetry", "$HAGEZI/wildcard/native.vivo-onlydomains.txt", "tracking", false,
            "Native tracking and telemetry of Vivo devices."),
        feed("native-tiktok", "TikTok telemetry", "$HAGEZI/wildcard/native.tiktok-onlydomains.txt", "tracking", false,
            "TikTok's tracking and telemetry endpoints."),
        feed("native-amazon", "Amazon telemetry", "$HAGEZI/wildcard/native.amazon-onlydomains.txt", "tracking", false,
            "Amazon device and app telemetry."),
        // FoxIO's sample JA4+ mapping: the only openly downloadable JA4 list with malware entries (ja4db.com now
        // needs an account). Converted at download time; only rows naming malware or C2 tooling are kept.
        // Off by default: a handful of entries, and the Sliver fingerprint is also Go's default TLS client.
        FeedEntity(
            id = "foxio-ja4-mapping", name = "FoxIO JA4+ mapping (malware rows)",
            url = "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv",
            category = "ja4", enabled = false, builtin = true, kind = FeedKinds.JA4, format = Ja4Converters.FORMAT_FOXIO_MAPPING,
            description = "JA4 fingerprints of Sliver, Cobalt Strike and IcedID from FoxIO's reference mapping. " +
                "Small and prone to false positives: Sliver's fingerprint is Go's default TLS client, which some " +
                "legitimate apps also use.",
        ),
        // Offline IP → ASN table. Public domain (PDDL 1.0), so it may be downloaded and used without conditions;
        // vigil credits the source anyway. On by default: it only labels connections and never blocks.
        FeedEntity(
            id = "iptoasn", name = "IP to ASN (iptoasn.com)", url = "https://iptoasn.com/data/ip2asn-combined.tsv.gz",
            category = AsnDatabase.CATEGORY, enabled = true, builtin = true, kind = FeedKinds.ASN, format = AsnDatabase.FORMAT_IPTOASN,
            description = "Names the network (autonomous system) behind each connection, e.g. \"AS13335 CLOUDFLARENET\", and " +
                "enables new-network alerts. Downloaded weekly (≈ 9 MB, ≈ 10 MB of memory while inspecting). " +
                "Data: iptoasn.com, public domain (PDDL 1.0).",
        ),
        // Tracker-company labels (AdGuard companiesdb, CC BY-SA 4.0). Downloaded by the device from AdGuard's
        // repository, not redistributed. On by default: it only labels destinations and never blocks.
        FeedEntity(
            id = TrackerDatabase.FEED_ID, name = "Tracker labels (AdGuard companiesdb)", url = TrackerDatabase.TRACKERS_URL,
            category = TrackerDatabase.CATEGORY, enabled = true, builtin = true, kind = FeedKinds.TRACKERS,
            format = TrackerDatabase.FORMAT_ADGUARD,
            description = "Names the company and kind of tracker behind a domain, e.g. \"Google · Advertising\", and lists the " +
                "tracker companies each app contacts. Labels only: nothing is blocked. Downloaded weekly (≈ 1.5 MB). " +
                "Data: ${TrackerDatabase.ATTRIBUTION}.",
        ),
    )

    val categories = listOf("malware", "phishing", "c2", "ja4", "tracking", "ads", "custom", AsnDatabase.CATEGORY, TrackerDatabase.CATEGORY)

    private fun feed(id: String, name: String, url: String, category: String, enabled: Boolean, description: String) =
        FeedEntity(id = id, name = name, url = url, category = category, enabled = enabled, builtin = true, description = description)
}
