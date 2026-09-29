package dev.vigil.inspector.data

import dev.vigil.inspector.R
import dev.vigil.inspector.ui.UiText

/**
 * Built-in feeds. URLs verified to serve formats vigil parses. The English
 * descriptions are what Room stores; the screen shows [descriptionText].
 */
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
    ) + spyware()

    // --- Spyware & stalkerware (FeedKinds.SPYWARE*) -----------------------------------------------
    // Downloaded by the device from the publishers, never redistributed. The MVT index adds one feed
    // per listed pack when it is downloaded (MvtIndex). Network indicators load as `malware`, so hits
    // raise threat alerts and are blocked; app packages and certificates are for the health check.
    const val ECHAP_REPO = "https://github.com/AssoEchap/stalkerware-indicators"
    private const val ECHAP_RAW = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master"
    const val ECHAP_LICENSE = "CC BY 4.0 (Echap)"
    const val MVT_INDEX_ID = "mvt-index"

    /** Licence and reference of the fixed spyware feeds (the MVT packs carry theirs, see [MvtIndex]). */
    val spywareSources: Map<String, Pair<String, String>> = mapOf(
        "echap-stalkerware-network" to (ECHAP_LICENSE to ECHAP_REPO),
        "echap-stalkerware-apps" to (ECHAP_LICENSE to ECHAP_REPO),
        "echap-watchware" to (ECHAP_LICENSE to ECHAP_REPO),
        MVT_INDEX_ID to ("MIT (MVT project)" to "https://github.com/mvt-project/mvt-indicators"),
    )

    private fun spyware() = listOf(
        FeedEntity(
            id = "echap-stalkerware-network", name = "Stalkerware network indicators (Echap)", url = "$ECHAP_RAW/generated/network.csv",
            category = "malware", enabled = true, builtin = true, kind = FeedKinds.SPYWARE, format = SpywareConverters.FORMAT_ECHAP_NETWORK_CSV,
            description = "Servers and websites of about 150 stalkerware apps (≈ 1,000 domains and IPs), labelled per app. " +
                "Data: Echap, CC BY 4.0.",
        ),
        FeedEntity(
            id = "echap-stalkerware-apps", name = "Stalkerware apps (Echap)", url = "$ECHAP_RAW/ioc.yaml",
            category = "malware", enabled = true, builtin = true, kind = FeedKinds.SPYWARE_APPS, format = SpywareConverters.FORMAT_ECHAP_IOC_YAML,
            description = "Package names and signing certificates of stalkerware apps, for the health check (≈ 100 KB). " +
                "Data: Echap, CC BY 4.0.",
        ),
        FeedEntity(
            id = "echap-watchware", name = "Monitoring apps (Echap watchware)", url = "$ECHAP_RAW/watchware.yaml",
            category = "malware", enabled = true, builtin = true, kind = FeedKinds.SPYWARE_APPS, format = SpywareConverters.FORMAT_ECHAP_WATCHWARE_YAML,
            description = "Legitimate parental-control and monitoring apps that can also be misused. The health check reports " +
                "them as warnings; they never raise alerts. Data: Echap, CC BY 4.0.",
        ),
        FeedEntity(
            id = MVT_INDEX_ID, name = "MVT spyware indicator packs", url = MvtIndex.URL,
            category = "malware", enabled = true, builtin = true, kind = FeedKinds.SPYWARE_INDEX, format = SpywareConverters.FORMAT_MVT_INDEX,
            description = "The list of mercenary-spyware packs published for the Mobile Verification Toolkit (Pegasus, Predator " +
                "and others, by Amnesty International, Citizen Lab and others). Adds one feed per pack below. Index: MIT.",
        ),
    )

    /** Stored descriptions of the feeds the user adds (see [FeedRepository]). */
    const val CUSTOM_DESCRIPTION = "Custom feed"
    const val CUSTOM_JA4_DESCRIPTION = "Custom JA4 feed"
    private const val TAXII_PREFIX = "TAXII 2.1 collection “"
    private const val TAXII_SUFFIX = "”"

    fun taxiiDescription(title: String) = "$TAXII_PREFIX$title$TAXII_SUFFIX"

    /** Translated descriptions of the built-in feeds, by feed id. */
    private val descriptionIds: Map<String, Int> = mapOf(
        "hagezi-tif-medium" to R.string.feeds_desc_hagezi_tif_medium,
        "urlhaus" to R.string.feeds_desc_urlhaus,
        "threatfox" to R.string.feeds_desc_threatfox,
        "feodo" to R.string.feeds_desc_feodo,
        "phishing-army" to R.string.feeds_desc_phishing_army,
        "hagezi-tif-ips" to R.string.feeds_desc_hagezi_tif_ips,
        "spamhaus-drop" to R.string.feeds_desc_spamhaus_drop,
        "hagezi-tif-full" to R.string.feeds_desc_hagezi_tif_full,
        "hagezi-pro" to R.string.feeds_desc_hagezi_pro,
        "adguard-dns" to R.string.feeds_desc_adguard_dns,
        "stevenblack" to R.string.feeds_desc_stevenblack,
        "disconnect" to R.string.feeds_desc_disconnect,
        "native-samsung" to R.string.feeds_desc_native_samsung,
        "native-xiaomi" to R.string.feeds_desc_native_xiaomi,
        "native-huawei" to R.string.feeds_desc_native_huawei,
        "native-oppo" to R.string.feeds_desc_native_oppo,
        "native-vivo" to R.string.feeds_desc_native_vivo,
        "native-tiktok" to R.string.feeds_desc_native_tiktok,
        "native-amazon" to R.string.feeds_desc_native_amazon,
        "foxio-ja4-mapping" to R.string.feeds_desc_foxio_ja4_mapping,
        "iptoasn" to R.string.feeds_desc_iptoasn,
        TrackerDatabase.FEED_ID to R.string.feeds_desc_trackers,
        "echap-stalkerware-network" to R.string.feeds_desc_echap_network,
        "echap-stalkerware-apps" to R.string.feeds_desc_echap_apps,
        "echap-watchware" to R.string.feeds_desc_echap_watchware,
        MVT_INDEX_ID to R.string.feeds_desc_mvt_index,
    )

    /** Translated names of the built-in feeds whose name describes them; the others are product names. */
    private val nameIds: Map<String, Int> = mapOf(
        "native-samsung" to R.string.feeds_name_native_samsung,
        "native-xiaomi" to R.string.feeds_name_native_xiaomi,
        "native-huawei" to R.string.feeds_name_native_huawei,
        "native-oppo" to R.string.feeds_name_native_oppo,
        "native-vivo" to R.string.feeds_name_native_vivo,
        "native-tiktok" to R.string.feeds_name_native_tiktok,
        "native-amazon" to R.string.feeds_name_native_amazon,
        "disconnect" to R.string.feeds_name_disconnect,
        "foxio-ja4-mapping" to R.string.feeds_name_foxio_ja4_mapping,
        "iptoasn" to R.string.feeds_name_iptoasn,
        TrackerDatabase.FEED_ID to R.string.feeds_name_trackers,
        "echap-stalkerware-network" to R.string.feeds_name_echap_network,
        "echap-stalkerware-apps" to R.string.feeds_name_echap_apps,
        "echap-watchware" to R.string.feeds_name_echap_watchware,
        MVT_INDEX_ID to R.string.feeds_name_mvt_index,
    )

    /** The name of [f] to show: translated for descriptive built-in names, else the stored name. */
    fun nameText(f: FeedEntity): UiText = (if (f.builtin) nameIds[f.id] else null)?.let { UiText.of(it) } ?: UiText.Raw(f.name)

    /**
     * The description of [f] in the app's language: built-in and custom feeds
     * are translated; others (MVT packs, which describe themselves) show the
     * stored text. Null when there is none.
     */
    fun descriptionText(f: FeedEntity): UiText? {
        val builtinId = if (f.builtin) descriptionIds[f.id] else null
        val d = f.description
        return when {
            builtinId == R.string.feeds_desc_trackers -> UiText.of(builtinId, TrackerDatabase.ATTRIBUTION)
            builtinId != null -> UiText.of(builtinId)
            f.builtin -> null
            f.kind == FeedKinds.LIST && d == CUSTOM_DESCRIPTION -> UiText.of(R.string.feeds_desc_custom)
            f.kind == FeedKinds.JA4 && d == CUSTOM_JA4_DESCRIPTION -> UiText.of(R.string.feeds_desc_custom_ja4)
            f.isTaxii && d.startsWith(TAXII_PREFIX) && d.endsWith(TAXII_SUFFIX) ->
                UiText.of(R.string.feeds_desc_taxii, d.removePrefix(TAXII_PREFIX).removeSuffix(TAXII_SUFFIX))
            else -> null
        } ?: d.takeIf { it.isNotEmpty() }?.let { UiText.Raw(it) }
    }

    val categories = listOf("malware", "phishing", "c2", "ja4", "tracking", "ads", "custom", AsnDatabase.CATEGORY, TrackerDatabase.CATEGORY)

    private fun feed(id: String, name: String, url: String, category: String, enabled: Boolean, description: String) =
        FeedEntity(id = id, name = name, url = url, category = category, enabled = enabled, builtin = true, description = description)
}
