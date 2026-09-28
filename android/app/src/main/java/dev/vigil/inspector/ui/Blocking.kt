package dev.vigil.inspector.ui

import dev.vigil.inspector.data.FeedEntity

/**
 * Registrable domains ("eTLD+1") without the full Public Suffix List: a
 * compact list of common multi-label public suffixes (country second-level
 * domains) and of shared hosting suffixes where every subdomain has a
 * different owner. Good enough to offer "block the whole site" next to
 * "block this host"; when unsure it offers nothing wider than the host.
 */
object DomainNames {
    /** Public suffixes of two labels (the last label alone is always one). */
    private val MULTI_LABEL_SUFFIXES = setOf(
        // United Kingdom, Australia, New Zealand, South Africa, Ireland
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "nhs.uk", "police.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
        "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz", "school.nz",
        "co.za", "org.za", "gov.za", "ac.za", "net.za", "web.za",
        // Asia
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "gr.jp", "ed.jp", "ad.jp", "lg.jp",
        "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr", "re.kr",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
        "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk",
        "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw", "idv.tw",
        "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in", "gen.in", "ind.in",
        "com.sg", "org.sg", "net.sg", "edu.sg", "gov.sg",
        "com.my", "org.my", "net.my", "gov.my", "edu.my",
        "co.id", "or.id", "ac.id", "go.id", "web.id", "net.id",
        "co.th", "or.th", "ac.th", "go.th", "in.th", "net.th",
        "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
        "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
        "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
        "com.bd", "net.bd", "org.bd", "gov.bd",
        "co.il", "org.il", "net.il", "ac.il", "gov.il", "muni.il",
        "com.sa", "gov.sa", "edu.sa", "net.sa", "org.sa",
        "com.tr", "org.tr", "net.tr", "gov.tr", "edu.tr", "gen.tr", "biz.tr",
        // Americas
        "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br",
        "com.mx", "org.mx", "gob.mx", "edu.mx", "net.mx",
        "com.ar", "org.ar", "gob.ar", "net.ar", "edu.ar",
        "com.co", "org.co", "gov.co", "edu.co", "net.co",
        "com.pe", "org.pe", "gob.pe", "edu.pe",
        "com.ve", "org.ve", "gob.ve",
        // Europe, Africa
        "com.ua", "net.ua", "org.ua", "gov.ua", "in.ua",
        "com.pl", "net.pl", "org.pl",
        "co.at", "or.at", "ac.at", "gv.at",
        "com.es", "org.es", "nom.es", "gob.es", "edu.es",
        "com.pt", "org.pt", "gov.pt",
        "com.gr", "gov.gr", "edu.gr",
        "com.ng", "org.ng", "gov.ng", "edu.ng",
        "com.eg", "gov.eg", "edu.eg",
        "co.ke", "or.ke", "go.ke", "ac.ke",
        // Shared hosting: each subdomain is a different site.
        "github.io", "gitlab.io", "herokuapp.com", "appspot.com", "blogspot.com", "netlify.app", "vercel.app",
        "pages.dev", "workers.dev", "r2.dev", "firebaseapp.com", "web.app", "fly.dev", "onrender.com", "glitch.me",
        "ngrok.io", "ngrok-free.app", "duckdns.org", "ddns.net", "no-ip.org", "myshopify.com", "wordpress.com",
        "tumblr.com", "azurewebsites.net", "cloudapp.net", "translate.goog",
    )

    /**
     * Infrastructure domains whose subdomains belong to unrelated customers
     * (cloud storage, CDNs): never offer anything wider than the host.
     */
    private val NEVER_WIDEN = setOf(
        "amazonaws.com", "cloudfront.net", "akamaized.net", "akamaihd.net", "akamaiedge.net", "edgekey.net",
        "edgesuite.net", "azureedge.net", "trafficmanager.net", "googleusercontent.com", "googleapis.com",
        "fastly.net", "fastlylb.net", "cloudflare.net", "b-cdn.net", "digitaloceanspaces.com",
        "windows.net", "core.windows.net", "blob.core.windows.net", "cdn77.org",
    )

    private val IPV4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")

    fun isIpLiteral(s: String): Boolean = IPV4.matches(s) || (s.contains(':') && s.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' || it == ':' || it == '.' })

    /** A DNS name vigil can have a rule for: at least two labels, not an address. Leading digits are fine (163.com). */
    fun isDomainName(s: String): Boolean {
        if (s.length > 253 || isIpLiteral(s)) return false
        val labels = s.split('.')
        if (labels.size < 2) return false
        return labels.all { it.isNotEmpty() && it.length <= 63 && it.all { c -> c.isLetterOrDigit() || c == '-' || c == '_' } } &&
            labels.last().any { it.isLetter() }
    }

    /**
     * The registrable domain of [host] (e.g. `api.shop.example.co.uk` →
     * `example.co.uk`), or null for addresses and bare suffixes. Returns
     * [host] itself for hosts under a shared infrastructure domain.
     */
    fun registrable(host: String): String? {
        val h = host.trim().trimEnd('.').lowercase()
        if (!isDomainName(h)) return null
        if (NEVER_WIDEN.any { h == it || h.endsWith(".$it") }) return h.takeIf { it !in NEVER_WIDEN }
        val labels = h.split('.')
        val suffixLabels = when {
            labels.size >= 2 && labels.takeLast(2).joinToString(".") in MULTI_LABEL_SUFFIXES -> 2
            else -> 1
        }
        if (labels.size <= suffixLabels) return null
        return labels.takeLast(suffixLabels + 1).joinToString(".")
    }

    /**
     * The names to offer for blocking [host]: the host itself and, when it
     * differs, its registrable domain.
     */
    fun blockChoices(host: String): List<String> {
        val h = host.trim().trimEnd('.').lowercase()
        if (!isDomainName(h)) return emptyList()
        val site = registrable(h)
        return if (site != null && site != h) listOf(h, site) else listOf(h)
    }

    /** The user rule (domain or parent) that matches [host] in [rules], if any. */
    fun matchingRule(host: String, rules: Collection<String>): String? {
        val h = host.lowercase()
        return rules.filter { h == it || h.endsWith(".$it") }.maxByOrNull { it.length }
    }
}

/** Plain-words explanations of the engine's block `reason` strings (see policy.rs `BlockReason::describe`). */
object BlockReasons {
    /**
     * [reason] is `feed:<id> (<rule>)`, `custom (<rule>)`, `app`, `ja4:<feed> (<rule>)`,
     * optionally with ` via CNAME <name>` inside the rule.
     */
    fun explain(reason: String?, feeds: List<FeedEntity>, appLabel: String? = null): String {
        if (reason.isNullOrBlank()) return "Blocked (no reason recorded)."
        val code = reason.substringBefore(' ').trim()
        val rule = reason.substringAfter('(', "").substringBeforeLast(')', "").ifBlank { null }
        val cname = rule?.substringAfter(" via CNAME ", "")?.ifBlank { null }
        val listed = rule?.substringBefore(" via CNAME ")?.ifBlank { null }
        val via = cname?.let { " The name is an alias (CNAME) of $it, which is listed." }.orEmpty()
        return when {
            code == "app" -> "All network access is blocked for ${appLabel ?: "this app"} (Apps → block all network access)."
            code == "custom" -> "Your block rule${listed?.let { " for $it" }.orEmpty()} (Settings → Custom rules).$via"
            code.startsWith("feed:") -> {
                val id = code.removePrefix("feed:")
                val feed = feeds.firstOrNull { it.id == id }
                val name = feed?.name ?: id
                val category = feed?.category?.let { " ($it)" }.orEmpty()
                "Listed by the feed “$name”$category${listed?.let { " as $it" }.orEmpty()}.$via"
            }
            code.startsWith("ja4:") -> "Its TLS fingerprint is listed by the JA4 feed ${code.removePrefix("ja4:")}" +
                (listed?.let { " ($it)" }.orEmpty()) + ", and blocking JA4 matches is on."
            else -> reason
        }
    }
}
