package dev.vigil.inspector.data

/**
 * Hosts of shared platforms (code hosting, file sharing, cloud storage,
 * messaging, URL shorteners, big web properties). An indicator on one of
 * them would block or flag a whole platform used by everyone, so indicator
 * sources never turn them into domain indicators: spyware packs drop such
 * domains, and TAXII keeps a URL indicator's host only when it is not one
 * (`https://github.com/x/y/a.apk` must not put github.com in a threat feed).
 */
object SharedPlatforms {
    /**
     * Platforms whose every subdomain is shared too: a host equal to or under
     * one of these is shared (`raw.githubusercontent.com`, `drive.google.com`,
     * `cdn.discordapp.com`, `dl.dropboxusercontent.com`…).
     */
    val TREES = setOf(
        // Google
        "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com", "youtube.com", "youtu.be", "goo.gl", "g.co",
        // Code hosting and software distribution
        "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "sourceforge.net", "codeberg.org",
        "apkpure.com", "apkmirror.com", "uptodown.com", "archive.org",
        // Apple, Microsoft
        "apple.com", "icloud.com", "icloud-content.com", "microsoft.com", "live.com", "onedrive.com", "1drv.ms", "office.com",
        // Meta, messaging, social
        "facebook.com", "fbcdn.net", "fb.me", "instagram.com", "whatsapp.com", "whatsapp.net", "wa.me",
        "telegram.org", "telegram.me", "t.me", "discord.com", "discordapp.com", "discordapp.net", "discord.gg",
        "twitter.com", "x.com", "t.co", "tiktok.com", "reddit.com", "linkedin.com", "lnkd.in",
        // File sharing and paste sites
        "dropbox.com", "dropboxusercontent.com", "db.tt", "mega.nz", "mega.io", "mediafire.com", "box.com",
        "wetransfer.com", "we.tl", "pastebin.com", "anonfiles.com", "transfer.sh",
        // URL shorteners
        "bit.ly", "tinyurl.com", "is.gd", "ow.ly", "rebrand.ly", "cutt.ly",
        // Infrastructure and big web properties
        "cloudflare.com", "amazon.com", "yandex.ru", "yandex.com",
    )

    /**
     * Hosting platforms whose subdomains belong to individual customers
     * (`evil.herokuapp.com`, `bucket.s3.amazonaws.com`): only the platform
     * itself (and its `www.`) is shared; a customer's subdomain stays a
     * valid indicator.
     */
    val APEXES = setOf(
        "github.io", "gitlab.io", "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "appspot.com", "firebaseio.com",
        "firebaseapp.com", "web.app", "azurewebsites.net", "windows.net", "core.windows.net", "blob.core.windows.net",
        "sharepoint.com", "pages.dev", "workers.dev", "herokuapp.com", "netlify.app", "vercel.app", "blogspot.com",
        "wordpress.com", "000webhostapp.com", "glitch.me", "onrender.com", "ngrok.io", "ngrok-free.app", "duckdns.org",
        "no-ip.com", "ddns.net", "weebly.com", "wixsite.com",
    )

    /** True if [host] (a normalised lower-case domain) is a shared platform. */
    fun isShared(host: String): Boolean {
        val h = host.lowercase().trimEnd('.')
        if (h in APEXES || h.removePrefix("www.") in APEXES) return true
        var d = h
        while (true) {
            if (d in TREES) return true
            val dot = d.indexOf('.')
            if (dot < 0) return false
            d = d.substring(dot + 1)
        }
    }
}
