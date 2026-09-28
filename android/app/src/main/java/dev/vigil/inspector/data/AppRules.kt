package dev.vigil.inspector.data

import dev.vigil.inspector.engine.AppDomainRuleConfig
import dev.vigil.inspector.engine.AppRuleConfig
import dev.vigil.inspector.engine.DeviceState
import kotlinx.serialization.Serializable

/**
 * When an app's network access is blocked, besides "always" (which is
 * [Settings.blockedPackages]). Evaluated by the engine against the device
 * state the VPN service pushes.
 */
@Serializable
data class AppRule(
    val blockWifi: Boolean = false,
    val blockCellular: Boolean = false,
    /** Needs usage access to know the foreground app (with the screen off every app is in the background). */
    val blockBackground: Boolean = false,
    val blockScreenOff: Boolean = false,
) {
    val isEmpty: Boolean get() = !blockWifi && !blockCellular && !blockBackground && !blockScreenOff

    /** Short description of the conditions, e.g. "on Wi-Fi, in the background". */
    fun describe(): String = listOfNotNull(
        "on Wi-Fi".takeIf { blockWifi },
        "on mobile data".takeIf { blockCellular },
        "in the background".takeIf { blockBackground },
        "with the screen off".takeIf { blockScreenOff },
    ).joinToString(", ")

    fun merge(o: AppRule) = AppRule(
        blockWifi = blockWifi || o.blockWifi,
        blockCellular = blockCellular || o.blockCellular,
        blockBackground = blockBackground || o.blockBackground,
        blockScreenOff = blockScreenOff || o.blockScreenOff,
    )
}

/** A domain (and its subdomains) allowed or blocked for one app ([app] is the app key). */
@Serializable
data class AppDomainRule(
    val app: String,
    val domain: String,
    /** [ALLOW] or [BLOCK]. */
    val action: String = BLOCK,
) {
    val isBlock: Boolean get() = action == BLOCK

    companion object {
        const val ALLOW = "allow"
        const val BLOCK = "block"
    }
}

/**
 * Pure helpers for the per-app rules: editing the settings lists and
 * resolving app keys to the UIDs the engine works with.
 */
object AppRules {
    fun rule(s: Settings, app: String): AppRule = s.appRules[app] ?: AppRule()

    /** Sets [app]'s conditions; an empty rule is removed. */
    fun setRule(s: Settings, app: String, rule: AppRule): Settings =
        s.copy(appRules = if (rule.isEmpty) s.appRules - app else s.appRules + (app to rule))

    fun domainRules(s: Settings, app: String): List<AppDomainRule> =
        s.appDomainRules.filter { it.app == app }.sortedBy { it.domain }

    /** The app's rule covering [host] (the most specific one), if any. */
    fun matchingDomainRule(s: Settings, app: String, host: String): AppDomainRule? {
        val h = host.lowercase().trimEnd('.')
        return s.appDomainRules.filter { it.app == app && (h == it.domain || h.endsWith(".${it.domain}")) }
            .maxByOrNull { it.domain.length }
    }

    /** Adds or replaces the rule for ([app], [domain]). */
    fun setDomainRule(s: Settings, app: String, domain: String, action: String): Settings {
        val d = normalize(domain)
        return s.copy(appDomainRules = s.appDomainRules.filterNot { it.app == app && it.domain == d } + AppDomainRule(app, d, action))
    }

    fun removeDomainRule(s: Settings, app: String, domain: String): Settings =
        s.copy(appDomainRules = s.appDomainRules.filterNot { it.app == app && it.domain == domain })

    fun normalize(domain: String): String = domain.trim().lowercase().removePrefix("*.").trimEnd('.')

    /**
     * The engine's `app_rules`. Rules are keyed by app (package or
     * `uid:<n>`); packages sharing a UID share one engine rule, so their
     * conditions are merged (any package's condition blocks the UID).
     * Apps that are not installed ([uidOf] null) are skipped.
     */
    fun engineRules(s: Settings, uidOf: (String) -> Int?): List<AppRuleConfig> =
        s.appRules.filterValues { !it.isEmpty }
            .mapNotNull { (app, r) -> uidOf(app)?.let { it to r } }
            .groupBy({ it.first }, { it.second })
            .map { (uid, rules) ->
                val r = rules.reduce(AppRule::merge)
                AppRuleConfig(uid, r.blockWifi, r.blockCellular, r.blockBackground, r.blockScreenOff)
            }
            .sortedBy { it.uid }

    /** The engine's `app_domain_rules` (shared UIDs: a rule applies to every package of the UID). */
    fun engineDomainRules(s: Settings, uidOf: (String) -> Int?): List<AppDomainRuleConfig> =
        s.appDomainRules.mapNotNull { r -> uidOf(r.app)?.let { AppDomainRuleConfig(it, r.domain, r.action) } }
            .distinct()
            .sortedWith(compareBy({ it.uid }, { it.domain }, { it.action }))

    /** Whether any app has a background condition (the foreground app must then be tracked). */
    fun needsForeground(s: Settings): Boolean = s.appRules.values.any { it.blockBackground }

    /**
     * The state pushed to the engine. The foreground app is only looked up
     * when a background rule exists ([needsForeground]) and the screen is
     * on (off: no app is in the foreground). [foregroundPackage] returns ""
     * for none and null when unknown (no usage access): background rules
     * then cannot apply, which the app detail screen points out.
     */
    fun deviceState(
        network: String,
        screenOn: Boolean,
        needsForeground: Boolean,
        foregroundPackage: () -> String?,
        uidOf: (String) -> Int?,
    ): DeviceState {
        val fg = when {
            !needsForeground -> null
            !screenOn -> emptyList()
            else -> foregroundPackage()?.let { pkg -> if (pkg.isEmpty()) emptyList() else listOfNotNull(uidOf(pkg)) }
        }
        return DeviceState(network, screenOn, fg)
    }
}
