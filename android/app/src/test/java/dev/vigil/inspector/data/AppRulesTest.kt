package dev.vigil.inspector.data

import dev.vigil.inspector.R
import dev.vigil.inspector.engine.AppDomainRuleConfig
import dev.vigil.inspector.engine.AppRuleConfig
import dev.vigil.inspector.engine.DeviceState
import dev.vigil.inspector.ui.UiText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppRulesTest {
    /** Two packages share UID 10300; "gone.app" is not installed. */
    private val uids = mapOf("com.chat" to 10123, "com.shop" to 10124, "com.shared.a" to 10300, "com.shared.b" to 10300, "uid:10400" to 10400)
    private val uidOf: (String) -> Int? = { uids[it] }

    @Test
    fun editingRules() {
        var s = Settings()
        s = AppRules.setRule(s, "com.chat", AppRule(blockWifi = true))
        assertEquals(AppRule(blockWifi = true), AppRules.rule(s, "com.chat"))
        assertEquals(AppRule(), AppRules.rule(s, "com.other"))
        // A rule without conditions is removed rather than stored.
        s = AppRules.setRule(s, "com.chat", AppRule())
        assertTrue(s.appRules.isEmpty())

        s = AppRules.setDomainRule(s, "com.chat", " *.Ads.Example.com. ", AppDomainRule.BLOCK)
        assertEquals(listOf(AppDomainRule("com.chat", "ads.example.com", "block")), s.appDomainRules)
        // Same app and domain: replaced, not duplicated.
        s = AppRules.setDomainRule(s, "com.chat", "ads.example.com", AppDomainRule.ALLOW)
        assertEquals(listOf(AppDomainRule("com.chat", "ads.example.com", "allow")), s.appDomainRules)
        s = AppRules.setDomainRule(s, "com.chat", "example.com", AppDomainRule.BLOCK)
        s = AppRules.setDomainRule(s, "com.shop", "example.com", AppDomainRule.ALLOW)
        assertEquals(listOf("ads.example.com", "example.com"), AppRules.domainRules(s, "com.chat").map { it.domain })
        // The most specific rule of that app covers a host.
        assertEquals("ads.example.com", AppRules.matchingDomainRule(s, "com.chat", "x.ads.example.com")?.domain)
        assertEquals("example.com", AppRules.matchingDomainRule(s, "com.chat", "www.example.com")?.domain)
        assertNull(AppRules.matchingDomainRule(s, "com.chat", "notexample.com"))
        assertEquals("allow", AppRules.matchingDomainRule(s, "com.shop", "example.com")?.action)
        s = AppRules.removeDomainRule(s, "com.chat", "example.com")
        assertEquals(listOf("ads.example.com"), AppRules.domainRules(s, "com.chat").map { it.domain })
        assertEquals(1, AppRules.domainRules(s, "com.shop").size)
    }

    @Test
    fun resolutionToUids() {
        val s = Settings(
            appRules = mapOf(
                "com.chat" to AppRule(blockBackground = true),
                "com.shared.a" to AppRule(blockWifi = true),
                "com.shared.b" to AppRule(blockScreenOff = true),
                "gone.app" to AppRule(blockCellular = true),
                "uid:10400" to AppRule(blockCellular = true),
            ),
            appDomainRules = listOf(
                AppDomainRule("com.shop", "tracker.example", AppDomainRule.ALLOW),
                AppDomainRule("com.chat", "ads.example.com", AppDomainRule.BLOCK),
                AppDomainRule("com.shared.a", "x.example", AppDomainRule.BLOCK),
                AppDomainRule("com.shared.b", "x.example", AppDomainRule.BLOCK),
                AppDomainRule("gone.app", "y.example", AppDomainRule.BLOCK),
            ),
        )
        assertEquals(
            listOf(
                AppRuleConfig(10123, blockBackground = true),
                // Shared UID: both packages' conditions apply to the UID.
                AppRuleConfig(10300, blockWifi = true, blockScreenOff = true),
                AppRuleConfig(10400, blockCellular = true),
            ),
            AppRules.engineRules(s, uidOf),
        )
        assertEquals(
            listOf(
                AppDomainRuleConfig(10123, "ads.example.com", "block"),
                AppDomainRuleConfig(10124, "tracker.example", "allow"),
                AppDomainRuleConfig(10300, "x.example", "block"),
            ),
            AppRules.engineDomainRules(s, uidOf),
        )
        assertTrue(AppRules.needsForeground(s))
        assertFalse(AppRules.needsForeground(Settings()))
        assertEquals(
            UiText.of(R.string.rules_condition_list, UiText.of(R.string.rules_condition_wifi), UiText.of(R.string.rules_condition_screen_off)),
            AppRule(blockWifi = true, blockScreenOff = true).describe(),
        )
        assertEquals(UiText.of(R.string.rules_condition_background), AppRule(blockBackground = true).describe())
        assertNull(AppRule().describe())
    }

    @Test
    fun deviceState() {
        var asked = 0
        fun state(screenOn: Boolean, needsFg: Boolean, fg: String?) =
            AppRules.deviceState(DeviceState.NETWORK_WIFI, screenOn, needsFg, { asked++; fg }, uidOf)
        // No background rule: the foreground app is not looked up at all.
        assertEquals(DeviceState("wifi", true, null), state(true, false, "com.chat"))
        assertEquals(0, asked)
        assertEquals(DeviceState("wifi", true, listOf(10123)), state(true, true, "com.chat"))
        // No app in the foreground (e.g. its activity paused), and unknown.
        assertEquals(DeviceState("wifi", true, emptyList()), state(true, true, ""))
        assertEquals(DeviceState("wifi", true, null), state(true, true, null))
        // Screen off: nothing is in the foreground; not looked up.
        asked = 0
        assertEquals(DeviceState("wifi", false, emptyList()), state(false, true, "com.chat"))
        assertEquals(0, asked)
        // A foreground package that no longer resolves is simply not listed.
        assertEquals(DeviceState("wifi", true, emptyList()), state(true, true, "gone.app"))
    }
}
