package dev.vigil.inspector.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.data.AppDomainRule
import dev.vigil.inspector.data.AppRules
import dev.vigil.inspector.data.Settings
import dev.vigil.inspector.ui.BlockReasons
import dev.vigil.inspector.ui.DomainNames
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.theme.VigilColors

/**
 * Block buttons for [host]: the host itself and, when different, its
 * registrable domain ("whole site"). Rules always cover subdomains. When a
 * user rule already blocks the host, offers to remove it instead. With the
 * app ([pkg]) the name was seen from, also offers to block it for that app
 * only, or to remove that app's rule for it.
 */
@Composable
fun BlockDomainButtons(
    host: String,
    settings: Settings,
    vm: MainViewModel,
    modifier: Modifier = Modifier,
    pkg: String? = null,
    appLabel: String? = null,
) {
    val rule = DomainNames.matchingRule(host, settings.denyDomains)
    val app = pkg?.takeIf { it != "unknown" }
    Column(modifier, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        if (rule != null) {
            OutlinedButton(onClick = { vm.removeRuleWithUndo(rule) }, Modifier.fillMaxWidth()) {
                Text(if (rule == host.lowercase()) "Remove block rule for $rule" else "Remove block rule for $rule (covers this name)")
            }
        } else {
            DomainNames.blockChoices(host).forEachIndexed { i, name ->
                if (i == 0) {
                    Button(onClick = { vm.blockDomain(name) }, Modifier.fillMaxWidth()) { Text("Block $name") }
                } else {
                    OutlinedButton(onClick = { vm.blockDomain(name) }, Modifier.fillMaxWidth()) { Text("Block the whole site $name") }
                }
            }
        }
        if (app != null) AppDomainRuleButtons(host, settings, vm, app, appLabel ?: app, offerAllow = false)
    }
}

/**
 * Per-app rule actions for [host] and the app [pkg]: remove its rule when
 * one covers the name, else block (and, with [offerAllow], allow) the name
 * for this app only.
 */
@Composable
fun AppDomainRuleButtons(host: String, settings: Settings, vm: MainViewModel, pkg: String, label: String, offerAllow: Boolean) {
    val appRule = AppRules.matchingDomainRule(settings, pkg, host)
    val name = host.lowercase().trimEnd('.')
    if (appRule != null) {
        val what = if (appRule.isBlock) "block" else "allow"
        OutlinedButton(onClick = { vm.removeAppDomainRule(pkg, appRule.domain) }, Modifier.fillMaxWidth()) {
            Text("Remove $label's $what rule for ${appRule.domain}")
        }
        return
    }
    if (!DomainNames.isDomainName(name)) return
    if (offerAllow) {
        OutlinedButton(onClick = { vm.setAppDomainRule(pkg, label, name, AppDomainRule.ALLOW) }, Modifier.fillMaxWidth()) {
            Text("Allow $name for $label only")
        }
    } else {
        OutlinedButton(onClick = { vm.setAppDomainRule(pkg, label, name, AppDomainRule.BLOCK) }, Modifier.fillMaxWidth()) {
            Text("Block $name for $label only")
        }
    }
}

/**
 * A bottom sheet about one DNS name: why it was blocked (from the stored
 * lookup's reason), block/allow with Undo, and a shortcut to its lookups.
 * [pkg] is the app of the row it was opened from, if any.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DomainSheet(
    name: String,
    vm: MainViewModel,
    nav: NavController,
    onDismiss: () -> Unit,
    pkg: String? = null,
    /** Reason of the row the sheet was opened from (null for an allowed row). */
    knownReason: String? = null,
    /** Load the newest blocked lookup's reason (when opened from a list of blocked names). */
    loadReason: Boolean = knownReason == null,
    showLookups: Boolean = true,
) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    val feeds by vm.feeds.collectAsStateWithLifecycle()
    val sheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var reason by remember(name) { mutableStateOf(knownReason) }
    var loaded by remember(name) { mutableStateOf(!loadReason) }
    LaunchedEffect(name) {
        if (!loaded) {
            reason = vm.blockReason(name)
            loaded = true
        }
    }
    val app = pkg?.takeIf { it != "unknown" }
    val appLabel = pkg?.let { rememberAppLabels(vm, listOf(it))(it) }
    val allowRule = DomainNames.matchingRule(name, settings.allowDomains)
    val appRule = app?.let { AppRules.matchingDomainRule(settings, it, name) }

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheet) {
        Column(
            Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = 24.dp).navigationBarsPadding(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(name, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            when {
                appRule != null -> Text(
                    "Your rule for ${appLabel ?: app} ${if (appRule.isBlock) "blocks" else "allows"} ${appRule.domain} " +
                        "(and its subdomains) for this app only" +
                        (if (appRule.isBlock) "." else ": feeds and global block rules do not apply to it there."),
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (appRule.isBlock) VigilColors.Block else VigilColors.Allow,
                )
                allowRule != null -> Text(
                    "Allowed by your rule for $allowRule: feeds and block rules do not apply to it.",
                    style = MaterialTheme.typography.bodyMedium, color = VigilColors.Allow,
                )
                reason != null -> {
                    Text("Why it was blocked", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(BlockReasons.explain(reason, feeds, appLabel), style = MaterialTheme.typography.bodyMedium, color = VigilColors.Block)
                }
                loaded && loadReason -> Text("No blocked lookup of this name is recorded.", style = MaterialTheme.typography.bodyMedium)
            }
            Spacer(Modifier.height(4.dp))
            val blocked = reason != null && allowRule == null
            val showBlock = !blocked && allowRule == null
            if (blocked && !BlockReasons.isPerApp(reason)) {
                Button(onClick = { vm.allowDomainWithUndo(name); onDismiss() }, Modifier.fillMaxWidth()) { Text("Always allow $name") }
                if (app != null && appRule == null) {
                    AppDomainRuleButtons(name, settings, vm, app, appLabel ?: app, offerAllow = true)
                }
                Text(
                    "An allow rule overrides threat feeds and block rules for this name and its subdomains" +
                        (if (app != null) "; “for ${appLabel ?: app} only” leaves other apps blocked." else "."),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (allowRule != null) {
                OutlinedButton(onClick = { vm.removeRuleWithUndo(allowRule); onDismiss() }, Modifier.fillMaxWidth()) { Text("Remove allow rule for $allowRule") }
            }
            if (showBlock) BlockDomainButtons(name, settings, vm, pkg = app, appLabel = appLabel)
            if (!showBlock && appRule != null && app != null) AppDomainRuleButtons(name, settings, vm, app, appLabel ?: app, offerAllow = false)
            if (showLookups) {
                OutlinedButton(onClick = {
                    vm.showLookups(name)
                    onDismiss()
                    nav.navigateTab("activity")
                }, Modifier.fillMaxWidth()) { Text("Show lookups") }
            }
            if (pkg != null && pkg != "unknown") {
                TextButton(onClick = { onDismiss(); nav.openApp(pkg) }) { Text("Open ${appLabel ?: pkg}") }
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}
