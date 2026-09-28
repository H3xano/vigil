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
import dev.vigil.inspector.data.Settings
import dev.vigil.inspector.ui.BlockReasons
import dev.vigil.inspector.ui.DomainNames
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.theme.VigilColors

/**
 * Block buttons for [host]: the host itself and, when different, its
 * registrable domain ("whole site"). Rules always cover subdomains. When a
 * user rule already blocks the host, offers to remove it instead.
 */
@Composable
fun BlockDomainButtons(host: String, settings: Settings, vm: MainViewModel, modifier: Modifier = Modifier) {
    val rule = DomainNames.matchingRule(host, settings.denyDomains)
    Column(modifier, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        if (rule != null) {
            OutlinedButton(onClick = { vm.removeRuleWithUndo(rule) }, Modifier.fillMaxWidth()) {
                Text(if (rule == host.lowercase()) "Remove block rule for $rule" else "Remove block rule for $rule (covers this name)")
            }
            return@Column
        }
        DomainNames.blockChoices(host).forEachIndexed { i, name ->
            if (i == 0) {
                Button(onClick = { vm.blockDomain(name) }, Modifier.fillMaxWidth()) { Text("Block $name") }
            } else {
                OutlinedButton(onClick = { vm.blockDomain(name) }, Modifier.fillMaxWidth()) { Text("Block the whole site $name") }
            }
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
    val appLabel = pkg?.let { rememberAppLabels(vm, listOf(it))(it) }
    val allowRule = DomainNames.matchingRule(name, settings.allowDomains)

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheet) {
        Column(
            Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = 24.dp).navigationBarsPadding(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(name, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            when {
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
            if (blocked && reason?.startsWith("app") != true) {
                Button(onClick = { vm.allowDomainWithUndo(name); onDismiss() }, Modifier.fillMaxWidth()) { Text("Always allow $name") }
                Text(
                    "An allow rule overrides threat feeds and block rules for this name and its subdomains.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (allowRule != null) {
                OutlinedButton(onClick = { vm.removeRuleWithUndo(allowRule); onDismiss() }, Modifier.fillMaxWidth()) { Text("Remove allow rule for $allowRule") }
            }
            if (!blocked && allowRule == null) BlockDomainButtons(name, settings, vm)
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
