package dev.vigil.inspector.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.R
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.asString
import dev.vigil.inspector.ui.components.EmptyState
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.theme.VigilColors

private val DOMAIN = Regex("^(\\*\\.)?([a-z0-9_-]+\\.)+[a-z0-9-]+$")

@Composable
fun RulesScreen(vm: MainViewModel, nav: NavController) {
    val s by vm.settings.collectAsStateWithLifecycle()
    var input by remember { mutableStateOf("") }
    val candidate = input.trim().lowercase().removePrefix("*.")
    val valid = DOMAIN.matches(candidate)
    val label = rememberAppLabels(vm, (s.blockedPackages + s.appRules.keys + s.appDomainRules.map { it.app }).distinct())
    Column(Modifier.fillMaxSize()) {
        VigilTopBar(stringResource(R.string.rules_title), nav)
        Text(
            stringResource(R.string.rules_intro),
            Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(input, { input = it }, Modifier.weight(1f), singleLine = true, placeholder = { Text("example.com") },
                isError = input.isNotBlank() && !valid)
        }
        Row(Modifier.padding(horizontal = 16.dp)) {
            Button(enabled = valid, onClick = { vm.denyDomain(candidate); input = "" }) { Text(stringResource(R.string.common_block)) }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(enabled = valid, onClick = { vm.allowDomain(candidate); input = "" }) { Text(stringResource(R.string.rules_allow)) }
        }
        LazyColumn {
            item { SectionTitle(stringResource(R.string.rules_section_blocked, s.denyDomains.size)) }
            if (s.denyDomains.isEmpty()) item { EmptyState(stringResource(R.string.rules_empty_block_title), stringResource(R.string.rules_empty_block_text)) }
            items(s.denyDomains.sorted(), key = { "d-$it" }) { d -> RuleRow(d, true) { vm.removeRule(d) } }
            item { SectionTitle(stringResource(R.string.rules_section_allowed, s.allowDomains.size)) }
            if (s.allowDomains.isEmpty()) item { EmptyState(stringResource(R.string.rules_empty_allow_title), stringResource(R.string.rules_empty_allow_text)) }
            items(s.allowDomains.sorted(), key = { "a-$it" }) { d -> RuleRow(d, false) { vm.removeRule(d) } }
            val conditional = s.appRules.filterValues { !it.isEmpty }.toSortedMap()
            val perApp = s.appDomainRules.sortedWith(compareBy({ label(it.app) }, { it.domain }))
            item { SectionTitle(stringResource(R.string.rules_section_per_app, s.blockedPackages.size + conditional.size + perApp.size)) }
            if (s.blockedPackages.isEmpty() && conditional.isEmpty() && perApp.isEmpty()) {
                item {
                    EmptyState(stringResource(R.string.rules_empty_per_app_title), stringResource(R.string.rules_empty_per_app_text))
                }
            }
            items(s.blockedPackages.sorted(), key = { "pb-$it" }) { app ->
                AppRuleRow(label(app), stringResource(R.string.rules_app_no_network), VigilColors.Block) { nav.openApp(app) }
            }
            items(conditional.entries.toList(), key = { "pc-${it.key}" }) { (app, rule) ->
                AppRuleRow(label(app), stringResource(R.string.rules_app_blocked_when, rule.describe()?.asString().orEmpty()), VigilColors.Medium) { nav.openApp(app) }
            }
            items(perApp, key = { "pd-${it.app}|${it.domain}" }) { r ->
                Row(Modifier.fillMaxWidth().clickable { nav.openApp(r.app) }.padding(start = 16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(r.domain, color = if (r.isBlock) VigilColors.Block else VigilColors.Allow)
                        Text(
                            stringResource(if (r.isBlock) R.string.rules_app_domain_blocked else R.string.rules_app_domain_allowed, label(r.app)),
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    IconButton(onClick = { vm.removeAppDomainRule(r.app, r.domain) }) { Icon(Icons.Default.Delete, stringResource(R.string.rules_remove_for, r.domain)) }
                }
            }
        }
    }
}

@Composable
private fun AppRuleRow(app: String, what: String, color: androidx.compose.ui.graphics.Color, onClick: () -> Unit) {
    Column(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 8.dp)) {
        Text(app)
        Text(what, style = MaterialTheme.typography.bodySmall, color = color)
    }
}

@Composable
private fun RuleRow(domain: String, blocked: Boolean, onDelete: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(start = 16.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(domain, Modifier.weight(1f), color = if (blocked) VigilColors.Block else VigilColors.Allow)
        IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, stringResource(R.string.rules_remove_for, domain)) }
    }
}
