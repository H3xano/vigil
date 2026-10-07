package dev.vigil.inspector.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.R
import dev.vigil.inspector.data.FeedCatalog
import dev.vigil.inspector.data.FeedEntity
import dev.vigil.inspector.data.AsnDatabase
import dev.vigil.inspector.data.FeedKinds
import dev.vigil.inspector.data.MvtIndex
import dev.vigil.inspector.data.TrackerDatabase
import dev.vigil.inspector.data.TaxiiCollection
import dev.vigil.inspector.ui.FeedWork
import dev.vigil.inspector.ui.Glossary
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.UiText
import dev.vigil.inspector.ui.asString
import dev.vigil.inspector.ui.rememberRetained
import dev.vigil.inspector.ui.components.HelpIcon
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.components.Tag
import dev.vigil.inspector.ui.formatCount
import dev.vigil.inspector.ui.formatRelative
import dev.vigil.inspector.ui.theme.VigilColors
import kotlinx.coroutines.launch

@Composable
fun FeedsScreen(vm: MainViewModel, nav: NavController) {
    val feeds by vm.feeds.collectAsStateWithLifecycle()
    val loaded by vm.loadedFeeds.collectAsStateWithLifecycle()
    val work by vm.feedWork.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    val trackersLoaded = rememberTrackerIndex() != null
    // Open dialogs survive rotation: the Add feed draft in memory (it may hold credentials), the delete target by id.
    val adding = rememberRetained("feeds.add") { null as FeedDraft? }
    var confirmDeleteId by rememberSaveable { mutableStateOf<String?>(null) }
    val confirmDelete = confirmDeleteId?.let { id -> feeds.firstOrNull { it.id == id } }
    val resources = LocalResources.current

    // Report when an update the user can see (running or waiting) finishes.
    var wasBusy by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(work) {
        if (work != FeedWork.IDLE) {
            wasBusy = true
        } else if (wasBusy) {
            wasBusy = false
            vm.showMessage(UiText.of(R.string.feeds_update_finished))
        }
    }

    Column(Modifier.fillMaxSize()) {
        VigilTopBar(stringResource(R.string.feeds_title), nav) {
            IconButton(onClick = {
                vm.refreshFeeds()
                vm.showMessage(UiText.of(R.string.feeds_updating))
            }, enabled = work != FeedWork.RUNNING) { Icon(Icons.Default.Refresh, stringResource(R.string.feeds_update_all)) }
            IconButton(onClick = { adding.value = FeedDraft() }) { Icon(Icons.Default.Add, stringResource(R.string.feeds_add_feed)) }
        }
        when (work) {
            FeedWork.RUNNING -> Progress(stringResource(R.string.feeds_progress_downloading))
            FeedWork.WAITING -> Progress(stringResource(R.string.feeds_progress_waiting))
            FeedWork.IDLE -> {}
        }
        LazyColumn {
            item {
                Row(Modifier.padding(start = 16.dp, end = 8.dp, top = 16.dp, bottom = 8.dp)) {
                    Text(
                        stringResource(R.string.feeds_intro),
                        Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    HelpIcon("C2", Glossary.C2)
                }
            }
            item {
                Ja4Settings(settings.blockJa4Matches, onBlock = vm::setBlockJa4Matches)
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
            val (spyware, others) = feeds.partition { it.kind in FeedKinds.SPYWARE_KINDS }
            val (taxii, lists) = others.partition { it.isTaxii }
            val groups = lists.groupBy { it.category }
            for (category in FeedCatalog.categories.filter { it in groups }) {
                item {
                    when (category) {
                        "ja4" -> SectionTitle(stringResource(R.string.feeds_section_ja4))
                        AsnDatabase.CATEGORY -> Row(verticalAlignment = Alignment.CenterVertically) {
                            SectionTitle(stringResource(R.string.feeds_section_asn))
                            HelpIcon("ASN", Glossary.ASN)
                        }
                        TrackerDatabase.CATEGORY -> TrackerLabelsHeader()
                        else -> SectionTitle(categoryTitle(category))
                    }
                }
                items(groups.getValue(category), key = { it.id }) { f ->
                    FeedRow(f, active = f.id in loaded || (f.kind == FeedKinds.TRACKERS && f.enabled && trackersLoaded), onToggle = { vm.setFeedEnabled(f.id, it) }, onDelete = { confirmDeleteId = f.id })
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
            if (spyware.isNotEmpty()) {
                item {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        SectionTitle(stringResource(R.string.feeds_section_spyware))
                        HelpIcon(stringResource(R.string.feeds_help_spyware_packs), Glossary.SPYWARE_PACKS)
                    }
                }
                item {
                    TextButton(onClick = { nav.navigate("health") }, Modifier.padding(horizontal = 8.dp)) { Text(stringResource(R.string.feeds_open_health_check)) }
                }
                // The index first, then Echap's lists, then the packs it lists.
                val ordered = spyware.sortedWith(
                    compareBy<FeedEntity> { if (it.kind == FeedKinds.SPYWARE_INDEX) 0 else if (it.id.startsWith(MvtIndex.ID_PREFIX)) 2 else 1 }
                        .thenBy { it.name.lowercase() },
                )
                items(ordered, key = { it.id }) { f ->
                    FeedRow(f, active = f.id in loaded, onToggle = { vm.setFeedEnabled(f.id, it) }, onDelete = { confirmDeleteId = f.id })
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
            if (taxii.isNotEmpty()) {
                item {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        SectionTitle(stringResource(R.string.feeds_section_taxii))
                        HelpIcon("TAXII", Glossary.TAXII)
                    }
                }
                items(taxii, key = { it.id }) { f ->
                    FeedRow(f, active = f.id in loaded, onToggle = { vm.setFeedEnabled(f.id, it) }, onDelete = { confirmDeleteId = f.id })
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
    }

    confirmDelete?.let { f ->
        AlertDialog(
            onDismissRequest = { confirmDeleteId = null },
            title = { Text(stringResource(R.string.feeds_delete_title, f.name)) },
            text = { Text(stringResource(R.string.feeds_delete_text)) },
            confirmButton = {
                TextButton(onClick = {
                    vm.deleteFeed(f.id)
                    vm.showMessage(UiText.of(R.string.feeds_deleted, f.name))
                    confirmDeleteId = null
                }) { Text(stringResource(R.string.feeds_delete)) }
            },
            dismissButton = { TextButton(onClick = { confirmDeleteId = null }) { Text(stringResource(R.string.common_cancel)) } },
        )
    }

    if (adding.value != null) AddFeedDialog(vm, adding, onDismiss = { adding.value = null })
}

/** Section title of a feed category; categories without a translation (c2, custom ones) show their id. */
@Composable
private fun categoryTitle(category: String): String = when (category) {
    "malware" -> stringResource(R.string.feeds_category_malware)
    "phishing" -> stringResource(R.string.feeds_category_phishing)
    "tracking" -> stringResource(R.string.feeds_category_tracking)
    "ads" -> stringResource(R.string.feeds_category_ads)
    "custom" -> stringResource(R.string.feeds_category_custom)
    else -> category
}

/** Explains JA4 matching and holds the block switch (alert-only by default). */
@Composable
private fun Ja4Settings(block: Boolean, onBlock: (Boolean) -> Unit) {
    Column(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
        Row(Modifier.padding(start = 16.dp, end = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(stringResource(R.string.feeds_ja4_title), Modifier.weight(1f), style = MaterialTheme.typography.titleSmall)
            HelpIcon(stringResource(R.string.feeds_help_ja4_match), Glossary.JA4_MATCH)
        }
        Text(
            stringResource(R.string.feeds_ja4_text),
            Modifier.padding(horizontal = 16.dp),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(
            Modifier.fillMaxWidth().toggleable(value = block, role = Role.Switch, onValueChange = onBlock)
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f).padding(end = 12.dp)) {
                Text(stringResource(R.string.feeds_ja4_block), style = MaterialTheme.typography.bodyLarge)
                Text(
                    stringResource(R.string.feeds_ja4_block_text),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(checked = block, onCheckedChange = null)
        }
    }
}

/** The Add feed dialog's fields; kept across rotation in memory only (the credentials never go to the saved state). */
private data class FeedDraft(
    val kind: String = FeedKinds.LIST,
    val name: String = "",
    val url: String = "https://",
    val category: String = "malware",
    val auth: String = "",
    // TAXII
    val authMode: String = "none",
    val user: String = "",
    val headerName: String = "Authorization",
    val collections: List<TaxiiCollection>? = null,
    val chosen: TaxiiCollection? = null,
    val lookupError: String? = null,
)

@Composable
private fun AddFeedDialog(vm: MainViewModel, state: MutableState<FeedDraft?>, onDismiss: () -> Unit) {
    val d = state.value ?: return
    fun edit(t: (FeedDraft) -> FeedDraft) {
        state.value = state.value?.let(t)
    }
    // A lookup in flight is not retained: after a rotation, look up again.
    var looking by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val resources = LocalResources.current

    val trimmedUrl = d.url.trim()
    val urlOk = (trimmedUrl.startsWith("https://") || trimmedUrl.startsWith("http://")) && trimmedUrl.length > 10
    // TAXII credentials as (header name, value).
    fun taxiiAuth(): Pair<String?, String?> = when (d.authMode) {
        "basic" -> "Authorization" to if (d.user.isBlank() && d.auth.isBlank()) null else
            "Basic " + java.util.Base64.getEncoder().encodeToString("${d.user}:${d.auth}".toByteArray())
        "header" -> d.headerName.trim().ifEmpty { "Authorization" } to d.auth.takeIf { it.isNotBlank() }
        else -> null to null
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.feeds_add_title)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Segmented(
                    listOf(FeedKinds.LIST to stringResource(R.string.feeds_kind_list), FeedKinds.JA4 to "JA4", FeedKinds.TAXII to "TAXII"),
                    d.kind, { k -> edit { it.copy(kind = k, collections = null, chosen = null, lookupError = null) } }, Modifier,
                )
                OutlinedTextField(d.name, { v -> edit { it.copy(name = v) } }, label = { Text(stringResource(R.string.feeds_field_name)) }, singleLine = true)
                OutlinedTextField(
                    d.url, { v -> edit { it.copy(url = v, collections = null, chosen = null) } },
                    label = { Text(stringResource(if (d.kind == FeedKinds.TAXII) R.string.feeds_field_taxii_url else R.string.feeds_field_url)) }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                )
                when (d.kind) {
                    FeedKinds.LIST -> {
                        SecretField(d.auth, { v -> edit { it.copy(auth = v) } }, stringResource(R.string.feeds_field_auth_optional))
                        CleartextWarning(trimmedUrl, hasSecret = d.auth.isNotBlank(), isFeed = true)
                        Segmented(threatCategories(), d.category, { v -> edit { it.copy(category = v) } }, Modifier)
                        Segmented(
                            listOf(
                                "tracking" to stringResource(R.string.feeds_seg_tracking),
                                "ads" to stringResource(R.string.feeds_seg_ads),
                                "custom" to stringResource(R.string.feeds_seg_other),
                            ),
                            d.category, { v -> edit { it.copy(category = v) } }, Modifier,
                        )
                    }
                    FeedKinds.JA4 -> {
                        SecretField(d.auth, { v -> edit { it.copy(auth = v) } }, stringResource(R.string.feeds_field_auth_optional))
                        CleartextWarning(trimmedUrl, hasSecret = d.auth.isNotBlank(), isFeed = true)
                        Hint(stringResource(R.string.feeds_ja4_hint))
                    }
                    FeedKinds.TAXII -> {
                        Segmented(
                            listOf(
                                "none" to stringResource(R.string.feeds_auth_none),
                                "basic" to stringResource(R.string.feeds_auth_basic),
                                "header" to stringResource(R.string.feeds_auth_api_key),
                            ),
                            d.authMode, { v -> edit { it.copy(authMode = v) } }, Modifier,
                        )
                        when (d.authMode) {
                            "basic" -> {
                                OutlinedTextField(d.user, { v -> edit { it.copy(user = v) } }, label = { Text(stringResource(R.string.feeds_field_username)) }, singleLine = true)
                                SecretField(d.auth, { v -> edit { it.copy(auth = v) } }, stringResource(R.string.feeds_field_password))
                            }
                            "header" -> {
                                OutlinedTextField(d.headerName, { v -> edit { it.copy(headerName = v) } }, label = { Text(stringResource(R.string.feeds_field_header_name)) }, singleLine = true)
                                SecretField(
                                    d.auth, { v -> edit { it.copy(auth = v) } }, stringResource(R.string.feeds_field_header_value),
                                    placeholder = stringResource(R.string.feeds_field_header_value_placeholder),
                                )
                            }
                        }
                        CleartextWarning(trimmedUrl, hasSecret = d.authMode != "none", isFeed = true)
                        OutlinedButton(enabled = urlOk && !looking, onClick = {
                            looking = true
                            edit { it.copy(lookupError = null) }
                            val (h, v) = taxiiAuth()
                            scope.launch {
                                vm.taxiiCollections(trimmedUrl, h, v)
                                    .onSuccess { list ->
                                        edit {
                                            it.copy(
                                                collections = list,
                                                chosen = list.singleOrNull { c -> c.canRead },
                                                lookupError = if (list.isEmpty()) resources.getString(R.string.feeds_taxii_no_collections) else null,
                                            )
                                        }
                                    }
                                    .onFailure { e -> edit { it.copy(lookupError = e.message ?: e.javaClass.simpleName) } }
                                looking = false
                            }
                        }) { Text(stringResource(if (looking) R.string.feeds_taxii_looking_up else R.string.feeds_taxii_find_collections)) }
                        d.lookupError?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = VigilColors.Block) }
                        d.collections?.forEach { c ->
                            Row(
                                Modifier.fillMaxWidth()
                                    .selectable(selected = d.chosen == c, enabled = c.canRead, role = Role.RadioButton, onClick = { edit { it.copy(chosen = c) } }),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                RadioButton(selected = d.chosen == c, onClick = null, enabled = c.canRead)
                                Column(Modifier.padding(start = 8.dp)) {
                                    Text(c.title, style = MaterialTheme.typography.bodyMedium)
                                    Text(
                                        if (c.canRead) c.id else stringResource(R.string.feeds_taxii_unreadable, c.id),
                                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                        if (d.chosen != null) {
                            Text(stringResource(R.string.feeds_taxii_treat_as), style = MaterialTheme.typography.bodySmall)
                            Segmented(threatCategories(), d.category, { v -> edit { it.copy(category = v) } }, Modifier)
                        }
                        Hint(stringResource(R.string.feeds_taxii_hint))
                    }
                }
            }
        },
        confirmButton = {
            val chosen = d.chosen
            val ready = d.name.isNotBlank() && urlOk && (d.kind != FeedKinds.TAXII || chosen != null)
            TextButton(enabled = ready, onClick = {
                if (d.kind == FeedKinds.TAXII && chosen != null) {
                    val (h, v) = taxiiAuth()
                    vm.addTaxii(d.name.trim(), chosen, d.category, h, v)
                } else {
                    vm.addFeed(d.name.trim(), trimmedUrl, d.category, d.auth, d.kind)
                }
                vm.showMessage(UiText.of(R.string.feeds_added, d.name.trim()))
                onDismiss()
            }) { Text(stringResource(R.string.feeds_add)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_cancel)) } },
    )
}

/** The threat categories offered for a feed; "C2" is not translated. */
@Composable
private fun threatCategories(): List<Pair<String, String>> = listOf(
    "malware" to stringResource(R.string.feeds_seg_malware),
    "c2" to "C2",
    "phishing" to stringResource(R.string.feeds_seg_phishing),
)

@Composable
private fun Hint(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun Progress(text: String) {
    Column(Modifier.fillMaxWidth()) {
        LinearProgressIndicator(Modifier.fillMaxWidth())
        Text(text, Modifier.padding(horizontal = 16.dp, vertical = 6.dp), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun FeedRow(f: FeedEntity, active: Boolean, onToggle: (Boolean) -> Unit, onDelete: () -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        // The text and switch form one toggle target announced with the feed name.
        Row(
            Modifier.weight(1f)
                .toggleable(value = f.enabled, role = Role.Switch, onValueChange = onToggle)
                .padding(start = 16.dp, end = if (f.builtin) 16.dp else 0.dp, top = 10.dp, bottom = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f).padding(end = 12.dp)) {
                Text(FeedCatalog.nameText(f).asString(), style = MaterialTheme.typography.bodyLarge)
                FeedCatalog.descriptionText(f)?.let { description ->
                    Text(description.asString(), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                if (f.isTaxii) {
                    Text(
                        stringResource(R.string.feeds_taxii_treated_as, f.url, f.category),
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Row(Modifier.padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (f.lastUpdated != null) {
                        Tag(
                            listOfNotNull(
                                f.domains.takeIf { it > 0 }?.let { pluralStringResource(R.plurals.feeds_tag_domains, it, formatCount(it.toLong())) },
                                f.ipRanges.takeIf { it > 0 }?.let { pluralStringResource(R.plurals.feeds_tag_ranges, it, formatCount(it.toLong())) },
                                f.ja4.takeIf { it > 0 }?.let { pluralStringResource(R.plurals.feeds_tag_ja4, it, formatCount(it.toLong())) },
                            ).joinToString(" · ").ifEmpty {
                                when (f.kind) {
                                    FeedKinds.SPYWARE_INDEX -> stringResource(R.string.feeds_tag_pack_list)
                                    FeedKinds.SPYWARE_APPS, FeedKinds.SPYWARE -> stringResource(R.string.feeds_tag_for_health_check)
                                    else -> stringResource(R.string.feeds_tag_empty)
                                }
                            },
                        )
                        Tag(stringResource(R.string.feeds_tag_updated, formatRelative(f.lastUpdated)))
                    } else if (f.enabled) {
                        Tag(stringResource(R.string.feeds_tag_not_downloaded), VigilColors.Low, filled = true)
                    }
                    if (active) Tag(stringResource(R.string.feeds_tag_active), VigilColors.Allow, filled = true)
                    if (f.url.startsWith("http://")) Tag("http", VigilColors.Medium, filled = true)
                }
                f.lastError?.let { Text(stringResource(R.string.feeds_error, it), style = MaterialTheme.typography.bodySmall, color = VigilColors.Block) }
                if (!f.builtin && f.url.startsWith("http://")) {
                    Text(
                        stringResource(if (f.authHeader != null) R.string.feeds_http_warning_credentials else R.string.feeds_http_warning),
                        style = MaterialTheme.typography.bodySmall, color = VigilColors.Medium,
                    )
                }
            }
            Switch(checked = f.enabled, onCheckedChange = null)
        }
        if (!f.builtin) IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, stringResource(R.string.feeds_delete_named, f.name)) }
    }
}

/**
 * A single-line field for tokens, passwords and Authorization headers,
 * masked until shown. The password keyboard type and disabled autocorrect
 * keep secrets out of keyboard suggestions and learned words.
 */
@Composable
fun SecretField(value: String, onChange: (String) -> Unit, label: String, modifier: Modifier = Modifier, placeholder: String? = null) {
    var visible by remember { mutableStateOf(false) }
    OutlinedTextField(
        value, onChange, modifier,
        label = { Text(label) },
        placeholder = placeholder?.let { { Text(it) } },
        singleLine = true,
        keyboardOptions = SECRET_KEYBOARD,
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        trailingIcon = {
            if (value.isNotEmpty()) TextButton(onClick = { visible = !visible }) { Text(stringResource(if (visible) R.string.feeds_secret_hide else R.string.feeds_secret_show)) }
        },
    )
}

/** Keyboard for secrets: password type, no autocorrect or suggestions. */
val SECRET_KEYBOARD = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false)

/**
 * Warns about plain-http endpoints: credentials travel in clear text, and a
 * feed downloaded over http can be modified by anyone on the network path.
 */
@Composable
fun CleartextWarning(url: String, hasSecret: Boolean, isFeed: Boolean) {
    if (!url.startsWith("http://")) return
    val text = when {
        hasSecret -> R.string.feeds_cleartext_secret
        isFeed -> R.string.feeds_cleartext_feed
        else -> R.string.feeds_cleartext_export
    }
    Text(stringResource(text), style = MaterialTheme.typography.bodySmall, color = VigilColors.Medium)
}
