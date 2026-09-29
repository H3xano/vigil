package dev.vigil.inspector.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.R
import dev.vigil.inspector.VigilApp
import dev.vigil.inspector.data.CompanyApps
import dev.vigil.inspector.data.CompanyHits
import dev.vigil.inspector.data.TrackerDatabase
import dev.vigil.inspector.data.TrackerIndex
import dev.vigil.inspector.data.TrackerMatch
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.components.Field
import dev.vigil.inspector.ui.components.HelpIcon
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.components.Tag
import dev.vigil.inspector.ui.formatCount
import dev.vigil.inspector.ui.asString
import dev.vigil.inspector.ui.theme.VigilColors

/** Explains tracker labels (help icons). */
@Composable
internal fun trackerHelp(): String = stringResource(R.string.trackers_help, TrackerDatabase.ATTRIBUTION)

/** The "Tracker labels" help icon. */
@Composable
private fun TrackerHelpIcon() = HelpIcon(stringResource(R.string.trackers_labels), trackerHelp())

/** The loaded tracker labels (null when off or not downloaded); rows use it without a view model. */
@Composable
fun rememberTrackerIndex(): TrackerIndex? {
    val app = LocalContext.current.applicationContext as VigilApp
    val index by app.trackers.index.collectAsStateWithLifecycle()
    return index
}

@Composable
private fun rememberTrackerMatch(host: String?): TrackerMatch? {
    val index = rememberTrackerIndex()
    return remember(index, host) { index?.match(host) }
}

/** A small "Google · Advertising" tag for a destination; nothing when the name has no label. */
@Composable
fun TrackerTag(host: String?) {
    val m = rememberTrackerMatch(host) ?: return
    val label = TrackerDatabase.label(m.tracker).asString()
    if (m.tracker.isTracking) Tag(label, VigilColors.Medium, filled = true)
    else Tag(label)
}

/** Tracker and company rows for the connection detail. */
@Composable
fun TrackerFields(host: String?) {
    val m = rememberTrackerMatch(host) ?: return
    val t = m.tracker
    val category = TrackerDatabase.categoryLabel(t.category).asString()
    Field(
        stringResource(R.string.trackers_field_tracker),
        if (m.domain != host?.lowercase()) stringResource(R.string.trackers_field_tracker_listed_as, t.name, category, m.domain)
        else stringResource(R.string.trackers_label, t.name, category),
        help = trackerHelp(),
    )
    // Company name and website: data, not translated.
    Field(stringResource(R.string.trackers_field_company), t.companyName?.let { c -> c + (t.companyWebsite?.let { " · $it" } ?: "") })
}

/** Section title and attribution for the tracker labels in the feed catalogue. */
@Composable
fun TrackerLabelsHeader() {
    val index = rememberTrackerIndex()
    val uri = LocalUriHandler.current
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SectionTitle(stringResource(R.string.trackers_labels))
            TrackerHelpIcon()
        }
        val loaded = index?.let {
            stringResource(
                R.string.trackers_labels_loaded,
                pluralStringResource(R.plurals.trackers_count_domains, it.domainCount, formatCount(it.domainCount.toLong())),
                pluralStringResource(R.plurals.trackers_count_trackers, it.trackerCount, formatCount(it.trackerCount.toLong())),
                pluralStringResource(R.plurals.trackers_count_companies, it.companyCount, formatCount(it.companyCount.toLong())),
            )
        }
        Text(
            stringResource(R.string.trackers_labels_text) + (loaded?.let { " $it" } ?: ""),
            Modifier.padding(horizontal = 16.dp),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(Modifier.padding(horizontal = 4.dp)) {
            TextButton(onClick = { uri.openUri(TrackerDatabase.SOURCE_URL) }) { Text("AdGuard companiesdb") }
            TextButton(onClick = { uri.openUri(TrackerDatabase.LICENSE_URL) }) { Text("CC BY-SA 4.0") }
        }
    }
}

/**
 * The app detail's "Trackers" section: companies [pkg] contacted in the
 * window, grouped with categories and counts; tapping a company lists its
 * domains. Emits nothing while loading.
 */
@Composable
fun AppTrackersSection(vm: MainViewModel, pkg: String, days: Int) {
    val source = remember(pkg) { vm.appTrackers(pkg) }
    val companiesOrOff by source.collectAsStateWithLifecycle(initialValue = LOADING)
    val companies = companiesOrOff
    if (companies === LOADING) return
    var open by rememberSaveable(pkg) { mutableStateOf<String?>(null) }
    var showAll by rememberSaveable(pkg) { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth()) {
        val tracking = companies?.count { it.tracking } ?: 0
        Row(verticalAlignment = Alignment.CenterVertically) {
            SectionTitle(
                if (companies == null) stringResource(R.string.trackers_section)
                else pluralStringResource(R.plurals.trackers_section_count, tracking, tracking),
            )
            TrackerHelpIcon()
        }
        when {
            companies == null -> Hint(stringResource(R.string.trackers_off))
            companies.isEmpty() -> Hint(pluralStringResource(R.plurals.trackers_none_in_window, days, days))
            else -> {
                val shown = if (showAll) companies else companies.take(COLLAPSED)
                for (c in shown) CompanyRow(c, expanded = open == c.company, onClick = { open = if (open == c.company) null else c.company })
                if (companies.size > COLLAPSED) {
                    TextButton(onClick = { showAll = !showAll }, Modifier.padding(horizontal = 4.dp)) {
                        Text(if (showAll) stringResource(R.string.trackers_show_fewer) else stringResource(R.string.trackers_show_all, companies.size))
                    }
                }
            }
        }
    }
}

private const val COLLAPSED = 5

/** Marker for "not loaded yet" (null means tracker labels are unavailable). */
private val LOADING: List<CompanyHits> = ArrayList()

@Composable
private fun Hint(text: String) {
    Text(text, Modifier.padding(horizontal = 16.dp, vertical = 4.dp), style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant)
}

/** Counts joined with " · ", e.g. "3 connections · 2 lookups · 1 blocked". */
@Composable
private fun hitsText(flows: Long, lookups: Long, blocked: Long): String = listOfNotNull(
    flows.takeIf { it > 0 }?.let { pluralStringResource(R.plurals.trackers_hits_connections, quantity(it), it) },
    lookups.takeIf { it > 0 }?.let { pluralStringResource(R.plurals.trackers_hits_lookups, quantity(it), it) },
    blocked.takeIf { it > 0 }?.let { pluralStringResource(R.plurals.trackers_hits_blocked, quantity(it), formatCount(it)) },
).joinToString(" · ")

/** A count as the quantity that selects a plural form. */
private fun quantity(n: Long): Int = n.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()

@Composable
private fun CompanyRow(c: CompanyHits, expanded: Boolean, onClick: () -> Unit) {
    Column(
        Modifier.fillMaxWidth()
            .clickable(
                onClickLabel = stringResource(if (expanded) R.string.trackers_hide_domains else R.string.trackers_show_domains),
                role = Role.Button, onClick = onClick,
            )
            .padding(horizontal = 16.dp, vertical = 8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(c.company, Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis,
                fontWeight = if (c.tracking) FontWeight.Medium else null)
            when {
                c.allBlocked -> Tag(stringResource(R.string.trackers_tag_blocked), VigilColors.Block, filled = true)
                c.blocked > 0 -> Tag(stringResource(R.string.trackers_tag_partly_blocked), VigilColors.Block)
                else -> Tag(stringResource(R.string.trackers_tag_allowed), VigilColors.Allow)
            }
        }
        Row(Modifier.padding(top = 3.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            for (cat in c.categories.take(3)) {
                if (TrackerDatabase.isTrackingCategory(cat)) Tag(TrackerDatabase.categoryLabel(cat).asString(), VigilColors.Medium, filled = true)
                else Tag(TrackerDatabase.categoryLabel(cat).asString())
            }
        }
        Text(
            stringResource(
                R.string.trackers_details,
                pluralStringResource(R.plurals.trackers_company_domains, c.domains.size, c.domains.size),
                hitsText(c.flows, c.lookups, c.blocked),
            ),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (expanded) {
            for (d in c.domains) {
                Column(Modifier.padding(start = 12.dp, top = 6.dp)) {
                    Text(d.domain, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis,
                        color = if (d.total > 0 && d.blocked >= d.total) VigilColors.Block else MaterialTheme.colorScheme.onSurface)
                    Text(
                        stringResource(
                            R.string.trackers_details,
                            stringResource(R.string.trackers_label, d.tracker.name, TrackerDatabase.categoryLabel(d.tracker.category).asString()),
                            hitsText(d.flows, d.lookups, d.blocked),
                        ),
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            c.website?.let { Text(it, Modifier.padding(start = 12.dp, top = 6.dp), style = MaterialTheme.typography.bodySmall, color = VigilColors.Info) }
        }
    }
}

/** Overview: the tracking companies contacted by the most apps in the last 24 hours. */
fun LazyListScope.topTrackerCompanies(companies: List<CompanyApps>, nav: NavController) {
    if (companies.isEmpty()) return
    item {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SectionTitle(stringResource(R.string.trackers_top_companies))
            TrackerHelpIcon()
        }
    }
    items(companies, key = { "t-" + it.company }) { c ->
        Row(
            Modifier.fillMaxWidth().clickable(onClickLabel = stringResource(R.string.trackers_open_apps)) { nav.navigateTab("apps") }.padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(c.company, maxLines = 1, overflow = TextOverflow.Ellipsis)
                val context = LocalContext.current
                Text(c.categories.joinToString(", ") { TrackerDatabase.categoryLabel(it).resolve(context) }, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Text(pluralStringResource(R.plurals.trackers_apps_count, c.apps, c.apps), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
