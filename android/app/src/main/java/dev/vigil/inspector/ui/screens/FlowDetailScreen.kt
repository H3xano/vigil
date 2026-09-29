package dev.vigil.inspector.ui.screens

import android.content.ClipData
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.R
import dev.vigil.inspector.data.AsnDatabase

import dev.vigil.inspector.data.FlowEntity
import dev.vigil.inspector.engine.PcapFilter
import dev.vigil.inspector.ui.BlockReasons
import dev.vigil.inspector.ui.CaptureExport
import dev.vigil.inspector.ui.PcapRequest
import dev.vigil.inspector.ui.DomainNames
import dev.vigil.inspector.ui.Glossary
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.components.EmptyState
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import dev.vigil.inspector.ui.components.AppIcon
import dev.vigil.inspector.ui.components.Field
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.formatBytes
import dev.vigil.inspector.ui.formatDateTime
import dev.vigil.inspector.ui.formatDuration
import dev.vigil.inspector.ui.theme.VigilColors

@Composable
fun FlowDetailScreen(vm: MainViewModel, nav: NavController, id: Long) {
    // null while loading; Lookup(null) once the query says the row does not exist.
    val lookup by remember(id) { vm.flow(id).map { Lookup(it) } }.collectAsStateWithLifecycle(initialValue = null)
    val settings by vm.settings.collectAsStateWithLifecycle()
    val feeds by vm.feeds.collectAsStateWithLifecycle()
    val clipboard = LocalClipboard.current
    val scope = rememberCoroutineScope()
    Column(Modifier.fillMaxSize()) {
        VigilTopBar(stringResource(R.string.flow_title), nav)
        val loaded = lookup ?: return@Column
        val f = loaded.flow
        if (f == null) {
            EmptyState(stringResource(R.string.flow_not_found), stringResource(R.string.flow_not_found_body))
            return@Column
        }
        val label = rememberAppLabels(vm, listOf(f.pkg))(f.pkg)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                AppIcon(f.pkg, label, 44.dp)
                Spacer(Modifier.width(12.dp))
                Column {
                    Text(f.domain ?: f.dstIp, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold,
                        color = if (f.isBlocked) VigilColors.Block else MaterialTheme.colorScheme.onSurface)
                    Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            SectionTitle(stringResource(R.string.flow_verdict))
            Field(stringResource(R.string.flow_verdict), stringResource(if (f.isBlocked) R.string.common_blocked else R.string.common_allowed))
            Field(stringResource(R.string.flow_reason), f.reason)
            Field(stringResource(R.string.flow_error), f.error)
            SectionTitle(stringResource(R.string.flow_destination))
            Field(stringResource(R.string.flow_domain), f.domain)
            Field(stringResource(R.string.flow_name_source), when (f.domainSource) {
                "sni" -> stringResource(R.string.flow_source_sni)
                "quic" -> stringResource(R.string.flow_source_quic)
                "http" -> stringResource(R.string.flow_source_http)
                "dns" -> stringResource(R.string.flow_source_dns)
                else -> null
            }, help = Glossary.NAME_SOURCE_AND_SNI)
            Field(stringResource(R.string.flow_address), "${f.dstIp}:${f.dstPort}", mono = true)
            val network = AsnDatabase.label(f.asn, f.asnName)
            val country = f.asnCountry
            Field(
                stringResource(R.string.flow_network),
                if (network != null && country != null) stringResource(R.string.flow_network_registered, network, country) else network,
                help = Glossary.ASN,
            )
            TrackerFields(f.domain)
            Field(stringResource(R.string.flow_path), when (f.via) {
                "direct" -> stringResource(R.string.activity_path_direct)
                "wireguard" -> stringResource(R.string.flow_path_wireguard)
                "socks5" -> stringResource(R.string.flow_path_socks5)
                null -> null
                else -> f.via
            }, help = Glossary.VIA)
            Field(stringResource(R.string.flow_transport), f.proto.uppercase())
            Field(stringResource(R.string.flow_protocol), f.appProto?.uppercase())
            SectionTitle(stringResource(R.string.flow_handshake))
            Field(stringResource(R.string.flow_tls_version), f.tlsVersion)
            Field("ALPN", f.alpn, help = Glossary.ALPN)
            Field("JA4", f.ja4, mono = true, help = Glossary.JA4)
            val ja4Feed = f.ja4Feed
            if (ja4Feed != null) {
                val ja4Label = f.ja4Label
                val blocked = f.isBlocked && f.reason?.startsWith("ja4:") == true
                Field(
                    stringResource(R.string.flow_ja4_match),
                    when {
                        ja4Label != null && blocked -> stringResource(R.string.flow_ja4_listed_as_blocked, ja4Label, ja4Feed)
                        ja4Label != null -> stringResource(R.string.flow_ja4_listed_as, ja4Label, ja4Feed)
                        blocked -> stringResource(R.string.flow_ja4_listed_blocked, ja4Feed)
                        else -> stringResource(R.string.flow_ja4_listed, ja4Feed)
                    },
                    help = Glossary.JA4_MATCH,
                )
            }
            Field("ECH", if (f.ech) stringResource(R.string.flow_ech_offered) else null, help = Glossary.ECH)
            Field(stringResource(R.string.flow_http_method), f.httpMethod)
            SectionTitle(stringResource(R.string.flow_traffic))
            Field(stringResource(R.string.flow_started), formatDateTime(f.ts))
            Field(stringResource(R.string.flow_duration), f.durationMs?.let(::formatDuration) ?: if (f.isActive) stringResource(R.string.flow_active) else null)
            Field(stringResource(R.string.flow_received), formatBytes(f.rx))
            Field(stringResource(R.string.flow_sent), formatBytes(f.tx))
            Field(
                stringResource(R.string.flow_app_state),
                when (f.background) {
                    true -> stringResource(R.string.flow_background)
                    false -> stringResource(R.string.flow_foreground)
                    null -> null
                },
            )
            Field(stringResource(R.string.flow_source), f.src, mono = true)
            Field(stringResource(R.string.flow_uid), f.uid?.toString())
            Field(stringResource(R.string.flow_tags), f.tags.takeIf { it.isNotEmpty() })

            SectionTitle(stringResource(R.string.flow_actions))
            val domain = f.domain
            Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (domain != null) {
                    BlockDomainButtons(domain, settings, vm, pkg = f.pkg, appLabel = label)
                    if (DomainNames.matchingRule(domain, settings.denyDomains) == null && f.domainSource == "dns") {
                        Text(
                            stringResource(R.string.flow_dns_hint_note, f.dstIp, domain),
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    val allowRule = DomainNames.matchingRule(domain, settings.allowDomains)
                    if (f.isBlocked && allowRule == null && !BlockReasons.isPerApp(f.reason)) {
                        OutlinedButton(onClick = { vm.allowDomainWithUndo(domain) }, Modifier.fillMaxWidth()) { Text(stringResource(R.string.flow_always_allow, domain)) }
                    }
                    if (f.isBlocked) {
                        Text(
                            BlockReasons.explain(f.reason, feeds, label),
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else if (f.pkg != "unknown" && f.pkg !in settings.blockedPackages) {
                    // No name to block: vigil's rules match names, not single addresses.
                    OutlinedButton(onClick = { vm.blockApp(f.pkg, label) }, Modifier.fillMaxWidth()) { Text(stringResource(R.string.apps_block_network, label)) }
                    Text(
                        stringResource(R.string.flow_no_name),
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (f.pkg != "unknown") OutlinedButton(onClick = { nav.openApp(f.pkg) }, Modifier.fillMaxWidth()) { Text(stringResource(R.string.flow_open_app, label)) }
                ExportPacketsButton(
                    vm, nav, stringResource(R.string.flow_export_packets),
                    PcapRequest(PcapFilter(flowIds = listOf(f.engineId)), CaptureExport.fileName("flow-${f.engineId}-${f.domain ?: f.dstIp}"), session = f.session),
                )
                val clipLabel = stringResource(R.string.flow_clip_indicators)
                OutlinedButton(onClick = {
                    val text = listOfNotNull(f.domain, "${f.dstIp}:${f.dstPort}", f.ja4).joinToString("\n")
                    scope.launch { clipboard.setClipEntry(ClipEntry(ClipData.newPlainText(clipLabel, text))) }
                }, Modifier.fillMaxWidth()) { Text(stringResource(R.string.flow_copy_indicators)) }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

private class Lookup(val flow: FlowEntity?)
