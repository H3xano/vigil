package dev.vigil.inspector.ui.screens

import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.annotation.StringRes
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.vigil.inspector.R
import dev.vigil.inspector.ui.MainViewModel

private class Step(val icon: ImageVector, @param:StringRes val title: Int, @param:StringRes val body: Int)

private val steps = listOf(
    Step(Icons.Default.Search, R.string.onboarding_welcome_title, R.string.onboarding_welcome_body),
    Step(Icons.Default.Lock, R.string.onboarding_vpn_title, R.string.onboarding_vpn_body),
    Step(Icons.Default.Refresh, R.string.onboarding_feeds_title, R.string.onboarding_feeds_body),
    Step(Icons.Default.Settings, R.string.onboarding_usage_title, R.string.onboarding_usage_body),
    Step(Icons.Default.Notifications, R.string.onboarding_notifications_title, R.string.onboarding_notifications_body),
    Step(Icons.Default.PlayArrow, R.string.onboarding_start_title, R.string.onboarding_start_body),
)

/**
 * First-run onboarding: a few skippable steps, shown until [onFinish] is
 * called (which persists the `onboarded` setting). The last step starts
 * inspection ([onStartInspecting]: notification prompt, then VPN consent).
 */
@Composable
fun OnboardingScreen(
    vm: MainViewModel,
    notificationsGranted: Boolean,
    onRequestNotifications: () -> Unit,
    onFinish: () -> Unit,
    onStartInspecting: () -> Unit,
) {
    var index by rememberSaveable { mutableIntStateOf(0) }
    // System back goes to the previous step; on the first one it leaves the app.
    BackHandler(enabled = index > 0) { index-- }
    val step = steps[index]
    val last = index == steps.lastIndex
    val context = LocalContext.current
    val usageAccess = usageAccessGranted(vm)
    Surface(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                LinearProgressIndicator(progress = { (index + 1f) / steps.size }, modifier = Modifier.weight(1f), drawStopIndicator = {})
                TextButton(onClick = onFinish, modifier = Modifier.padding(start = 8.dp)) { Text(stringResource(R.string.onboarding_skip)) }
            }
            Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(top = 32.dp)) {
                Icon(step.icon, null, Modifier.size(48.dp), tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.height(16.dp))
                Text(stringResource(step.title), Modifier.semantics { heading() }, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(12.dp))
                Text(stringResource(step.body), style = MaterialTheme.typography.bodyLarge)
                Spacer(Modifier.height(20.dp))
                when (index) {
                    3 -> if (usageAccess) {
                        Text(stringResource(R.string.onboarding_usage_granted), color = MaterialTheme.colorScheme.primary)
                    } else {
                        OutlinedButton(onClick = { context.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) }) { Text(stringResource(R.string.onboarding_usage_grant)) }
                    }
                    4 -> if (Build.VERSION.SDK_INT < 33 || notificationsGranted) {
                        Text(stringResource(R.string.onboarding_notifications_allowed), color = MaterialTheme.colorScheme.primary)
                    } else {
                        OutlinedButton(onClick = onRequestNotifications) { Text(stringResource(R.string.onboarding_notifications_allow)) }
                    }
                }
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                if (index > 0) TextButton(onClick = { index-- }) { Text(stringResource(R.string.onboarding_back)) } else Spacer(Modifier)
                if (last) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = onFinish) { Text(stringResource(R.string.onboarding_not_now)) }
                        Button(onClick = onStartInspecting) { Text(stringResource(R.string.onboarding_start_button)) }
                    }
                } else {
                    Button(onClick = { index++ }) { Text(stringResource(R.string.onboarding_next)) }
                }
            }
        }
    }
}
