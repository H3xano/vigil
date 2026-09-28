package dev.vigil.inspector.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBox
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import dev.vigil.inspector.ui.screens.ActivityScreen
import dev.vigil.inspector.ui.screens.AlertsScreen
import dev.vigil.inspector.ui.screens.AppDetailScreen
import dev.vigil.inspector.ui.screens.DnsScreen
import dev.vigil.inspector.ui.screens.AppsScreen
import dev.vigil.inspector.ui.screens.DashboardScreen
import dev.vigil.inspector.ui.screens.ExportScreen
import dev.vigil.inspector.ui.screens.FeedsScreen
import dev.vigil.inspector.ui.screens.FlowDetailScreen
import dev.vigil.inspector.ui.screens.OnboardingScreen
import dev.vigil.inspector.ui.screens.RulesScreen
import dev.vigil.inspector.ui.screens.SettingsScreen
import dev.vigil.inspector.ui.screens.UpstreamScreen
import dev.vigil.inspector.ui.theme.VigilTheme
import dev.vigil.inspector.vpn.VigilVpnService

class MainActivity : ComponentActivity() {
    private val vm: MainViewModel by viewModels()
    /** Destination requested by an intent (launcher shortcut or notification). */
    private val destination = kotlinx.coroutines.flow.MutableStateFlow<String?>(null)

    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            VigilVpnService.start(this)
        } else {
            vm.showMessage("VPN permission was not granted, so inspection did not start.")
        }
    }

    /** Whether the notification request was made by [startInspection] (then VPN consent follows). */
    private var startAfterNotificationPrompt = false
    private val notificationsGranted = kotlinx.coroutines.flow.MutableStateFlow(false)
    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        notificationsGranted.value = granted
        if (startAfterNotificationPrompt) {
            startAfterNotificationPrompt = false
            requestVpnConsent()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        // Only on a fresh start: after a configuration change the intent was already handled.
        if (savedInstanceState == null) destination.value = Routes.sanitize(intent?.getStringExtra(EXTRA_DESTINATION))
        startAfterNotificationPrompt = savedInstanceState?.getBoolean(STATE_START_PENDING) ?: false
        notificationsGranted.value = hasNotificationPermission()
        setContent {
            VigilTheme {
                val settings by vm.settings.collectAsStateWithLifecycle()
                if (!settings.onboarded) {
                    val granted by notificationsGranted.collectAsStateWithLifecycle()
                    OnboardingScreen(
                        vm,
                        notificationsGranted = granted,
                        onRequestNotifications = {
                            if (Build.VERSION.SDK_INT >= 33) notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
                        },
                        onFinish = { vm.updateSettings { it.copy(onboarded = true) } },
                        onStartInspecting = {
                            vm.updateSettings { it.copy(onboarded = true) }
                            startInspection()
                        },
                    )
                    return@VigilTheme
                }
                val nav = rememberNavController()
                val target by destination.collectAsStateWithLifecycle()
                LaunchedEffect(target) {
                    target?.let { route ->
                        destination.value = null
                        // Routes are whitelisted, but never let a bad request crash the app.
                        runCatching {
                            nav.navigate(route) {
                                popUpTo("dashboard") { saveState = true }
                                launchSingleTop = true
                            }
                        }.onFailure { Log.w("vigil.ui", "cannot open $route: ${it.message}") }
                    }
                }
                VigilScaffold(nav)
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(STATE_START_PENDING, startAfterNotificationPrompt)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        Routes.sanitize(intent.getStringExtra(EXTRA_DESTINATION))?.let { destination.value = it }
    }

    private fun hasNotificationPermission() = Build.VERSION.SDK_INT < 33 ||
        ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    /**
     * Starts inspection. Asks for notifications first (Android 13+), then for
     * VPN consent once that prompt is answered, so the two dialogs never overlap.
     */
    fun startInspection() {
        if (!hasNotificationPermission()) {
            startAfterNotificationPrompt = true
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            requestVpnConsent()
        }
    }

    private fun requestVpnConsent() {
        val consent = VpnService.prepare(this)
        if (consent != null) vpnConsent.launch(consent) else VigilVpnService.start(this)
    }

    fun stopInspection() = VigilVpnService.stop(this)

    private data class Tab(val route: String, val label: String, val icon: ImageVector)

    @Composable
    private fun VigilScaffold(nav: NavHostController) {
        val tabs = listOf(
            Tab("dashboard", "Overview", Icons.Default.Home),
            Tab("activity", "Activity", Icons.AutoMirrored.Filled.List),
            Tab("apps", "Apps", Icons.Default.AccountBox),
            Tab("alerts", "Alerts", Icons.Default.Warning),
            Tab("settings", "Settings", Icons.Default.Settings),
        )
        val backStack by nav.currentBackStackEntryAsState()
        val route = backStack?.destination?.route
        val unseen by vm.unseenAlerts.collectAsStateWithLifecycle()
        val snackbar = remember { SnackbarHostState() }
        // Messages stay queued in the view model until shown, so a message
        // raised during onboarding or a rotation is not lost. If the activity
        // is recreated mid-display, the same message is shown again.
        val pending by vm.messages.collectAsStateWithLifecycle()
        val head = pending.firstOrNull()
        LaunchedEffect(head?.id) {
            if (head == null) return@LaunchedEffect
            val result = snackbar.showSnackbar(
                head.text,
                actionLabel = head.actionLabel,
                withDismissAction = head.actionLabel != null,
                duration = if (head.actionLabel != null) SnackbarDuration.Long else SnackbarDuration.Short,
            )
            if (result == SnackbarResult.ActionPerformed) head.action?.invoke()
            vm.messageShown(head.id)
        }
        Scaffold(
            snackbarHost = { SnackbarHost(snackbar) },
            bottomBar = {
                if (tabs.any { it.route == route }) {
                    NavigationBar {
                        tabs.forEach { tab ->
                            NavigationBarItem(
                                selected = route == tab.route,
                                onClick = {
                                    // A fresh visit to Activity starts unfiltered.
                                    if (tab.route == "activity" && route != "activity") vm.clearActivityFilters()
                                    nav.navigate(tab.route) {
                                        popUpTo("dashboard") { saveState = true }
                                        launchSingleTop = true
                                        restoreState = true
                                    }
                                },
                                icon = {
                                    if (tab.route == "alerts" && unseen > 0) {
                                        BadgedBox(badge = { Badge { Text(if (unseen > 99) "99+" else unseen.toString()) } }) { Icon(tab.icon, null) }
                                    } else {
                                        Icon(tab.icon, null)
                                    }
                                },
                                label = { Text(tab.label) },
                            )
                        }
                    }
                }
            },
        ) { padding ->
            NavHost(nav, startDestination = "dashboard", modifier = Modifier.padding(bottom = padding.calculateBottomPadding())) {
                composable("dashboard") { DashboardScreen(vm, nav, onStart = ::startInspection, onStop = ::stopInspection) }
                composable("activity") { ActivityScreen(vm, nav) }
                composable("apps") { AppsScreen(vm, nav) }
                composable("alerts") { AlertsScreen(vm, nav) }
                composable("settings") { SettingsScreen(vm, nav) }
                composable("feeds") { FeedsScreen(vm, nav) }
                composable("export") { ExportScreen(vm, nav) }
                composable("rules") { RulesScreen(vm, nav) }
                composable("dns") { DnsScreen(vm, nav) }
                composable("upstream") { UpstreamScreen(vm, nav) }
                composable("app/{pkg}", arguments = listOf(navArgument("pkg") { type = NavType.StringType })) {
                    AppDetailScreen(vm, nav, it.arguments?.getString("pkg").orEmpty())
                }
                composable("flow/{id}", arguments = listOf(navArgument("id") { type = NavType.LongType })) {
                    FlowDetailScreen(vm, nav, it.arguments?.getLong("id") ?: 0)
                }
            }
        }
    }

    companion object {
        const val EXTRA_DESTINATION = "destination"
        private const val STATE_START_PENDING = "start_pending"
    }
}
