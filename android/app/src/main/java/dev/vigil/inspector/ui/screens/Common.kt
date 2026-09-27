package dev.vigil.inspector.ui.screens

import androidx.compose.foundation.layout.RowScope
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.style.TextOverflow
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.ui.MainViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VigilTopBar(title: String, nav: NavController? = null, actions: @Composable RowScope.() -> Unit = {}) {
    TopAppBar(
        title = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        navigationIcon = {
            if (nav != null) {
                IconButton(onClick = { nav.popBackStack() }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") }
            }
        },
        actions = actions,
    )
}

/**
 * App labels for [keys], resolved off the main thread by the view model.
 * Until a label arrives the package name (or "UID n") is shown.
 */
@Composable
fun rememberAppLabels(vm: MainViewModel, keys: List<String>): (String) -> String {
    val labels by vm.labels.collectAsStateWithLifecycle()
    LaunchedEffect(keys) { vm.requestLabels(keys) }
    return { key -> labels[key] ?: vm.fallbackLabel(key) }
}

/** Whether usage access is granted, re-checked whenever the screen resumes (e.g. back from Settings). */
@Composable
fun usageAccessGranted(vm: MainViewModel): Boolean {
    var granted by remember { mutableStateOf(vm.app.foreground.hasPermission()) }
    LifecycleResumeEffect(Unit) {
        granted = vm.app.foreground.hasPermission()
        onPauseOrDispose { }
    }
    return granted
}
