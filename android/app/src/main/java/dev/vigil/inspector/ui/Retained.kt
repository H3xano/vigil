package dev.vigil.inspector.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewmodel.compose.viewModel

/**
 * Holds UI state of one screen across configuration changes. It lives in
 * the screen's navigation back stack entry (its ViewModelStoreOwner), so it
 * is dropped when the screen is left, and it is kept in memory only: unlike
 * rememberSaveable nothing goes into the saved-instance Bundle, which makes
 * it the place for unsaved form drafts that may contain tokens, passwords
 * or WireGuard keys.
 */
class RetainedStateStore : ViewModel() {
    internal val values = HashMap<String, MutableState<*>>()
}

/**
 * Like `remember { mutableStateOf(init()) }`, but survives rotation (see
 * [RetainedStateStore]). [key] must be unique within the screen.
 */
@Suppress("UNCHECKED_CAST")
@Composable
fun <T> rememberRetained(key: String, init: () -> T): MutableState<T> {
    val store: RetainedStateStore = viewModel()
    return remember(store, key) { store.values.getOrPut(key) { mutableStateOf(init()) } as MutableState<T> }
}
