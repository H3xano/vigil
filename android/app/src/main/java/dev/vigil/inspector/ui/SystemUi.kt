package dev.vigil.inspector.ui

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.util.Log
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import androidx.core.net.toUri
import dev.vigil.inspector.R

private const val TAG = "vigil.ui"

private fun Context.noAppFound() = Toast.makeText(this, R.string.common_no_app, Toast.LENGTH_LONG).show()

/**
 * Starts [intent] (a system settings screen, a web page), showing a short
 * message instead of crashing when no app on the device handles it (some
 * builds lack a settings page or a browser). Returns whether it started.
 */
fun Context.startActivitySafely(intent: Intent): Boolean = try {
    startActivity(intent)
    true
} catch (_: ActivityNotFoundException) {
    noAppFound()
    false
} catch (e: SecurityException) {
    Log.w(TAG, "cannot start ${intent.action}: ${e.message}")
    noAppFound()
    false
}

/** Opens [url] in a browser (see [startActivitySafely]). */
fun Context.openUrlSafely(url: String): Boolean = startActivitySafely(Intent(Intent.ACTION_VIEW, url.toUri()))

/** Launches [this] (a file picker), showing a message when no app provides one. Returns whether it started. */
fun <I> ActivityResultLauncher<I>.launchSafely(context: Context, input: I): Boolean = try {
    launch(input)
    true
} catch (_: ActivityNotFoundException) {
    context.noAppFound()
    false
}

/**
 * Deletes a document the user just created with the file picker when nothing
 * could be written to it, so no empty file is left behind. Best effort:
 * not every document provider supports deleting. Blocking (provider IPC).
 */
fun discardDocument(context: Context, uri: Uri): Boolean = try {
    DocumentsContract.deleteDocument(context.contentResolver, uri)
} catch (e: Exception) {
    Log.w(TAG, "could not delete the unused document: ${e.message}")
    false
}
