package dev.vigil.inspector.ui

import android.content.Context
import androidx.annotation.PluralsRes
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

/**
 * Text produced outside Compose (validation, status messages, data-layer
 * results) that must follow the app's language. Code that has no Context
 * returns a [UiText]; the UI resolves it. Unit tests compare the resource ids
 * and arguments instead of English wording.
 */
sealed interface UiText {
    /** Text that is not translated: a name, an address, a server's own error message. */
    data class Raw(val text: String) : UiText

    data class Res(@param:StringRes val id: Int, val args: List<Any> = emptyList()) : UiText

    data class Plural(@param:PluralsRes val id: Int, val count: Int, val args: List<Any> = emptyList()) : UiText

    fun resolve(context: Context): String {
        val res = context.resources
        return when (this) {
            is Raw -> text
            is Res -> res.getString(id, *resolveArgs(context))
            is Plural -> res.getQuantityString(id, count, *resolveArgs(context))
        }
    }

    private fun resolveArgs(context: Context): Array<Any> = when (this) {
        is Raw -> emptyArray()
        is Res -> args.map { if (it is UiText) it.resolve(context) else it }.toTypedArray()
        is Plural -> args.map { if (it is UiText) it.resolve(context) else it }.toTypedArray()
    }

    companion object {
        fun of(@StringRes id: Int, vararg args: Any): UiText = Res(id, args.toList())
        fun plural(@PluralsRes id: Int, count: Int, vararg args: Any): UiText = Plural(id, count, args.toList())
    }
}

@Composable
fun UiText.asString(): String = resolve(LocalContext.current)
