package dev.vigil.inspector.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/** Semantic colours used for verdicts and severities in both themes. */
object VigilColors {
    val Block = Color(0xFFE5484D)
    val Allow = Color(0xFF30A46C)
    val High = Color(0xFFE5484D)
    val Medium = Color(0xFFF76B15)
    val Low = Color(0xFFFFB224)
    val Info = Color(0xFF3E9BF4)
    val Accent = Color(0xFF12A594)

    fun severity(s: String) = when (s) {
        "high" -> High
        "medium" -> Medium
        "low" -> Low
        else -> Info
    }
}

private val Dark = darkColorScheme(
    primary = Color(0xFF3DD9C1),
    onPrimary = Color(0xFF00382F),
    primaryContainer = Color(0xFF0B4F45),
    onPrimaryContainer = Color(0xFFA6F5E6),
    secondary = Color(0xFF9CC9FF),
    background = Color(0xFF0D1117),
    onBackground = Color(0xFFE6EDF3),
    surface = Color(0xFF0D1117),
    onSurface = Color(0xFFE6EDF3),
    surfaceVariant = Color(0xFF1C2330),
    onSurfaceVariant = Color(0xFF9DA7B3),
    surfaceContainer = Color(0xFF151B24),
    surfaceContainerHigh = Color(0xFF1C2330),
    surfaceContainerLow = Color(0xFF121820),
    outline = Color(0xFF3A4452),
    outlineVariant = Color(0xFF262E3A),
    error = Color(0xFFFF6B6B),
)

private val Light = lightColorScheme(
    primary = Color(0xFF00796B),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFB8F2E6),
    onPrimaryContainer = Color(0xFF00201B),
    secondary = Color(0xFF2F6BB3),
    background = Color(0xFFF7F9FB),
    surface = Color(0xFFF7F9FB),
    surfaceVariant = Color(0xFFE3E8EE),
    onSurfaceVariant = Color(0xFF4A5563),
    surfaceContainer = Color(0xFFEEF2F6),
    surfaceContainerHigh = Color(0xFFE6EBF0),
    surfaceContainerLow = Color(0xFFF2F5F8),
)

@Composable
fun VigilTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (dark) Dark else Light, content = content)
}
