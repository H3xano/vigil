package dev.vigil.inspector.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/** Semantic colours for one theme. */
@Immutable
data class SemanticColors(
    val block: Color,
    val allow: Color,
    val medium: Color,
    val low: Color,
    val info: Color,
    /** Background alpha of filled tags. */
    val tintAlpha: Float,
)

/** The original palette; bright enough on the dark background. */
private val DarkSemantic = SemanticColors(
    block = Color(0xFFE5484D),
    allow = Color(0xFF30A46C),
    medium = Color(0xFFF76B15),
    low = Color(0xFFFFB224),
    info = Color(0xFF3E9BF4),
    tintAlpha = 0.18f,
)

/**
 * Darker shades for the light theme: each reaches at least 4.5:1 (WCAG AA)
 * against the light surfaces and against its own filled-tag tint.
 */
private val LightSemantic = SemanticColors(
    block = Color(0xFFA8201A),
    allow = Color(0xFF146336),
    medium = Color(0xFF9A3C06),
    low = Color(0xFF7A4D00),
    info = Color(0xFF17559F),
    tintAlpha = 0.12f,
)

private val LocalSemanticColors = staticCompositionLocalOf { DarkSemantic }

/** Semantic colours used for verdicts and severities, resolved for the current theme. */
object VigilColors {
    val Block: Color @Composable @ReadOnlyComposable get() = LocalSemanticColors.current.block
    val Allow: Color @Composable @ReadOnlyComposable get() = LocalSemanticColors.current.allow
    val High: Color @Composable @ReadOnlyComposable get() = LocalSemanticColors.current.block
    val Medium: Color @Composable @ReadOnlyComposable get() = LocalSemanticColors.current.medium
    val Low: Color @Composable @ReadOnlyComposable get() = LocalSemanticColors.current.low
    val Info: Color @Composable @ReadOnlyComposable get() = LocalSemanticColors.current.info
    val TintAlpha: Float @Composable @ReadOnlyComposable get() = LocalSemanticColors.current.tintAlpha

    @Composable
    @ReadOnlyComposable
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
    CompositionLocalProvider(LocalSemanticColors provides if (dark) DarkSemantic else LightSemantic) {
        MaterialTheme(colorScheme = if (dark) Dark else Light, content = content)
    }
}
