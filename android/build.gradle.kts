buildscript {
    dependencies {
        // AGP 9 compiles Kotlin itself (built-in Kotlin) and only depends on
        // KGP 2.2.10 at runtime; this pins the Kotlin compiler to the same
        // version as the compose and serialization compiler plugins below.
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.20")
    }
}

plugins {
    id("com.android.application") version "9.4.1" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "2.4.20" apply false
    id("com.google.devtools.ksp") version "2.3.12" apply false
}
