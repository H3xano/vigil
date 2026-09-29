# Translating vigil

vigil's interface is written in English and every user-visible string lives
in Android string resources, so it can be translated without touching code.
This page is for translators and for developers adding text.

## For translators

The English source strings are split by area, in
`android/app/src/main/res/values/`:

| File | What it covers |
|---|---|
| `strings.xml` | App name and strings shared by several screens (Cancel, Undo, Save…) |
| `strings_app.xml` | Navigation, onboarding, glossary, VPN notifications |
| `strings_monitor.xml` | Overview, Connections, DNS, connection detail, Apps |
| `strings_alerts.xml` | Alert titles and sentences, alert notifications |
| `strings_feeds.xml` | Feeds, tracker labels, rules, blocking explanations |
| `strings_health.xml` | The spyware health check and its report |
| `strings_settings.xml` | Settings, upstream (WireGuard, SOCKS5, encrypted DNS), packet capture, SIEM export |

A translation goes into `values-<language>/` with the same file names, for
example `values-fr/strings_alerts.xml` or `values-pt-rBR/strings_app.xml`.
Leave out strings you have not translated: Android falls back to English
for each missing string.

Please keep:

- **Placeholders** such as `%1$s` and `%2$d`, in any order your language
  needs. `%1$s` is text (an app name, a host name), `%1$d` a number. The
  comment above a string says what each one is.
- **Plurals** (`<plurals>`): give every quantity your language uses
  (`zero`, `one`, `two`, `few`, `many`, `other`), not only English's `one`
  and `other`.
- **Escapes:** write an apostrophe as `\'`, a double quote as `\"`, and a
  literal percent sign as `%%` in strings that have placeholders.
- **Names as they are:** vigil, WireGuard, SOCKS5, DNS, DoH, DoT, JA4, ECS,
  TAXII, MISP, Wireshark and other protocol or product names. Strings
  marked `translatable="false"` are not translated.
- **Tone:** the health check speaks to people who may be afraid of being
  watched. Keep its texts calm, plain and non-alarming.

Short labels (tabs, buttons, segmented choices) have little room; the
comment says so where it matters. Check long translations with a large
font size.

What stays in English on purpose: the events and records vigil sends to a
SIEM, the alert message stored with each alert (it is exported; the screens
build a translated sentence from the alert's kind and details instead), log
messages, and the names of feeds and data sources. Not translated yet: the
details of feed download errors and the publishers' descriptions of spyware
packs, which are stored as text when they are downloaded.

### Trying a translation

Build and install the debug APK (see [DEVELOPMENT.md](DEVELOPMENT.md)),
then on Android 13 or later choose the language for vigil alone under
Settings → Apps → vigil → Language. The list of languages is generated at
build time from the `values-*` folders.

## For developers

- Never put user-visible English in Kotlin. In Compose use
  `stringResource` / `pluralStringResource`; elsewhere `context.getString`.
  Code without a `Context` (validation, view-model and data-layer messages)
  returns a `UiText` (`ui/UiText.kt`), which the UI resolves; unit tests
  compare its resource id and arguments rather than English wording.
- Whole sentences with positional placeholders; never glue translated
  fragments together, and always use `<plurals>` for counts.
- Add a string to the file of its area, with the area's key prefix, and a
  comment when a translator needs context.
- `StringResourcesTest` fails the build when a screen passes an English
  literal to `Text`, a label, a title or a content description.
- The debug build enables the pseudolocales **en-XA** (accented, about 30%
  longer) and **ar-XB** (right-to-left). Pick them under Developer options →
  Languages to find clipped text and layout that ignores RTL.

## Hosting translations

No translation platform is set up yet. Hosted Weblate offers free hosting to
open-source projects (a "component" per `strings*.xml` file, file format
"Android String Resource", with pull requests to GitHub), and F-Droid picks
up translations with each release. Fastlane store texts live in
`fastlane/metadata/android/<locale>/` and can be translated the same way.
