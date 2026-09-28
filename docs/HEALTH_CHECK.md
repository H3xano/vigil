# Spyware packs and the health check

vigil ships a catalogue group, **Spyware & stalkerware**, and a **health
check** screen for people who fear they are being monitored and for the
helpdesks that support them. Everything is matched on the device; the
indicator files are downloaded by the device from their publishers and are
never redistributed with vigil.

## Sources

| Feed id | Source (raw.githubusercontent.com) | Kind | Default | Licence | Refresh |
|---|---|---|---|---|---|
| `echap-stalkerware-network` | `AssoEchap/stalkerware-indicators/master/generated/network.csv` | `spyware` (loaded as `malware`) | on | CC BY 4.0 | daily |
| `echap-stalkerware-apps` | `AssoEchap/stalkerware-indicators/master/ioc.yaml` | `spyware_apps` (health check only) | on | CC BY 4.0 | daily |
| `echap-watchware` | `AssoEchap/stalkerware-indicators/master/watchware.yaml` | `spyware_apps` (warnings only) | on | CC BY 4.0 | daily |
| `mvt-index` | `mvt-project/mvt-indicators/main/indicators.yaml` | `spyware_index` (adds the packs) | on | MIT | daily |
| `mvt-<path slug>` | one per pack listed by the index | `spyware` (loaded as `malware`) | on, except Echap's STIX copy | per owner, below | every 3 days |

The index is only followed for packs hosted by these GitHub owners, whose
licence is shown with each pack: `mvt-project` (MIT), `AmnestyTech`
(CC BY 2.0), `AssoEchap` (CC BY 4.0). Other owners, other entry types and
paths with `..` or unusual characters are skipped (`MvtIndex.rawUrl`). Packs
the index stops listing are removed; a new index listing less than half the
previous packs is refused. In September 2026 the index listed 19 packs
(about 6,500 domains, 70 IPs, 700 package names and 500 certificates in
total); Echap's `stalkerware.stix2` (4.6 MB) is off by default because the
three Echap feeds carry the same data.

## What a download produces

`FeedRepository` downloads (size-capped: 1 MB for the index, 32 MB per
pack), converts and validates like any feed, keeping the previous copy on
failure or when the indicator count collapses below 10 %:

- `<id>.spy.json` (`SpywarePack`): the indicators grouped by spyware family
  or app (`label`), each group an `indicator` or a `warning` (Echap entries
  of type `watchware`), with domains, IPs, package names and certificates
  (`SHA1:<HEX>` / `SHA256:<HEX>`), plus the licence, reference and download
  time;
- `<id>.txt`: the domains and IPs of `indicator` groups, one per line, for
  the engine. Only `spyware` feeds are loaded (`FeedKinds.loadsIntoEngine`).

Conversion details: STIX bundles are streamed object by object
(`StixStream`), and each indicator takes the name of the `malware` object
its `indicates` relationship points to. IP addresses in `domain-name`
patterns become IPs. URL indicators are ignored (they point at code-hosting
pages), and apex domains of shared platforms (`github.com`, `appspot.com`,
`firebaseio.com` …) are dropped from every source. File hashes, process
names, e-mail addresses and iOS-only indicators are not used. YAML is read
by `MiniYaml`, a small reader for the block style these files use (no YAML
library in the APK).

## Live protection

Spyware pack domains and IPs are threat entries: lookups are sinkholed,
connections refused, and `threat_domain` / `threat_ip` alerts raised. The
app adds the family and pack to the alert (`detail.spyware`, see
[EVENTS.md](EVENTS.md#spyware-labels-app-side)).

## The health check

Overview → "Spyware health check", Settings, or the Spyware group of Threat
intelligence. `HealthCheck` (pure, unit-tested) compares:

1. **Installed apps**: every package name, and the SHA-1 and SHA-256 of
   every signing certificate (current signers and the key-rotation
   history), against the packs' package names and certificates.
2. **Network history**: the stored DNS lookups, connections (by domain and
   by address) and learned destinations, blocked ones included, against the
   packs' domains (the name or any parent domain), IPs and IPv4 ranges.
   History covers the retention period (7 days by default); learned
   destinations up to 90 days.
3. **Readiness**: which packs are on and when they were updated (older than
   8 days is reported), and whether inspection is running.

Verdicts: *No known indicators*, *Warnings* (only monitoring apps),
*Indicators found*, or *Not checked* (no pack downloaded). Each finding
shows the app, package, certificate or domain, first and last seen, how
often and how often blocked, the pack with its licence and reference link.
The guidance is written for people at risk: do not uninstall right away if
someone may notice; contact Access Now's Digital Security Helpline
(<https://www.accessnow.org/help/>) or a service listed by the Coalition
Against Stalkerware (<https://stopstalkerware.org/>); no known indicators
is not proof of safety.

The report can be shared as text or saved as JSON (Storage Access
Framework); it includes the time, vigil's version and each pack's update
time, counts and licence. It is held in memory only.

## Limits

- Only documented spyware is covered, and only by the indicators listed
  above; most mercenary-spyware packs target iOS and contribute domains
  only.
- The network part only sees what vigil recorded while inspecting, within
  the retention period.
- A renamed stalkerware app signed with a new certificate is not
  recognised.

## Checking on a device

Enable the group, update feeds, then:

- Feeds screen: the index row shows "pack list", about 19 `mvt-…` rows
  appear after it, each with domain/IP counts; Echap's STIX pack is off.
- `adb shell run-as dev.vigil.inspector.debug ls files/feeds` shows
  `*.spy.json` next to the `.txt` files.
- Look up a pack domain (for example one from Echap's `network.csv`): the
  alert names the stalkerware.
- Install a test app whose package name is listed (the check matches the
  package name alone, so any APK built with such an `applicationId` will
  do) and run the health check; share the text report and save the JSON.
