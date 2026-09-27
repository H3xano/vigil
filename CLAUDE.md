# vigil: notes for AI assistants

On-device Android network inspector: a Rust engine (`core/`) behind a local
VpnService, and a Kotlin/Compose app (`android/`).

Before doing anything, read:

1. `docs/STATUS.md`: what is done and verified, the prioritised backlog,
   known limitations and the decision log.
2. `docs/DEVELOPMENT.md`: toolchain, build and test commands, the gotchas
   list and the code map (including the cross-language contracts that must
   stay in sync).

Working rules for this repo:

- Every test suite was green at 0.1.0. Keep it that way: run
  `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`,
  `scripts/e2e-netns.sh`, `scripts/jni-smoke.sh`, and
  `./gradlew lintDebug testDebugUnitTest`. For app or engine behaviour
  changes, also run `scripts/android-e2e.sh` on the emulator.
- When changing the event or config JSON, update both sides and `docs/EVENTS.md`.
- Update `docs/STATUS.md` (state table, backlog, decision log) and
  `CHANGELOG.md` at the end of each work session.
- Never commit `android/keystore.properties`, keystores, `local.properties`,
  or generated `jniLibs/`.
- Commits are authored as H3xano; the remote is the private repo
  `github.com/H3xano/vigil`.
