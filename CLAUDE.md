# vigil: notes for AI assistants

On-device Android network inspector: a Rust engine (`core/`) behind a local
VpnService, and a Kotlin/Compose app (`android/`).

Before doing anything, read:

1. `docs/STATUS.md`: start with **"Resume here"** (open owner actions and
   state), then what is done and verified, the prioritised backlog, known
   limitations and the decision log.
2. `docs/DEVELOPMENT.md`: toolchain, build and test commands, the gotchas
   list and the code map (including the cross-language contracts that must
   stay in sync), plus the **release checklist**.

Working rules for this repo:

- Every test suite is green after the post-0.4.0 work (packet capture,
  per-app rules, spyware packs, tracker labels, review fixes). Keep it that
  way: run `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test --locked`,
  `scripts/e2e-netns.sh`, `scripts/jni-smoke.sh`, and
  `./gradlew lintDebug testDebugUnitTest -Pvigil.skipCargo=true`. For app or
  engine behaviour changes, also run `scripts/android-e2e.sh`,
  `scripts/android-lifecycle.sh` (`SKIP_BOOT=1` to skip the reboot),
  `scripts/android-features.sh` and `scripts/android-newfeatures.sh` on the emulators (AVDs `vigil35` and
  `vigil36`, one at a time).
- When changing the event or config JSON, update both sides and `docs/EVENTS.md`.
- Update `docs/STATUS.md` (state table, backlog, decision log) and
  `CHANGELOG.md` at the end of each work session.
- Never commit `android/keystore.properties`, keystores, `local.properties`,
  or generated `jniLibs/`.
- Commits are authored as **H3xano <h3xano@gmail.com>** (set in
  `.git/config`; check it in new worktrees) and must **not** contain `Co-Authored-By` or
  "Generated with Claude" lines (owner's explicit preference). The same goes for
  PR bodies and merge commits.
- The remote is the **public** repo `github.com/H3xano/vigil`: never commit
  secrets, local paths or anything private. The release keystore lives in
  `~/.vigil-release/` on the owner's machine.
- Commit freely; **push, tag and publish releases only when the owner asks**.
- Parallel work: sub-agents in git worktrees, one area each, with the
  cross-language contract (config/event JSON, JNI) written into their prompt;
  keep them off each other's files, cap builds (`CARGO_BUILD_JOBS=3`,
  Gradle `--max-workers=2`), and merge + run the full matrix in the main
  session. The machine has 14 GB: the emulator gets OOM-killed next to
  several builds.
