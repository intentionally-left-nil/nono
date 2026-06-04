# Plan: Pack-Relative Session Hook Scripts with Provenance

## Goal

Allow `session_hooks.{before,after}.script` in pack-store profiles to use a
`$PACK_DIR/...` prefix, bind it to the containing pack's lockfile entry for
tamper detection, and reject `$PACK_DIR` in user-authored profiles. Preserve
`merge_profiles()` purity.

## Scope

- **In:** `session_hooks.before.script` and `session_hooks.after.script`.
- **In:** Q1 fix — `load_registry_profile` (`profile/mod.rs:2105`) injects
  `pack_key` into `profile.packs`, matching the other two pack-store loaders.
- **Out:** re-verifying `WriteFile`-materialized files; `$PACK_DIR(ns/name)`
  cross-pack syntax; substitution on any other field; any other variables.

## Data model

`SessionHook` (`profile/mod.rs:1189`) gains an internal-only field:

```rust
#[serde(skip)]
pub(crate) source_pack: Option<String>,   // "ns/name", internal-only
```

`#[serde(skip)]` on both serialize and deserialize sides ensures the tag is
never on disk and never user-supplied (`deny_unknown_fields` rejects any
forged value). `String` is sufficient — pack components are restricted to
alphanumerics plus `-`, `_`, `.` by `validate_package_component`
(`package.rs:306`), so a single `/` cleanly separates ns and name.

## Substitution: load-time

Substitution happens in the loaders, in the same places that already inject
`pack_key` into `profile.packs`. Merge stays pure; the runtime sees an
absolute `PathBuf`.

Two helpers in `profile/mod.rs`:

```rust
fn apply_pack_dir_to_session_hooks(
    profile: &mut Profile,
    pack_key: &str,
    pack_dir: &Path,
) -> Result<()>;

fn reject_pack_dir_in_session_hooks(profile: &Profile, source: &Path) -> Result<()>;
```

`apply_pack_dir_to_session_hooks`, for each of `before` and `after`:

- Treat `script` as `&str` via `to_str()` (error if non-UTF-8).
- If it starts with `"$PACK_DIR/"` → strip prefix, join the remainder onto
  `pack_dir`, store the absolute `PathBuf` in `script`, set
  `source_pack = Some(pack_key.into())`.
- If it contains `$PACK_DIR` anywhere else (bare `$PACK_DIR`,
  `$PACK_DIRfoo`, `prefix/$PACK_DIR/...`) → error:
  `"$PACK_DIR must appear only as a leading prefix in session hook script paths"`.
- If it is an absolute path with no `$PACK_DIR` → leave untouched, no
  `source_pack` tag. Pack profiles may legitimately reference out-of-band
  absolute scripts; these fall through to `validate_hook_script` only, the
  same as today.
- If it is a relative path with no `$PACK_DIR` → leave untouched; existing
  `validate_hook_script` will reject ("must be absolute").

`reject_pack_dir_in_session_hooks`:

- If either hook's script string contains `$PACK_DIR` → error:
  `"$PACK_DIR is only valid in pack-store profiles; profile {source} is user-authored"`.

Plain `starts_with` / `contains` string operations. No new shared helper
module, no expand_vars reuse.

## Loader call sites

| Site | File:line | Today | Change |
|---|---|---|---|
| `load_profile_inner` pack-store branch | `profile/mod.rs:1922` | injects `pack_key` | + `apply_pack_dir_to_session_hooks` |
| `load_profile_inner` user-profile / file-path branches | nearby | nothing | + `reject_pack_dir_in_session_hooks` |
| `load_registry_profile` | `profile/mod.rs:2105` | no injection (latent gap) | inject `pack_key` (Q1 fix) + apply helper |
| `load_base_profile_raw` pack-store branches | `:2447`, `:2475` | injects `pack_key` | + `apply_pack_dir_to_session_hooks` |
| `load_base_profile_raw` user-profile / file-path branches | nearby | nothing | + `reject_pack_dir_in_session_hooks` |

`pack_dir` is `package::package_install_dir(namespace, name)` parsed from the
`pack_key`.

## Merge

`merge_profiles` (`profile/mod.rs:2506`): no functional change. The hook
precedence at lines 2651-2654 selects whole `SessionHook` structs, so
`source_pack` rides through unchanged. The cross-pack `extends` case from
research §5 works for free: a hook defined in pack B's profile, inherited
by pack A's profile, surfaces in the merged profile with
`source_pack = Some("b/base")` and an absolute path under B's install dir.

## Verification: post-merge membership check

New function in `profile_runtime.rs`:

```rust
fn verify_session_hook_provenance(profile: &Profile, lockfile: &Lockfile) -> Result<()>;
```

For each of `before` and `after`:

- If `source_pack` is `None` → skip (local-trust path).
- Else:
  - Look up `LockedPackage` for `source_pack` in `lockfile.packages`.
    Missing → error.
  - Compute `pack_dir = package_install_dir(ns, name)`.
  - Compute artifact key = `script.strip_prefix(&pack_dir)?` as a
    forward-slash string.
  - Look up that key in `LockedPackage.artifacts`. Missing → error: the
    hook is not a declared artifact of the containing pack.
- SHA-256 was already verified by `verify_profile_packs()` upstream; no
  re-hashing in this pass.

Call site: `prepare_profile_with_options` (`profile_runtime.rs:421`),
immediately after `verify_profile_packs()` at line 470.

This is the Q5 design: pure key lookup, naturally rejects `..` traversal,
and cannot reach packs other than the containing or `extends`-base pack
because `source_pack` is set only by the loader at the site where the hook
JSON came from.

## Hook execution

`hook_runtime.rs` unchanged. `validate_hook_script` (`hook_runtime.rs:210`)
continues to run on every hook — defense in depth (Q6). Pack-resolved
scripts under `~/.config/nono/packages/...` satisfy its checks (absolute,
owned by current user, parent not world-writable, executable bit set).

## PreparedSandbox plumbing

No change. `SessionHooks` already clones verbatim through
`sandbox_prepare.rs:1106`, `launch_runtime.rs:276`, and
`execution_runtime.rs:274`. The `source_pack` tag rides along, unused after
verification (kept for potential future audit logging; cheap).

## Tests

`profile/mod.rs` test module:

- `apply_pack_dir_to_session_hooks` strips `$PACK_DIR/` and tags
  `source_pack`.
- Rejects `$PACK_DIR` in non-leading positions, bare `$PACK_DIR`.
- Pack-store profile with a plain absolute script: untouched, no tag.
- `reject_pack_dir_in_session_hooks` errors on user-authored profile with
  `$PACK_DIR` anywhere.
- `merge_profiles` propagates `source_pack` (child overrides; child
  inherits base).
- Cross-pack `extends`: A extends B; B's `$PACK_DIR/...` hook surfaces in
  the merged profile with `source_pack = Some("b/base")` and B's absolute
  path.

`profile_runtime.rs` test module:

- `verify_session_hook_provenance` accepts a hook whose stripped path is in
  `LockedPackage.artifacts`.
- Rejects when the artifact entry is missing (covers `..` traversal — the
  stripped path will not match any real key).
- Rejects when `source_pack` is absent from the lockfile.

Existing tests at `profile/mod.rs:4815-4912` pass unchanged — none use
`$PACK_DIR`.

## Files touched

- `crates/nono-cli/src/profile/mod.rs` — `SessionHook` field, two helpers,
  four loader call-site changes (including the Q1 fix in
  `load_registry_profile`), unit tests.
- `crates/nono-cli/src/profile_runtime.rs` — `verify_session_hook_provenance`,
  invoked from `prepare_profile_with_options`, unit tests.
- No other files.

## Out of scope (confirmed)

- Re-verifying wiring-materialized files (`WriteFile` directives) — known
  gap; recommend a doc note in a separate task suggesting `$PACK_DIR/...`
  for new packs.
- Cross-pack `$PACK_DIR(ns/name)` syntax.
- Substitution on any other field; any variable other than `$PACK_DIR`.
- `PackIdentity` newtype refactor — `String` matches the existing
  `Profile.packs` convention; can be revisited later.
