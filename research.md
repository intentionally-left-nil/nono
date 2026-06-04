# Session Hook Path Substitution: Research & Design Notes

## Problem

Session hooks (`session_hooks.before` / `session_hooks.after` in a profile)
require a fully absolute, hardcoded path in the `script` field. This is fine
for user-authored local profiles, but it makes pack-shipped profiles
non-relocatable: a pack author cannot reference a script that lives inside
their own pack without knowing the user's installation prefix.

The goal is to support pack-relative hook references (e.g.
`"$PACK_DIR/hooks/setup.sh"`) for registry-distributed packs, while keeping
the existing absolute-path requirement for user-authored profiles.

The hard constraint: any solution must preserve nono's tamper-detection
guarantee. If someone modifies a hook script after install, we must detect it
before executing the script.

---

## Question 1: How do session hooks work today?

### Current implementation

- `SessionHook { script: PathBuf, timeout_secs: Option<u64> }` defined at
  `crates/nono-cli/src/profile/mod.rs:1185-1218`.
- Deserialized directly as a `PathBuf` from JSON. **No variable substitution
  is applied to the `script` field anywhere.**
- Flow: profile load → `sandbox_prepare.rs:1106` copies into
  `PreparedSandbox` → `launch_runtime.rs:276` copies into `ExecutionFlags`
  → `execution_runtime.rs:274` calls `hook_runtime::execute_before_hook()`.
- `validate_hook_script()` in `hook_runtime.rs:210` enforces: absolute path,
  canonicalizable, executable, owned by current user or root, parent
  directory not world-writable.

### Existing substitution systems

Two completely disjoint systems exist:

| System | Location | Variables | Used for |
|---|---|---|---|
| `profile::expand_vars()` | `profile/mod.rs:2849` | `$HOME`, `$WORKDIR`, `$TMPDIR`, `$NONO_PACKAGES`, XDG, `~` | Filesystem paths, command_args |
| `wiring::expand_vars()` | `wiring.rs:648` | `$PACK_DIR`, `$NS`, `$PLUGIN`, `$HOME`, `$XDG_CONFIG_HOME`, `$NOW` | Install-time wiring directives only |

Neither is ever called on `session_hooks.script`. `$PACK_DIR` exists today
only at pack install time; it never surfaces at session-execution time.

---

## Question 2: How does provenance work for pack artifacts vs. local profiles?

### Registry packs

- Stored in `~/.config/nono/packages/<ns>/<name>/`.
- A single lockfile at `~/.config/nono/packages/lockfile.json` maps
  `<ns>/<name>` → `LockedPackage { artifacts: BTreeMap<String, LockedArtifact> }`.
- Each `LockedArtifact` holds `sha256` and `artifact_type`.
- `verify_profile_packs()` (`profile_runtime.rs:66-162`) runs at every
  session start: re-reads every artifact from disk, re-hashes it, hard-errors
  on mismatch. Sigstore bundle is also re-verified.
- This is the strongest guarantee in the codebase. Any modification of a
  declared artifact between install and run is caught.

### Local profiles

- Stored in `~/.config/nono/profiles/<name>.json` or referenced by a bare
  file path.
- No lockfile entry, no SHA, no signature. The trust model is
  "the user owns this, the user is trusted." Existing
  `validate_hook_script()` checks (ownership, executability, world-writable
  parent) prevent third-party injection but do not detect user-initiated
  changes.

### The verification gap

Manifest-declared artifacts (`Profile`, `Instruction`, `TrustPolicy`,
`Groups`, `Plugin`) are SHA-verified continuously. Files written outside the
pack store by `WriteFile` wiring directives are recorded in a separate
`wiring_record` field and **never re-verified at session time**. The
deployed copy at `$HOME/.claude/hooks/x.sh` can be modified silently after
install.

---

## Question 3: What syntax should pack-relative hooks use, and how do we keep
provenance attached?

### Why install-time materialization fails

If `nono pull` resolves `$PACK_DIR/hooks/setup.sh` at install time and writes
the absolute path into a profile on disk, all that the runtime sees later is
a literal absolute path. To recover the trust class ("this came from a pack,
verify against lockfile"), the runtime would have to do filesystem-location
detection: canonicalize, see if the result falls inside some
`package_install_dir(ns, name)`, then look up the artifact. This is brittle
(symlink/canonicalization quirks, breaks if pack is uninstalled, conflates
local-trust paths that happen to live inside the pack store) and creates an
implicit coupling between filesystem layout and trust class.

**Conclusion: the variable form must be preserved on disk.** The presence
of `$PACK_DIR` in the JSON is itself the trust signal saying "apply
pack-trust rules to this hook."

### The two trust classes

| Form | Trust class | Verification | Allowed in |
|---|---|---|---|
| `$PACK_DIR/relative/path.sh` | Registry-attested | Resolved path must be a declared artifact in containing pack's lockfile; SHA-256 re-checked at session start | Pack-store profiles only |
| `/absolute/path.sh` | Local-trust | Existing `validate_hook_script()` (ownership, executability, world-writable parent) | User-authored profiles only |

Pack-store profile JSON is itself a SHA-verified artifact, so the bytes
`"$PACK_DIR/..."` are sealed by the pack's attestation. The pack author
committed to running their script.

---

## Question 4: Should `$PACK_DIR` reach into dependency packs?

`profile.packs[]` declares **runtime dependencies** — other packs that must
be present and intact at launch. This is distinct from **containment**: a
profile is contained in at most one pack (zero for user profiles).

`$PACK_DIR` is naturally a containment concept. Allowing it to reach into a
dependency pack would:

- Detach the script from its signing identity (pack A executing bytes signed
  by pack B's identity, but referenced from A's signed JSON).
- Expand the attack surface of content-only dep packs (`Groups`,
  `TrustPolicy`) by pressuring them to expose executables.
- Introduce version-drift surprises (dep upgrade silently swaps script).
- Complicate audit and revocation (cross-graph traversal).

If a pack genuinely needs another pack's script, the correct primitives
remain available: vendor the script under your own attestation, or use
wiring materialization (with the explicit local-trust trade-off).

**Conclusion: `$PACK_DIR` resolves only against the pack that contains the
profile.** Dependency packs do not participate.

---

## Question 5: How does `extends` differ from dependencies, and what does it
mean for cross-pack hooks?

| | `extends` | `packs[]` (dependencies) |
|---|---|---|
| Lifecycle | Load-time, in-memory merge | Runtime SHA verification |
| Composes content | Yes (field-by-field merge) | No |
| Materialized on disk | No | No |
| Brings hooks in | Yes (via merge) | No |
| Cross-pack reach | Yes (base may live in another pack) | N/A |

`resolve_extends()` (`profile/mod.rs:2316`) recursively loads each base and
folds them via `merge_profiles()` (`profile/mod.rs:2506`). The merge is a
**pure function**: takes two owned `Profile` values, returns a new
`Profile`, no I/O, no errors, no global state.

The merged profile is in-memory only. There is no on-disk materialization of
the merge result.

### The cross-pack hook case

If pack `a/derived` extends `b/base`, and `b/base`'s profile defines a hook
with `$PACK_DIR/...`, the merged profile inherits that hook. The bytes
saying `$PACK_DIR/...` came from B's signed JSON, so the only correct
resolution is: `$PACK_DIR` points at `b/base`'s install directory; the hook
is verified against `b/base`'s lockfile entry.

This is the **only** code path through which a hook from one pack runs
through a profile contained in another pack. It is gated by the explicit
`extends` declaration, which is a deliberate authoring decision.

---

## Question 6: Is it sufficient to lean on existing pack verification?

`verify_profile_packs()` runs before any hook executes (it is invoked inside
`prepare_profile_with_options()`, which runs before `PreparedSandbox` is
built and well before `execute_before_hook()`). It already SHA-verifies
every entry in each `LockedPackage.artifacts`.

Therefore the new hook handler only needs a **membership check**:

> "Does the resolved `$PACK_DIR/relative/path.sh` correspond to an entry in
> the containing pack's `LockedPackage.artifacts` map?"

If yes — SHA was already verified upstream, safe to execute.
If no — reject. This catches the "random file in the pack directory that
was added later, undeclared as an artifact" case.

Splitting responsibilities this way:
- `verify_profile_packs()` answers "is everything we know about intact?"
- Hook handler answers "is this thing we're about to run something we know
  about?"

Together they cover both modification and injection. No re-hashing in the
hook handler is required.

### Lockfile coordination

There is only **one lockfile** (`~/.config/nono/packages/lockfile.json`),
keyed by `<ns>/<name>`. Multi-pack lookups (e.g. extends-cross-pack case)
are simple `BTreeMap` lookups against the same already-loaded snapshot.
This is the same pattern `verify_profile_packs()` already uses.

---

## Question 7: How do we propagate source-pack identity through a pure merge?

The merge function is pure and should stay pure. Embedding lockfile reads
or filesystem checks inside `merge_profiles()` would force it to become
`Result`-returning, take extra context, and scatter verification across a
function whose job is structural composition.

### Options considered

**A. Tag-and-propagate.** Add `source_pack: Option<PackIdentity>` to
`SessionHook`. The loader sets it when deserializing from a pack-store JSON
file. Merge picks one whole `SessionHook` or the other (current logic at
line 2652 already does this with `child.session_hooks.before.or(base.…)`),
so the tag rides through unchanged. Verification + `$PACK_DIR` expansion
happens in a dedicated post-merge pass alongside `verify_profile_packs()`.
Minimal merge change. Mirrors existing
"pure structural merge → separate impure verification pass" pattern.

**B. Resolve at load time, typed enum.** Loader expands `$PACK_DIR`
immediately and stores a typed `enum HookScript { PackArtifact { pack,
relative, absolute }, LocalAbsolute(PathBuf) }`. Type-system enforces
trust-class separation. Slightly more invasive than A.

**C. Two-phase profile lifecycle.** Introduce
`RawProfile → ResolvedProfile` types. Most architecturally pure but largest
code change.

**Conclusion: Option A.** It is the smallest change, preserves merge
purity, and matches the existing codebase pattern of separating pure
composition from impure verification passes.

---

## Question 8: What's the blast radius of fixing the verification list so
extends-cross-pack hooks are always covered?

Already mostly handled in the codebase:

- `load_profile_inner` auto-injects the containing pack into `profile.packs`
  at line 1930.
- `load_base_profile_raw` (used by `resolve_extends`) auto-injects in both
  pack-store branches at lines 2449 and 2477. Comment at 2444-2446 makes
  the intent explicit.
- `merge_profiles` propagates via `dedup_append(&base.packs, &child.packs)`
  at line 2676.

The remaining asymmetry — `load_registry_profile` at line 2105 doesn't
auto-inject — is a pre-existing latent bug and is being tracked separately
from this work.

---

## Conclusions

1. **Keep `$PACK_DIR` as a literal in the on-disk JSON.** The variable form
   is the trust signal. Install-time materialization erases the signal and
   forces brittle filesystem-location heuristics later.

2. **`$PACK_DIR` binds to the containing pack only.** Dependency packs and
   sibling packs do not participate. The single exception, where the hook
   actually executes from a different pack's directory, is the explicit
   `extends` chain — and even there, the resolution is "the pack containing
   the JSON file the hook line came from," which is a containment relation,
   not a dependency one.

3. **Two trust classes, distinguished by syntax in the profile JSON:**
   - Pack-relative (`$PACK_DIR/...`) — only valid in pack-store profiles;
     resolved path must be a declared artifact in the containing pack's
     lockfile entry; covered by `verify_profile_packs()` SHA check.
   - Absolute (`/...`) — only valid in user-authored profiles; covered by
     existing `validate_hook_script()` ownership/permissions checks.

4. **Add a `source_pack: Option<PackIdentity>` tag to `SessionHook`,
   populated by the loader.** Merge stays pure; the tag rides through
   unchanged because merge selects whole hook structs, not field-merges
   within them. After merge, each hook carries an unambiguous origin.

5. **Verification responsibilities split cleanly:**
   - `verify_profile_packs()` (existing) — SHA-verifies all lockfile-declared
     artifacts in every pack reachable from the merged profile.
   - New post-merge hook pass — for each hook with a `source_pack` tag,
     expand `$PACK_DIR` against the tagged pack's install directory, then
     verify the resolved relative path is a declared artifact in that pack's
     `LockedPackage.artifacts`.
   - Hooks without a tag continue through `validate_hook_script()` only.

6. **The lockfile is a single file with multi-pack lookups; extends across
   packs is a `BTreeMap` lookup, not a coordination problem.**

7. **The merge function stays pure.** All new I/O lives in the post-merge
   verification pass, alongside existing `verify_profile_packs()`.

## Out of scope for this work

- Fixing the `load_registry_profile` auto-injection asymmetry (separate
  pre-existing bug).
- Re-verifying wiring-materialized files (`WriteFile` directives) at session
  start.
- Cross-pack `$PACK_DIR` syntax such as `$PACK_DIR(ns/name)`.
- Variable substitution for fields other than `session_hooks.script`.
