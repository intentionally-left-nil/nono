//! Python launcher entry point for the `python-launcher` cargo feature.
//!
//! This module is a fork of the nono CLI main path, adapted to act as the
//! entry point for a CPython binary built by the python-sandbox feedstock.
//!
//! ## Execution model
//!
//! ```text
//! $PREFIX/bin/python3.x  (outer, unsandboxed)
//!     │
//!     ├─ NONO_CAP_FILE set? (ADR-4)
//!     │
//!     ├─ YES → inner(): unset _CONDA_PYTHON_ARGV0, call Py_BytesMain
//!     │
//!     └─ NO  → outer():
//!              validate $PREFIX from current_exe()
//!              resolve profile name
//!              prepare_sandbox (profile → caps + secrets + hooks + network)
//!              validate proxy bypass / reject dangerous secret env vars
//!              start proxy if profile has network policy
//!              run before-hook (if configured), capture exported env vars
//!              write cap file
//!              execute_supervised → fork → sandbox → execve(self)
//!                  └─ re-exec'd child loops back to YES
//!              run after-hook (if configured)
//! ```
//!
//! ## Key invariants
//!
//! - `profile::set_launcher_prefix` is called before any profile load so
//!   `$PREFIX` tokens in profile paths and set_vars expand correctly.
//! - `_CONDA_PYTHON_ARGV0` is injected via `ExecConfig.env_vars` (bypasses
//!   profile allow/deny filtering) so CPython sees the original argv[0] that
//!   the user typed and can find `pyvenv.cfg` for virtual-env detection.
//! - The inner branch unconditionally unsets `_CONDA_PYTHON_ARGV0` so user
//!   Python code never observes it.

use crate::cli::SandboxArgs;
use crate::exec_strategy::{ExecConfig, is_dangerous_env_var};
use crate::execution_runtime::{cleanup_capability_state_file, write_capability_state_file};
use crate::launch_runtime::{
    ExecutionFlags, ProxyLaunchOptions, RollbackLaunchOptions, SessionLaunchOptions,
    TrustLaunchOptions, select_threading_context,
};
use crate::profile;
use crate::proxy_runtime::{prepare_proxy_launch_options, start_proxy_runtime};
use crate::sandbox_prepare::{prepare_sandbox, validate_external_proxy_bypass};
use crate::supervised_runtime::{SupervisedRuntimeContext, execute_supervised_runtime};
#[cfg(unix)]
use crate::{DETACHED_SESSION_ID_ENV, hook_runtime, session};
use nono::{NonoError, Result};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

// ── libpython C-ABI entry point (ADR-11) ─────────────────────────────────────
//
// Py_BytesMain is the correct embedding entry point for bytes argv (i.e. the
// same raw bytes the OS provides), as opposed to Py_Main which takes wchar_t.
// The symbol is resolved at load time via DT_NEEDED (ELF) / LC_LOAD_DYLIB
// (Mach-O) linkage arranged by build.rs when --features python-launcher is
// active.  The build script validates that libpython is present at link time;
// conda-build's DSO check then validates it again at packaging time.
unsafe extern "C" {
    fn Py_BytesMain(argc: std::os::raw::c_int, argv: *mut *mut std::os::raw::c_char)
        -> std::os::raw::c_int;
}

// ── Constants ────────────────────────────────────────────────────────────────

/// Default profile used when neither `CONDA_PYTHON_PROFILE` nor
/// `$PREFIX/conda-meta/state` specifies one.
const DEFAULT_PROFILE: &str = "intentionally-left-nil/python";

/// Environment variable the user or `$PREFIX/conda-meta/state` may set to
/// override the profile name.
const CONDA_PYTHON_PROFILE_ENV: &str = "CONDA_PYTHON_PROFILE";

/// Internal env var used to carry the original `argv[0]` across the execve
/// boundary so CPython can find `pyvenv.cfg` for virtual-env detection.
/// Injected via `ExecConfig.env_vars` (bypasses allow/deny).
/// Unset by the inner branch before handing control to CPython.
const CONDA_PYTHON_ARGV0_ENV: &str = "_CONDA_PYTHON_ARGV0";

// ── Entry point ──────────────────────────────────────────────────────────────

/// Called from `main()` when the `python-launcher` feature is active.
pub fn run() -> ! {
    // Initialise tracing so errors from deep inside the nono machinery are
    // visible.  Mirror the minimal setup used by the standard CLI.
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_env("NONO_LOG")
                .add_directive(tracing::Level::WARN.into()),
        )
        .with_writer(std::io::stderr)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    // ADR-4: detect sandbox by checking for NONO_CAP_FILE, which nono injects
    // unconditionally into every sandboxed child (outside the allow/deny
    // filtering pipeline, and unreachable by profile set_vars).  This is a
    // correctness check, not a security boundary — see ADR-4 for rationale.
    if std::env::var_os("NONO_CAP_FILE").is_some() {
        inner()
    } else {
        match outer() {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("python-launcher: {e}");
                std::process::exit(1);
            }
        }
    }
}

// ── Outer (unsandboxed parent) ────────────────────────────────────────────────

fn outer() -> Result<()> {
    // Capture original argv[0] before we do anything else.
    let original_argv: Vec<String> = std::env::args().collect();
    let original_argv0 = original_argv.first().cloned().unwrap_or_default();

    // 1. Derive and validate $PREFIX from the real binary location.
    let prefix = prefix::resolve_prefix_from_current_exe()?;
    prefix::validate_prefix(&prefix)?;

    // 2. Register $PREFIX for expand_vars substitution in all profile fields.
    profile::set_launcher_prefix(prefix.to_string_lossy().into_owned());

    // 3. Resolve profile name.
    let profile_name = profile_resolution::resolve_profile_name(&prefix)?;

    // 4. Build a minimal SandboxArgs that tells prepare_sandbox which profile
    //    to load.  allow_cwd is set to true so the launcher automatically
    //    grants access to the working directory without requiring a profile
    //    update or an interactive prompt (equivalent to --allow-cwd on the
    //    CLI).  All other fields remain at Default so we don't accidentally
    //    apply CLI-flag-driven policy.
    let args = SandboxArgs {
        profile: Some(profile_name),
        allow_cwd: true,
        ..SandboxArgs::default()
    };

    // 5. Run the standard sandbox preparation pipeline: loads the profile,
    //    builds CapabilitySet, resolves network/credential/env policy.
    let mut prepared = prepare_sandbox(&args, /*silent=*/ true)?;

    // 5a. Validate that profile-supplied --upstream-bypass entries actually
    //     have a matching --upstream-proxy.  Standard `nono run` rejects
    //     bypass-without-proxy at preflight; mirror that here so a malformed
    //     profile fails loudly at startup instead of half-applying.
    validate_external_proxy_bypass(&args, &prepared)?;

    // 6. Prepare proxy launch options from the prepared sandbox.
    let proxy = prepare_proxy_launch_options(&args, &prepared, /*silent=*/ true)?;

    // 7. Start proxy (no-op if the profile has no network policy).
    let active_proxy = start_proxy_runtime(&proxy, &mut prepared.caps)?;
    let proxy_env_vars = active_proxy.env_vars;
    let proxy_handle = active_proxy.handle;

    // 8. Reject secret env-var mappings that target dangerous variables
    //    (LD_PRELOAD, DYLD_*, BASH_ENV, …) before they can be injected into
    //    the sandboxed child.  Mirror of execution_runtime.rs:234-241.
    for secret in &prepared.secrets {
        if is_dangerous_env_var(&secret.env_var) {
            return Err(NonoError::ConfigParse(format!(
                "secret mapping targets dangerous environment variable: {}",
                secret.env_var
            )));
        }
    }

    // 9. Write capability state file so `nono why --self` works inside the
    //    sandboxed Python.  Mirror of execution_runtime::execute_sandboxed.
    let allowed_domain_strs: Vec<String> = prepared
        .allow_domain
        .iter()
        .map(|e| e.domain().to_string())
        .collect();
    let cap_file_path = write_capability_state_file(
        &prepared.caps,
        &prepared.bypass_protection_paths,
        &allowed_domain_strs,
        &[], // domain endpoints not needed for the launcher
        /*silent=*/ true,
    )
    .unwrap_or_else(|| std::path::PathBuf::from("/dev/null"));

    // 10. Resolve the current directory; fall back to / if not covered.
    let workdir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let current_dir = crate::execution_runtime::execution_start_dir(&workdir, &prepared.caps)?;

    // 11. The re-exec target is ourselves.
    let self_exe = std::env::current_exe()
        .map_err(|e| NonoError::SandboxInit(format!("cannot determine current_exe: {e}")))?;

    // Build command: self as argv[0], then original argv[1..] so the sandboxed
    // inner process sees the same arguments the user typed.
    let command: Vec<String> = std::iter::once(self_exe.to_string_lossy().into_owned())
        .chain(original_argv.iter().skip(1).cloned())
        .collect();

    // 12. Build ExecutionFlags for the supervised runtime.
    //     Hooks must be wired here so before/after-hook execution below sees
    //     the profile-declared scripts; ExecutionFlags::defaults() leaves
    //     session_hooks empty.
    let mut flags = ExecutionFlags::defaults(/*silent=*/ true)?;
    flags.proxy = proxy;
    flags.session = SessionLaunchOptions {
        profile_name: args.profile.clone(),
        ..SessionLaunchOptions::default()
    };
    flags.rollback = RollbackLaunchOptions::default();
    flags.trust = TrustLaunchOptions::default();
    flags.session_hooks = std::mem::take(&mut prepared.session_hooks);
    flags.bypass_protection_paths = prepared.bypass_protection_paths.clone();

    // 13. Allocate a stable session id shared by before- and after-hooks so
    //     paired setup/teardown scripts see the same NONO_SESSION_ID.  Only
    //     allocated when at least one hook is configured; mirror of
    //     execution_runtime.rs:270-276.  We deliberately do NOT consult
    //     DETACHED_SESSION_ID_ENV: the python launcher cannot be invoked
    //     under `nono run --detached` (the supervisor sets that variable
    //     before spawning the child), and re-using a parent supervisor's id
    //     here would conflate two unrelated sessions.
    #[cfg(unix)]
    let hook_session_id: Option<String> = (flags.session_hooks.before.is_some()
        || flags.session_hooks.after.is_some())
    .then(session::generate_session_id);

    // 14. Run the before-hook (if any) and capture its exported env vars.
    //     Failures are logged and demoted to "no exported vars" so a broken
    //     hook script never blocks Python from starting (mirror of
    //     execution_runtime.rs:280-303).
    #[cfg(unix)]
    let hook_env_vars_owned: Vec<(String, String)> = flags
        .session_hooks
        .before
        .as_ref()
        .zip(hook_session_id.as_deref())
        .map(|(before, session_id)| {
            match hook_runtime::execute_before_hook(before, session_id, &current_dir) {
                Ok(env) => {
                    if !env.is_empty() {
                        info!(
                            "Before-hook exported {} env vars (script: {})",
                            env.len(),
                            before.script.display()
                        );
                    }
                    env
                }
                Err(e) => {
                    warn!("Before-hook failed (continuing): {e}");
                    Vec::new()
                }
            }
        })
        .unwrap_or_default();
    #[cfg(not(unix))]
    let hook_env_vars_owned: Vec<(String, String)> = Vec::new();

    // 15. Assemble env_vars (hook + credentials + proxy + argv0 preservation).
    //     Order matches execution_runtime.rs:307-318: hook vars are prepended
    //     first so secrets/proxy override them, then _CONDA_PYTHON_ARGV0 is
    //     appended last (highest precedence) so nothing can override it.
    let mut env_vars_owned: Vec<(String, String)> = hook_env_vars_owned;
    for s in &prepared.secrets {
        env_vars_owned.push((s.env_var.clone(), s.value.as_str().to_owned()));
    }
    for (k, v) in &proxy_env_vars {
        env_vars_owned.push((k.clone(), v.clone()));
    }
    env_vars_owned.push((CONDA_PYTHON_ARGV0_ENV.to_owned(), original_argv0));

    // Lifetime-bind to the String storage above.
    let env_vars: Vec<(&str, &str)> = env_vars_owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    // 16. Pick a threading context that matches what the runtime is about
    //     to do.  `Strict` asserts no threads exist at fork time, which is
    //     incorrect when the proxy thread or a keyring lookup has been
    //     initialised — mirror of execution_runtime.rs:320-325.  Trust scan
    //     is never run by the launcher (#13), so we pass false for both
    //     trust-related flags.
    let threading = select_threading_context(
        !prepared.secrets.is_empty(),
        flags.proxy.is_active(),
        /* trust_scan_performed = */ false,
        /* trust_interception_active = */ false,
    );

    // 17. Build ExecConfig — exhaustive struct literal so a new upstream
    //     field will produce a compile error here, not a silent miss.
    let config = ExecConfig {
        command: &command,
        resolved_program: &self_exe,
        caps: &prepared.caps,
        env_vars,
        cap_file: &cap_file_path,
        current_dir: &current_dir,
        no_diagnostics: true,
        diagnostics_json: false,
        proxy_diagnostics: proxy_handle.as_ref().and_then(|h| {
            let d = h.diagnostics();
            if d.is_empty() { None } else { Some(d) }
        }),
        threading,
        // The launcher does not run a trust scan (instruction-file
        // verification is not part of the python-sandbox threat model);
        // there are therefore no protected paths to surface in diagnostics.
        protected_paths: &[],
        profile_save_base: None,
        ignored_denial_paths: &prepared.ignored_denial_paths,
        suppressed_system_service_operations: &prepared.suppressed_system_service_operations,
        startup_timeout: None,
        capability_elevation: prepared.capability_elevation,
        #[cfg(target_os = "linux")]
        seccomp_proxy_fallback: {
            let needs_proxy = matches!(
                prepared.caps.network_mode(),
                nono::NetworkMode::ProxyOnly { .. }
            );
            if needs_proxy {
                !nono::Sandbox::detect_abi()
                    .ok()
                    .is_some_and(|abi| abi.has_network())
            } else {
                false
            }
        },
        #[cfg(target_os = "linux")]
        af_unix_mediation: prepared.af_unix_mediation,
        allowed_env_vars: prepared.allowed_env_vars,
        denied_env_vars: prepared.denied_env_vars,
        set_vars: prepared.set_vars.unwrap_or_default(),
    };

    // 18. Run supervised.  This forks, applies the sandbox in the child,
    //     exec's self, then waits in the parent.
    let exit_code = execute_supervised_runtime(SupervisedRuntimeContext {
        config: &config,
        caps: &prepared.caps,
        command: &command,
        session: &flags.session,
        rollback: &flags.rollback,
        trust: &flags.trust,
        proxy: &flags.proxy,
        proxy_handle: proxy_handle.as_ref(),
        executable_identity: None,
        audit_signer: None,
        redaction_policy: &nono::ScrubPolicy::secure_default(),
        silent: true,
    })?;

    // 19. Run the after-hook (if any) before cleanup.  Failures are logged
    //     but never override the child exit code — mirror of
    //     execution_runtime.rs:449-457.
    #[cfg(unix)]
    if let (Some(after), Some(session_id)) = (
        flags.session_hooks.after.as_ref(),
        hook_session_id.as_deref(),
    ) && let Err(e) =
        hook_runtime::execute_after_hook(after, session_id, &current_dir, exit_code)
    {
        warn!("After-hook failed: {e}");
    }

    // 20. Cleanup in the same order as execution_runtime::execute_sandboxed.
    cleanup_capability_state_file(&cap_file_path);
    drop(config);
    drop(prepared.secrets);
    drop(proxy_handle);
    std::process::exit(exit_code);
}

// ── Inner (sandboxed re-exec'd child) ────────────────────────────────────────

fn inner() -> ! {
    // Recover the original argv[0] that the user typed (e.g. a venv symlink
    // path) so CPython can find pyvenv.cfg.  Unset immediately — user Python
    // code must not observe this internal variable.
    let original_argv0 = std::env::var(CONDA_PYTHON_ARGV0_ENV).ok();
    // SAFETY: we are single-threaded at this point (the sandbox has just been
    // applied; no threads have been spawned in the child).
    unsafe { std::env::remove_var(CONDA_PYTHON_ARGV0_ENV) };

    let mut argv: Vec<String> = std::env::args().collect();
    if let Some(argv0) = original_argv0 {
        if !argv.is_empty() {
            argv[0] = argv0;
        }
    }

    // Marshal Vec<String> → Vec<CString> → Vec<*mut c_char> for Py_BytesMain.
    //
    // argv[0] has already been restored to the original value the user typed
    // (e.g. a venv symlink path) by the block above, so CPython's getpath.py
    // can find pyvenv.cfg and venv detection works correctly (ADR-5).
    //
    // Any argv element that contains an interior NUL is replaced with an empty
    // string rather than panicking; CPython would have truncated at the NUL
    // anyway, and this keeps inner() -> ! infallible.
    let cstrings: Vec<CString> = argv
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap_or_default())
        .collect();
    let mut c_argv: Vec<*mut std::os::raw::c_char> = cstrings
        .iter()
        .map(|cs| cs.as_ptr() as *mut std::os::raw::c_char)
        .collect();

    // SAFETY:
    // - We are the only thread at this point: the sandbox has just been applied
    //   via execve into a fresh process image; no other threads exist.
    // - c_argv has the same lifetime as cstrings; both outlive the Py_BytesMain
    //   call because they are stack-allocated in this frame and Py_BytesMain
    //   does not return (it calls exit() internally after running Python).
    // - argc is exactly c_argv.len(), which matches cstrings.len().
    let exit_code = unsafe {
        Py_BytesMain(
            c_argv.len() as std::os::raw::c_int,
            c_argv.as_mut_ptr(),
        )
    };

    // Py_BytesMain normally does not return (it calls Py_Exit / exit()
    // internally).  If it does return, honour the exit code it provides.
    std::process::exit(exit_code);
}

// ── Prefix derivation and validation (ADR-8) ─────────────────────────────────

mod prefix {
    use crate::{config, state_paths};
    use nono::{NonoError, Result};
    use std::path::{Path, PathBuf};

    /// Derive $PREFIX from the real binary location by stripping `bin/<name>`.
    ///
    /// Uses `current_exe()` (kernel-controlled, unspoofable from userspace).
    pub(super) fn resolve_prefix_from_current_exe() -> Result<PathBuf> {
        let exe = std::env::current_exe()
            .map_err(|e| NonoError::SandboxInit(format!("cannot determine current_exe: {e}")))?;
        let canonical = exe
            .canonicalize()
            .map_err(|e| NonoError::PathCanonicalization {
                path: exe.clone(),
                source: e,
            })?;
        // Strip bin/<name>: canonical must be <prefix>/bin/<name>
        let bin_dir = canonical.parent().ok_or_else(|| {
            NonoError::SandboxInit(format!(
                "cannot derive $PREFIX: {} has no parent directory",
                canonical.display()
            ))
        })?;
        if bin_dir.file_name().and_then(|n| n.to_str()) != Some("bin") {
            return Err(NonoError::SandboxInit(format!(
                "cannot derive $PREFIX: expected executable inside a `bin/` directory, \
                 got {}",
                canonical.display()
            )));
        }
        let prefix = bin_dir.parent().ok_or_else(|| {
            NonoError::SandboxInit(format!(
                "cannot derive $PREFIX: {} has no parent (bin/ at filesystem root?)",
                canonical.display()
            ))
        })?;
        Ok(prefix.to_path_buf())
    }

    /// Validate that `prefix` is a safe conda environment root.
    ///
    /// Hard-errors on:
    /// - non-absolute path
    /// - path equal to `/`
    /// - fewer than 3 path components (e.g. `/opt` is too shallow)
    /// - path equal to or an ancestor of `$HOME`
    /// - path equal to or an ancestor of any nono protected state root
    pub(super) fn validate_prefix(prefix: &Path) -> Result<()> {
        if !prefix.is_absolute() {
            return Err(NonoError::SandboxInit(format!(
                "$PREFIX must be absolute, got: {}",
                prefix.display()
            )));
        }

        if prefix == Path::new("/") {
            return Err(NonoError::SandboxInit(
                "$PREFIX must not be the filesystem root".to_string(),
            ));
        }

        let component_count = prefix.components().count();
        if component_count < 3 {
            return Err(NonoError::SandboxInit(format!(
                "$PREFIX must have at least 3 path components, got {} ({})",
                component_count,
                prefix.display()
            )));
        }

        // Must not be equal to or an ancestor of $HOME.
        let home_str = config::validated_home()?;
        let home = Path::new(&home_str);
        if home.starts_with(prefix) {
            return Err(NonoError::SandboxInit(format!(
                "$PREFIX {} is equal to or an ancestor of $HOME {} — \
                 granting $PREFIX would expose the home directory",
                prefix.display(),
                home.display()
            )));
        }

        // Must not be equal to or an ancestor of any nono protected state root.
        let protected = state_paths::protected_state_roots()?;
        for root in &protected {
            if root.starts_with(prefix) {
                return Err(NonoError::SandboxInit(format!(
                    "$PREFIX {} is equal to or an ancestor of nono protected state \
                     path {} — this would expose nono internal state to the sandbox",
                    prefix.display(),
                    root.display()
                )));
            }
        }

        Ok(())
    }
}

// ── Profile name resolution (ADR-7) ──────────────────────────────────────────

mod profile_resolution {
    use crate::python_launcher::{CONDA_PYTHON_PROFILE_ENV, DEFAULT_PROFILE};
    use nono::Result;
    use std::path::Path;

    /// Resolve the profile name in precedence order:
    /// 1. `CONDA_PYTHON_PROFILE` environment variable
    /// 2. `$PREFIX/conda-meta/state` JSON `env_vars` key
    /// 3. Compile-time default (`intentionally-left-nil/python`)
    pub(super) fn resolve_profile_name(prefix: &Path) -> Result<String> {
        // 1. Environment variable
        if let Ok(name) = std::env::var(CONDA_PYTHON_PROFILE_ENV) {
            let name = name.trim().to_owned();
            if !name.is_empty() {
                return Ok(name);
            }
        }

        // 2. conda-meta/state
        if let Ok(Some(name)) =
            super::conda_meta::read_env_var_from_state(prefix, CONDA_PYTHON_PROFILE_ENV)
        {
            let name = name.trim().to_owned();
            if !name.is_empty() {
                return Ok(name);
            }
        }

        // 3. Default
        Ok(DEFAULT_PROFILE.to_owned())
    }
}

// ── conda-meta/state parsing ──────────────────────────────────────────────────

mod conda_meta {
    use nono::Result;
    use std::path::Path;

    /// Read a single key from `$PREFIX/conda-meta/state`'s `env_vars` object.
    ///
    /// Returns `Ok(None)` when:
    /// - the file does not exist
    /// - the file is not valid JSON
    /// - the key is absent
    ///
    /// Never returns an error for a missing or malformed state file — that
    /// would prevent the launcher from starting in a fresh environment.
    pub(super) fn read_env_var_from_state(prefix: &Path, key: &str) -> Result<Option<String>> {
        let state_path = prefix.join("conda-meta").join("state");
        let contents = match std::fs::read_to_string(&state_path) {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };
        let value: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let env_vars = match value.get("env_vars") {
            Some(v) => v,
            None => return Ok(None),
        };
        Ok(env_vars
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned()))
    }
}
