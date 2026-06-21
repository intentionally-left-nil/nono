//! Build script for nono-cli
//!
//! Embeds policy and hook scripts into the binary at compile time.
//!
//! ## python-launcher feature: DT_NEEDED linkage against libpython
//!
//! When the `python-launcher` cargo feature is enabled, this script wires up
//! the DT_NEEDED (ELF) / LC_LOAD_DYLIB (Mach-O) dependency on libpython so
//! that `Py_BytesMain` can be called directly from `python_launcher::inner()`.
//!
//! Two environment variables must be set by the feedstock build script before
//! `cargo build --features python-launcher` is invoked:
//!
//! - `PYTHON_LAUNCHER_LIB_DIR`  — absolute path to the directory containing
//!   libpython (i.e. `$PREFIX/lib`).  Passed as `rustc-link-search=native=…`.
//!
//! - `PYTHON_LAUNCHER_LIB_NAME` — the library name without the `lib` prefix
//!   and without the extension, e.g. `python3.14` or `python3.14t`.
//!   Passed as `rustc-link-lib=dylib=…`.
//!
//! The relocatable rpath ($ORIGIN/../lib on Linux, @loader_path/../lib on
//! macOS) is injected by the feedstock build script via RUSTFLAGS rather than
//! here, because rustc link-arg ordering relative to the system linker flags
//! is more predictable when set in RUSTFLAGS.  This script only handles the
//! -L / -l pair that produces the actual DT_NEEDED entry.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Rebuild if data files change
    println!("cargo:rerun-if-changed=data/");

    // ── python-launcher: DT_NEEDED linkage against libpython ─────────────────
    //
    // Only wire this up when the feature is actually enabled.  The cfg check
    // here mirrors the #[cfg(feature = "python-launcher")] gates in main.rs
    // and python_launcher.rs, so a normal nono build is completely unaffected.
    if env::var("CARGO_FEATURE_PYTHON_LAUNCHER").is_ok() {
        // PYTHON_LAUNCHER_LIB_DIR must be set; fail loudly if absent so the
        // feedstock build script gets an immediate actionable error rather than
        // a cryptic linker failure about a missing Py_BytesMain symbol.
        let lib_dir = env::var("PYTHON_LAUNCHER_LIB_DIR").unwrap_or_else(|_| {
            panic!(
                "PYTHON_LAUNCHER_LIB_DIR must be set when building with \
                 --features python-launcher (expected: absolute path to the \
                 directory containing libpython, e.g. $PREFIX/lib)"
            )
        });

        let lib_name = env::var("PYTHON_LAUNCHER_LIB_NAME").unwrap_or_else(|_| {
            panic!(
                "PYTHON_LAUNCHER_LIB_NAME must be set when building with \
                 --features python-launcher (expected: library name without \
                 'lib' prefix or extension, e.g. 'python3.14' or 'python3.14t')"
            )
        });

        // Validate that the library actually exists before emitting the
        // directives; this surfaces a missing libpython as a build-script
        // error rather than a linker error, with a cleaner message.
        #[cfg(target_os = "linux")]
        let lib_filename = format!("lib{lib_name}.so");
        #[cfg(target_os = "macos")]
        let lib_filename = format!("lib{lib_name}.dylib");
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let lib_filename = format!("lib{lib_name}.so"); // fallback for check only

        let lib_path = Path::new(&lib_dir).join(&lib_filename);
        if !lib_path.exists() {
            panic!(
                "PYTHON_LAUNCHER_LIB_DIR={lib_dir}: expected {lib_filename} not found at \
                 {lib_path}. Ensure libpython is built and installed into $PREFIX/lib \
                 before running `cargo build --features python-launcher`.",
                lib_path = lib_path.display(),
            );
        }

        println!("cargo:rustc-link-search=native={lib_dir}");
        println!("cargo:rustc-link-lib=dylib={lib_name}");

        // Rerun if the library itself changes (e.g. python version bump).
        println!("cargo:rerun-if-env-changed=PYTHON_LAUNCHER_LIB_DIR");
        println!("cargo:rerun-if-env-changed=PYTHON_LAUNCHER_LIB_NAME");
        println!("cargo:rerun-if-changed={}", lib_path.display());
    }

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir);

    // === Embed policy JSON ===
    let policy_path = Path::new("data/policy.json");
    if policy_path.exists() {
        let content = fs::read_to_string(policy_path).expect("Failed to read policy.json");

        // Write to OUT_DIR for include_str! macro
        fs::write(out_path.join("policy.json"), &content)
            .expect("Failed to write policy.json to OUT_DIR");

        println!("cargo:rustc-env=POLICY_JSON_EMBEDDED=1");
    } else {
        println!("cargo:warning=data/policy.json not found");
        println!("cargo:rustc-env=POLICY_JSON_EMBEDDED=0");
    }

    // === Embed network policy JSON ===
    let net_policy_path = Path::new("data/network-policy.json");
    if net_policy_path.exists() {
        let content =
            fs::read_to_string(net_policy_path).expect("Failed to read network-policy.json");
        fs::write(out_path.join("network-policy.json"), &content)
            .expect("Failed to write network-policy.json to OUT_DIR");
        println!("cargo:rustc-env=NETWORK_POLICY_JSON_EMBEDDED=1");
    } else {
        println!("cargo:warning=data/network-policy.json not found");
        println!("cargo:rustc-env=NETWORK_POLICY_JSON_EMBEDDED=0");
    }

    // === Embed profile JSON Schema ===
    let schema_path = Path::new("data/nono-profile.schema.json");
    if schema_path.exists() {
        let content = fs::read_to_string(schema_path).expect("Failed to read profile schema");
        fs::write(out_path.join("nono-profile.schema.json"), &content)
            .expect("Failed to write profile schema to OUT_DIR");
    }

    // === Embed profile authoring guide ===
    let guide_path = Path::new("data/profile-authoring-guide.md");
    if guide_path.exists() {
        let content =
            fs::read_to_string(guide_path).expect("Failed to read profile authoring guide");
        fs::write(out_path.join("profile-authoring-guide.md"), &content)
            .expect("Failed to write profile authoring guide to OUT_DIR");
    }
}
