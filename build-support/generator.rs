//! Embed only identities explicitly supplied by the builder.

use std::{env, fs, path::PathBuf, process::Command};

#[path = "build_identity_input.rs"]
mod input;

pub fn run() {
    for name in [
        "AG_SOURCE_COMMIT",
        "AG_BUILD_IDENTITY",
        "RUSTC",
        "CARGO_FEATURE_SYSTEMD_DBUS",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../build-support/generator.rs");
    println!("cargo:rerun-if-changed=../../build-support/build_identity_input.rs");
    let read = |name| match env::var(name) {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => panic!("{name} must be UTF-8"),
    };
    let source = read("AG_SOURCE_COMMIT");
    let source = input::source_commit(source.as_deref()).expect("invalid source identity");
    let build = read("AG_BUILD_IDENTITY");
    let build = input::build_identity(build.as_deref()).expect("invalid build identity");
    let rustc = Command::new(env::var_os("RUSTC").expect("Cargo supplies RUSTC"))
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|version| version.trim().to_owned());
    let target = env::var("TARGET").expect("Cargo supplies TARGET");
    let version = env::var("CARGO_PKG_VERSION").expect("Cargo supplies CARGO_PKG_VERSION");
    let version = format!("{version} ({})", source.unwrap_or("source unavailable"));
    let systemd_dbus = env::var_os("CARGO_FEATURE_SYSTEMD_DBUS").is_some();
    let generated = format!(
        "/// Whether the systemd-dbus feature was enabled.\n\
         pub const SYSTEMD_DBUS: bool = {systemd_dbus:?};\n\
         /// Builder-declared source commit, if supplied.\n\
         pub const SOURCE_COMMIT: Option<&str> = {source:?};\n\
         /// Builder-declared build identity, if supplied.\n\
         pub const BUILD_ID: Option<&str> = {build:?};\n\
         /// Compiler version captured by the build script.\n\
         pub const RUSTC: Option<&str> = {rustc:?};\n\
         /// Cargo target triple.\n\
         pub const TARGET: &str = {target:?};\n\
         /// Human-readable package and source identity.\n\
         pub const VERSION_STRING: &str = {version:?};\n"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    fs::write(out.join("build_identity.rs"), generated).expect("write build identity");
}
