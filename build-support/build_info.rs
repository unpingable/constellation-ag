//! Read-only executable identity; builder declarations are not source verification.

use std::{
    ffi::OsStr,
    io::{self, Write},
};

use serde::Serialize;

include!(concat!(env!("OUT_DIR"), "/build_identity.rs"));

#[derive(Debug, Serialize)]
/// Compile-time declarations for one AG executable.
pub struct BuildInfo<'a> {
    /// AG-local reporting schema.
    pub schema: &'static str,
    /// Executable name.
    pub component: &'a str,
    /// Cargo package version.
    pub version: &'static str,
    /// Full source commit explicitly declared by the builder, if supplied.
    pub source_commit: Option<&'static str>,
    /// Builder-assigned occurrence identity, if supplied.
    pub build_id: Option<&'static str>,
    /// Compiler version captured during compilation, if available.
    pub rustc: Option<&'static str>,
    /// Cargo target triple.
    pub target: &'static str,
    /// Whether this executable was compiled with debug assertions.
    pub debug_assertions: bool,
    /// Whether this package enabled the systemd D-Bus executor backend.
    pub systemd_dbus: bool,
}

impl<'a> BuildInfo<'a> {
    #[must_use]
    /// Return the declarations embedded in this executable's package.
    pub const fn current(component: &'a str) -> Self {
        Self {
            schema: "ag.build_info.v1",
            component,
            version: env!("CARGO_PKG_VERSION"),
            source_commit: SOURCE_COMMIT,
            build_id: BUILD_ID,
            rustc: RUSTC,
            target: TARGET,
            debug_assertions: cfg!(debug_assertions),
            systemd_dbus: SYSTEMD_DBUS,
        }
    }
}

/// Handle an identity probe only when it is the sole argument, before any
/// enrollment, stdin, configuration, store or external command is consulted.
///
/// # Errors
/// Returns an error if the requested identity cannot be written to stdout.
pub fn write_if_requested(component: &str) -> io::Result<bool> {
    let mut args = std::env::args_os().skip(1);
    let argument = args.next();
    if args.next().is_some() {
        return Ok(false);
    }
    let mut stdout = io::stdout().lock();
    match argument.as_deref() {
        Some(flag) if flag == OsStr::new("--build-info") => {
            serde_json::to_writer(&mut stdout, &BuildInfo::current(component))
                .map_err(io::Error::other)?;
            writeln!(stdout)?;
        }
        Some(flag) if flag == OsStr::new("--version") || flag == OsStr::new("-V") => {
            writeln!(stdout, "{component} {VERSION_STRING}")?;
        }
        _ => return Ok(false),
    }
    stdout.flush()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_compile_time_identity_without_inventing_missing_inputs() {
        let value = serde_json::to_value(BuildInfo::current("ag-loopctl")).unwrap();
        assert_eq!(value["schema"], "ag.build_info.v1");
        assert_eq!(value["component"], "ag-loopctl");
        assert_eq!(value["source_commit"].as_str(), SOURCE_COMMIT);
        assert_eq!(value["build_id"].as_str(), BUILD_ID);
        assert_eq!(value["debug_assertions"], cfg!(debug_assertions));
    }
}
