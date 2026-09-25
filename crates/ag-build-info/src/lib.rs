//! Compile-time identity for shipped AG executables.
//!
//! Every shipped executable answers `--version` with its component name, the
//! workspace version and, for release automation builds, the full source
//! commit; and `--build-info` with one compact JSON document. Both are
//! answered from compile-time constants before any argument parsing,
//! configuration, store or stdin read.

use std::fmt::Write as _;
use std::io::{self, Write as _};

mod source_commit;

pub use source_commit::{SOURCE_COMMIT_VARIABLE, parse_source_commit};

include!(concat!(env!("OUT_DIR"), "/source_commit_generated.rs"));

/// Stable schema identifier of the `--build-info` document.
pub const BUILD_INFO_SCHEMA: &str = "ag.build-info/v1";

/// Workspace version compiled into every executable.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The `--version` line for one component.
#[must_use]
pub fn version_line(component: &str) -> String {
    match SOURCE_COMMIT {
        Some(commit) => format!("{component} {VERSION} ({commit})"),
        None => format!("{component} {VERSION}"),
    }
}

/// The compact JSON `--build-info` document for one component.
#[must_use]
pub fn build_info_json(component: &str) -> String {
    let commit = SOURCE_COMMIT.map_or_else(|| "null".to_owned(), |commit| format!("\"{commit}\""));
    format!(
        "{{\"component\":{},\"debug_assertions\":{},\"schema\":\"{BUILD_INFO_SCHEMA}\",\
         \"source_commit\":{commit},\"version\":\"{VERSION}\"}}",
        json_string(component),
        cfg!(debug_assertions),
    )
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            character if u32::from(character) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(character));
            }
            character => out.push(character),
        }
    }
    out.push('"');
    out
}

/// Answers `--version` or `--build-info` when it is the process's only
/// argument, and returns whether it did. Callers invoke this first in `main`.
///
/// # Errors
///
/// Returns an output error if standard output cannot be written or flushed.
pub fn answer_identity_request(component: &str) -> io::Result<bool> {
    let mut arguments = std::env::args_os().skip(1);
    let (Some(only), None) = (arguments.next(), arguments.next()) else {
        return Ok(false);
    };
    let line = if only == "--version" {
        version_line(component)
    } else if only == "--build-info" {
        build_info_json(component)
    } else {
        return Ok(false);
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output.write_all(line.as_bytes())?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_info_is_closed_canonical_json() {
        let document = build_info_json("fixture-\"component\"");
        let commit = SOURCE_COMMIT.map_or_else(|| "null".to_owned(), |c| format!("\"{c}\""));
        assert_eq!(
            document,
            format!(
                "{{\"component\":\"fixture-\\\"component\\\"\",\"debug_assertions\":{},\
                 \"schema\":\"ag.build-info/v1\",\"source_commit\":{commit},\"version\":\"{VERSION}\"}}",
                cfg!(debug_assertions)
            )
        );
    }

    #[test]
    fn version_line_carries_the_recorded_commit() {
        match SOURCE_COMMIT {
            Some(commit) => {
                assert_eq!(parse_source_commit(Some(commit)), Ok(Some(commit)));
                assert_eq!(version_line("x"), format!("x {VERSION} ({commit})"));
            }
            None => assert_eq!(version_line("x"), format!("x {VERSION}")),
        }
    }

    #[test]
    fn source_commit_accepts_only_a_full_lowercase_commit_id() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(parse_source_commit(None), Ok(None));
        assert_eq!(parse_source_commit(Some("")), Ok(None));
        assert_eq!(parse_source_commit(Some(commit)), Ok(Some(commit)));
        for rejected in [
            "0123456789abcdef0123456789abcdef0123456",
            "0123456789abcdef0123456789abcdef012345678",
            "0123456789ABCDEF0123456789abcdef01234567",
            " 0123456789abcdef0123456789abcdef01234567",
            "HEAD",
        ] {
            let error = parse_source_commit(Some(rejected)).expect_err(rejected);
            assert!(error.contains(SOURCE_COMMIT_VARIABLE), "{error}");
        }
    }
}
