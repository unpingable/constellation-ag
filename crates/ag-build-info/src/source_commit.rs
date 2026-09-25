// Shared by build.rs (through #[path]) and the library, so the build-time
// acceptance rule and the unit tests exercise one function.

/// Name of the environment variable release automation sets at compile time.
pub const SOURCE_COMMIT_VARIABLE: &str = "AG_SOURCE_COMMIT";

/// Accept `AG_SOURCE_COMMIT` as unset or empty (no recorded commit) or as
/// exactly 40 lowercase hexadecimal characters; refuse every other value.
///
/// # Errors
///
/// Returns a diagnostic naming the rule when the value is non-empty and is not
/// 40 lowercase hexadecimal characters.
pub fn parse_source_commit(value: Option<&str>) -> Result<Option<&str>, String> {
    match value {
        None | Some("") => Ok(None),
        Some(commit) => {
            let well_formed = commit.len() == 40
                && commit
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
            if well_formed {
                Ok(Some(commit))
            } else {
                Err(format!(
                    "{SOURCE_COMMIT_VARIABLE} must be 40 lowercase hexadecimal characters \
                     (a full git commit id), got {commit:?}"
                ))
            }
        }
    }
}
