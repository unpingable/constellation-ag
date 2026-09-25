//! Record the source commit release automation names at compile time.

use std::env;
use std::fs;
use std::path::PathBuf;

#[path = "src/source_commit.rs"]
mod source_commit;

use source_commit::{SOURCE_COMMIT_VARIABLE, parse_source_commit};

fn main() {
    println!("cargo:rerun-if-env-changed={SOURCE_COMMIT_VARIABLE}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/source_commit.rs");
    let value = env::var_os(SOURCE_COMMIT_VARIABLE).map(|raw| {
        raw.into_string().unwrap_or_else(|_| {
            eprintln!("ag-build-info: {SOURCE_COMMIT_VARIABLE} is not valid UTF-8");
            std::process::exit(1);
        })
    });
    let commit = match parse_source_commit(value.as_deref()) {
        Ok(commit) => commit.map(str::to_owned),
        Err(diagnostic) => {
            eprintln!("ag-build-info: {diagnostic}");
            std::process::exit(1);
        }
    };
    let generated = format!(
        "/// Source commit recorded through `{SOURCE_COMMIT_VARIABLE}` at compile time.\n\
         pub const SOURCE_COMMIT: Option<&str> = {commit:?};\n"
    );
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("cargo provides OUT_DIR"));
    fs::write(out_dir.join("source_commit_generated.rs"), generated)
        .expect("write generated source commit constant");
}
