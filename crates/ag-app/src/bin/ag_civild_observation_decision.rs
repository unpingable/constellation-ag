//! Ordinary read-only AG consumer for a Monitor-acquired civild observation.

use ag_app::civild_observation::decide_civild_observation;
use std::io::{self, Read as _};

fn main() {
    if let Err(error) = run() {
        eprintln!("ag-civild-observation-decision refused: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let source = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }
    let bytes = if source == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .take(2 * 1024 * 1024)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read Monitor inventory from stdin: {error}"))?;
        bytes
    } else {
        std::fs::read(&source)
            .map_err(|error| format!("read Monitor inventory {source}: {error}"))?
    };
    let decision = decide_civild_observation(&bytes)?;
    let output = decision.canonical_bytes()?;
    print!(
        "{}",
        String::from_utf8(output).map_err(|_| "decision was not UTF-8".to_owned())?
    );
    Ok(())
}

fn usage() -> String {
    "usage: ag-civild-observation-decision INVENTORY_JSON|-".to_owned()
}
