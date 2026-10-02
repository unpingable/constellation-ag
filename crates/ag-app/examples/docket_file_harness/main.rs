//! The Docket file harness drives the Linux `ag-effectd` executor; it is
//! built only for Linux.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
fn main() -> () {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("docket_file_harness: unsupported on this platform; it drives the Linux effect executor");
    std::process::exit(78);
}
