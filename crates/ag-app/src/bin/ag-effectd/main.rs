//! `ag-effectd` is part of the Linux daemon surface (systemd activation, Landlock,
//! `SO_PEERCRED`, the Linux effect executor). It is built only for Linux;
//! other kernels get a binary that refuses with EX_CONFIG so the platform
//! boundary is explicit rather than silent.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ag-effectd: unsupported on this platform; it is the Linux daemon surface of Agent Governor");
    std::process::exit(78);
}
