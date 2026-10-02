//! Shared daemon and CLI implementation for Agent Governor NG.

#[cfg(target_os = "linux")]
pub mod agd;
#[cfg(target_os = "linux")]
pub mod api;
pub mod config;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod custody;
pub mod derived;
pub mod descriptor_path;
pub mod docket_issuance;
#[cfg(target_os = "linux")]
pub mod doctor;
#[cfg(target_os = "linux")]
pub mod effect_executor_adapter;
#[cfg(target_os = "linux")]
pub mod effectd;
#[cfg(target_os = "linux")]
pub mod effectd_activation;
#[cfg(target_os = "linux")]
mod exact_exec;
pub mod governed_campaign_production_v1;
pub mod governed_campaign_v0;
pub mod governed_campaign_v1;
pub mod governed_loop;
pub mod governed_ports;
pub mod intervention_ingress;
#[cfg(target_os = "linux")]
pub mod managed_pointer;
pub mod peer;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub mod rpc_auth;
#[cfg(target_os = "linux")]
pub mod runtime;
#[cfg(target_os = "linux")]
pub mod signed_transport;
pub mod standing_authority;
pub mod transport;
#[cfg(target_os = "linux")]
pub mod worker;
#[cfg(target_os = "linux")]
pub mod worker_protocol;
pub mod worker_session;

use tracing_subscriber::EnvFilter;

/// Installs structured logging with a conservative default filter.
pub fn init_logging(service: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
    tracing::info!(service, "service starting");
}
