//! Local read-only operator interface for persisted governed campaigns.

use std::net::SocketAddr;
use std::path::PathBuf;

use ag_operator_ui::server::{serve, validate_bind_ip};
use ag_operator_ui::source::{
    DocketReadSourceV1, MaudeAcquisitionReadSourceV1, MaudeObjectiveReadSourceV1,
    NightshiftReadSourceV1, ObjectiveOwnerProjectionSourceV1, OperatorReaderV1,
    OperatorSourceConfigV1,
};
use anyhow::{Context as _, Result, bail};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "ag-operator-ui",
    about = "Phosphor: loopback-only, read-only governed-runtime inspector"
)]
struct Args {
    /// Directory containing immediate canonical AG campaign `.sqlite` stores.
    #[arg(long, conflicts_with = "demo_corpus")]
    campaign_root: Option<PathBuf>,

    /// Absolute path to the canonical `ag-loopctl` executable.
    #[arg(long, conflicts_with = "demo_corpus")]
    ag_loopctl: Option<PathBuf>,

    /// Deterministic captured corpus for presentation qualification only.
    #[arg(long, conflicts_with_all = ["campaign_root", "ag_loopctl", "nightshift_bin", "nightshift_store", "docket_bin", "docket_state", "maude_acquisition_bin", "maude_acquisition_ledger", "maude_objective_bin", "maude_objective_plan", "maude_objective_expected_plan_digest", "objective_owner_bin", "objective_owner_config", "objective_owner_id", "objective_owner_capability", "objective_owner_source_revision", "objective_owner_expected_plan_digest", "public_objective_projection"])]
    demo_corpus: Option<PathBuf>,

    /// Absolute path to the canonical `nightshift` executable.
    #[arg(long, requires = "nightshift_store")]
    nightshift_bin: Option<PathBuf>,

    /// Existing Nightshift canonical store.
    #[arg(long, requires = "nightshift_bin")]
    nightshift_store: Option<PathBuf>,

    /// Absolute path to the canonical `docket` executable.
    #[arg(long, requires = "docket_state")]
    docket_bin: Option<PathBuf>,

    /// Existing Docket state directory.
    #[arg(long, requires = "docket_bin")]
    docket_state: Option<PathBuf>,

    /// Absolute path to the closed Maude acquisition CLI.
    #[arg(long, requires = "maude_acquisition_ledger")]
    maude_acquisition_bin: Option<PathBuf>,

    /// Existing Maude acquisition trigger/request/event ledger.
    #[arg(long, requires = "maude_acquisition_bin")]
    maude_acquisition_ledger: Option<PathBuf>,

    /// Absolute path to the closed Maude `PlanDocument` reader.
    #[arg(long, requires_all = ["maude_objective_plan", "maude_objective_expected_plan_digest"])]
    maude_objective_bin: Option<PathBuf>,

    /// Existing `PlanDocument` file consulted by the bounded Maude reader.
    #[arg(long, requires_all = ["maude_objective_bin", "maude_objective_expected_plan_digest"])]
    maude_objective_plan: Option<PathBuf>,

    /// Exact expected `sha256:` `PlanDocument` digest for the objective read.
    #[arg(long, requires_all = ["maude_objective_bin", "maude_objective_plan"])]
    maude_objective_expected_plan_digest: Option<String>,

    #[arg(long, requires_all = ["objective_owner_config", "objective_owner_id", "objective_owner_capability", "objective_owner_source_revision", "objective_owner_expected_plan_digest"])]
    objective_owner_bin: Option<PathBuf>,
    #[arg(long, requires = "objective_owner_bin")]
    objective_owner_config: Option<PathBuf>,
    #[arg(long, requires = "objective_owner_bin")]
    objective_owner_id: Option<String>,
    #[arg(long, requires = "objective_owner_bin")]
    objective_owner_capability: Option<String>,
    #[arg(long, requires = "objective_owner_bin")]
    objective_owner_source_revision: Option<String>,
    #[arg(long, requires = "objective_owner_bin")]
    objective_owner_expected_plan_digest: Option<String>,

    /// Separately approved public-safe objective projection artifact.
    #[arg(long)]
    public_objective_projection: Option<PathBuf>,

    /// Explicit approved public receipt URL; repeat for each allowed URL.
    #[arg(long = "public-approved-receipt-url")]
    public_approved_receipt_urls: Vec<String>,

    /// Loopback address for the local HTTP listener.
    #[arg(long, default_value = "127.0.0.1:8417")]
    bind: SocketAddr,
}

fn main() -> Result<()> {
    let args = Args::parse();
    validate_bind_ip(args.bind.ip()).map_err(anyhow::Error::msg)?;
    let reader = if let Some(corpus) = args.demo_corpus {
        OperatorReaderV1::from_demo_corpus(&corpus)
            .map_err(anyhow::Error::msg)
            .context("validate deterministic operator demo corpus")?
    } else {
        let nightshift = match (args.nightshift_bin, args.nightshift_store) {
            (Some(program), Some(store)) => Some(NightshiftReadSourceV1 { program, store }),
            (None, None) => None,
            _ => bail!("Nightshift binary and store must be configured together"),
        };
        let docket = match (args.docket_bin, args.docket_state) {
            (Some(program), Some(state)) => Some(DocketReadSourceV1 { program, state }),
            (None, None) => None,
            _ => bail!("Docket binary and state must be configured together"),
        };
        let maude_acquisition = match (args.maude_acquisition_bin, args.maude_acquisition_ledger) {
            (Some(program), Some(ledger)) => Some(MaudeAcquisitionReadSourceV1 { program, ledger }),
            (None, None) => None,
            _ => bail!("Maude acquisition binary and ledger must be configured together"),
        };
        let maude_objective = match (
            args.maude_objective_bin,
            args.maude_objective_plan,
            args.maude_objective_expected_plan_digest,
        ) {
            (Some(program), Some(plan), Some(expected_plan_digest)) => {
                Some(MaudeObjectiveReadSourceV1 {
                    program,
                    plan,
                    expected_plan_digest,
                })
            }
            (None, None, None) => None,
            _ => bail!(
                "Maude objective binary, plan, and expected digest must be configured together"
            ),
        };
        let objective_owner_projection = match (
            args.objective_owner_bin,
            args.objective_owner_config,
            args.objective_owner_id,
            args.objective_owner_capability,
            args.objective_owner_source_revision,
            args.objective_owner_expected_plan_digest,
        ) {
            (
                Some(program),
                Some(config),
                Some(expected_owner_id),
                Some(expected_owner_capability),
                Some(expected_source_revision),
                Some(expected_plan_digest),
            ) => Some(ObjectiveOwnerProjectionSourceV1 {
                program,
                config,
                expected_owner_id,
                expected_owner_capability,
                expected_source_revision,
                expected_plan_digest,
            }),
            (None, None, None, None, None, None) => None,
            _ => bail!(
                "objective owner binary, config, identity, capability, source revision, and plan digest must be configured together"
            ),
        };
        OperatorReaderV1::new(OperatorSourceConfigV1 {
            campaign_root: args
                .campaign_root
                .context("--campaign-root is required outside demo mode")?,
            ag_loopctl: args
                .ag_loopctl
                .context("--ag-loopctl is required outside demo mode")?,
            nightshift,
            docket,
            maude_acquisition,
            maude_objective,
            objective_owner_projection,
            public_objective_projection: args.public_objective_projection,
            public_approved_receipt_urls: args.public_approved_receipt_urls.into_iter().collect(),
        })
        .map_err(anyhow::Error::msg)
        .context("validate read-only operator sources")?
    };
    serve(args.bind, reader).map_err(anyhow::Error::msg)
}
