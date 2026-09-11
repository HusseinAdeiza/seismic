//! The operator half: act on your own node.
//!
//! This CLI is for any operator joining a Seismic network. It is
//! cloud-agnostic and starts at the node descriptor — it consumes a descriptor
//! for an already-running node and talks to it over HTTP. **It never
//! provisions**: producing descriptors is the Pulumi program's job. Founding a
//! network, or auditing one, is the other CLI's job (`seismic-tee-network`),
//! and this crate must never depend on it: the crates are split on that line
//! so the compiler enforces it, and this half plus [`seismic_tee_common`] stays
//! free of founder-only dependencies.
//!
//! Three commands, in the order an operator meets them: [`configure`] delivers
//! a node's config on first boot and waits for it to come up, [`verify`]
//! appraises a running node's attestation, and [`status`] watches the
//! first-boot disk wipe on its own. The founder CLI configures a cohort by
//! doing to each node what these do to one, so the flows behind the commands
//! — building the config, POSTing it, the status poller, the appraisal — are
//! this crate's library surface as well as its binary's.

pub mod args;
pub mod configure;
pub mod status;
pub mod verify;

/// The fake server and fixtures the tests here share with the network crate's.
#[cfg(test)]
pub(crate) use seismic_tee_common::test_support;

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use seismic_tee_common::Manifest;

/// The name the binary is installed and invoked as.
pub const BIN_NAME: &str = "seismic-tee-node";

#[derive(Debug, Parser)]
#[command(
    name = BIN_NAME,
    version,
    about = "Configure and verify your own Seismic TEE node",
    long_about = "Configure and verify your own Seismic TEE node.\n\n\
                  Cloud-agnostic, and never provisions: it consumes a \
                  descriptor of an already-running node and reaches the node \
                  over HTTP."
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Declared in workflow order, which is the order `--help` lists them in.
#[derive(Debug, Subcommand)]
enum Command {
    /// Configure a node to join a network: assemble + POST config to tdx-init.
    Configure(configure::ConfigureArgs),
    /// Deploy-verify a node's TDX attestation against the intended image.
    Verify(verify::VerifyArgs),
    /// Watch a node's first-boot LUKS provisioning progress.
    Status(status::StatusArgs),
}

/// Read `--manifest`: present, and a manifest the strict v1 schema accepts.
///
/// Every command starts here, because every command's other inputs are
/// checked against it — the manifest is what makes a genesis or a policy
/// *this* network's rather than some network's.
pub fn load_manifest(path: &Path) -> anyhow::Result<Manifest> {
    if !path.is_file() {
        bail!("--manifest file not found: {}", path.display());
    }
    Manifest::load(path).with_context(|| format!("--manifest {}: invalid manifest", path.display()))
}

/// Parse the command line and run it.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: starting the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async {
        match cli.command {
            Command::Configure(args) => configure::run(args).await,
            Command::Verify(args) => verify::run(args).await,
            Command::Status(args) => status::run(args).await,
        }
    });
    match result {
        Ok(code) => code,
        Err(error) => {
            // The whole chain, one cause per line: a DCAP failure is several
            // layers deep and the last one alone rarely says what happened.
            eprintln!("error: {error:?}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;
    use crate::test_support::{FIXTURE_MANIFEST, write_file};

    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    /// The released binary reports the crate's version, which is what an
    /// operator quotes when reporting a problem.
    #[test]
    fn the_binary_is_named_and_versioned() {
        let command = Cli::command();
        assert_eq!(command.get_name(), BIN_NAME);
        assert_eq!(command.get_version(), Some(env!("CARGO_PKG_VERSION")));
    }

    /// The three operator commands, listed in workflow order.
    #[test]
    fn the_commands_are_listed_in_workflow_order() {
        let names: Vec<_> = Cli::command()
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect();
        assert_eq!(names, ["configure", "verify", "status"]);
    }

    /// The argv the docs and runbook spell, exactly.
    #[test]
    fn the_documented_invocations_parse() {
        for argv in [
            vec![
                "configure",
                "--node",
                "/tmp/nodes.json",
                "--bootnode",
                "enode://ab@1.2.3.4:30303",
                "--manifest",
                "./network-manifest.json",
            ],
            vec![
                "configure",
                "--node",
                "nodes/nodes.json",
                "--name",
                "tmp-devnet-1-2",
                "--bootnode",
                "enode://ab@1.2.3.4:30303",
                "--manifest",
                "network-manifest.json",
                "--no-verify",
                "--yes",
            ],
            vec![
                "configure",
                "-y",
                "--node",
                "n.json",
                "--bootnode",
                "enode://ab@1.2.3.4:30303",
                "--manifest",
                "m.json",
                "--dump-config",
                "/tmp/n.init-config.toml",
            ],
            vec![
                "verify",
                "--node",
                "/tmp/nodes.json",
                "--manifest",
                "./network-manifest.json",
            ],
            vec![
                "verify",
                "--node",
                "n.json",
                "--manifest",
                "m.json",
                "--measurements",
                "measurements.json",
                "--attestation-type",
                "azure-tdx",
                "--pccs-url",
                "http://pccs",
            ],
            vec!["status", "--node", "n.json", "--name", "dev-2"],
            vec!["status", "--node", "n.json", "--once"],
            vec!["status", "--node", "n.json", "--interval", "10"],
        ] {
            let full: Vec<&str> = std::iter::once(BIN_NAME)
                .chain(argv.iter().copied())
                .collect();
            assert!(Cli::try_parse_from(&full).is_ok(), "{argv:?}");
        }
    }

    #[test]
    fn the_manifest_is_checked_before_anything_reads_it() {
        let dir = tempfile::tempdir().unwrap();

        let error = load_manifest(&dir.path().join("absent.json"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("--manifest file not found"), "{error}");

        let bad = write_file(&dir, "bad.json", br#"{"manifest_version": 1}"#);
        let error = format!("{:?}", load_manifest(&bad).unwrap_err());
        assert!(error.contains("invalid manifest"), "{error}");
        assert!(error.contains("bad.json"), "{error}");

        let good = write_file(&dir, "network-manifest.json", FIXTURE_MANIFEST);
        assert_eq!(load_manifest(&good).unwrap().eth.chain_id, 5124);
    }
}
