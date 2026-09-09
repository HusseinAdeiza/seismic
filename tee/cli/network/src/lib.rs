//! The founder half: bring a whole network into existence.
//!
//! This CLI is run by whoever founds a network — one of Seismic's, a fork, or
//! a private devnet. It spans both sides of the cohort's existence: deriving
//! the artifact set that *is* the network's identity from its authored inputs,
//! which needs no machine at all, and then harvesting each node's founding
//! keys and configuring the cohort, which needs all of them running. What it
//! never does is provision — the descriptors come from the Pulumi program,
//! which provisions one node or N from one stack.
//!
//! Five commands, in founding order: [`init`] scaffolds a network directory's
//! authored inputs; [`harvest`] collects and DCAP-verifies the cohort's
//! founding keys; [`assemble`] derives the artifact set and mints
//! `network_id`; [`validate`] re-runs every gate over it; [`configure`]
//! founds the cohort — one genesis node plus its joiners — and asserts the
//! launch against what the manifest pins. Between `init` and `harvest` the
//! cohort is provisioned with the Pulumi program; `pulumi destroy` tears it
//! down.
//!
//! Every rule the network's identity rests on — the manifest's canonical bytes
//! and strict schema, admission-ID derivation and registry genesis storage,
//! DCAP verification of a quote — has exactly one implementation, in the
//! enclave repo, and this crate links it. The two helpers whose only
//! implementation is a foreign repo's node binary (`summit genesis`,
//! `seismic-reth genesis-hash`) are shell-outs ([`shell_outs`]). The [`tools`]
//! group exposes the linked enclave libraries at a subprocess boundary for
//! standalone use — an auditor replaying an archived founding quote needs
//! nothing but this binary.
//!
//! It is the only crate allowed to depend on both sides: founding a network
//! includes doing to each node what [`seismic_tee_node`] does to one. It stays
//! in the private repo when the public operator repo is extracted, so anything
//! an operator needs belongs on the other side of the seam — the node
//! descriptor — not here.

pub mod assemble;
pub mod bootnodes;
pub mod configure;
pub mod dashboard;
pub mod founding;
pub mod gates;
pub mod harvest;
pub mod init;
pub mod launch;
pub mod shell_outs;
pub mod tools;
pub mod validate;

use std::io::Write as _;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// The name the binary is installed and invoked as.
pub const BIN_NAME: &str = "seismic-tee-network";

#[derive(Debug, Parser)]
#[command(
    name = BIN_NAME,
    version,
    about = "Found a Seismic network",
    long_about = "Found a Seismic network: scaffold its inputs, harvest a cohort's founding \
                  keys, assemble its identity, and configure the cohort.\n\n\
                  Never provisions: like the operator CLI it starts at the node descriptors, \
                  which the Pulumi program produces.\n\n\
                  Joining an existing network is the operator CLI's job (seismic-tee-node), \
                  not this one's.",
    after_help = "Commands are listed in the order they should be run: init → harvest → \
                  assemble → validate → configure. Between init and harvest, provision the \
                  cohort with the seismic_node Pulumi program (tee/pulumi/seismic_node); \
                  pulumi destroy tears it down."
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Declared in founding order, which is the order `--help` lists them in.
#[derive(Debug, Subcommand)]
enum Command {
    /// Scaffold a network directory's authored inputs.
    Init(init::InitArgs),
    /// Harvest + DCAP-verify a founding cohort's summit keys into inputs/.
    Harvest(harvest::HarvestArgs),
    /// Derive the artifact set from a network directory's inputs.
    Assemble(assemble::AssembleArgs),
    /// Re-run all gates over an assembled network directory.
    Validate(validate::ValidateArgs),
    /// Configure a cohort in parallel: one genesis + N joiners, one command.
    Configure(configure::ConfigureArgs),
    /// The enclave libraries at a subprocess boundary: render and check
    /// manifests, promote and compile policies, replay archived quotes.
    Tools(tools::ToolsCli),
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
            Command::Init(args) => init::run(args).await,
            Command::Harvest(args) => harvest::run(args).await,
            Command::Assemble(args) => assemble::run(args).await,
            Command::Validate(args) => validate::run(args).await,
            Command::Configure(args) => configure::run(args).await,
            Command::Tools(tools) => {
                let output = tools::run(tools).await?;
                // Byte-verbatim: a rendered manifest or a passed-through
                // policy must reach stdout exactly as the library produced it.
                let mut stdout = std::io::stdout().lock();
                stdout
                    .write_all(&output)
                    .and_then(|()| stdout.flush())
                    .map(|()| ExitCode::SUCCESS)
                    .map_err(Into::into)
            }
        }
    });
    match result {
        Ok(code) => code,
        Err(error) => {
            // The whole chain, one cause per line: a DCAP failure is several
            // layers deep and the last one alone rarely says what happened.
            // Nothing reaches stdout on failure — the `tools` subprocess
            // contract.
            eprintln!("error: {error:?}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    /// The released binary reports the crate's version, which is what a
    /// founder records alongside a founding.
    #[test]
    fn the_binary_is_named_and_versioned() {
        let command = Cli::command();
        assert_eq!(command.get_name(), BIN_NAME);
        assert_eq!(command.get_version(), Some(env!("CARGO_PKG_VERSION")));
    }

    /// The two binaries are distinct front-ends, split by audience.
    #[test]
    fn the_two_clis_are_named_apart() {
        assert_ne!(BIN_NAME, seismic_tee_node::BIN_NAME);
    }

    /// The five founding commands in founding order, then the tools.
    #[test]
    fn the_commands_are_listed_in_founding_order() {
        let names: Vec<_> = Cli::command()
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect();
        assert_eq!(
            names,
            [
                "init",
                "harvest",
                "assemble",
                "validate",
                "configure",
                "tools"
            ]
        );
    }

    /// The argv the README and runbook spell, exactly.
    #[test]
    fn the_documented_invocations_parse() {
        for argv in [
            vec![
                "init",
                "tee/networks/devnet-3",
                "--reth-genesis",
                "https://raw.githubusercontent.com/SeismicSystems/seismic-reth/seismic/crates/seismic/chainspec/res/genesis/dev.json",
                "--summit-genesis",
                "tee/networks/summit-genesis-starter.toml",
                "--measurements",
                "../seismic-images/build/measurements.json",
                "--founders",
                "2",
            ],
            vec![
                "init",
                "n",
                "--reth-genesis",
                "g.json",
                "--summit-genesis",
                "s.toml",
                "--measurements",
                "m.json",
                "--name",
                "x",
                "--force",
            ],
            vec!["harvest", "tee/networks/devnet-3"],
            vec![
                "harvest",
                "n",
                "--attestation-type",
                "azure-tdx",
                "--pccs-url",
                "http://pccs",
                "--force",
            ],
            vec!["assemble", "tee/networks/devnet-3"],
            vec![
                "assemble",
                "n",
                "--registry",
                "0x1000000000000000000000000000000000000001",
                "--authority",
                "0x1000000000000000000000000000000000000002",
                "--force",
                "--reth-bin",
                "/x/seismic-reth",
                "--summit-bin",
                "/x/summit",
            ],
            vec!["validate", "tee/networks/devnet-3"],
            vec!["validate", "n", "--reth-bin", "r", "--summit-bin", "s"],
            vec![
                "configure",
                "--genesis",
                "devnet-3-1",
                "--manifest",
                "tee/networks/devnet-3/network-manifest.json",
            ],
            vec![
                "configure",
                "--genesis",
                "a",
                "--join",
                "b",
                "--manifest",
                "m.json",
                "--no-verify",
                "--email",
                "x@y",
            ],
            vec![
                "configure",
                "--genesis",
                "a",
                "--manifest",
                "m.json",
                "--measurements",
                "m.json",
                "--pccs-url",
                "http://pccs",
            ],
            vec!["tools", "manifest", "render", "-"],
            vec!["tools", "admission", "compile", "-"],
            vec![
                "tools",
                "verify",
                "harvest",
                "--record",
                "r.json",
                "--collateral",
                "c.json",
                "--policy",
                "p.json",
            ],
            vec![
                "tools",
                "verify",
                "deploy",
                "--endpoint",
                "http://n:7878",
                "--manifest",
                "m.json",
                "--policy",
                "p.json",
            ],
        ] {
            let full: Vec<&str> = std::iter::once(BIN_NAME)
                .chain(argv.iter().copied())
                .collect();
            assert!(Cli::try_parse_from(&full).is_ok(), "{argv:?}");
        }
    }
}
