//! `seismic-tee`: the Seismic TEE deploy CLI — one binary over the three
//! library crates.
//!
//! The command groups follow the parties of
//! [the trust model](https://github.com/SeismicSystems/seismic/blob/main/docs/tee/trust-model.md#the-trust-anchor-per-action),
//! whose table names who takes each trust-sensitive action in a network's
//! life:
//!
//! - `ctx` — anyone: name a network and select which one — and which of its
//!   nodes — is current ([`seismic_tee_context::cmd`]).
//! - `network` — the genesis deployer: found a network. The party's anchor is
//!   its own verification at assemble, which is what these commands
//!   implement ([`seismic_tee_network`]).
//! - `node` — standing up and appraising a node. Named for its subject rather
//!   than a party: the validator's actions in the table are the enclave's,
//!   not a human's, and a non-staking full-node operator runs the same
//!   commands ([`seismic_tee_node`]).
//! - `admission` — governance: measurement admission from the human side,
//!   the pipeline from an image's measurements to the policy record a
//!   network accepts. Authoring and review exist today; changing a live
//!   network's accepted set on-chain lands in the same group
//!   ([`seismic_tee_admission`]).
//! - `verify-founding` — the auditor's, at the top level: the auditor takes
//!   no trust-sensitive action, and their subject is the network's record as
//!   a whole, not any one party's work
//!   ([`seismic_tee_network::verify_founding`]).
//!
//! The client and security council have no CLI work today, so no group
//! stands empty for them.
//!
//! This crate is the mount point and nothing else. The library crates' one-way
//! dependency rule — `common` and `admission` on neither side, `node` only on
//! `common`, only `network` on both — is what keeps each party's crate free
//! of the others' dependencies, and a binary that links them all changes
//! nothing about it.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use seismic_tee_admission::AdmissionCommand;
use seismic_tee_context::cmd::CtxCommand;
use seismic_tee_network::NetworkCommand;
use seismic_tee_network::verify_founding::VerifyFoundingArgs;
use seismic_tee_node::NodeCommand;

/// The name the binary is installed and invoked as.
const BIN_NAME: &str = "seismic-tee";

#[derive(Debug, Parser)]
#[command(
    name = BIN_NAME,
    version,
    about = "Found, join, govern and audit a Seismic TEE network",
    long_about = "The Seismic TEE deploy CLI.\n\n\
                  One command group per party of the trust model — network (the genesis \
                  deployer: found a network), node (stand up and appraise a node), admission \
                  (governance: the policies that decide which images a network accepts) — and \
                  the auditor's verify-founding at the top level.\n\n\
                  Never provisions: every command starts at the node descriptors the Pulumi \
                  program produces, or at a network directory."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The groups in the trust model's order of appearance in a network's life:
/// founded, joined, governed — then audited. Each one-liner leads with the
/// party it is for, so the listing doubles as a who-runs-what.
#[derive(Debug, Subcommand)]
enum Command {
    /// Anyone: select the network and node the other commands act on, and
    /// reach the selected node from a shell.
    Ctx {
        #[command(subcommand)]
        command: CtxCommand,
    },
    /// Network founder: scaffold a network's inputs, harvest a cohort's
    /// founding keys, assemble its identity, configure the cohort.
    #[command(
        long_about = "Found a Seismic network: scaffold its inputs, harvest a cohort's founding \
                      keys, assemble its identity, and configure the cohort.\n\n\
                      Never provisions: like every group it starts at the node descriptors, \
                      which the Pulumi program produces.\n\n\
                      Joining an existing network is `seismic-tee node configure`, not a \
                      command of this group.",
        after_help = "Commands are listed in the order they should be run: init → harvest → \
                      assemble → validate → configure. Between init and harvest, provision the \
                      cohort with the seismic_node Pulumi program (tee/pulumi/seismic_node); \
                      pulumi destroy tears it down.\n\n\
                      Auditing a founding afterwards is `seismic-tee verify-founding`: not a \
                      founding step, and not a command of this group."
    )]
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    /// Node operator: configure your node on first boot, verify its
    /// attestation, watch its first-boot disk wipe.
    #[command(
        long_about = "Stand up and appraise a Seismic TEE node: configure it on first boot, \
                      verify its attestation, watch its first-boot disk wipe.\n\n\
                      Cloud-agnostic, and never provisions: each command consumes a descriptor \
                      of an already-running node and reaches the node over HTTP."
    )]
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Governance: author and review the measurement policies that decide
    /// which images a network accepts.
    #[command(
        long_about = "Measurement admission from the human side: the pipeline from an \
                      image's `make measure` output to the policy record a network accepts. \
                      promote authors the record; compile reports what it admits — the \
                      admission IDs and the registry genesis storage seeding them — for \
                      review before it is pinned at founding or proposed to a live network.\n\n\
                      Runs the same compiler `network assemble` pins the founding policy \
                      with. Changing a live network's accepted set on-chain is not here yet.",
        after_help = "Commands are listed in pipeline order: promote → compile."
    )]
    Admission {
        #[command(subcommand)]
        command: AdmissionCommand,
    },
    /// Auditor: verify a founding — the genesis validator set's TEE
    /// provenance — from a committed network directory, offline.
    VerifyFounding(VerifyFoundingArgs),
}

fn main() -> ExitCode {
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
            Command::Ctx { command } => seismic_tee_context::cmd::run(command),
            Command::Network { command } => seismic_tee_network::run(command).await,
            Command::Node { command } => seismic_tee_node::run(command).await,
            Command::Admission { command } => seismic_tee_admission::run(command),
            Command::VerifyFounding(args) => seismic_tee_network::verify_founding::run(args).await,
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

    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    /// The released binary reports the crate's version, which is what a
    /// founder records alongside a founding and an operator quotes when
    /// reporting a problem.
    #[test]
    fn the_binary_is_named_and_versioned() {
        let command = Cli::command();
        assert_eq!(command.get_name(), BIN_NAME);
        assert_eq!(command.get_version(), Some(env!("CARGO_PKG_VERSION")));
    }

    fn subcommand_names(command: &clap::Command) -> Vec<String> {
        command
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect()
    }

    /// One group per party with CLI work, in the order a network meets them,
    /// and the auditor's command at the top level.
    #[test]
    fn the_groups_follow_the_trust_models_parties() {
        let cli = Cli::command();
        assert_eq!(
            subcommand_names(&cli),
            ["ctx", "network", "node", "admission", "verify-founding"]
        );
        let group = |name: &str| subcommand_names(cli.find_subcommand(name).unwrap());
        assert_eq!(
            group("ctx"),
            [
                "use",
                "list",
                "show",
                "env",
                "exec",
                "set-network",
                "set-nodes",
                "unset"
            ]
        );
        assert_eq!(
            group("network"),
            ["init", "harvest", "assemble", "validate", "configure"]
        );
        assert_eq!(group("node"), ["configure", "verify", "status"]);
        assert_eq!(group("admission"), ["promote", "compile"]);
        assert!(subcommand_names(cli.find_subcommand("verify-founding").unwrap()).is_empty());
    }

    /// "Harvest" is the founder's internal step name: an auditor never types
    /// it, and the retired `tools` spellings are gone rather than aliased.
    #[test]
    fn retired_spellings_do_not_parse() {
        for argv in [
            vec!["network", "verify-harvest", "n"],
            vec!["verify-harvest", "n"],
            vec!["network", "verify-founding", "n"],
            vec!["tools", "admission", "compile", "p.json"],
            vec!["network", "tools", "admission", "compile", "p.json"],
            vec!["admission", "compile", "-"],
            vec!["configure", "--node", "n.json", "--manifest", "m.json"],
        ] {
            let full: Vec<&str> = std::iter::once(BIN_NAME)
                .chain(argv.iter().copied())
                .collect();
            let parsed = Cli::try_parse_from(&full);
            // `-` is a path like any other now, so it parses; it just names
            // a file called `-`. Everything else is a usage error.
            if argv == ["admission", "compile", "-"] {
                assert!(parsed.is_ok(), "{argv:?}");
            } else {
                assert!(parsed.is_err(), "{argv:?}");
            }
        }
    }

    /// The argv the README and runbook spell, exactly.
    #[test]
    fn the_documented_invocations_parse() {
        for argv in [
            // network
            vec![
                "network",
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
                "network",
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
            vec!["network", "harvest", "tee/networks/devnet-3"],
            vec![
                "network",
                "harvest",
                "n",
                "--attestation-type",
                "azure-tdx",
                "--pccs-url",
                "http://pccs",
                "--force",
            ],
            vec!["network", "assemble", "tee/networks/devnet-3"],
            vec![
                "network",
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
            vec!["network", "validate", "tee/networks/devnet-3"],
            vec![
                "network",
                "validate",
                "n",
                "--reth-bin",
                "r",
                "--summit-bin",
                "s",
            ],
            vec![
                "network",
                "configure",
                "--genesis",
                "devnet-3-1",
                "--manifest",
                "tee/networks/devnet-3/network-manifest.json",
            ],
            vec![
                "network",
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
                "network",
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
            // node
            vec![
                "node",
                "configure",
                "--node",
                "/tmp/nodes.json",
                "--bootnode",
                "enode://ab@1.2.3.4:30303",
                "--manifest",
                "./network-manifest.json",
            ],
            vec![
                "node",
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
                "tmp-devnet-1-2",
            ],
            vec![
                "node",
                "configure",
                "-y",
                "dev-2",
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
                "node",
                "verify",
                "--node",
                "/tmp/nodes.json",
                "--manifest",
                "./network-manifest.json",
            ],
            vec![
                "node",
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
            vec!["node", "status", "--node", "n.json", "--name", "dev-2"],
            vec!["node", "status", "--node", "n.json", "--once"],
            vec!["node", "status", "--node", "n.json", "--interval", "10"],
            // resolved from the context
            vec!["node", "status"],
            vec!["node", "status", "--name", "alpha"],
            vec!["node", "verify", "--context", "devnet-1/alpha"],
            vec![
                "node",
                "configure",
                "--bootnode",
                "enode://ab@1.2.3.4:30303",
                "--yes",
                "alpha",
            ],
            // admission
            vec![
                "admission",
                "compile",
                "tee/networks/devnet-3/measurement-policy-bootstrap.json",
            ],
            vec![
                "admission",
                "promote",
                "../seismic-images/build/measurements.json",
                "--attestation-type",
                "azure-tdx",
            ],
            vec![
                "admission",
                "promote",
                "m.json",
                "--measurement-id",
                "img.vhd",
            ],
            // the audit
            vec!["verify-founding", "tee/networks/devnet-3"],
            vec!["verify-founding", "n", "--record", "n-2"],
        ] {
            let full: Vec<&str> = std::iter::once(BIN_NAME)
                .chain(argv.iter().copied())
                .collect();
            assert!(Cli::try_parse_from(&full).is_ok(), "{argv:?}");
        }
    }
}
