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
//! It is the only crate allowed to depend on both sides: founding a network
//! includes doing to each node what [`seismic_tee_node`] does to one.
//!
//! It stays in the private repo when the public operator repo is extracted, so
//! anything an operator needs belongs on the other side of the seam — the node
//! descriptor — not here.
//!
//! Until the founding commands are ported, the Python CLI of the same name
//! runs them and reaches the enclave libraries through this binary's [`tools`]
//! group.

pub mod tools;

use std::io::Write as _;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// The name the binary is installed and invoked as.
pub const BIN_NAME: &str = "seismic-tee-network";

#[derive(Debug, Parser)]
#[command(
    name = BIN_NAME,
    version,
    about = "Found and operate a Seismic network",
    long_about = "Found and operate a Seismic network: harvest a cohort's \
                  founding keys, assemble its identity, and configure it.\n\n\
                  Never provisions: like the operator CLI it starts at the \
                  node descriptors, which the Pulumi program produces.\n\n\
                  Joining an existing network is the operator CLI's job \
                  (seismic-tee-node), not this one's."
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// The enclave libraries at the subprocess boundary, for the Python CLI
    /// that still orchestrates a founding.
    Tools(tools::ToolsCli),
}

/// Parse the command line and run it.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Tools(tools) => tools::run(tools),
    };
    match result {
        Ok(output) => {
            // Byte-verbatim: a rendered manifest or a passed-through policy
            // must reach stdout exactly as the library produced it.
            let mut stdout = std::io::stdout().lock();
            if stdout
                .write_all(&output)
                .and_then(|()| stdout.flush())
                .is_err()
            {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            // The whole chain, one cause per line: a DCAP failure is several
            // layers deep and the last one alone rarely says what happened.
            // Nothing reaches stdout on failure — the subprocess contract.
            eprintln!("error: {err:?}");
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

    /// The argv the Python side sends, exactly: the seam is that spelling.
    #[test]
    fn the_tools_group_answers_the_python_sides_argv() {
        for argv in [
            vec!["tools", "manifest", "render", "-"],
            vec!["tools", "manifest", "parse", "-"],
            vec![
                "tools",
                "admission",
                "promote",
                "--attestation-type",
                "azure-tdx",
                "-",
            ],
            vec!["tools", "admission", "compile", "-"],
            vec![
                "tools",
                "verify",
                "harvest",
                "--record",
                "-",
                "--policy",
                "p.json",
                "--dump-collateral",
                "c.json",
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
                "--pccs-url",
                "http://pccs",
            ],
        ] {
            let full: Vec<&str> = std::iter::once(BIN_NAME)
                .chain(argv.iter().copied())
                .collect();
            assert!(Cli::try_parse_from(&full).is_ok(), "{argv:?}");
        }
    }
}
