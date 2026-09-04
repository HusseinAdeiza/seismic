//! The operator half: act on your own node.
//!
//! This CLI is for any operator joining a Seismic network. It is
//! cloud-agnostic and starts at the node descriptor — it consumes a descriptor
//! for an already-running node and talks to it over HTTP. **It never
//! provisions**: producing descriptors is the Pulumi program's job. Founding a
//! network is the other CLI's job (`seismic-tee-network`), and this crate must
//! never depend on it: the public operator repo is extracted along that line,
//! and this half plus [`seismic_tee_common`] lifts out wholesale.

use std::process::ExitCode;

use clap::Parser;

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
pub struct Cli {}

/// Parse the command line and run it.
pub fn run() -> ExitCode {
    let _cli = Cli::parse();

    // `--help` and `--version` answer for themselves, so reaching here means a
    // bare invocation, and there is nothing yet to do.
    eprintln!("{BIN_NAME}: no commands are implemented yet.");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

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
}
