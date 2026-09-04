//! The founder half: bring a whole network into existence.
//!
//! This CLI is run by whoever founds a network — one of Seismic's, a fork, or
//! a private devnet. It spans both sides of the cohort's existence: deriving
//! the artifact set that *is* the network's identity from its authored inputs,
//! which needs no machine at all, and then harvesting each node's founding
//! keys and configuring the cohort, which needs all of them running. What it
//! never does is provision — the descriptors come from the Pulumi program and
//! the cohort helper beside it, for one node or N.
//!
//! It is the only crate allowed to depend on both sides: founding a network
//! includes doing to each node what [`seismic_tee_node`] does to one.
//!
//! It stays in the private repo when the public operator repo is extracted, so
//! anything an operator needs belongs on the other side of the seam — the node
//! descriptor — not here.

use std::process::ExitCode;

use clap::Parser;

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
}
