//! The layout of a network directory.
//!
//! A network directory holds the authored inputs under `inputs/` and the
//! derived artifact set at the top level. Everything top-level is hash-pinned
//! by the manifest; everything under `inputs/` is provenance; `nodes/` is
//! mutable infra state, regenerated per deploy and gitignored:
//!
//! ```text
//! inputs/reth-genesis.json                     policy-free genesis
//! inputs/summit-genesis.toml                   summit parameter choices
//! inputs/measurements.json                     raw PCR map from `make measure`
//! inputs/founder-withdrawal-credentials.json   one address per founder
//! inputs/harvest/<node>.json                   harvested founding pubkeys + quote
//! inputs/harvest/dcap-collateral/<node>.json   the collateral that quote verified against
//!
//! network-manifest.json                        the network's identity; SHA-256 = network_id
//! reth-genesis.json                            the input genesis with compiled
//!                                              registry storage injected
//! summit-genesis.toml                          the completed summit genesis
//! measurement-policy-bootstrap.json            the founding accepted measurement set
//!
//! nodes/<node>.json                            node descriptors
//! nodes/bootnodes.json                         the founding enode set
//! ```
//!
//! These are layout facts, not configuration: both CLIs name them, so they are
//! spelled once here.

use std::path::{Path, PathBuf};

/// The network's identity document. Its exact bytes hash to `network_id`.
pub const MANIFEST_FILENAME: &str = "network-manifest.json";
/// "bootstrap" because this is only the *founding* allowlist — what the
/// manifest's `bootstrap_policy_hash` pins and the registry's genesis storage
/// is compiled from. The live policy is the registry contract's state, which
/// the authority can mutate after genesis.
pub const POLICY_FILENAME: &str = "measurement-policy-bootstrap.json";
pub const RETH_GENESIS_FILENAME: &str = "reth-genesis.json";
/// Both the authored input and the shipped artifact use this basename: same
/// format, the artifact being the input with the derived fields filled in.
pub const SUMMIT_GENESIS_FILENAME: &str = "summit-genesis.toml";
pub const MEASUREMENTS_FILENAME: &str = "measurements.json";
pub const FOUNDERS_FILENAME: &str = "founder-withdrawal-credentials.json";

pub const INPUTS_DIRNAME: &str = "inputs";
pub const HARVEST_DIRNAME: &str = "harvest";
/// A subdirectory, so a glob over `harvest/*.json` never sees the collateral.
pub const COLLATERAL_DIRNAME: &str = "dcap-collateral";
pub const NODES_DIRNAME: &str = "nodes";
pub const BOOTNODES_FILENAME: &str = "bootnodes.json";

/// One network directory, addressed by the layout above.
///
/// Constructing it asserts nothing about what exists on disk: `init` builds a
/// directory that only has inputs, `assemble` fills in the artifact set, and
/// each command reports what it needs and can't find.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkDir {
    root: PathBuf,
}

impl NetworkDir {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    // The derived artifact set.

    pub fn manifest(&self) -> PathBuf {
        self.root.join(MANIFEST_FILENAME)
    }

    pub fn policy(&self) -> PathBuf {
        self.root.join(POLICY_FILENAME)
    }

    pub fn reth_genesis(&self) -> PathBuf {
        self.root.join(RETH_GENESIS_FILENAME)
    }

    pub fn summit_genesis(&self) -> PathBuf {
        self.root.join(SUMMIT_GENESIS_FILENAME)
    }

    // The authored inputs.

    pub fn inputs(&self) -> PathBuf {
        self.root.join(INPUTS_DIRNAME)
    }

    pub fn input_reth_genesis(&self) -> PathBuf {
        self.inputs().join(RETH_GENESIS_FILENAME)
    }

    pub fn input_summit_genesis(&self) -> PathBuf {
        self.inputs().join(SUMMIT_GENESIS_FILENAME)
    }

    pub fn input_measurements(&self) -> PathBuf {
        self.inputs().join(MEASUREMENTS_FILENAME)
    }

    pub fn founders(&self) -> PathBuf {
        self.inputs().join(FOUNDERS_FILENAME)
    }

    pub fn harvest(&self) -> PathBuf {
        self.inputs().join(HARVEST_DIRNAME)
    }

    pub fn harvest_record(&self, node: &str) -> PathBuf {
        self.harvest().join(format!("{node}.json"))
    }

    pub fn collateral(&self) -> PathBuf {
        self.harvest().join(COLLATERAL_DIRNAME)
    }

    pub fn collateral_record(&self, node: &str) -> PathBuf {
        self.collateral().join(format!("{node}.json"))
    }

    // Infra state.

    pub fn nodes(&self) -> PathBuf {
        self.root.join(NODES_DIRNAME)
    }

    pub fn descriptor(&self, node: &str) -> PathBuf {
        self.nodes().join(format!("{node}.json"))
    }

    pub fn bootnodes(&self) -> PathBuf {
        self.nodes().join(BOOTNODES_FILENAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed `tee/networks/example-devnet/` is the shape these paths
    /// describe; spot-check one path per tier against it.
    #[test]
    fn paths_hang_off_the_root() {
        let dir = NetworkDir::new("tee/networks/devnet-3");

        assert_eq!(
            dir.manifest(),
            Path::new("tee/networks/devnet-3/network-manifest.json")
        );
        assert_eq!(
            dir.input_measurements(),
            Path::new("tee/networks/devnet-3/inputs/measurements.json")
        );
        assert_eq!(
            dir.harvest_record("dev-bootstrap-node-1"),
            Path::new("tee/networks/devnet-3/inputs/harvest/dev-bootstrap-node-1.json")
        );
        assert_eq!(
            dir.collateral_record("dev-bootstrap-node-1"),
            Path::new(
                "tee/networks/devnet-3/inputs/harvest/dcap-collateral/dev-bootstrap-node-1.json"
            )
        );
        assert_eq!(
            dir.descriptor("dev-bootstrap-node-1"),
            Path::new("tee/networks/devnet-3/nodes/dev-bootstrap-node-1.json")
        );
        assert_eq!(
            dir.bootnodes(),
            Path::new("tee/networks/devnet-3/nodes/bootnodes.json")
        );
    }

    /// The artifact set and the inputs it was derived from share basenames and
    /// must never collide.
    #[test]
    fn the_artifact_set_never_collides_with_its_inputs() {
        let dir = NetworkDir::new("n");
        assert_ne!(dir.reth_genesis(), dir.input_reth_genesis());
        assert_ne!(dir.summit_genesis(), dir.input_summit_genesis());
    }
}
