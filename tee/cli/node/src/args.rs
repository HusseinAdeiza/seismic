//! `--node <file> [--name <name>]`: how a single-node command names its node.
//!
//! Shared by `configure`, `verify` and `status`, so an operator who learns one
//! command's way of pointing at a node has learned all three. The file is the
//! descriptor map (see [`seismic_tee_common::descriptor`]); `--name` picks the
//! entry when the map holds several.

use std::path::PathBuf;

use anyhow::bail;
use clap::Args;
use seismic_tee_common::{NodeDescriptor, load_descriptors, select_descriptor};

#[derive(Debug, Clone, Args)]
pub struct NodeArgs {
    /// Descriptor map JSON: `pulumi stack output nodes --json`, i.e.
    /// {<name>: {public_ip, fqdn}, …} (a network directory keeps it at
    /// nodes/nodes.json). Provides the node's public_ip/fqdn. With one entry
    /// it is the node; with several, --name says which.
    #[arg(long, value_name = "FILE")]
    pub node: PathBuf,

    /// Which node in --node to act on (its key). Optional when the file holds
    /// exactly one.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
}

impl NodeArgs {
    /// Resolve the flags to the one node, with its name.
    ///
    /// Every failure names the file: absent, malformed, or not singling out a
    /// node.
    pub fn load(&self) -> anyhow::Result<(String, NodeDescriptor)> {
        if !self.node.is_file() {
            bail!("--node descriptor file not found: {}", self.node.display());
        }
        let descriptors = load_descriptors(&self.node)?;
        let (name, descriptor) =
            select_descriptor(&descriptors, self.name.as_deref(), &self.node.display())?;
        Ok((name.to_string(), descriptor.clone()))
    }

    /// These flags as they were given, for a suggested follow-up command that
    /// must name the same node. Leading space included, so it splices into
    /// a command line.
    pub fn as_flags(&self) -> String {
        let mut flags = format!(" --node {}", self.node.display());
        if let Some(name) = &self.name {
            flags.push_str(&format!(" --name {name}"));
        }
        flags
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Probe {
        #[command(flatten)]
        node: NodeArgs,
    }

    fn args(argv: &[&str]) -> NodeArgs {
        Probe::try_parse_from(std::iter::once(&"probe").chain(argv))
            .expect("well-formed argv")
            .node
    }

    const TWO: &str = r#"{
        "node-1": {"public_ip": "203.0.113.7", "fqdn": "node1.example.com"},
        "node-2": {"public_ip": "203.0.113.99", "fqdn": "other.example"}
    }"#;

    #[test]
    fn name_picks_the_node_out_of_a_cohort_map() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.json");
        std::fs::write(&path, TWO).unwrap();

        let (name, descriptor) = args(&["--node", path.to_str().unwrap(), "--name", "node-2"])
            .load()
            .unwrap();
        assert_eq!(name, "node-2");
        assert_eq!(descriptor.fqdn, "other.example");
        assert_eq!(descriptor.public_ip, "203.0.113.99");
    }

    #[test]
    fn a_cohort_map_without_name_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.json");
        std::fs::write(&path, TWO).unwrap();

        let err = args(&["--node", path.to_str().unwrap()])
            .load()
            .unwrap_err()
            .to_string();
        assert!(err.contains("--name"), "{err}");
    }

    #[test]
    fn a_missing_file_is_named_by_flag() {
        let err = args(&["--node", "/absent/nodes.json"])
            .load()
            .unwrap_err()
            .to_string();
        assert!(err.contains("--node descriptor file not found"), "{err}");
        assert!(err.contains("/absent/nodes.json"), "{err}");
    }

    #[test]
    fn the_flags_splice_into_a_suggested_command() {
        assert_eq!(args(&["--node", "n.json"]).as_flags(), " --node n.json");
        assert_eq!(
            args(&["--node", "n.json", "--name", "dev-2"]).as_flags(),
            " --node n.json --name dev-2"
        );
    }
}
