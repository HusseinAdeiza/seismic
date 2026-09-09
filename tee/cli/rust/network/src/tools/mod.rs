//! `tools`: the enclave libraries, at the subprocess boundary.
//!
//! The Python CLIs still orchestrate a founding, and every rule a network's
//! identity rests on — the manifest's canonical bytes and strict schema,
//! admission-ID derivation and registry genesis storage, DCAP verification of
//! a quote — has exactly one implementation, in the enclave repo. Until the
//! orchestration is ported, Python reaches those implementations by running a
//! binary. It used to run three of them, one per enclave crate; now it runs
//! this one, which links the same crates:
//!
//! ```text
//! seismic-manifest render|parse            -> tools manifest render|parse
//! seismic-measurement-admission promote|compile
//!                                          -> tools admission promote|compile
//! verify-quote harvest|deploy              -> tools verify harvest|deploy
//! ```
//!
//! Each subcommand keeps the retired binary's contract — the same flags, `-`
//! for stdin, the same bytes on stdout, a message on stderr and a nonzero exit
//! with nothing on stdout for every failure — so the Python side changed only
//! its argv. What the Rust commands will do with these libraries when they
//! own the orchestration is a different question, answered per command as it
//! is ported; this group exists for the seam and retires with the Python.

pub mod admission;
pub mod manifest;
pub mod verify;

use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::{Parser, Subcommand};

/// `seismic-tee-network tools`.
#[derive(Debug, Parser)]
pub struct ToolsCli {
    #[command(subcommand)]
    command: ToolsCommand,
}

#[derive(Debug, Subcommand)]
enum ToolsCommand {
    /// Render and schema-check network manifests (seismic-network-manifest).
    Manifest(manifest::ManifestCli),
    /// Promote measurements into a policy and compile it
    /// (seismic-measurement-admission).
    Admission(admission::AdmissionCli),
    /// DCAP-verify founding harvest quotes and provisioned nodes
    /// (verify-quote).
    Verify(verify::VerifyCli),
}

/// Run one tool and return the bytes it puts on stdout.
///
/// Bytes rather than a string: a rendered manifest and a passed-through
/// policy are hash-committed, so they must reach stdout exactly as the library
/// produced them. Every failure is the error, which the caller prints to
/// stderr with nothing on stdout — the contract each retired binary had.
pub fn run(cli: ToolsCli) -> anyhow::Result<Vec<u8>> {
    match cli.command {
        ToolsCommand::Manifest(cli) => manifest::run(cli),
        ToolsCommand::Admission(cli) => admission::run(cli),
        ToolsCommand::Verify(cli) => {
            // Verification is async (collateral fetches, the node's RPC); the
            // rest of the CLI is not yet, so the runtime lives here for now.
            let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;
            runtime.block_on(verify::run(cli))
        }
    }
}

/// Read an input document from `path`, or from stdin for `-`.
///
/// `-` is the subprocess boundary's way of handing over exact bytes without a
/// temp file: a promoted policy and a manifest document both travel this way.
pub(crate) fn read_input(what: &str, path: &Path) -> anyhow::Result<Vec<u8>> {
    if path == Path::new("-") {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading {what} from stdin"))?;
        return Ok(bytes);
    }
    std::fs::read(path).with_context(|| format!("reading {what} {}", path.display()))
}

/// Read a file whose path came from a flag, so the failure names the flag.
///
/// A reader who mistypes a path must be told about the path, never that the
/// artifact it was supposed to hold is bad.
pub(crate) async fn read_flag_file(flag: &str, path: &PathBuf) -> anyhow::Result<Vec<u8>> {
    tokio::fs::read(path)
        .await
        .with_context(|| format!("reading {flag} {}", path.display()))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;

    /// The enclave schema crate's `fixtures/network-manifest-v1.json`, byte
    /// for byte: the canonical rendering the renderer must reproduce, and the
    /// values every manifest-reading test here parses.
    pub(crate) const FIXTURE_MANIFEST: &str = r#"{
  "eth": {
    "chain_id": 5124,
    "genesis_hash": "0x78ab9057bb67f95a6182969c5d755ac02802c98c0d2f0d8daeb52f4bddc60be5"
  },
  "manifest_version": 1,
  "measurements": {
    "bootstrap_policy_hash": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "contracts": {
      "authority": "0x1000000000000000000000000000000000000002",
      "registry": "0x1000000000000000000000000000000000000001"
    }
  },
  "name": "seismic-devnet-3",
  "summit": {
    "genesis_config_digest": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "namespace": "seismic-devnet-3"
  }
}
"#;

    /// SHA-256 of [`FIXTURE_MANIFEST`]: the schema crate's pinned vector.
    pub(crate) const FIXTURE_NETWORK_ID: &str =
        "0x8ef142e3f2bf15f8b201c4d8cda7848a9e846222c62b5615d4d36c7fccd98a24";

    pub(crate) fn write_file(dir: &tempfile::TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).expect("writing test input");
        path
    }
}
