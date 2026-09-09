//! `tools manifest`: the network manifest's one emitter and its strict parser.
//!
//! `seismic-network-manifest` is parse-only so that no node build can
//! re-serialize the file; `seismic-manifest` (the enclave's renderer crate)
//! is the one place the canonical bytes come from. Deploy links both: `render`
//! turns a document with the manifest's values, in any JSON formatting, into
//! the canonical `network-manifest.json` bytes (whose SHA-256 is the
//! `network_id`), and `parse` is the strict v1 verdict every reader runs
//! before trusting a field.

use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use seismic_manifest::{NetworkManifestV1, render};

use super::read_input;

#[derive(Debug, Parser)]
pub struct ManifestCli {
    #[command(subcommand)]
    command: ManifestCommand,
}

#[derive(Debug, Subcommand)]
enum ManifestCommand {
    /// Render a manifest document (any JSON formatting) as the canonical
    /// network-manifest.json bytes on stdout, after a strict schema parse.
    Render {
        /// Path to the manifest document (`-` for stdin).
        document: PathBuf,
    },
    /// Put a network-manifest.json through the strict v1 parser, the one
    /// every node reads the file with. Exit 0 if it parses; no stdout.
    Parse {
        /// Path to the manifest file (`-` for stdin).
        manifest: PathBuf,
    },
}

pub fn run(cli: ManifestCli) -> anyhow::Result<Vec<u8>> {
    match cli.command {
        ManifestCommand::Render { document } => {
            let bytes = read_input("the manifest document", &document)?;
            // Strictly parsed first, so invalid values never render.
            let manifest = parse(&bytes)?;
            Ok(render(&manifest))
        }
        ManifestCommand::Parse { manifest } => {
            let bytes = read_input("the manifest", &manifest)?;
            parse(&bytes)?;
            Ok(Vec::new())
        }
    }
}

/// The strict verdict, as the schema crate words it: the Python side relays
/// the message as the manifest's schema error, so nothing is added to it.
fn parse(bytes: &[u8]) -> anyhow::Result<NetworkManifestV1> {
    NetworkManifestV1::from_json_bytes(bytes).context("the manifest does not satisfy the v1 schema")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::tests::{FIXTURE_MANIFEST, FIXTURE_NETWORK_ID, write_file};

    fn render_cli(path: &std::path::Path) -> ManifestCli {
        ManifestCli::try_parse_from(["manifest".as_ref(), "render".as_ref(), path.as_os_str()])
            .expect("well-formed argv")
    }

    fn parse_cli(path: &std::path::Path) -> ManifestCli {
        ManifestCli::try_parse_from(["manifest".as_ref(), "parse".as_ref(), path.as_os_str()])
            .expect("well-formed argv")
    }

    /// The bytes are the renderer crate's, whatever the input's formatting:
    /// hashing them gives the crate's pinned network_id vector.
    #[test]
    fn render_is_canonical_and_parse_accepts_it() {
        let dir = tempfile::tempdir().unwrap();
        let value: serde_json::Value = serde_json::from_str(FIXTURE_MANIFEST).unwrap();
        let compact = write_file(
            &dir,
            "compact.json",
            &serde_json::to_string(&value).unwrap(),
        );

        let rendered = run(render_cli(&compact)).unwrap();
        assert_eq!(
            seismic_manifest::NetworkId::from_manifest_bytes(&rendered).to_string(),
            FIXTURE_NETWORK_ID
        );
        assert_eq!(std::str::from_utf8(&rendered).unwrap(), FIXTURE_MANIFEST);

        let canonical = write_file(&dir, "canonical.json", FIXTURE_MANIFEST);
        assert_eq!(run(render_cli(&canonical)).unwrap(), rendered);
        // A passing parse puts nothing on stdout.
        assert_eq!(run(parse_cli(&canonical)).unwrap(), b"");
    }

    /// A rejection names the field, so the Python side can relay the verdict
    /// as the schema error it is.
    #[test]
    fn rejections_name_the_field() {
        let dir = tempfile::tempdir().unwrap();
        let mut value: serde_json::Value = serde_json::from_str(FIXTURE_MANIFEST).unwrap();
        value["tx_io_pk"] = "0x02ab".into();
        let bad = write_file(&dir, "bad.json", &value.to_string());

        for cli in [render_cli(&bad), parse_cli(&bad)] {
            let error = format!("{:?}", run(cli).unwrap_err());
            assert!(error.contains("tx_io_pk"), "{error}");
        }

        let not_json = write_file(&dir, "not.json", "{not json");
        assert!(run(parse_cli(&not_json)).is_err());
    }

    #[test]
    fn a_missing_file_is_named() {
        let error = format!(
            "{:?}",
            run(parse_cli(&PathBuf::from("/absent/m.json"))).unwrap_err()
        );
        assert!(error.contains("/absent/m.json"), "{error}");
    }
}
