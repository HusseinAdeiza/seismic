//! The network manifest, held as the bytes it is identified by.
//!
//! `network_id = SHA-256(file bytes)`, so the manifest travels as opaque bytes
//! through every hop: deploy artifact → the config POST → tdx-init →
//! `/run/seismic/conf/`. Any byte change, even a reformat, names a different
//! network and fails loudly at the first binding check.
//!
//! That makes "hash the same bytes you parse" the rule the whole scheme rests
//! on, so this type holds both and derives the id itself — a caller can't pair
//! a parsed manifest with an id from somewhere else. The schema is the enclave
//! repo's [`seismic_network_manifest`], the same code every node parses the
//! manifest with, linked rather than mirrored.

use std::ops::Deref;
use std::path::Path;

use seismic_network_manifest::{NetworkId, NetworkManifestV1};

use crate::error::{Error, Result};

/// A manifest and the bytes it was parsed from, with the id those bytes derive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    bytes: Vec<u8>,
    network_id: NetworkId,
    parsed: NetworkManifestV1,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|e| Error::read(path, e))?;
        Self::from_json_bytes(bytes).map_err(|source| Error::ManifestSchema {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn from_json_bytes(
        bytes: impl Into<Vec<u8>>,
    ) -> std::result::Result<Self, seismic_network_manifest::ManifestError> {
        let bytes = bytes.into();
        Ok(Self {
            network_id: NetworkId::from_manifest_bytes(&bytes),
            parsed: NetworkManifestV1::from_json_bytes(&bytes)?,
            bytes,
        })
    }

    /// The exact bytes to deliver onward. Never re-serialize the parsed value:
    /// that is a different document and a different network.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }
}

/// Read the manifest's fields straight off the value.
impl Deref for Manifest {
    type Target = NetworkManifestV1;

    fn deref(&self) -> &Self::Target {
        &self.parsed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim `tee/networks/example-devnet/network-manifest.json`.
    const EXAMPLE_DEVNET: &[u8] =
        include_bytes!("../../../../networks/example-devnet/network-manifest.json");

    #[test]
    fn parses_the_committed_example_network() {
        let manifest = Manifest::from_json_bytes(EXAMPLE_DEVNET).unwrap();

        assert_eq!(manifest.name, "example-devnet");
        assert_eq!(manifest.eth.chain_id, 5124);
        assert_eq!(manifest.summit.namespace, "example-devnet");
    }

    /// The digest is pinned rather than recomputed the way the constructor
    /// does it, so this catches the enclave crate changing how `network_id` is
    /// derived — the one drift that would silently rename every network.
    ///
    /// Recompute with:
    /// `sha256sum tee/networks/example-devnet/network-manifest.json`
    #[test]
    fn the_id_is_the_hash_of_the_file_bytes() {
        let manifest = Manifest::from_json_bytes(EXAMPLE_DEVNET).unwrap();

        assert_eq!(manifest.bytes(), EXAMPLE_DEVNET);
        assert_eq!(
            manifest.network_id().to_string(),
            "0xb0951428c4ddcdc7b7b4701c97bc356ba5a82528c3a4ed35d8cd6a876a5a7e8e"
        );
    }

    /// One trailing newline is a different network — the property the whole
    /// deliver-verbatim rule exists to protect.
    #[test]
    fn a_reformat_is_a_different_network() {
        let reformatted = [EXAMPLE_DEVNET, b"\n"].concat();

        assert_ne!(
            Manifest::from_json_bytes(EXAMPLE_DEVNET)
                .unwrap()
                .network_id(),
            Manifest::from_json_bytes(reformatted).unwrap().network_id(),
        );
    }

    #[test]
    fn a_load_failure_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("network-manifest.json");
        std::fs::write(&path, br#"{"manifest_version": 1}"#).unwrap();

        let err = Manifest::load(&path).unwrap_err().to_string();
        assert!(err.contains("network-manifest.json"), "{err}");
    }
}
