//! Shared foundation for the two deploy CLIs.
//!
//! Everything here is common to `seismic-tee-node` (operator-facing) and
//! `seismic-tee-network` (founder-facing): the node descriptor map that is the
//! seam between them, the network-directory layout they both read, the
//! manifest they both trust and the gates it puts the other artifacts
//! through, and the HTTP, JSON-RPC and error types they both speak.
//!
//! This crate depends on neither side, so nothing founder-only belongs in it:
//! the operator crate must stay buildable without a single founder-only
//! dependency.

pub mod artifact;
pub mod descriptor;
pub mod error;
pub mod http;
pub mod manifest;
pub mod network_dir;
pub mod rpc;
#[cfg(feature = "test-support")]
pub mod test_support;

pub use artifact::Artifact;
pub use descriptor::{Descriptors, NodeDescriptor, load_descriptors, select_descriptor};
pub use error::{Error, Result};
pub use manifest::Manifest;
pub use network_dir::NetworkDir;
