//! Shared foundation for the two deploy CLIs.
//!
//! Everything here is common to `seismic-tee-node` (operator-facing) and
//! `seismic-tee-network` (founder-facing): the node descriptor map that is the
//! seam between them, the network-directory layout they both read, the
//! manifest they both trust, and the HTTP and error types they both speak.
//!
//! This crate depends on neither side. It is the half that lifts out with the
//! operator CLI when the public operator repo is extracted, so nothing
//! founder-only belongs in it.

pub mod descriptor;
pub mod error;
pub mod http;
pub mod manifest;
pub mod network_dir;

pub use descriptor::{Descriptors, NodeDescriptor, load_descriptors, select_descriptor};
pub use error::{Error, Result};
pub use manifest::Manifest;
pub use network_dir::NetworkDir;
