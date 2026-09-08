//! Node descriptor: the handoff from provisioning to configuration.
//!
//! A *descriptor* is a small JSON file describing one provisioned node — the
//! public IP to reach it at (`public_ip`) and the FQDN clients use (`fqdn`).
//! It is the boundary between the infrastructure layer (provisioning, owned by
//! Pulumi and run standalone) and these CLIs: a CLI consumes a descriptor and
//! never wraps Pulumi.
//!
//! The seismic_node Pulumi program's `nodes` output is one `{public_ip, fqdn}`
//! per node, keyed by name, and one file per node is split out of it. A
//! bring-your-own-infra operator (Terraform, manual console, …) can hand-write
//! the same shape: only those two keys are read, and any extra keys are
//! ignored.
//!
//! The file's stem is the node's name across a cohort
//! (`dev-bootstrap-node-1.json` → `dev-bootstrap-node-1`), which is how the
//! descriptors, the harvest records, and the founding validator slots line up.

use std::path::Path;

use serde::{Deserialize, Deserializer};

use crate::error::{Error, Result};

/// One provisioned node, as named by its descriptor file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeDescriptor {
    /// The descriptor file's stem.
    pub name: String,
    /// The address the operator-only ports are reached on.
    pub public_ip: String,
    /// The node's DNS name — the cert domain, and where clients reach its RPC.
    pub fqdn: String,
}

/// A key that must carry a usable value, in each of the states it can be in.
///
/// The nesting is what separates an absent key from a present one holding
/// `null`: the outer `Option` is serde's "was the key there at all", the inner
/// one is the `null`. Both are rejected, but they are different mistakes and an
/// operator is told which — a key that isn't there is usually a typo, while a
/// `null` is usually Pulumi reporting an output that never got set.
type RequiredKey = Option<Option<String>>;

/// Deserialize a [`RequiredKey`], recording that the key was present.
///
/// The outer `Option` has to be filled in here rather than left to serde:
/// serde reads a JSON `null` as `None` at every level of nesting, so a plain
/// `Option<Option<String>>` collapses `null` and absent back into the one value
/// this type exists to tell apart. serde reaches this function only for a key
/// that was written, which is exactly what the outer `Some` means.
fn present_key<'de, D>(deserializer: D) -> std::result::Result<RequiredKey, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Some(Option::deserialize(deserializer)?))
}

/// Exactly the two keys read out of the file. Unknown keys are ignored, so a
/// whole `pulumi stack output --json` parses.
#[derive(Deserialize)]
struct DescriptorFile {
    #[serde(default, deserialize_with = "present_key")]
    public_ip: RequiredKey,
    #[serde(default, deserialize_with = "present_key")]
    fqdn: RequiredKey,
    /// The keys this file has that aren't read. Kept only so a failure can
    /// name them: the mistake is nearly always a neighbouring key, and an
    /// operator staring at "missing `public_ip`" wants to see what was there.
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

impl DescriptorFile {
    /// Every key the file actually had, sorted.
    ///
    /// "Had" means the key was written, whatever its value: a `public_ip` set
    /// to `null` is listed, because the point of this list is to show the
    /// operator what is in front of them.
    fn keys(&self) -> Vec<&str> {
        let mut keys: Vec<&str> = self.extra.keys().map(String::as_str).collect();
        if self.public_ip.is_some() {
            keys.push("public_ip");
        }
        if self.fqdn.is_some() {
            keys.push("fqdn");
        }
        keys.sort_unstable();
        keys
    }
}

impl NodeDescriptor {
    /// Read and validate a descriptor, naming the node after the file.
    ///
    /// Reading is the only way to build one from JSON: every failure names the
    /// offending file, which is the whole point of a hand-writable format.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|e| Error::read(path, e))?;
        let name = path
            .file_stem()
            .ok_or_else(|| {
                Error::gate(format!(
                    "descriptor path {} has no file name",
                    path.display()
                ))
            })?
            .to_string_lossy()
            .into_owned();
        Self::parse(name, path, &bytes)
    }

    fn parse(name: String, path: &Path, bytes: &[u8]) -> Result<Self> {
        let file: DescriptorFile =
            serde_json::from_slice(bytes).map_err(|e| Error::json(path, e))?;

        // An absent key, an explicit `null`, and an empty string all fail the
        // same way — a descriptor that can't reach a node — and all three are
        // caught here rather than at the first request. They are reported
        // apart, though, because the fix differs: only the absent case is
        // helped by listing the keys that *were* there, and only it is likely
        // to be a typo. Saying "missing" for a key the operator can plainly see
        // in the file sends them looking in the wrong place.
        let require = |key: &str, value: &RequiredKey| match value {
            Some(Some(value)) if !value.is_empty() => Ok(value.clone()),
            Some(Some(_)) => Err(Error::gate(format!(
                "descriptor {} has an empty `{key}`",
                path.display(),
            ))),
            Some(None) => Err(Error::gate(format!(
                "descriptor {} has `{key}` set to null \
                 (Pulumi emits null for an output that never got set)",
                path.display(),
            ))),
            None => Err(Error::gate(format!(
                "descriptor {} is missing required key `{key}`; got keys {:?}",
                path.display(),
                file.keys(),
            ))),
        };

        Ok(Self {
            name,
            public_ip: require("public_ip", &file.public_ip)?,
            fqdn: require("fqdn", &file.fqdn)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    const FULL: &[u8] = br#"{"public_ip": "203.0.113.7", "fqdn": "az-1.seismicdev.net"}"#;

    fn parse(bytes: &[u8]) -> Result<NodeDescriptor> {
        NodeDescriptor::parse(
            "dev-bootstrap-node-1".into(),
            &PathBuf::from("nodes/dev-bootstrap-node-1.json"),
            bytes,
        )
    }

    #[test]
    fn parses_the_two_keys() {
        let d = parse(FULL).unwrap();

        assert_eq!(d.name, "dev-bootstrap-node-1");
        assert_eq!(d.public_ip, "203.0.113.7");
        assert_eq!(d.fqdn, "az-1.seismicdev.net");
    }

    #[test]
    fn ignores_extra_keys_so_a_whole_stack_output_parses() {
        let stack_output = br#"{
            "public_ip": "203.0.113.7",
            "fqdn": "az-1.seismicdev.net",
            "resource_group": "dev-bootstrap-node-1",
            "vm_id": "/subscriptions/0000/resourceGroups/dev-bootstrap-node-1"
        }"#;

        assert_eq!(parse(stack_output).unwrap(), parse(FULL).unwrap());
    }

    /// Absent, explicitly `null`, and empty all fail: none reaches a node.
    ///
    /// Each is reported as the mistake it is. Asserting on the distinguishing
    /// phrase, not just on `"public_ip"`, is the point — the key name alone
    /// appears in all three, so a test that checks only that would pass even if
    /// every case reported "missing", which is what an operator staring at a
    /// `public_ip` line in their own file must not be told.
    #[test]
    fn reports_an_absent_null_and_empty_key_apart() {
        let cases = [
            (
                &br#"{"fqdn": "az-1.seismicdev.net"}"#[..],
                "is missing required key `public_ip`",
            ),
            (
                &br#"{"public_ip": null, "fqdn": "az-1.seismicdev.net"}"#[..],
                "has `public_ip` set to null",
            ),
            (
                &br#"{"public_ip": "", "fqdn": "az-1.seismicdev.net"}"#[..],
                "has an empty `public_ip`",
            ),
        ];

        for (bytes, expected) in cases {
            let err = parse(bytes).unwrap_err().to_string();
            assert!(err.contains(expected), "{err}");
            assert!(err.contains("dev-bootstrap-node-1.json"), "{err}");
        }
    }

    /// A key that is present but unusable is never called "missing", and the
    /// key list — which exists to catch a typo — never contradicts the
    /// sentence in front of it by listing the key it just called absent.
    #[test]
    fn a_present_but_unusable_key_is_not_called_missing() {
        for bytes in [
            &br#"{"public_ip": null, "fqdn": "az-1.seismicdev.net"}"#[..],
            &br#"{"public_ip": "", "fqdn": "az-1.seismicdev.net"}"#[..],
        ] {
            let err = parse(bytes).unwrap_err().to_string();
            assert!(!err.contains("missing"), "{err}");
            assert!(!err.contains("got keys"), "{err}");
        }
    }

    /// The failure names the keys that *were* there, because the mistake is
    /// nearly always a neighbouring key rather than an empty file.
    #[test]
    fn a_missing_key_reports_the_keys_the_file_had() {
        let err = parse(br#"{"publicIp": "203.0.113.7", "fqdn": "az-1.seismicdev.net"}"#)
            .unwrap_err()
            .to_string();

        assert!(err.contains("missing required key `public_ip`"), "{err}");
        assert!(err.contains(r#"["fqdn", "publicIp"]"#), "{err}");
    }

    #[test]
    fn names_the_node_after_the_file_and_names_the_file_on_failure() {
        let dir = tempfile::tempdir().unwrap();

        let good = dir.path().join("dev-bootstrap-node-2.json");
        std::fs::write(&good, FULL).unwrap();
        assert_eq!(
            NodeDescriptor::load(&good).unwrap().name,
            "dev-bootstrap-node-2"
        );

        let malformed = dir.path().join("dev-bootstrap-node-3.json");
        std::fs::write(&malformed, b"not json").unwrap();
        let err = NodeDescriptor::load(&malformed).unwrap_err().to_string();
        assert!(err.contains("dev-bootstrap-node-3.json"), "{err}");

        let err = NodeDescriptor::load(&dir.path().join("absent.json"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("absent.json"), "{err}");
    }
}
