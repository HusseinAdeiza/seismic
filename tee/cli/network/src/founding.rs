//! The founding inputs a network directory holds before `assemble` runs.
//!
//! Three files, read by three commands: the authored withdrawal credentials
//! (`inputs/founder-withdrawal-credentials.json`), the harvested founding
//! records (`inputs/harvest/<node>.json`), and the cohort's descriptor map
//! (`nodes/nodes.json`). `harvest` reads the first and the last to size the
//! cohort before it fetches anything; `assemble` pairs all three into the
//! founding validator set it pins; `configure` joins the records with the map
//! for the IPs it delivers and the keys it asserts the launch against. Each
//! reader validates everything it reads even when an earlier command already
//! did: these are plain committed files that may have been copied, committed
//! and edited between commands.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, bail};
use seismic_tee_common::network_dir::{NODES_DIRNAME, NODES_FILENAME};
use seismic_tee_common::{Descriptors, NetworkDir, load_descriptors};
use serde::Serialize;

/// Summit's consensus (BLS) port: each validator entry in the completed summit
/// genesis pins `<ip>:<port>`. IPs are operational data — the config digest
/// excludes them — so they are delivered but never pinned.
pub const SUMMIT_CONSENSUS_PORT: u16 = 18551;

/// `s` is exactly `nbytes` of bare lowercase hex — summit's keystore wire
/// spelling, the form the genesis config digest commits to. Any other spelling
/// is rejected, never normalized, so nothing non-canonical is laundered into
/// the pinned set.
pub fn is_bare_hex(s: &str, nbytes: usize) -> bool {
    s.len() == 2 * nbytes
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `s` is `0x` + 40 hex digits (either case): an address as the withdrawal
/// credentials spell one.
pub fn is_address(s: &str) -> bool {
    s.strip_prefix("0x")
        .is_some_and(|digits| digits.len() == 40 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Load the authored `founder-withdrawal-credentials.json`: one 0x-prefixed
/// address per founder, in a JSON array.
///
/// A list rather than a node-name mapping so the founders' addresses are
/// authorable before any box exists — they are a fact about the founders, not
/// about the infrastructure. [`load_founding_set`] pairs the i-th address with
/// the i-th founding validator in node-name order.
pub fn load_founder_credentials(path: &Path) -> anyhow::Result<Vec<String>> {
    if !path.is_file() {
        bail!(
            "{} not found — author it as a JSON array of the founders' withdrawal credentials \
             (0x-prefixed addresses), one per founding node",
            path.display()
        );
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("{}: not valid JSON", path.display()))?;
    let Some(entries) = value.as_array() else {
        bail!(
            "{}: expected a JSON array of withdrawal credentials (0x-prefixed addresses), one \
             per founding node",
            path.display()
        );
    };
    let mut addresses = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(address) = entry.as_str() else {
            bail!(
                "{}: expected a JSON array of withdrawal credentials (0x-prefixed addresses), \
                 one per founding node",
                path.display()
            );
        };
        addresses.push(address.to_string());
    }
    let mut bad: Vec<&str> = addresses
        .iter()
        .map(String::as_str)
        .filter(|a| !is_address(a))
        .collect();
    bad.sort_unstable();
    bad.dedup();
    if !bad.is_empty() {
        bail!(
            "{}: withdrawal credentials must be 0x + 40 hex chars; bad entr(ies): {}",
            path.display(),
            bad.join(", ")
        );
    }
    Ok(addresses)
}

/// One archived founding record, as the fields the founding is built from.
///
/// `document` is the whole file as archived — the input to the verify-quote
/// library's harvest check, handed back unchanged so what is re-verified is
/// what was verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundingRecord {
    /// The ed25519 node pubkey, bare lowercase hex (32 bytes).
    pub node_public_key: String,
    /// The BLS consensus pubkey, bare lowercase hex (48 bytes).
    pub consensus_public_key: String,
    /// The archived file, whole.
    pub document: serde_json::Value,
}

/// The harvested founding records, keyed by node name (the file stem).
pub type FoundingRecords = BTreeMap<String, FoundingRecord>;

/// Read the harvested founding records (`inputs/harvest/<node>.json`).
///
/// Validates the fields the founding set is built from — nonce, both pubkeys,
/// the evidence object — and rejects a pubkey repeated across boxes: summit's
/// genesis keys validator accounts by node pubkey, so a repeated key silently
/// collapses the set, and a shared consensus key is accidental-equivocation
/// material.
pub fn load_harvest_records(dir: &NetworkDir) -> anyhow::Result<FoundingRecords> {
    let harvest_dir = dir.harvest();
    let mut paths: Vec<_> = match std::fs::read_dir(&harvest_dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_some_and(|ext| ext == "json"))
            .collect(),
        Err(_) => Vec::new(),
    };
    paths.sort();
    if paths.is_empty() {
        bail!(
            "no harvest records in {} — assemble pins the founding validator set from them; \
             provision the cohort (the Pulumi program's `nodes` map) and run `seismic-tee network \
             harvest` first",
            harvest_dir.display()
        );
    }

    let mut records = FoundingRecords::new();
    for path in paths {
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let document: serde_json::Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("{}: not valid JSON", path.display()))?;
        let Some(object) = document.as_object() else {
            bail!("{}: expected a JSON object", path.display());
        };
        let field = |name: &str, nbytes: usize| -> anyhow::Result<String> {
            match object.get(name).and_then(serde_json::Value::as_str) {
                Some(value) if is_bare_hex(value, nbytes) => Ok(value.to_string()),
                other => bail!(
                    "{}: {name}: expected {nbytes}-byte lowercase bare hex, got {}",
                    path.display(),
                    other.map_or_else(|| "nothing".to_string(), |v| format!("{v:?}")),
                ),
            }
        };
        field("harvest_nonce", 32)?;
        let node_public_key = field("node_public_key", 32)?;
        let consensus_public_key = field("consensus_public_key", 48)?;
        if !object
            .get("evidence")
            .is_some_and(serde_json::Value::is_object)
        {
            bail!(
                "{}: no evidence object — without the archived quote the record cannot be \
                 re-verified, so it must not be pinned",
                path.display()
            );
        }
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        records.insert(
            name,
            FoundingRecord {
                node_public_key,
                consensus_public_key,
                document,
            },
        );
    }

    for (key_field, key_of) in [
        (
            "node_public_key",
            (|r: &FoundingRecord| r.node_public_key.as_str()) as fn(&FoundingRecord) -> &str,
        ),
        ("consensus_public_key", |r: &FoundingRecord| {
            r.consensus_public_key.as_str()
        }),
    ] {
        let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
        for (name, record) in &records {
            let key = key_of(record);
            if let Some(first) = seen.get(key) {
                bail!(
                    "{first} and {name} carry the same {key_field} ({key}); the harvest is not \
                     the distinct founder set being pinned — re-found and re-harvest"
                );
            }
            seen.insert(key, name);
        }
    }
    Ok(records)
}

/// Load the network's descriptor map, `nodes/nodes.json`, as a gate.
///
/// Every failure — no file, not JSON, an entry the CLIs can't act on — names
/// the file and says where the map comes from, since the fix is always the
/// same one command (save the stack's `nodes` output there again).
pub fn load_descriptor_map(dir: &NetworkDir) -> anyhow::Result<Descriptors> {
    let path = dir.nodes_file();
    if !path.is_file() {
        bail!(
            "{} not found — save the cohort's descriptor map there: `pulumi stack output nodes \
             --json > {NODES_DIRNAME}/{NODES_FILENAME}` (a bring-your-own-infra operator \
             hand-writes the same shape: {{<name>: {{public_ip, fqdn}}, …}})",
            path.display()
        );
    }
    Ok(load_descriptors(&path)?)
}

/// One founding validator as `summit genesis set-validators` takes it:
/// harvested keys in summit's bare-lowercase-hex keystore spelling, the
/// authored credentials, and the descriptor IP with the consensus port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Validator {
    pub node_public_key: String,
    pub consensus_public_key: String,
    pub ip_address: String,
    pub withdrawal_credentials: String,
}

/// The founding cohort as `assemble` pins it: the summit validator entries and
/// the harvest records they came from (for quote re-verification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundingSet {
    pub validators: Vec<Validator>,
    pub records: FoundingRecords,
}

/// Pair the harvested cohort with its authored withdrawal credentials and
/// current IPs into summit validator entries.
///
/// The credentials are positional: the i-th authored address goes to the i-th
/// harvested box in node-name order, and the counts must match exactly — one
/// address short means a box can't be pinned, one too many means the harvest
/// isn't the cohort the founders authored for, and either way assembling would
/// pin a set other than the intended one. The pairing is printed and lands
/// visibly in the emitted genesis, since nothing downstream can tell a swapped
/// pair from an intended one. IPs come from the cohort's descriptor map:
/// delivered in the genesis file but excluded from its config digest, so the
/// committed file is a founding-era snapshot and IP churn never re-founds.
pub fn load_founding_set(dir: &NetworkDir) -> anyhow::Result<FoundingSet> {
    let founders = load_founder_credentials(&dir.founders())?;
    let records = load_harvest_records(dir)?;
    if founders.len() != records.len() {
        bail!(
            "{} carries {} withdrawal credential(s) but {} box(es) were harvested into {} ({}) — \
             author one address per founding node",
            dir.founders().display(),
            founders.len(),
            records.len(),
            dir.harvest().display(),
            records.keys().cloned().collect::<Vec<_>>().join(", "),
        );
    }
    let descriptors = load_descriptor_map(dir)?;
    let mut validators = Vec::with_capacity(records.len());
    for ((name, record), credentials) in records.iter().zip(&founders) {
        let Some(descriptor) = descriptors.get(name) else {
            bail!(
                "{} has no node {name:?} — the descriptor map (the Pulumi stack's `nodes` output) \
                 supplies each founding validator's IP. A harvested box that is gone from the map \
                 means the cohort changed under the harvest: re-found rather than assembling",
                dir.nodes_file().display()
            );
        };
        eprintln!("founding validator {name}: withdrawals to {credentials}");
        validators.push(Validator {
            node_public_key: record.node_public_key.clone(),
            consensus_public_key: record.consensus_public_key.clone(),
            ip_address: format!("{}:{SUMMIT_CONSENSUS_PORT}", descriptor.public_ip),
            withdrawal_credentials: credentials.clone(),
        });
    }
    Ok(FoundingSet {
        validators,
        records,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::json;

    use super::*;

    pub(crate) const NODE_KEY_1: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    pub(crate) const NODE_KEY_2: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    pub(crate) fn consensus_key(byte: &str) -> String {
        byte.repeat(48)
    }

    /// Evidence in the backend's own serialization, claiming Azure TDX: a
    /// stand-in quote (`[1, 2, 3]` as base64) under the platform metadata
    /// the holder serves. Parses as an `AttestationExchangeMessage`; never
    /// verifies.
    pub(crate) fn azure_evidence() -> serde_json::Value {
        json!({
            "attestation_evidence": {
                "quote": "AQID",
                "platform": {
                    "attestation_type": "azure-tdx",
                    "ram_bytes": 0,
                    "num_disks": 0,
                    "acpi": null,
                },
            },
        })
    }

    /// Evidence declaring no attestation, in the backend's serialization.
    pub(crate) fn no_attestation_evidence() -> serde_json::Value {
        json!({"attestation_evidence": null})
    }

    /// A harvest record as the harvest builds it from the holder's answer.
    pub(crate) fn record(node_key: &str, consensus_byte: &str) -> serde_json::Value {
        json!({
            "harvest_nonce": "11".repeat(32),
            "node_public_key": node_key,
            "consensus_public_key": consensus_key(consensus_byte),
            "evidence": azure_evidence(),
        })
    }

    pub(crate) fn write(dir: &NetworkDir, relative: &Path, contents: &str) {
        let path = dir.root().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    pub(crate) fn write_harvest(dir: &NetworkDir, name: &str, record: &serde_json::Value) {
        write(
            dir,
            &Path::new("inputs/harvest").join(format!("{name}.json")),
            &record.to_string(),
        );
    }

    pub(crate) fn network_dir() -> (tempfile::TempDir, NetworkDir) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = NetworkDir::new(tmp.path());
        (tmp, dir)
    }

    #[test]
    fn hex_spellings_are_checked_not_normalized() {
        assert!(is_bare_hex(NODE_KEY_1, 32));
        assert!(!is_bare_hex(&NODE_KEY_1.to_uppercase(), 32));
        assert!(!is_bare_hex(&format!("0x{NODE_KEY_1}"), 32));
        assert!(!is_bare_hex(&NODE_KEY_1[1..], 32));

        assert!(is_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"));
        assert!(!is_address("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"));
        assert!(!is_address("0xf39F"));
    }

    #[test]
    fn founder_credentials_are_a_list_of_addresses() {
        let (_tmp, dir) = network_dir();
        let path = dir.founders();

        let err = load_founder_credentials(&path).unwrap_err().to_string();
        assert!(err.contains("not found"), "{err}");
        assert!(err.contains("one per founding node"), "{err}");

        write(
            &dir,
            Path::new("inputs/founder-withdrawal-credentials.json"),
            r#"["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "0x0000000000000000000000000000000000000001"]"#,
        );
        assert_eq!(load_founder_credentials(&path).unwrap().len(), 2);

        write(
            &dir,
            Path::new("inputs/founder-withdrawal-credentials.json"),
            r#"["0xf39F", "nope", "0xf39F"]"#,
        );
        let err = load_founder_credentials(&path).unwrap_err().to_string();
        assert!(err.contains("bad entr(ies): 0xf39F, nope"), "{err}");

        write(
            &dir,
            Path::new("inputs/founder-withdrawal-credentials.json"),
            r#"{"node-1": "0xf39F"}"#,
        );
        let err = load_founder_credentials(&path).unwrap_err().to_string();
        assert!(err.contains("expected a JSON array"), "{err}");
    }

    #[test]
    fn harvest_records_are_read_in_name_order_with_their_documents() {
        let (_tmp, dir) = network_dir();
        write_harvest(&dir, "node-2", &record(NODE_KEY_2, "dd"));
        write_harvest(&dir, "node-1", &record(NODE_KEY_1, "cc"));

        let records = load_harvest_records(&dir).unwrap();
        assert_eq!(records.keys().collect::<Vec<_>>(), ["node-1", "node-2"]);
        assert_eq!(records["node-1"].node_public_key, NODE_KEY_1);
        assert_eq!(records["node-1"].document, record(NODE_KEY_1, "cc"));
    }

    #[test]
    fn an_empty_harvest_names_the_prerequisite() {
        let (_tmp, dir) = network_dir();
        let err = load_harvest_records(&dir).unwrap_err().to_string();
        assert!(err.contains("no harvest records"), "{err}");
        assert!(err.contains("seismic-tee network harvest"), "{err}");
    }

    #[test]
    fn a_record_with_a_bad_field_is_rejected_by_file() {
        let (_tmp, dir) = network_dir();
        let mut bad = record(NODE_KEY_1, "cc");
        bad["node_public_key"] = json!(NODE_KEY_1.to_uppercase());
        write_harvest(&dir, "node-1", &bad);
        let err = load_harvest_records(&dir).unwrap_err().to_string();
        assert!(err.contains("node-1.json"), "{err}");
        assert!(err.contains("node_public_key"), "{err}");

        let mut bad = record(NODE_KEY_1, "cc");
        bad.as_object_mut().unwrap().remove("evidence");
        write_harvest(&dir, "node-1", &bad);
        let err = load_harvest_records(&dir).unwrap_err().to_string();
        assert!(err.contains("no evidence object"), "{err}");
    }

    #[test]
    fn a_repeated_pubkey_is_not_a_distinct_founder_set() {
        let (_tmp, dir) = network_dir();
        write_harvest(&dir, "node-1", &record(NODE_KEY_1, "cc"));
        write_harvest(&dir, "node-2", &record(NODE_KEY_1, "dd"));
        let err = load_harvest_records(&dir).unwrap_err().to_string();
        assert!(err.contains("node-1 and node-2"), "{err}");
        assert!(err.contains("node_public_key"), "{err}");

        write_harvest(&dir, "node-2", &record(NODE_KEY_2, "cc"));
        let err = load_harvest_records(&dir).unwrap_err().to_string();
        assert!(err.contains("consensus_public_key"), "{err}");
    }

    #[test]
    fn the_descriptor_map_is_a_gate_naming_the_command_that_makes_it() {
        let (_tmp, dir) = network_dir();
        let err = load_descriptor_map(&dir).unwrap_err().to_string();
        assert!(err.contains("nodes/nodes.json"), "{err}");
        assert!(err.contains("pulumi stack output nodes --json"), "{err}");

        write(
            &dir,
            Path::new("nodes/nodes.json"),
            r#"{"node-1": {"public_ip": "203.0.113.7", "fqdn": "n1.example.com"}}"#,
        );
        assert_eq!(load_descriptor_map(&dir).unwrap().len(), 1);
    }

    #[test]
    fn the_founding_set_pairs_records_credentials_and_ips_in_name_order() {
        let (_tmp, dir) = network_dir();
        write_harvest(&dir, "node-2", &record(NODE_KEY_2, "dd"));
        write_harvest(&dir, "node-1", &record(NODE_KEY_1, "cc"));
        write(
            &dir,
            Path::new("inputs/founder-withdrawal-credentials.json"),
            &format!(r#"["0x{}", "0x{}"]"#, "01".repeat(20), "02".repeat(20)),
        );
        write(
            &dir,
            Path::new("nodes/nodes.json"),
            r#"{"node-1": {"public_ip": "203.0.113.7", "fqdn": "n1.example.com"},
                "node-2": {"public_ip": "203.0.113.8", "fqdn": "n2.example.com"}}"#,
        );

        let set = load_founding_set(&dir).unwrap();
        assert_eq!(set.validators.len(), 2);
        assert_eq!(set.validators[0].node_public_key, NODE_KEY_1);
        assert_eq!(set.validators[0].ip_address, "203.0.113.7:18551");
        assert_eq!(
            set.validators[0].withdrawal_credentials,
            format!("0x{}", "01".repeat(20))
        );
        assert_eq!(set.validators[1].node_public_key, NODE_KEY_2);
        assert_eq!(set.validators[1].ip_address, "203.0.113.8:18551");
        assert_eq!(set.records.len(), 2);
    }

    #[test]
    fn a_count_mismatch_and_a_box_gone_from_the_map_are_cohort_changes() {
        let (_tmp, dir) = network_dir();
        write_harvest(&dir, "node-1", &record(NODE_KEY_1, "cc"));
        write_harvest(&dir, "node-2", &record(NODE_KEY_2, "dd"));
        write(
            &dir,
            Path::new("inputs/founder-withdrawal-credentials.json"),
            &format!(r#"["0x{}"]"#, "01".repeat(20)),
        );
        let err = load_founding_set(&dir).unwrap_err().to_string();
        assert!(
            err.contains("1 withdrawal credential(s) but 2 box(es)"),
            "{err}"
        );
        assert!(err.contains("node-1, node-2"), "{err}");

        write(
            &dir,
            Path::new("inputs/founder-withdrawal-credentials.json"),
            &format!(r#"["0x{}", "0x{}"]"#, "01".repeat(20), "02".repeat(20)),
        );
        write(
            &dir,
            Path::new("nodes/nodes.json"),
            r#"{"node-1": {"public_ip": "203.0.113.7", "fqdn": "n1.example.com"}}"#,
        );
        let err = load_founding_set(&dir).unwrap_err().to_string();
        assert!(err.contains("has no node \"node-2\""), "{err}");
        assert!(err.contains("re-found"), "{err}");
    }
}
