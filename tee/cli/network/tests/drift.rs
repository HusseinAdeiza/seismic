//! Cross-repo drift guards (run via `make -C tee/cli drift`, or the
//! repo-root `make test-drift`).
//!
//! These check this repo against the current state of its sibling repos,
//! reached either by fetching a pinned artifact over HTTP or by running a
//! binary built from a sibling branch. Every test needing something outside
//! this workspace belongs here, so `make test` stays hermetic with nothing to
//! skip and every test runs in exactly one CI job. CI runs this module as its
//! own non-required job, where a failure names the exact cross-repo check.
//!
//! `#[ignore]` marks the whole file: the default `cargo nextest run` skips it,
//! and the drift target runs it with `--run-ignored only`. The suite never
//! skips *within* itself — a missing prerequisite is a failure, because a
//! guard that quietly passes when its tooling is missing is how a committed
//! artifact goes stale unnoticed. It needs:
//!
//! - network reach to raw.githubusercontent.com (the cross-repo tests fetch
//!   pinned artifacts from sibling repos);
//! - `seismic-reth` on PATH, for the `genesis-hash` subcommand (CI installs a
//!   prebuilt release with the setup-sreth action).
//!
//! The enclave crates under test — the admission compiler, the manifest
//! renderer and schema — are linked at the rev the workspace pins, so moving
//! them is a deploy PR that bumps the pin, not something CI discovers.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use alloy_primitives::keccak256;
use seismic_manifest::render;
use seismic_measurement_admission::genesis::REGISTRY_RUNTIME_CODE_HASH;
use seismic_tee_common::NetworkDir;
use seismic_tee_common::network_dir::MANIFEST_FILENAME;
use seismic_tee_network::founding::Validator;
use seismic_tee_network::gates::{ArtifactSet, run_validation_gates};
use seismic_tee_network::shell_outs::{Derivations, ShellOuts};

/// The deploy repo root: this file is `tee/cli/network/tests/drift.rs`.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("network/ sits three levels under the repo root")
        .to_path_buf()
}

fn networks_dir() -> PathBuf {
    repo_root().join("tee").join("networks")
}

/// Fetch a cross-repo artifact, failing the calling test if it can't.
///
/// An HTTP 4xx/5xx means the artifact moved or the ref is gone — a real drift
/// signal, not flaky network — so it fails at once. A transport-level failure
/// is retried once, then fails: this suite never skips.
async fn fetch_live(url: &str) -> Vec<u8> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let mut last = None;
    for _ in 0..2 {
        match client.get(url).send().await {
            Ok(response) => {
                let response = response
                    .error_for_status()
                    .unwrap_or_else(|e| panic!("cross-repo artifact gone: {e}"));
                match response.bytes().await {
                    Ok(bytes) => return bytes.to_vec(),
                    Err(e) => last = Some(e),
                }
            }
            Err(e) => last = Some(e),
        }
    }
    panic!("cross-repo artifact unreachable after retry: {last:?}");
}

/// Network directories git tracks.
///
/// A real deployment writes its network directory here too, so enumerating
/// the filesystem would validate whichever devnet the developer last founded.
/// Only the committed ones are this repo's to keep passing.
fn committed_network_dirs() -> Vec<NetworkDir> {
    let listed = std::process::Command::new("git")
        .args(["ls-files", "-z", "--"])
        .arg(networks_dir())
        .current_dir(repo_root())
        .output()
        .expect("git ls-files");
    assert!(listed.status.success(), "git ls-files failed");
    let dirs: BTreeSet<PathBuf> = String::from_utf8_lossy(&listed.stdout)
        .split('\0')
        .filter(|path| path.ends_with(&format!("/{MANIFEST_FILENAME}")))
        .map(|path| repo_root().join(path).parent().unwrap().to_path_buf())
        .collect();
    assert!(
        !dirs.is_empty(),
        "no committed network directory under {}",
        networks_dir().display()
    );
    dirs.into_iter().map(NetworkDir::new).collect()
}

/// The registry runtime-code pin. The admission crate pins keccak256 of the
/// canonical MeasurementRegistry deployed bytecode; the gates enforce that pin
/// against the genesis alloc, so a stale pin already fails assembly loudly.
/// This is the early warning: the crate's pin must match the artifact the reth
/// genesis builder installs.
#[tokio::test]
#[ignore = "cross-repo: fetches the seismic repo's contract artifact"]
async fn admission_crate_pins_current_registry_runtime() {
    const URL: &str = "https://raw.githubusercontent.com/SeismicSystems/seismic/main/\
                       contracts/artifacts/MeasurementRegistry.json";
    let artifact: serde_json::Value = serde_json::from_slice(&fetch_live(URL).await).unwrap();
    let runtime = artifact["deployedBytecode"]["object"]
        .as_str()
        .expect("deployedBytecode.object");
    let runtime = hex::decode(runtime.strip_prefix("0x").unwrap_or(runtime)).unwrap();
    assert_eq!(keccak256(&runtime), REGISTRY_RUNTIME_CODE_HASH);
}

/// The committed starter summit genesis tracks summit's parameter set.
///
/// `tee/networks/summit-genesis-starter.toml` carries every founder-reviewable
/// summit genesis parameter, explicitly — defaults included, so the founder
/// reviews each one. Summit owns the schema, and its `example_genesis.toml` is
/// a complete rendering of it, so a parameter summit adds or renames shows up
/// as a key-set mismatch here. Values are not compared: each is a per-network
/// choice.
#[tokio::test]
#[ignore = "cross-repo: fetches summit's example genesis"]
async fn starter_carries_summits_parameter_set() {
    const URL: &str =
        "https://raw.githubusercontent.com/SeismicSystems/summit/main/example_genesis.toml";
    // Not parameters: the two fields assemble derives per network.
    let derived: BTreeSet<&str> = ["eth_genesis_hash", "validators"].into();

    let example: toml::Table =
        toml::from_str(std::str::from_utf8(&fetch_live(URL).await).unwrap()).unwrap();
    let starter: toml::Table = toml::from_str(
        &std::fs::read_to_string(networks_dir().join("summit-genesis-starter.toml")).unwrap(),
    )
    .unwrap();
    let starter_keys: BTreeSet<&str> = starter.keys().map(String::as_str).collect();
    let example_keys: BTreeSet<&str> = example.keys().map(String::as_str).collect();
    assert!(starter_keys.is_disjoint(&derived), "{starter_keys:?}");
    assert_eq!(&starter_keys | &derived, example_keys);
    // The namespace slot ships empty: the visible fill-me init replaces with
    // the network name (unique per network — replay domain).
    assert_eq!(starter["namespace"].as_str(), Some(""));
}

/// A committed network directory's manifest is exactly what the renderer
/// renders from its own values: a rendering change would re-found every
/// existing network on its next assemble.
#[test]
#[ignore = "cross-repo: the committed network directories against the pinned renderer"]
fn committed_manifests_are_the_renderers_bytes() {
    for dir in committed_network_dirs() {
        let committed = std::fs::read(dir.manifest()).unwrap();
        let parsed = seismic_manifest::NetworkManifestV1::from_json_bytes(&committed).unwrap();
        assert_eq!(
            render(&parsed),
            committed,
            "{} is not its own rendering",
            dir.manifest().display()
        );
    }
}

/// The real `seismic-reth genesis-hash`, with the committed digest fed back
/// in for summit's half: summit publishes no release binary.
struct RethOnly {
    reth: ShellOuts,
    committed_digest: [u8; 32],
}

impl Derivations for RethOnly {
    async fn reth_genesis_hash(&self, genesis: &[u8]) -> anyhow::Result<[u8; 32]> {
        self.reth.reth_genesis_hash(genesis).await
    }

    async fn summit_config_digest(&self, _genesis: &[u8]) -> anyhow::Result<[u8; 32]> {
        Ok(self.committed_digest)
    }

    async fn summit_set_validators(
        &self,
        _template: &[u8],
        _validators: &[Validator],
    ) -> anyhow::Result<Vec<u8>> {
        unreachable!("validation never emits a genesis")
    }
}

/// Committed network directories still pass their own gates.
///
/// `tee/networks/example-devnet/` is the documented example of the
/// network-directory shape, and the hermetic suite builds its own artifacts,
/// so nothing else reads it. Re-running the real gates over it keeps the
/// example honest, and turns a semantic change in the admission compiler or in
/// reth's genesis-header encoding into a failure here rather than a surprise
/// at the next `assemble`.
///
/// One gate does not recompute here: `summit genesis digest` needs a summit
/// build, and summit publishes no release binary, so this test feeds the
/// committed digest back in. Every other gate — genesis hash, chain id, policy
/// hash, contract accounts, and the exact registry-account storage — runs
/// against the real artifacts.
#[tokio::test]
#[ignore = "cross-repo: needs seismic-reth on PATH"]
async fn committed_network_dirs_pass_their_gates() {
    for dir in committed_network_dirs() {
        let set = ArtifactSet::load(&dir).unwrap();
        let derive = RethOnly {
            reth: ShellOuts::default(),
            committed_digest: set.manifest.summit.genesis_config_digest,
        };
        let warnings = run_validation_gates(&set, &derive)
            .await
            .unwrap_or_else(|e| panic!("{}: {e:?}", dir.root().display()));
        assert!(
            warnings.is_empty(),
            "{}: {warnings:?}",
            dir.root().display()
        );
    }
}
