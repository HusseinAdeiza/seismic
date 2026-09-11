//! `assemble`: derive the artifact set from a network directory's inputs.
//!
//! ```text
//! seismic-tee-network assemble tee/networks/devnet-3
//! ```
//!
//! The step that pins the founding validator set into `network_id`. It reads
//! the authored inputs and the harvest under `inputs/`, re-verifies every
//! archived founding quote offline against the collateral snapshot filed
//! beside it, compiles the measurement policy and injects the registry storage
//! into its copy of the reth genesis, completes the summit genesis with the
//! derived `eth_genesis_hash` and the founding validator set through summit's
//! own emitter, renders the manifest through the enclave's renderer, runs
//! every gate over the result, and writes the four artifacts at the
//! directory's top level. Everything top-level is hash-pinned by the manifest;
//! everything under `inputs/` is provenance.
//!
//! Each artifact is its input with derived fields filled in — never authored
//! twice. The summit genesis's `eth_genesis_hash` is derived from the reth
//! genesis, so whatever the input declares is replaced; the registry account's
//! storage is derived from the policy, so whatever the input holds is
//! replaced; the manifest itself is pure output. Edits go to the inputs, then
//! re-assemble. A manifest is immutable for the network's lifetime: an
//! existing one is never overwritten without `--force`.

use std::path::PathBuf;
use std::process::ExitCode;

use alloy_primitives::Address;
use anyhow::{Context as _, bail};
use clap::Args;
use seismic_manifest::{
    ContractsManifest, EthManifest, MeasurementsManifest, NetworkManifestV1, SummitManifest, render,
};
use seismic_measurement_admission::promote_measurements;
use seismic_tee_common::network_dir::INPUTS_DIRNAME;
use seismic_tee_common::{Artifact, Manifest, NetworkDir};
use seismic_verify_quote::{
    ArchivedSnapshot, HarvestCollateral, HarvestRecord, SeismicMeasurementPolicy, collateral,
    verify_harvest,
};
use sha2::{Digest as _, Sha256};

use crate::founding::{FoundingRecords, Validator, load_founding_set};
use crate::gates::{
    ArtifactSet, compile, hex_0x, inject_registry_genesis_storage, run_validation_gates,
};
use crate::init::{absolute, network_name};
use crate::shell_outs::{DerivationArgs, Derivations};

/// Genesis-alloc addresses of the admission-policy contracts, named by role as
/// in the manifest schema: registry = the measurement allowlist
/// (MeasurementRegistry.sol), authority = its mutation authority (today
/// MeasurementAuthorityDev.sol).
pub const DEFAULT_REGISTRY: &str = "0x1000000000000000000000000000000000000001";
pub const DEFAULT_AUTHORITY: &str = "0x1000000000000000000000000000000000000002";

/// The platform a policy promoted from the measurements input pins, unless
/// told otherwise.
pub const DEFAULT_ATTESTATION_TYPE: &str = "azure-tdx";

/// The artifact set as `assemble` derived it, before it is written.
#[derive(Debug, Clone)]
pub struct Assembled {
    /// The rendered manifest, strictly parsed back, with its network id.
    pub manifest: Manifest,
    /// The promoted policy, byte-verbatim: the manifest commits to its hash.
    pub policy: Vec<u8>,
    /// The input reth genesis with the compiled registry storage injected —
    /// what `eth.genesis_hash` was computed from.
    pub reth_genesis: Vec<u8>,
    /// The completed summit genesis, as summit emitted it — what
    /// `summit.genesis_config_digest` was computed from.
    pub summit_genesis: Vec<u8>,
    pub warnings: Vec<String>,
}

/// Everything `assemble` derives from.
#[derive(Debug, Clone)]
pub struct AssembleInputs<'a> {
    pub name: &'a str,
    /// The authored, policy-free reth genesis.
    pub reth_genesis: &'a Artifact,
    /// The authored summit parameters.
    pub summit_genesis: &'a Artifact,
    /// The promoted policy document.
    pub policy: &'a [u8],
    /// The founding set, paired and in node-name order.
    pub validators: &'a [Validator],
    pub registry: Address,
    pub authority: Address,
}

/// Set `eth_genesis_hash` in an authored summit genesis to the computed value.
///
/// The hash is derived from the reth genesis — never authored — but summit's
/// genesis parser requires the field to be present in the TOML it reads, so
/// the template fed to `summit genesis set-validators` must carry it. Any
/// declared value is dropped (it can only be stale copy-paste) and the
/// computed one is prepended — always valid TOML for a top-level key;
/// set-validators re-renders the completed file, which is what
/// `genesis_config_digest` commits to and the artifact set ships.
pub fn fill_eth_genesis_hash(
    authored: &[u8],
    eth_genesis_hash: [u8; 32],
) -> anyhow::Result<Vec<u8>> {
    let text = std::str::from_utf8(authored).context("summit genesis is not valid TOML")?;
    let mut kept = String::with_capacity(text.len() + 96);
    let mut in_table = false;
    for line in text.split_inclusive('\n') {
        let stripped = line.trim_start();
        // Top-level keys can only appear before the first table header; a
        // same-named key inside a table (none exists today) is left alone.
        if stripped.starts_with('[') {
            in_table = true;
        }
        let is_hash_line = !in_table
            && stripped
                .strip_prefix("eth_genesis_hash")
                .is_some_and(|rest| rest.trim_start().starts_with('='));
        if !is_hash_line {
            kept.push_str(line);
        }
    }
    let parsed: toml::Table = toml::from_str(&kept).context("summit genesis is not valid TOML")?;
    if parsed.contains_key("eth_genesis_hash") {
        bail!(
            "could not replace the authored file's declared eth_genesis_hash (unusual TOML \
             layout); delete the line by hand — the value is derived from the reth genesis"
        );
    }
    let mut out = format!("eth_genesis_hash = \"{}\"\n", hex_0x(&eth_genesis_hash));
    out.push_str(&kept);
    Ok(out.into_bytes())
}

/// Assemble, render, and gate-check a v1 network manifest and the artifacts
/// it pins.
pub async fn assemble(
    inputs: &AssembleInputs<'_>,
    derive: &impl Derivations,
) -> anyhow::Result<Assembled> {
    let genesis: serde_json::Value = serde_json::from_slice(inputs.reth_genesis.bytes())
        .with_context(|| format!("{} is not valid JSON", inputs.reth_genesis.path().display()))?;
    let chain_id = genesis.get("config").and_then(|c| c.get("chainId"));
    let Some(chain_id) = chain_id.and_then(serde_json::Value::as_u64) else {
        bail!(
            "reth genesis config.chainId is {}, not an int",
            chain_id.map_or_else(|| "absent".to_string(), ToString::to_string)
        );
    };

    let authored_text = std::str::from_utf8(inputs.summit_genesis.bytes()).with_context(|| {
        format!(
            "{} is not valid TOML",
            inputs.summit_genesis.path().display()
        )
    })?;
    let authored: toml::Table = toml::from_str(authored_text).with_context(|| {
        format!(
            "{} is not valid TOML",
            inputs.summit_genesis.path().display()
        )
    })?;
    let Some(namespace) = authored.get("namespace").and_then(toml::Value::as_str) else {
        bail!(
            "summit genesis has no namespace string (got {})",
            authored
                .get("namespace")
                .map_or_else(|| "nothing".to_string(), ToString::to_string)
        );
    };

    // The registry account's genesis storage is derived, not authored: the
    // policy document is compiled and its registry_genesis_storage injected
    // into the shipped genesis copy, so eth.genesis_hash commits to the
    // reviewed policy. The gates then re-validate the injected copy against
    // an independent compile of the same document.
    let report = compile(inputs.policy)?;
    let reth_genesis_bytes =
        inject_registry_genesis_storage(inputs.reth_genesis.bytes(), inputs.registry, &report)?;
    let eth_hash = derive.reth_genesis_hash(&reth_genesis_bytes).await?;
    if let Some(declared) = authored
        .get("eth_genesis_hash")
        .and_then(toml::Value::as_str)
        && declared.to_lowercase() != hex_0x(&eth_hash)
    {
        eprintln!(
            "replacing the authored eth_genesis_hash {declared} with the computed {} (the value \
             is derived from the reth genesis)",
            hex_0x(&eth_hash)
        );
    }

    if inputs.validators.is_empty() {
        bail!(
            "no founding validators — the validator set is pinned from the harvest, and a \
             founding with an empty set is not a network"
        );
    }
    // summit requires the field to *parse* a genesis (its Genesis type has no
    // serde default), and set-validators loads the template before replacing
    // whatever set it declares — so an input authored without one gets an
    // empty placeholder purely to make the template loadable. The shipped set
    // always comes from `validators`.
    let mut authored_bytes = inputs.summit_genesis.bytes().to_vec();
    if !authored.contains_key("validators") {
        let mut with_placeholder = b"validators = []\n".to_vec();
        with_placeholder.append(&mut authored_bytes);
        authored_bytes = with_placeholder;
    }
    let template = fill_eth_genesis_hash(&authored_bytes, eth_hash)?;
    let summit_genesis_bytes = derive
        .summit_set_validators(&template, inputs.validators)
        .await?;
    let config_digest = derive.summit_config_digest(&summit_genesis_bytes).await?;

    // Rendering belongs to the enclave's renderer: the values assembled here
    // go to it as the typed manifest and the canonical bytes come back, then
    // are strictly parsed back — so a bad manifest never leaves this command,
    // and the gates run over the same bytes that ship.
    let rendered = render(&NetworkManifestV1 {
        manifest_version: NetworkManifestV1::VERSION,
        name: inputs.name.to_string(),
        eth: EthManifest {
            chain_id,
            genesis_hash: eth_hash,
        },
        summit: SummitManifest {
            genesis_config_digest: config_digest,
            namespace: namespace.to_string(),
        },
        measurements: MeasurementsManifest {
            bootstrap_policy_hash: Sha256::digest(inputs.policy).into(),
            contracts: ContractsManifest {
                registry: inputs.registry.into_array(),
                authority: inputs.authority.into_array(),
            },
        },
    });
    let manifest =
        Manifest::from_json_bytes(rendered).context("the rendered manifest does not parse")?;

    let set = ArtifactSet {
        manifest,
        reth_genesis: Artifact::new(inputs.reth_genesis.path(), reth_genesis_bytes),
        summit_genesis: Artifact::new(inputs.summit_genesis.path(), summit_genesis_bytes),
        policy: Artifact::new("measurement-policy-bootstrap.json", inputs.policy),
    };
    let warnings = run_validation_gates(&set, derive).await?;
    let ArtifactSet {
        manifest,
        reth_genesis,
        summit_genesis,
        policy,
    } = set;
    Ok(Assembled {
        manifest,
        policy: policy.bytes().to_vec(),
        reth_genesis: reth_genesis.bytes().to_vec(),
        summit_genesis: summit_genesis.bytes().to_vec(),
        warnings,
    })
}

/// Write the network artifact set: manifest, policy, and assemble's copies of
/// the genesis artifacts the manifest commits to.
///
/// A manifest is immutable for the network's lifetime — refuse to overwrite
/// an existing one unless forced.
pub fn write_artifact_set(
    dir: &NetworkDir,
    assembled: &Assembled,
    force: bool,
) -> anyhow::Result<()> {
    let manifest_path = dir.manifest();
    if manifest_path.exists() && !force {
        let existing = std::fs::read(&manifest_path)
            .with_context(|| format!("reading {}", manifest_path.display()))?;
        bail!(
            "{} already exists (network_id {}); a manifest is immutable — pass --force only for a \
             new network",
            manifest_path.display(),
            hex_0x(&Sha256::digest(&existing)),
        );
    }
    std::fs::create_dir_all(dir.root())
        .with_context(|| format!("creating {}", dir.root().display()))?;
    for (path, bytes) in [
        (manifest_path, assembled.manifest.bytes()),
        (dir.policy(), assembled.policy.as_slice()),
        (dir.reth_genesis(), assembled.reth_genesis.as_slice()),
        (dir.summit_genesis(), assembled.summit_genesis.as_slice()),
    ] {
        std::fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
        eprintln!("wrote {}", path.display());
    }
    Ok(())
}

/// Re-verify every archived founding record against `policy`, offline, at
/// the instant its own collateral snapshot was held to.
///
/// The harvest verified these records when it collected them, but nothing
/// downstream trusts that run's verdict: assemble is the step that pins the
/// validator set into `network_id`, so it hands each archived record back to
/// the verifier before pinning anything, and `verify-harvest` runs the same
/// function over the committed directory for as long as it exists (the
/// records are plain files that may have been copied, committed, and edited
/// since the harvest).
///
/// Each record is checked against the snapshot archived beside it, so this
/// gate behaves the same on the founding day and four hundred days later. A
/// record with no snapshot fails: Intel's live collateral would answer for it
/// today and stop answering in about a month, which would make the verdict
/// depend on when it ran. Fails on the first record that does not verify,
/// naming it; one line per verified record on stderr.
pub async fn verify_harvest_records(
    dir: &NetworkDir,
    records: &FoundingRecords,
    policy: &[u8],
) -> anyhow::Result<()> {
    // Replaying a snapshot parses Intel's material, whose TLS-bearing types
    // want a rustls process default; see `tools verify` for why one has to
    // be chosen. Idempotent: a second install is a no-op error.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Fail closed: there is no accept-any path, so an unparseable policy must
    // stop the run rather than widen it.
    let policy = SeismicMeasurementPolicy::from_json_bytes(policy)
        .context("loading the measurement policy")?;
    for (name, record) in records {
        let collateral_path = dir.collateral_record(name);
        if !collateral_path.is_file() {
            bail!(
                "{name}: no DCAP collateral archived at {} — the founding quote can only be \
                 re-verified against the collateral its own harvest used, so this cohort has to be \
                 re-harvested (or re-founded) rather than assembled around",
                collateral_path.display()
            );
        }
        let verdict = async {
            let document = std::fs::read_to_string(&collateral_path)
                .with_context(|| format!("reading {}", collateral_path.display()))?;
            let archived: ArchivedSnapshot = collateral::parse(&document).with_context(|| {
                format!("{} is not an archived snapshot", collateral_path.display())
            })?;
            let record: HarvestRecord = serde_json::from_value(record.document.clone())
                .with_context(|| {
                    format!(
                        "{} is not a harvest record",
                        dir.harvest_record(name).display()
                    )
                })?;
            verify_harvest(
                record,
                policy.clone(),
                HarvestCollateral::Archived(Box::new(archived)),
            )
            .await
        }
        .await;
        if let Err(error) = verdict {
            bail!(
                "{name}: {error:?}\nA founding key whose archived quote does not verify must not \
                 be pinned — re-found (or re-harvest an unchanged cohort) rather than assembling \
                 around it"
            );
        }
        eprintln!("{name}: archived founding quote verified");
    }
    Ok(())
}

#[derive(Debug, Args)]
pub struct AssembleArgs {
    /// Network directory from `init`: reads its inputs/ (reth-genesis.json,
    /// summit-genesis.toml, measurements.json, the founder credentials and
    /// the harvest), takes the network name from its basename, and writes the
    /// artifact set at the top level.
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,

    /// Platform the policy promoted from inputs/measurements.json pins.
    #[arg(long, value_name = "TYPE", default_value = DEFAULT_ATTESTATION_TYPE)]
    pub attestation_type: String,

    /// Measurement-registry contract address in the genesis alloc.
    #[arg(long, value_name = "ADDRESS", default_value = DEFAULT_REGISTRY)]
    pub registry: Address,

    /// Registry mutation-authority contract address.
    #[arg(long, value_name = "ADDRESS", default_value = DEFAULT_AUTHORITY)]
    pub authority: Address,

    /// Overwrite an existing manifest (a new network identity).
    #[arg(long)]
    pub force: bool,

    #[command(flatten)]
    pub derivations: DerivationArgs,
}

pub async fn run(args: AssembleArgs) -> anyhow::Result<ExitCode> {
    let root = absolute(&args.dir)?;
    let name = network_name(&root)?;
    let dir = NetworkDir::new(&root);

    let inputs = [
        dir.input_reth_genesis(),
        dir.input_summit_genesis(),
        dir.input_measurements(),
    ];
    let missing: Vec<String> = inputs
        .iter()
        .filter(|p| !p.exists())
        .map(|p| p.display().to_string())
        .collect();
    if !missing.is_empty() {
        bail!(
            "missing authored input(s): {} — authored inputs live under {INPUTS_DIRNAME}/; \
             scaffold them with `init`",
            missing.join(", ")
        );
    }
    let [reth_genesis, summit_genesis, measurements] = inputs;

    let founding = load_founding_set(&dir)?;
    eprintln!(
        "founding set: {} validator(s) from {}",
        founding.validators.len(),
        dir.harvest().display()
    );
    let raw = std::fs::read(&measurements)
        .with_context(|| format!("reading {}", measurements.display()))?;
    let policy = promote_measurements(&raw, None, Some(&args.attestation_type))
        .with_context(|| format!("{}", measurements.display()))?;

    // The offline replay gate — the same function `verify-harvest` runs over
    // the committed directory afterwards.
    verify_harvest_records(&dir, &founding.records, &policy).await?;

    let assembled = assemble(
        &AssembleInputs {
            name: &name,
            reth_genesis: &Artifact::read(&reth_genesis)?,
            summit_genesis: &Artifact::read(&summit_genesis)?,
            policy: &policy,
            validators: &founding.validators,
            registry: args.registry,
            authority: args.authority,
        },
        &args.derivations.shell_outs(),
    )
    .await?;
    for warning in &assembled.warnings {
        eprintln!("warning: {warning}");
    }
    write_artifact_set(&dir, &assembled, args.force)?;
    println!("network_id: {}", assembled.manifest.network_id());
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::Path;

    use seismic_tee_common::network_dir::MANIFEST_FILENAME;
    use seismic_tee_common::test_support::write_file;

    use super::*;
    use crate::gates::tests::{EXAMPLE_POLICY, EXAMPLE_RETH_GENESIS, REGISTRY, other_policy};

    pub(crate) const AUTHORITY: Address =
        alloy_primitives::address!("0x1000000000000000000000000000000000000002");

    /// A founding validator entry as `load_founding_set` builds it.
    pub(crate) fn validator() -> Validator {
        Validator {
            node_public_key: "ab".repeat(32),
            consensus_public_key: "cd".repeat(48),
            ip_address: "203.0.113.7:18551".into(),
            withdrawal_credentials: format!("0x{}", "f3".repeat(20)),
        }
    }

    /// Stand-ins for the two binaries: a fixed genesis hash, a content-derived
    /// digest (a byte hash, not summit's SSZ digest, so tamper-detection gates
    /// still fire), and a line-level splice for set-validators (not a
    /// re-render, so byte-oriented assertions about the rest of the template
    /// stay meaningful).
    pub(crate) struct Fake {
        pub eth_hash: [u8; 32],
        /// A fixed digest instead of the content-derived one: lets a test
        /// reach the gates *behind* the digest gate with a tampered file.
        pub digest: Option<[u8; 32]>,
    }

    impl Default for Fake {
        fn default() -> Self {
            Self {
                eth_hash: [0x12; 32],
                digest: None,
            }
        }
    }

    impl Derivations for Fake {
        async fn reth_genesis_hash(&self, _genesis: &[u8]) -> anyhow::Result<[u8; 32]> {
            Ok(self.eth_hash)
        }

        async fn summit_config_digest(&self, genesis: &[u8]) -> anyhow::Result<[u8; 32]> {
            Ok(self
                .digest
                .unwrap_or_else(|| Sha256::digest(genesis).into()))
        }

        async fn summit_set_validators(
            &self,
            template: &[u8],
            validators: &[Validator],
        ) -> anyhow::Result<Vec<u8>> {
            let mut sorted = validators.to_vec();
            sorted.sort_by(|a, b| a.node_public_key.cmp(&b.node_public_key));
            let entries: Vec<String> = sorted
                .iter()
                .map(|v| {
                    format!(
                        "{{ consensus_public_key = {:?}, ip_address = {:?}, node_public_key = {:?}, \
                         withdrawal_credentials = {:?} }}",
                        v.consensus_public_key,
                        v.ip_address,
                        v.node_public_key,
                        v.withdrawal_credentials
                    )
                })
                .collect();
            let text = String::from_utf8(template.to_vec()).unwrap();
            assert!(
                text.contains("validators = []\n"),
                "the template carries the placeholder set"
            );
            Ok(text
                .replacen(
                    "validators = []\n",
                    &format!("validators = [{}]\n", entries.join(", ")),
                    1,
                )
                .into_bytes())
        }
    }

    /// An authored artifact set in a temp dir: the example network's reth
    /// genesis (its registry predeploy is the canonical runtime) and a
    /// minimal summit genesis with no eth_genesis_hash (assemble fills it).
    pub(crate) struct Authored {
        pub dir: tempfile::TempDir,
        pub reth_genesis: PathBuf,
        pub summit_genesis: PathBuf,
    }

    pub(crate) fn authored() -> Authored {
        let dir = tempfile::tempdir().unwrap();
        let reth_genesis = write_file(&dir, "reth-genesis.json", EXAMPLE_RETH_GENESIS);
        let summit_genesis =
            write_file(&dir, "summit-genesis.toml", b"namespace = \"testnet-1\"\n");
        Authored {
            dir,
            reth_genesis,
            summit_genesis,
        }
    }

    pub(crate) async fn assemble_with(
        authored: &Authored,
        policy: &[u8],
        fake: &Fake,
    ) -> anyhow::Result<Assembled> {
        assemble(
            &AssembleInputs {
                name: "testnet-1",
                reth_genesis: &Artifact::read(&authored.reth_genesis).unwrap(),
                summit_genesis: &Artifact::read(&authored.summit_genesis).unwrap(),
                policy,
                validators: &[validator()],
                registry: REGISTRY,
                authority: AUTHORITY,
            },
            fake,
        )
        .await
    }

    #[tokio::test]
    async fn assemble_passes_its_own_gates_and_is_deterministic() {
        let authored = authored();
        let first = assemble_with(&authored, EXAMPLE_POLICY, &Fake::default())
            .await
            .unwrap();
        let second = assemble_with(&authored, EXAMPLE_POLICY, &Fake::default())
            .await
            .unwrap();
        assert_eq!(first.manifest.bytes(), second.manifest.bytes());
        assert_eq!(first.manifest.network_id(), second.manifest.network_id());
        assert!(first.warnings.is_empty(), "{:?}", first.warnings);

        // The manifest carries the derived values.
        assert_eq!(first.manifest.name, "testnet-1");
        assert_eq!(first.manifest.eth.chain_id, 5124);
        assert_eq!(first.manifest.eth.genesis_hash, [0x12; 32]);
        assert_eq!(first.manifest.summit.namespace, "testnet-1");
        assert_eq!(
            first.manifest.measurements.bootstrap_policy_hash,
            <[u8; 32]>::from(Sha256::digest(EXAMPLE_POLICY))
        );
        assert_eq!(
            first.manifest.measurements.contracts.registry,
            REGISTRY.into_array()
        );
        assert_eq!(first.policy, EXAMPLE_POLICY);
    }

    /// The registry storage is injected into assemble's genesis copy from the
    /// policy's compile, and eth.genesis_hash is computed over that copy —
    /// so the hash commits to the reviewed policy.
    #[tokio::test]
    async fn assemble_injects_the_registry_storage_it_pins() {
        let authored = authored();
        let policy = other_policy();
        let assembled = assemble_with(&authored, &policy, &Fake::default())
            .await
            .unwrap();
        let genesis: serde_json::Value = serde_json::from_slice(&assembled.reth_genesis).unwrap();
        let storage = genesis["alloc"][&hex_0x(REGISTRY.as_slice())]["storage"]
            .as_object()
            .unwrap();
        let report = compile(&policy).unwrap();
        assert_eq!(storage.len(), report.registry_genesis_storage.len());
        // The example's committed storage was compiled from another policy,
        // and was replaced wholesale.
        let example: serde_json::Value = serde_json::from_slice(EXAMPLE_RETH_GENESIS).unwrap();
        assert_ne!(
            genesis["alloc"][&hex_0x(REGISTRY.as_slice())]["storage"],
            example["alloc"][&hex_0x(REGISTRY.as_slice())]["storage"]
        );
    }

    /// The summit genesis is completed: the derived hash first, then the
    /// founding set through summit's emitter; a declared hash is replaced.
    #[tokio::test]
    async fn assemble_completes_the_summit_genesis() {
        let authored = authored();
        std::fs::write(
            &authored.summit_genesis,
            format!(
                "eth_genesis_hash = \"0x{}\"\nnamespace = \"testnet-1\"\nleader_timeout_ms = 2000\n",
                "de".repeat(32)
            ),
        )
        .unwrap();
        let assembled = assemble_with(&authored, EXAMPLE_POLICY, &Fake::default())
            .await
            .unwrap();
        let text = String::from_utf8(assembled.summit_genesis.clone()).unwrap();
        assert!(
            text.starts_with(&format!("eth_genesis_hash = \"0x{}\"\n", "12".repeat(32))),
            "{text}"
        );
        assert!(!text.contains(&"de".repeat(32)), "{text}");
        let parsed: toml::Table = toml::from_str(&text).unwrap();
        let validators = parsed["validators"].as_array().unwrap();
        assert_eq!(validators.len(), 1);
        assert_eq!(
            validators[0]["node_public_key"].as_str(),
            Some("ab".repeat(32).as_str())
        );
        assert_eq!(parsed["leader_timeout_ms"].as_integer(), Some(2000));
        // The digest commits to the emitted genesis.
        assert_eq!(
            assembled.manifest.summit.genesis_config_digest,
            <[u8; 32]>::from(Sha256::digest(&assembled.summit_genesis))
        );
    }

    #[tokio::test]
    async fn assemble_rejects_an_empty_validator_set() {
        let authored = authored();
        let err = assemble(
            &AssembleInputs {
                name: "testnet-1",
                reth_genesis: &Artifact::read(&authored.reth_genesis).unwrap(),
                summit_genesis: &Artifact::read(&authored.summit_genesis).unwrap(),
                policy: EXAMPLE_POLICY,
                validators: &[],
                registry: REGISTRY,
                authority: AUTHORITY,
            },
            &Fake::default(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("no founding validators"), "{err}");
    }

    #[tokio::test]
    async fn assemble_warns_on_the_default_summit_namespace() {
        let authored = authored();
        std::fs::write(&authored.summit_genesis, "namespace = \"_SUMMIT\"\n").unwrap();
        let assembled = assemble_with(&authored, EXAMPLE_POLICY, &Fake::default())
            .await
            .unwrap();
        assert!(
            assembled.warnings.iter().any(|w| w.contains("_SUMMIT")),
            "{:?}",
            assembled.warnings
        );
    }

    #[tokio::test]
    async fn assemble_needs_a_chain_id_and_a_namespace() {
        let string_chain_id = authored();
        std::fs::write(
            &string_chain_id.reth_genesis,
            r#"{"config": {"chainId": "5124"}, "alloc": {}}"#,
        )
        .unwrap();
        let err = assemble_with(&string_chain_id, EXAMPLE_POLICY, &Fake::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("chainId"), "{err}");

        let no_namespace = authored();
        std::fs::write(&no_namespace.summit_genesis, "leader_timeout_ms = 2000\n").unwrap();
        let err = assemble_with(&no_namespace, EXAMPLE_POLICY, &Fake::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no namespace string"), "{err}");
    }

    /// The `eth_genesis_hash` line is replaced only at the top level; a
    /// same-named key inside a table is left alone.
    #[test]
    fn fill_eth_genesis_hash_replaces_the_top_level_key_only() {
        let filled = fill_eth_genesis_hash(
            b"eth_genesis_hash = \"0xdead\"\nnamespace = \"n\"\n[extra]\neth_genesis_hash = \"0xdead\"\n",
            [0x12; 32],
        )
        .unwrap();
        let text = String::from_utf8(filled).unwrap();
        assert_eq!(
            text,
            format!(
                "eth_genesis_hash = \"0x{}\"\nnamespace = \"n\"\n[extra]\neth_genesis_hash = \"0xdead\"\n",
                "12".repeat(32)
            )
        );

        // A layout the line scan cannot rewrite fails rather than shipping a
        // stale hash.
        let err = fill_eth_genesis_hash(b"\"eth_genesis_hash\" = \"0xdead\"\n", [0x12; 32])
            .unwrap_err()
            .to_string();
        assert!(err.contains("delete the line by hand"), "{err}");
    }

    /// The artifact set lands at the directory's top level; the manifest is
    /// immutable without --force; the written bytes are the assembled ones.
    #[tokio::test]
    async fn write_artifact_set_refuses_to_overwrite_a_manifest() {
        let authored = authored();
        let assembled = assemble_with(&authored, EXAMPLE_POLICY, &Fake::default())
            .await
            .unwrap();
        let out = NetworkDir::new(authored.dir.path().join("out"));
        write_artifact_set(&out, &assembled, false).unwrap();
        for path in [
            out.manifest(),
            out.policy(),
            out.reth_genesis(),
            out.summit_genesis(),
        ] {
            assert!(path.is_file(), "{}", path.display());
        }
        assert_eq!(
            std::fs::read(out.manifest()).unwrap(),
            assembled.manifest.bytes()
        );
        assert_eq!(
            std::fs::read(out.reth_genesis()).unwrap(),
            assembled.reth_genesis
        );
        assert_eq!(
            std::fs::read(out.summit_genesis()).unwrap(),
            assembled.summit_genesis
        );
        // Round-trip: the written bytes hash back to the same network_id.
        assert_eq!(
            Manifest::load(&out.manifest()).unwrap().network_id(),
            assembled.manifest.network_id()
        );

        let err = write_artifact_set(&out, &assembled, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("immutable"), "{err}");
        assert!(err.contains(MANIFEST_FILENAME), "{err}");
        write_artifact_set(&out, &assembled, true).unwrap();
    }

    /// The `init` → `assemble` loop: authored inputs under inputs/, the
    /// derived artifact set at the top level, the inputs untouched.
    #[tokio::test]
    async fn init_then_assemble_share_a_directory() {
        let authored = authored();
        let net = NetworkDir::new(authored.dir.path().join("networks").join("testnet-1"));
        let raw = write_file(
            &authored.dir,
            "raw-measurements.json",
            br#"{"measurement_id": "img.vhd", "measurements": {"4": {"expected": "ab"}}}"#,
        );
        crate::init::init_network_dir(
            &crate::init::fetch_client().unwrap(),
            &net,
            &crate::init::InitInputs {
                name: "testnet-1",
                reth_genesis: authored.reth_genesis.to_str().unwrap(),
                measurements: raw.to_str().unwrap(),
                summit_genesis: authored.summit_genesis.to_str().unwrap(),
                founders: 1,
            },
            false,
        )
        .await
        .unwrap();
        let authored_summit = std::fs::read(net.input_summit_genesis()).unwrap();

        let assembled = assemble(
            &AssembleInputs {
                name: "testnet-1",
                reth_genesis: &Artifact::read(&net.input_reth_genesis()).unwrap(),
                summit_genesis: &Artifact::read(&net.input_summit_genesis()).unwrap(),
                policy: EXAMPLE_POLICY,
                validators: &[validator()],
                registry: REGISTRY,
                authority: AUTHORITY,
            },
            &Fake::default(),
        )
        .await
        .unwrap();
        write_artifact_set(&net, &assembled, false).unwrap();

        assert_eq!(
            std::fs::read(net.input_summit_genesis()).unwrap(),
            authored_summit
        );
        assert_eq!(
            std::fs::read(net.input_reth_genesis()).unwrap(),
            EXAMPLE_RETH_GENESIS
        );
        assert_eq!(
            std::fs::read(net.summit_genesis()).unwrap(),
            assembled.summit_genesis
        );
        assert_eq!(
            std::fs::read(net.reth_genesis()).unwrap(),
            assembled.reth_genesis
        );
        assert_ne!(net.reth_genesis(), net.input_reth_genesis());
    }

    /// Re-verification is offline and per record: a record with no snapshot
    /// beside it fails closed, before any verifier runs; a snapshot that is
    /// not one is named.
    #[tokio::test]
    async fn harvest_records_need_their_archived_collateral() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = NetworkDir::new(tmp.path());
        let mut records = FoundingRecords::new();
        records.insert(
            "node-1".to_string(),
            crate::founding::FoundingRecord {
                node_public_key: "ab".repeat(32),
                consensus_public_key: "cd".repeat(48),
                document: serde_json::json!({
                    "harvest_nonce": "11".repeat(32),
                    "node_public_key": "ab".repeat(32),
                    "consensus_public_key": "cd".repeat(48),
                    "evidence": {"attestation_type": "none", "attestation": []},
                }),
            },
        );
        let err = verify_harvest_records(&dir, &records, EXAMPLE_POLICY)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("node-1: no DCAP collateral archived"), "{err}");
        assert!(err.contains("re-harvested"), "{err}");

        std::fs::create_dir_all(dir.collateral()).unwrap();
        std::fs::write(dir.collateral_record("node-1"), "{ not a snapshot").unwrap();
        let err = verify_harvest_records(&dir, &records, EXAMPLE_POLICY)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("node-1:"), "{err}");
        assert!(err.contains("is not an archived snapshot"), "{err}");
        assert!(err.contains("must not be pinned"), "{err}");

        // Fail closed on the policy, before any record is looked at.
        let err = verify_harvest_records(&dir, &records, b"{ not a policy")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("measurement policy"), "{err}");
    }

    #[test]
    fn the_addresses_parse_from_the_flags() {
        let args = AssembleArgs::try_parse_from_probe(&["assemble", "/nets/x"]);
        assert_eq!(args.registry, REGISTRY);
        assert_eq!(args.authority, AUTHORITY);
        assert_eq!(args.attestation_type, DEFAULT_ATTESTATION_TYPE);
        assert!(!args.force);
        assert_eq!(args.derivations.reth_bin, "seismic-reth");
        assert_eq!(args.dir, Path::new("/nets/x"));
    }

    impl AssembleArgs {
        fn try_parse_from_probe(argv: &[&str]) -> Self {
            use clap::Parser as _;
            #[derive(clap::Parser)]
            struct Probe {
                #[command(flatten)]
                args: AssembleArgs,
            }
            Probe::try_parse_from(argv).expect("well-formed argv").args
        }
    }
}
