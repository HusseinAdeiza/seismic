//! `validate`: re-run all gates over an assembled network directory.
//!
//! ```text
//! seismic-tee network validate tee/networks/devnet-3
//! ```
//!
//! Audits the artifact set `assemble` wrote there — manifest, injected reth
//! genesis, completed summit genesis, policy — against each other, with the
//! same derivations (`seismic-reth genesis-hash`, `summit genesis digest`, the
//! linked admission compiler) `assemble` used. Read-only and re-runnable: the
//! check to run after a merge, before a founding, or whenever an artifact set
//! is suspected of having drifted from its inputs.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use seismic_tee_common::NetworkDir;

use crate::gates::{ArtifactSet, run_validation_gates};
use crate::init::absolute;
use crate::shell_outs::DerivationArgs;

#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// Network directory: audits the artifact set `assemble` wrote there
    /// (manifest, summit genesis, policy) against its reth genesis.
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,

    #[command(flatten)]
    pub derivations: DerivationArgs,
}

pub async fn run(args: ValidateArgs) -> anyhow::Result<ExitCode> {
    let dir = NetworkDir::new(absolute(&args.dir)?);
    let set = ArtifactSet::load(&dir)?;
    let warnings = run_validation_gates(&set, &args.derivations.shell_outs()).await?;
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }
    println!("network_id: {}", set.manifest.network_id());
    eprintln!("all validation gates passed");
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use seismic_tee_common::network_dir::MANIFEST_FILENAME;
    use serde_json::json;

    use super::*;
    use crate::assemble::tests::{Fake, assemble_with, authored};
    use crate::assemble::write_artifact_set;
    use crate::gates::hex_0x;
    use crate::gates::tests::{EXAMPLE_POLICY, REGISTRY, other_policy};

    /// An assembled network directory on disk, ready to be tampered with.
    async fn assembled_dir() -> (tempfile::TempDir, NetworkDir) {
        let authored = authored();
        let assembled = assemble_with(&authored, EXAMPLE_POLICY, &Fake::default())
            .await
            .unwrap();
        let dir = NetworkDir::new(authored.dir.path().join("net"));
        write_artifact_set(&dir, &assembled, false).unwrap();
        (authored.dir, dir)
    }

    async fn validate(dir: &NetworkDir) -> anyhow::Result<Vec<String>> {
        run_validation_gates(&ArtifactSet::load(dir).unwrap(), &Fake::default()).await
    }

    fn failure(result: anyhow::Result<Vec<String>>) -> String {
        format!("{:?}", result.unwrap_err())
    }

    fn edit_genesis(dir: &NetworkDir, edit: impl FnOnce(&mut serde_json::Value)) {
        let mut genesis: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.reth_genesis()).unwrap()).unwrap();
        edit(&mut genesis);
        std::fs::write(dir.reth_genesis(), genesis.to_string()).unwrap();
    }

    #[tokio::test]
    async fn an_assembled_directory_passes_and_a_missing_one_is_named() {
        let (_tmp, dir) = assembled_dir().await;
        assert!(validate(&dir).await.unwrap().is_empty());

        let err = ArtifactSet::load(&NetworkDir::new(_tmp.path().join("absent")))
            .unwrap_err()
            .to_string();
        assert!(err.contains(MANIFEST_FILENAME), "{err}");
        assert!(err.contains("seismic-tee network assemble"), "{err}");
    }

    /// Every pin is re-derived: a genesis hash, a digest, a policy hash or a
    /// summit field that disagrees with the manifest fails by name.
    #[tokio::test]
    async fn each_pin_is_a_gate() {
        let (_tmp, dir) = assembled_dir().await;

        let err = failure(
            run_validation_gates(
                &ArtifactSet::load(&dir).unwrap(),
                &Fake {
                    eth_hash: [0x34; 32],
                    digest: None,
                },
            )
            .await,
        );
        assert!(err.contains("eth.genesis_hash mismatch"), "{err}");
        assert!(
            err.contains(&format!("recomputed 0x{}", "34".repeat(32))),
            "{err}"
        );

        // The digest is over the summit genesis bytes: any edit breaks it.
        let summit = std::fs::read_to_string(dir.summit_genesis()).unwrap();
        std::fs::write(dir.summit_genesis(), format!("{summit}# tampered\n")).unwrap();
        let err = failure(validate(&dir).await);
        assert!(
            err.contains("summit.genesis_config_digest mismatch"),
            "{err}"
        );
        std::fs::write(dir.summit_genesis(), &summit).unwrap();

        // The policy hash is a byte hash.
        let policy = std::fs::read(dir.policy()).unwrap();
        std::fs::write(dir.policy(), [policy.as_slice(), b"\n"].concat()).unwrap();
        let err = failure(validate(&dir).await);
        assert!(err.contains("bootstrap_policy_hash mismatch"), "{err}");
        std::fs::write(dir.policy(), &policy).unwrap();

        edit_genesis(&dir, |g| g["config"]["chainId"] = json!(9999));
        let err = failure(validate(&dir).await);
        assert!(err.contains("chainId 9999"), "{err}");
    }

    /// The summit genesis's own copies of the derived values must agree with
    /// the manifest. The digest gate comes first and is content-derived here,
    /// so the fake is pinned to the manifest's digest to reach the field
    /// gates behind it.
    #[tokio::test]
    async fn the_summit_genesis_fields_must_match_the_manifest() {
        let (_tmp, dir) = assembled_dir().await;
        let set = ArtifactSet::load(&dir).unwrap();
        let pinned = Fake {
            eth_hash: [0x12; 32],
            digest: Some(set.manifest.summit.genesis_config_digest),
        };
        let original = std::fs::read_to_string(dir.summit_genesis()).unwrap();

        let wrong_hash = original.replacen(
            &format!("eth_genesis_hash = \"0x{}\"", "12".repeat(32)),
            &format!("eth_genesis_hash = \"0x{}\"", "56".repeat(32)),
            1,
        );
        assert_ne!(wrong_hash, original);
        std::fs::write(dir.summit_genesis(), &wrong_hash).unwrap();
        let err = failure(run_validation_gates(&ArtifactSet::load(&dir).unwrap(), &pinned).await);
        assert!(err.contains("summit genesis eth_genesis_hash is"), "{err}");
        assert!(
            err.contains(&format!("manifest has 0x{}", "12".repeat(32))),
            "{err}"
        );

        let wrong_namespace =
            original.replacen("namespace = \"testnet-1\"", "namespace = \"other\"", 1);
        assert_ne!(wrong_namespace, original);
        std::fs::write(dir.summit_genesis(), &wrong_namespace).unwrap();
        let err = failure(run_validation_gates(&ArtifactSet::load(&dir).unwrap(), &pinned).await);
        assert!(err.contains("namespace \"other\""), "{err}");
        assert!(err.contains("summit.namespace \"testnet-1\""), "{err}");
    }

    /// The gates re-run over the on-disk genesis catch every way the registry
    /// account can disagree with the policy it was compiled from.
    #[tokio::test]
    async fn the_registry_account_is_held_to_the_policy() {
        let (_tmp, dir) = assembled_dir().await;
        let registry = hex_0x(REGISTRY.as_slice());

        edit_genesis(&dir, |g| {
            g["alloc"][&registry]["storage"] = json!({});
        });
        let err = failure(validate(&dir).await);
        assert!(err.contains("genesis storage is empty"), "{err}");

        // A genesis assembled around another policy: same slots, other words.
        let other = crate::gates::compile(&other_policy()).unwrap();
        edit_genesis(&dir, |g| {
            let storage: serde_json::Map<String, serde_json::Value> = other
                .registry_genesis_storage
                .iter()
                .map(|(s, w)| (hex_0x(s.as_slice()), json!(hex_0x(w.as_slice()))))
                .collect();
            g["alloc"][&registry]["storage"] = json!(storage);
        });
        let err = failure(validate(&dir).await);
        assert!(
            err.contains("does not match the compiled policy artifact"),
            "{err}"
        );
        assert!(err.contains("missing"), "{err}");
        assert!(err.contains("unexplained"), "{err}");

        edit_genesis(&dir, |g| {
            g["alloc"][&registry]["code"] = json!("0x600160005500");
        });
        let err = failure(validate(&dir).await);
        assert!(
            err.contains("not the canonical MeasurementRegistry runtime"),
            "{err}"
        );

        edit_genesis(&dir, |g| {
            g["alloc"].as_object_mut().unwrap().remove(&registry);
        });
        let err = failure(validate(&dir).await);
        assert!(err.contains("measurements.contracts.registry"), "{err}");
        assert!(err.contains("not in the reth genesis alloc"), "{err}");
    }

    #[tokio::test]
    async fn a_contract_without_code_is_rejected() {
        let (_tmp, dir) = assembled_dir().await;
        edit_genesis(&dir, |g| {
            g["alloc"]["0x1000000000000000000000000000000000000002"]["code"] = json!("");
        });
        let err = failure(validate(&dir).await);
        assert!(err.contains("measurements.contracts.authority"), "{err}");
        assert!(err.contains("has no code"), "{err}");
    }
}
