//! `tools verify`: the relying-party checks over Seismic node quotes.
//!
//! Clap over the enclave's `seismic-verify-quote` library, which holds the
//! verification itself: two checks sharing one DCAP path.
//!
//! - `harvest` checks one founding node's summit-keys harvest quote, taking
//!   that node's whole harvest record. `--dump-collateral` writes the Intel
//!   collateral the verification consumed, once the quote has verified, for
//!   the founding archive to keep; `--collateral` is the other end of that
//!   archive — the record is replayed against the snapshot beside it, at the
//!   instant it was held to, reaching no collateral service.
//! - `deploy` checks a freshly provisioned node before the operator relies on
//!   it, by challenging its attestation service with a fresh nonce.
//!
//! Exit 0 plus one JSON object on stdout means verified. Every failure — bad
//! input, binding mismatch, measurement mismatch, DCAP failure — is an error
//! on stderr with a nonzero exit and nothing on stdout. Verification-only:
//! nothing here touches a local TPM, so it runs on any dev platform.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::{Args, Parser, Subcommand};
use seismic_verify_quote::{
    ArchivedSnapshot, HarvestCollateral, HarvestRecord, SeismicMeasurementPolicy, collateral,
    verify_deploy, verify_harvest,
};

use super::{read_flag_file, read_input};

#[derive(Debug, Parser)]
pub struct VerifyCli {
    #[command(subcommand)]
    command: VerifyCommand,
}

#[derive(Debug, Subcommand)]
enum VerifyCommand {
    /// DCAP-verify one founding node's summit-keys harvest quote, given that
    /// node's harvest record from the founding archive.
    Harvest(HarvestCli),
    /// DCAP-verify a freshly provisioned node before relying on it, by
    /// challenging its attestation service with a fresh nonce.
    Deploy(DeployCli),
}

/// Flags shared by every verification purpose.
#[derive(Debug, Args)]
struct CommonArgs {
    /// Measurement-policy JSON pinning the intended image measurements.
    /// Required: a quote from an unintended image must not pass.
    #[arg(long, value_name = "PATH")]
    policy: PathBuf,

    /// Optional PCCS URL for DCAP collateral, instead of the backend default.
    #[arg(long, value_name = "URL")]
    pccs_url: Option<String>,
}

#[derive(Debug, Args)]
struct HarvestCli {
    /// The node's harvest record, e.g. a founding archive's
    /// `inputs/harvest/<node>.json` (`-` reads stdin).
    #[arg(long, value_name = "PATH")]
    record: PathBuf,

    /// Write the DCAP collateral this verification consumed to PATH, once
    /// the quote has verified. Somewhere disposable: the caller archives it.
    #[arg(long, value_name = "PATH")]
    dump_collateral: Option<PathBuf>,

    /// Verify against the archived collateral snapshot at PATH, at the
    /// instant it was held to, instead of fetching and using the wall clock.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["dump_collateral", "pccs_url"]
    )]
    collateral: Option<PathBuf>,

    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Debug, Args)]
struct DeployCli {
    /// The node's attestation-service JSON-RPC endpoint,
    /// e.g. http://<node-ip>:7878.
    #[arg(long, value_name = "URL")]
    endpoint: String,

    /// The network-manifest.json the node is expected to have booted with.
    /// Its exact bytes are the network identity the binding commits to.
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,

    #[command(flatten)]
    common: CommonArgs,
}

pub async fn run(cli: VerifyCli) -> anyhow::Result<Vec<u8>> {
    // Collateral fetches go over TLS, and the dependency graph enables more
    // than one rustls crypto provider (the attestation backend's aws-lc-rs,
    // the DCAP verifier's ring), which leaves rustls no process default to
    // pick. Choose the backend's, as the attestation service does. Idempotent:
    // a second install is a no-op error.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let report = match cli.command {
        VerifyCommand::Harvest(harvest) => run_harvest(harvest).await?,
        VerifyCommand::Deploy(deploy) => run_deploy(deploy).await?,
    };
    let mut bytes = report.to_string().into_bytes();
    bytes.push(b'\n');
    Ok(bytes)
}

async fn run_harvest(cli: HarvestCli) -> anyhow::Result<serde_json::Value> {
    // Resolve everything the filesystem can fail on before any verification:
    // DCAP costs collateral round-trips, so a mistyped path should not be
    // discovered on the far side of them.
    let record_bytes = read_input("--record", &cli.record)?;
    let record: HarvestRecord =
        serde_json::from_slice(&record_bytes).context("--record is not a harvest record")?;
    let policy = load_policy(&cli.common.policy).await?;
    let collateral = match &cli.collateral {
        Some(path) => HarvestCollateral::Archived(Box::new(read_archived_collateral(path).await?)),
        None => HarvestCollateral::Live {
            pccs_url: cli.common.pccs_url,
        },
    };

    let verified = verify_harvest(record, policy, collateral).await?;
    // After the verdict, never before: a burned harvest must not leave a
    // half-archive behind for a later reader to trust.
    if let Some(path) = &cli.dump_collateral {
        let document = verified.archived_collateral()?;
        tokio::fs::write(path, document)
            .await
            .with_context(|| format!("writing --dump-collateral {}", path.display()))?;
    }
    Ok(verified.to_json())
}

async fn run_deploy(cli: DeployCli) -> anyhow::Result<serde_json::Value> {
    // Read every local input before contacting the node: a mistyped path
    // should not be discovered on the far side of an RPC round-trip.
    let manifest_bytes = read_flag_file("--manifest", &cli.manifest).await?;
    let policy = load_policy(&cli.common.policy).await?;

    let verified =
        verify_deploy(&cli.endpoint, &manifest_bytes, policy, cli.common.pccs_url).await?;
    Ok(verified.to_json())
}

/// Load the measurement policy, failing closed: there is no accept-any path,
/// so an unparseable policy must stop the run rather than widen it.
async fn load_policy(path: &Path) -> anyhow::Result<SeismicMeasurementPolicy> {
    SeismicMeasurementPolicy::from_file(path.to_path_buf())
        .await
        .with_context(|| format!("loading measurement policy {}", path.display()))
}

/// Read the archived collateral snapshot `--collateral` names.
///
/// Both failures are the flag's, not the founding's: a reader who mistypes the
/// path must not be told the quote failed to verify.
async fn read_archived_collateral(path: &Path) -> anyhow::Result<ArchivedSnapshot> {
    let document = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("reading --collateral {}", path.display()))?;
    collateral::parse(&document).with_context(|| {
        format!(
            "--collateral {} is not an archived snapshot",
            path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::tests::{FIXTURE_MANIFEST, write_file};

    /// A policy that parses. Its measurements never get checked here: every
    /// case fails before verification, which is the point — no test in this
    /// file reaches live DCAP.
    const VALID_POLICY: &str = r#"[
      {
        "attestation_type": "azure-tdx",
        "measurement_id": "tools-verify-test.vhd",
        "measurements": {
          "pcr4": { "expected_any": ["d57063c0669599b885c43a0683436a3463ad49513ddb3996e6fc96040508fd8e"] }
        }
      }
    ]"#;

    const NONCE_HEX: &str = "7777777777777777777777777777777777777777777777777777777777777777";
    const NODE_PK_HEX: &str = "8888888888888888888888888888888888888888888888888888888888888888";
    const CONSENSUS_PK_HEX: &str = "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999";

    const NO_ATTESTATION: &str = r#"{ "attestation_type": "none", "attestation": [] }"#;

    /// A harvest record carrying `evidence` verbatim.
    fn record_json(evidence: &str) -> String {
        format!(
            r#"{{
              "harvest_nonce": "{NONCE_HEX}",
              "node_public_key": "{NODE_PK_HEX}",
              "consensus_public_key": "{CONSENSUS_PK_HEX}",
              "evidence": {evidence}
            }}"#
        )
    }

    fn parse(argv: &[&str]) -> Result<VerifyCli, clap::Error> {
        VerifyCli::try_parse_from(std::iter::once(&"verify").chain(argv))
    }

    fn harvest_cli(record: &Path, policy: &Path, extra: &[&str]) -> VerifyCli {
        let mut argv = vec![
            "harvest",
            "--record",
            record.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ];
        argv.extend_from_slice(extra);
        parse(&argv).expect("well-formed argv")
    }

    fn deploy_cli(endpoint: &str, manifest: &Path, policy: &Path) -> VerifyCli {
        parse(&[
            "deploy",
            "--endpoint",
            endpoint,
            "--manifest",
            manifest.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ])
        .expect("well-formed argv")
    }

    async fn failure(cli: VerifyCli) -> String {
        format!("{:?}", run(cli).await.unwrap_err())
    }

    /// Capturing the collateral is optional and harvest-only: a live deploy
    /// challenge is judged against live collateral and archives nothing.
    #[test]
    fn dump_collateral_is_optional_and_harvest_only() {
        let dir = tempfile::tempdir().unwrap();
        let record = write_file(&dir, "node-1.json", &record_json("{}"));
        let policy = write_file(&dir, "policy.json", VALID_POLICY);
        let destination = dir.path().join("node-1-collateral.json");

        let VerifyCommand::Harvest(harvest) = harvest_cli(&record, &policy, &[]).command else {
            panic!("expected the harvest subcommand");
        };
        assert_eq!(harvest.dump_collateral, None);

        let VerifyCommand::Harvest(harvest) = harvest_cli(
            &record,
            &policy,
            &["--dump-collateral", destination.to_str().unwrap()],
        )
        .command
        else {
            panic!("expected the harvest subcommand");
        };
        assert_eq!(
            harvest.dump_collateral.as_deref(),
            Some(destination.as_path())
        );

        assert!(
            parse(&[
                "deploy",
                "--endpoint",
                "http://127.0.0.1:1",
                "--manifest",
                policy.to_str().unwrap(),
                "--policy",
                policy.to_str().unwrap(),
                "--dump-collateral",
                destination.to_str().unwrap(),
            ])
            .is_err()
        );
    }

    /// `--collateral` is the whole collateral input, so it excludes both the
    /// flag that captures and the flag that points at a PCCS.
    #[test]
    fn offline_mode_excludes_capture_and_the_pccs() {
        let dir = tempfile::tempdir().unwrap();
        let record = write_file(&dir, "node-1.json", &record_json("{}"));
        let policy = write_file(&dir, "policy.json", VALID_POLICY);
        let snapshot = dir.path().join("node-1-collateral.json");

        for extra in [
            ["--dump-collateral", snapshot.to_str().unwrap()],
            ["--pccs-url", "http://127.0.0.1:8081"],
        ] {
            let argv = [
                "harvest",
                "--record",
                record.to_str().unwrap(),
                "--policy",
                policy.to_str().unwrap(),
                "--collateral",
                snapshot.to_str().unwrap(),
                extra[0],
                extra[1],
            ];
            assert!(parse(&argv).is_err(), "{argv:?}");
        }
    }

    /// Offline mode fails by flag name on every way the snapshot can be
    /// unusable: a reader who mistypes the path must not be told the founding
    /// failed to verify.
    #[tokio::test]
    async fn offline_mode_fails_by_flag_name_on_an_unusable_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let record = write_file(&dir, "node-1.json", &record_json(NO_ATTESTATION));
        let policy = write_file(&dir, "policy.json", VALID_POLICY);

        for document in ["not json at all", r#"{ "version": 2 }"#] {
            let snapshot = write_file(&dir, "snapshot.json", document);
            let error = failure(harvest_cli(
                &record,
                &policy,
                &["--collateral", snapshot.to_str().unwrap()],
            ))
            .await;
            assert!(error.contains("--collateral"), "{error}");
        }

        let missing = dir.path().join("absent.json");
        let error = failure(harvest_cli(
            &record,
            &policy,
            &["--collateral", missing.to_str().unwrap()],
        ))
        .await;
        assert!(error.contains("--collateral"), "{error}");
    }

    /// The dump follows the verdict: a run that does not verify leaves no
    /// collateral behind for a later reader to mistake for provenance.
    #[tokio::test]
    async fn a_failed_verification_writes_no_collateral() {
        let dir = tempfile::tempdir().unwrap();
        let record = write_file(&dir, "node-1.json", &record_json(NO_ATTESTATION));
        let policy = write_file(&dir, "policy.json", VALID_POLICY);
        let destination = dir.path().join("node-1-collateral.json");

        let cli = harvest_cli(
            &record,
            &policy,
            &["--dump-collateral", destination.to_str().unwrap()],
        );
        assert!(run(cli).await.is_err());
        assert!(!destination.exists());
    }

    #[tokio::test]
    async fn malformed_and_missing_records_are_rejected_by_flag_name() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_file(&dir, "policy.json", VALID_POLICY);

        let record = write_file(&dir, "node-1.json", "{ not a record");
        let error = failure(harvest_cli(&record, &policy, &[])).await;
        assert!(error.contains("--record"), "{error}");

        // Evidence that is not an envelope fails as a bad record, before any
        // collateral is fetched.
        let record = write_file(&dir, "node-2.json", &record_json(r#""not an envelope""#));
        let error = failure(harvest_cli(&record, &policy, &[])).await;
        assert!(error.contains("--record"), "{error}");

        let error = failure(harvest_cli(&dir.path().join("absent.json"), &policy, &[])).await;
        assert!(error.contains("reading --record"), "{error}");
    }

    /// Fail-closed on the policy: no accept-any path, so an unparseable
    /// policy stops the run rather than widening it.
    #[tokio::test]
    async fn malformed_policy_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let record = write_file(
            &dir,
            "node-1.json",
            &record_json(r#"{ "attestation_type": "azure-tdx", "attestation": [1, 2, 3] }"#),
        );
        let policy = write_file(&dir, "policy.json", "{ not a policy");

        let error = failure(harvest_cli(&record, &policy, &[])).await;
        assert!(error.contains("measurement policy"), "{error}");
    }

    /// Local inputs resolve before the node is contacted: the endpoint points
    /// nowhere, and the failures are the local files'.
    #[tokio::test]
    async fn deploy_resolves_local_inputs_before_contacting_the_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_file(&dir, "policy.json", VALID_POLICY);

        let error = failure(deploy_cli(
            "http://127.0.0.1:1",
            &dir.path().join("absent.json"),
            &policy,
        ))
        .await;
        assert!(error.contains("reading --manifest"), "{error}");

        let manifest = write_file(&dir, "network-manifest.json", FIXTURE_MANIFEST);
        let bad_policy = write_file(&dir, "bad-policy.json", "{ not a policy");
        let error = failure(deploy_cli("http://127.0.0.1:1", &manifest, &bad_policy)).await;
        assert!(error.contains("measurement policy"), "{error}");
    }
}
