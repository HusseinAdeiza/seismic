//! `tools admission`: the measurement-admission pipeline's two compiler steps.
//!
//! Promotion and policy→genesis-storage compilation are schema knowledge —
//! which registers form guest identity, which value forms are canonical, how
//! admission IDs key registry storage — with one implementation, the enclave's
//! `seismic-measurement-admission` crate. `promote` turns raw `make measure`
//! output into the policy document (or passes an already-promoted one through
//! byte-verbatim, since the manifest commits to its bytes by hash); `compile`
//! reports the admission IDs a policy admits and the registry genesis storage
//! seeding them.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use seismic_measurement_admission::{CompileReport, compile_policy, promote_measurements};

use super::read_input;

#[derive(Debug, Parser)]
pub struct AdmissionCli {
    #[command(subcommand)]
    command: AdmissionCommand,
}

#[derive(Debug, Subcommand)]
enum AdmissionCommand {
    /// Promote raw `make measure` output into a measurement-policy document
    /// (JSON on stdout): one record binding exactly the schema registers,
    /// compiled before it is emitted. An input that already is a record
    /// list is compiled and passed through byte-verbatim.
    Promote {
        /// Path to the make-measure measurements file (`-` for stdin).
        measurements: PathBuf,
        /// Policy record id, conventionally the registered image artifact
        /// filename; overrides one stamped into the measurements file.
        #[arg(long)]
        measurement_id: Option<String>,
        /// Default attestation type when the measurements file carries none.
        #[arg(long)]
        attestation_type: Option<String>,
    },
    /// Compile a measurement-policy document into the admission IDs it
    /// admits and the registry genesis storage seeding them (JSON on stdout).
    Compile {
        /// Path to the measurement-policy.json document (`-` for stdin).
        policy: PathBuf,
    },
}

pub fn run(cli: AdmissionCli) -> anyhow::Result<Vec<u8>> {
    match cli.command {
        AdmissionCommand::Promote {
            measurements,
            measurement_id,
            attestation_type,
        } => {
            let bytes = read_input("the measurements", &measurements)?;
            Ok(promote_measurements(
                &bytes,
                measurement_id.as_deref(),
                attestation_type.as_deref(),
            )?)
        }
        AdmissionCommand::Compile { policy } => {
            let bytes = read_input("the policy", &policy)?;
            let compiled = compile_policy(&bytes)?;
            Ok(CompileReport::new(&compiled).to_json().into_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::tests::write_file;

    /// `make measure` output as its wrapper: every populated register, the
    /// stamped artifact id, extra fields the policy must not carry.
    fn raw_measurements() -> String {
        serde_json::json!({
            "measurement_id": "img.vhd",
            "attestation_type": "azure-tdx",
            "measurements": {
                "4": {"expected": "ab".repeat(32)},
                "9": {"expected": "cd".repeat(32)},
                "11": {"expected": "ef".repeat(32)},
                "12": {"expected": "00".repeat(32)},
            },
            "event_log": [],
        })
        .to_string()
    }

    fn promote_cli(path: &std::path::Path, extra: &[&str]) -> AdmissionCli {
        let mut argv: Vec<std::ffi::OsString> =
            vec!["admission".into(), "promote".into(), path.into()];
        argv.extend(extra.iter().map(Into::into));
        AdmissionCli::try_parse_from(argv).expect("well-formed argv")
    }

    fn compile_cli(path: &std::path::Path) -> AdmissionCli {
        AdmissionCli::try_parse_from(["admission".as_ref(), "compile".as_ref(), path.as_os_str()])
            .expect("well-formed argv")
    }

    #[test]
    fn promote_selects_the_schema_registers_and_compile_reports_them() {
        let dir = tempfile::tempdir().unwrap();
        let raw = write_file(&dir, "measurements.json", &raw_measurements());

        let policy = run(promote_cli(&raw, &["--attestation-type", "azure-tdx"])).unwrap();
        let records: serde_json::Value = serde_json::from_slice(&policy).unwrap();
        let record = &records[0];
        assert_eq!(record["measurement_id"], "img.vhd");
        assert_eq!(record["attestation_type"], "azure-tdx");
        let registers: Vec<_> = record["measurements"].as_object().unwrap().keys().collect();
        assert_eq!(registers, ["pcr4", "pcr9", "pcr11"]);

        let policy_path = write_file(&dir, "policy.json", std::str::from_utf8(&policy).unwrap());
        let report: serde_json::Value =
            serde_json::from_slice(&run(compile_cli(&policy_path)).unwrap()).unwrap();
        assert_eq!(report["accepted_count"], 1);
        assert!(report["registry_genesis_storage"].is_object());
    }

    /// The manifest commits to a policy's bytes, so an already-promoted
    /// document leaves exactly as it arrived — odd formatting included.
    #[test]
    fn an_already_promoted_policy_passes_through_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let odd = format!(
            "[{{\"measurement_id\": \"x\", \"attestation_type\": \"azure-tdx\",   \
             \"measurements\": {{\"4\": {{\"expected\": \"{}\"}}, \"9\": {{\"expected\": \
             \"{}\"}}, \"11\": {{\"expected\": \"{}\"}}}}}}]",
            "ab".repeat(32),
            "cd".repeat(32),
            "ef".repeat(32)
        );
        let path = write_file(&dir, "policy.json", &odd);
        assert_eq!(run(promote_cli(&path, &[])).unwrap(), odd.as_bytes());
    }

    /// The compiler's diagnostics are the failure: a wrapper missing a schema
    /// register is refused by naming it.
    #[test]
    fn promote_surfaces_compiler_diagnostics() {
        let dir = tempfile::tempdir().unwrap();
        let partial = serde_json::json!({
            "measurement_id": "img.vhd",
            "measurements": {"4": {"expected": "ab".repeat(32)}},
        })
        .to_string();
        let path = write_file(&dir, "partial.json", &partial);
        let error = format!("{:?}", run(promote_cli(&path, &[])).unwrap_err());
        assert!(error.contains("pcr9"), "{error}");

        let empty = write_file(&dir, "empty.json", "[]");
        assert!(run(compile_cli(&empty)).is_err());
    }
}
