#![cfg(unix)]
//! Black-box tests of the targeting verbs.
//!
//! `env` and `exec` are defined by what crosses the process boundary — the
//! bytes on stdout, the variables a child sees, the exit code that comes
//! back — so they are tested through the real binary rather than in process.
//! Each test runs `seismic-tee` (`env!("CARGO_BIN_EXE_seismic-tee")`) with a
//! cleared environment, `HOME`/`XDG_CONFIG_HOME` pointed at a fresh tempdir
//! carrying its own `config.toml`, and a scratch `PATH` holding one
//! executable stand-in: a `scast` shell script that appends its argv and
//! `$ETH_RPC_URL` and `$SEISMIC_CONTEXT` to `$SEISMIC_TEST_LOG` and exits 7.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;

/// `devnet-1/alpha` current, a two-node table.
const TWO_NODE_CONFIG: &str = r#"
current = "devnet-1/alpha"

[networks.devnet-1]
dir = "/x"

[networks.devnet-1.nodes]
alpha = { public_ip = "203.0.113.7", fqdn = "alpha.example.com" }
beta = { public_ip = "203.0.113.8", fqdn = "beta.example.com" }
"#;

/// The same cohort, with the selection stopping at the network — no default
/// node — so a single-node command needs `--name` to say which.
const NETWORK_ONLY_CONFIG: &str = r#"
current = "devnet-1"

[networks.devnet-1]
dir = "/x"

[networks.devnet-1.nodes]
alpha = { public_ip = "203.0.113.7", fqdn = "alpha.example.com" }
beta = { public_ip = "203.0.113.8", fqdn = "beta.example.com" }
"#;

/// A tempdir standing in for the operator's whole environment: its own
/// `$HOME`/`$XDG_CONFIG_HOME`, and a `PATH` holding only the `scast` stub —
/// nothing a test does reaches outside it.
struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new(config: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();

        let config_dir = dir.path().join("config/seismic");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(config_dir.join("config.toml"), config).unwrap();

        let bin_dir = dir.path().join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let scast = bin_dir.join("scast");
        fs::write(
            &scast,
            "#!/bin/sh\n{ echo \"$@\"; echo \"$ETH_RPC_URL\"; echo \"$SEISMIC_CONTEXT\"; } >> \
             \"$SEISMIC_TEST_LOG\"\nexit 7\n",
        )
        .unwrap();
        fs::set_permissions(&scast, fs::Permissions::from_mode(0o755)).unwrap();

        Self { dir }
    }

    /// The binary, with a clean environment carrying only what the sandbox
    /// sets up. A test adds `SEISMIC_CONTEXT` or `--context` on top of this.
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_seismic-tee"));
        command
            .env_clear()
            .env("HOME", self.dir.path().join("home"))
            .env("XDG_CONFIG_HOME", self.dir.path().join("config"))
            .env("PATH", self.dir.path().join("bin"))
            .env("SEISMIC_TEST_LOG", self.log_path());
        command
    }

    fn log_path(&self) -> PathBuf {
        self.dir.path().join("scast.log")
    }

    fn log(&self) -> String {
        fs::read_to_string(self.log_path()).unwrap_or_default()
    }
}

#[test]
fn env_prints_only_export_lines_on_stdout() {
    let sandbox = Sandbox::new(TWO_NODE_CONFIG);

    let output = sandbox.command().args(["ctx", "env"]).output().unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "export ETH_RPC_URL='https://alpha.example.com/rpc'\n\
         export SEISMIC_CONTEXT='devnet-1/alpha'\n"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("context devnet-1/alpha →"), "{stderr}");
}

#[test]
fn env_unset_is_the_reverse() {
    let sandbox = Sandbox::new(TWO_NODE_CONFIG);

    let output = sandbox
        .command()
        .args(["ctx", "env", "--unset"])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "unset ETH_RPC_URL\nunset SEISMIC_CONTEXT\n"
    );
}

#[test]
fn exec_hands_the_child_the_selected_nodes_rpc_url_and_context() {
    let sandbox = Sandbox::new(TWO_NODE_CONFIG);

    let output = sandbox
        .command()
        .args(["ctx", "exec", "--", "scast", "block-number"])
        .output()
        .unwrap();

    assert!(output.status.success() || output.status.code() == Some(7));
    let log = sandbox.log();
    let mut lines = log.lines();
    assert_eq!(lines.next(), Some("block-number"));
    assert_eq!(lines.next(), Some("https://alpha.example.com/rpc"));
    assert_eq!(lines.next(), Some("devnet-1/alpha"));
}

#[test]
fn exec_propagates_the_childs_exit_code() {
    let sandbox = Sandbox::new(TWO_NODE_CONFIG);

    let output = sandbox
        .command()
        .args(["ctx", "exec", "--", "scast"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn exec_dry_run_runs_nothing() {
    let sandbox = Sandbox::new(TWO_NODE_CONFIG);

    let output = sandbox
        .command()
        .args(["ctx", "exec", "--dry-run", "--", "scast", "block-number"])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(!sandbox.log_path().exists());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("scast block-number"), "{stdout}");
    assert!(stdout.contains("https://alpha.example.com/rpc"), "{stdout}");
    assert!(
        stdout.contains("SEISMIC_CONTEXT=devnet-1/alpha"),
        "{stdout}"
    );
}

#[test]
fn the_env_var_beats_the_persisted_selection() {
    let sandbox = Sandbox::new(TWO_NODE_CONFIG); // current = devnet-1/alpha

    let output = sandbox
        .command()
        .env("SEISMIC_CONTEXT", "devnet-1/beta")
        .args(["ctx", "env"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("devnet-1/beta"), "{stdout}");
    assert!(stdout.contains("beta.example.com"), "{stdout}");
}

#[test]
fn the_flag_beats_the_env_var() {
    let sandbox = Sandbox::new(TWO_NODE_CONFIG);

    let output = sandbox
        .command()
        .env("SEISMIC_CONTEXT", "devnet-1/beta")
        .args(["ctx", "env", "--context", "devnet-1/alpha"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("devnet-1/alpha"), "{stdout}");
    assert!(stdout.contains("alpha.example.com"), "{stdout}");
}

#[test]
fn a_network_only_context_needs_name() {
    let sandbox = Sandbox::new(NETWORK_ONLY_CONFIG);

    let output = sandbox.command().args(["ctx", "env"]).output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("alpha"), "{stderr}");
    assert!(stderr.contains("beta"), "{stderr}");

    let output = sandbox
        .command()
        .args(["ctx", "env", "--name", "alpha"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("alpha.example.com"), "{stdout}");
    // The pin names the node it resolved to, not just the network, so the
    // next command in that shell needs no --name.
    assert!(
        stdout.contains("export SEISMIC_CONTEXT='devnet-1/alpha'"),
        "{stdout}"
    );
}
