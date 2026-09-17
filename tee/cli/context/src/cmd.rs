//! `ctx`: name networks, and select which one — and which of its nodes — the
//! other commands act on.
//!
//! Eight verbs. [`CtxCommand::Use`] selects a context and refuses one that
//! points at nothing; [`CtxCommand::List`] and [`CtxCommand::Show`] read the
//! file back; [`CtxCommand::Env`] and [`CtxCommand::Exec`] hand the selection
//! to a shell or a child process (their own modules, [`crate::env`] and
//! [`crate::exec`]); [`CtxCommand::SetNetwork`] registers or updates a network's
//! pointers; [`CtxCommand::SetNodes`] imports a network's cohort from stdin,
//! the way `aws eks update-kubeconfig` merges a cluster the cloud reported;
//! [`CtxCommand::Unset`] clears the selection. Nothing outside this module
//! writes the file.

use std::io::{IsTerminal as _, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, bail};
use clap::{Args, Subcommand};
use clap_complete::ArgValueCandidates;
use seismic_tee_common::descriptor::parse_descriptors;
use seismic_tee_common::load_descriptors;

use crate::complete;
use crate::config::{Network, Shape};
use crate::env::{self, EnvArgs};
use crate::exec::{self, ExecArgs};
use crate::{Context, Selected, Selection, path, write};

/// The `ctx` command group: name networks, and select which one — and which
/// of its nodes — the commands act on.
#[derive(Debug, Subcommand)]
pub enum CtxCommand {
    /// Select the network, and node, the other commands act on:
    /// <network>, <network>/<node>, or `-` for the previous.
    Use(UseArgs),
    /// List every <network>/<node> in the file, marking the current one.
    List(ListArgs),
    /// Show the current selection and the paths and RPC URL it resolves to.
    Show(ListArgs),
    /// Print export lines for the selected node: eval "$(seismic-tee ctx env)".
    Env(EnvArgs),
    /// Run a command with the selected node's ETH_RPC_URL set.
    Exec(ExecArgs),
    /// Register a network by name, or update it: where its artifact set is
    /// (--dir, or --manifest, or --source with --network-id), and optionally
    /// its nodes from a file. Nodes can also be set separately, in either
    /// order.
    SetNetwork(SetNetworkArgs),
    /// Store a network's nodes from stdin, as the provisioner prints them:
    /// pulumi stack output nodes --json | seismic-tee ctx set-nodes <NETWORK>.
    /// Creates the network when it is not registered yet.
    SetNodes(SetNodesArgs),
    /// Clear the current selection.
    Unset(ListArgs),
}

/// Run one `ctx` command.
pub fn run(command: CtxCommand) -> anyhow::Result<ExitCode> {
    match command {
        CtxCommand::Use(args) => run_use(args),
        CtxCommand::List(args) => run_list(args),
        CtxCommand::Show(args) => run_show(args),
        CtxCommand::Env(args) => env::run(args),
        CtxCommand::Exec(args) => exec::run(args),
        CtxCommand::SetNetwork(args) => run_set_network(args),
        CtxCommand::SetNodes(args) => run_set_nodes(args),
        CtxCommand::Unset(args) => run_unset(args),
    }
}

#[derive(Debug, Args)]
pub struct UseArgs {
    /// <network>, <network>/<node>, or `-` for the previous selection. A bare
    /// name with no `/` is a registered network when one is named that; else
    /// a node when exactly one network is registered; else a network.
    #[arg(value_name = "CONTEXT", add = ArgValueCandidates::new(complete::selections))]
    pub selection: Option<String>,

    /// Context file to write. Default: $XDG_CONFIG_HOME/seismic/config.toml,
    /// else ~/.config/seismic/config.toml.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

/// `--config` alone: what `list`, `show` and `unset` need.
#[derive(Debug, Clone, Default, Args)]
pub struct ListArgs {
    /// Context file to read. Default: $XDG_CONFIG_HOME/seismic/config.toml,
    /// else ~/.config/seismic/config.toml.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct SetNetworkArgs {
    /// The name to register the network under.
    #[arg(value_name = "NAME", add = ArgValueCandidates::new(complete::networks))]
    pub name: String,

    /// A network directory (from `network init`): the committed artifact
    /// set — manifest, genesis, policy, harvest records.
    #[arg(long, value_name = "DIR")]
    pub dir: Option<PathBuf>,
    /// The network manifest, for a network handed over as loose files.
    #[arg(long, value_name = "FILE")]
    pub manifest: Option<PathBuf>,
    /// A published artifact set's source. Fetching is not implemented yet;
    /// pairs with --network-id.
    #[arg(long, value_name = "URL")]
    pub source: Option<String>,
    /// SHA-256 of the network's manifest, pinned so a fetched or cached
    /// artifact set is refused unless it matches.
    #[arg(long, value_name = "ID")]
    pub network_id: Option<String>,
    /// The nodes too, from a descriptor-map file (the `pulumi stack output
    /// nodes --json` shape), for a network handed over as files. Otherwise
    /// `ctx set-nodes` stores them from stdin.
    #[arg(long, value_name = "FILE")]
    pub nodes: Option<PathBuf>,

    /// Context file to write. Default: $XDG_CONFIG_HOME/seismic/config.toml,
    /// else ~/.config/seismic/config.toml.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct SetNodesArgs {
    /// The network to import the cohort into. Created, with nodes only,
    /// when unregistered.
    #[arg(value_name = "NETWORK", add = ArgValueCandidates::new(complete::networks))]
    pub name: String,

    /// Context file to write. Default: $XDG_CONFIG_HOME/seismic/config.toml,
    /// else ~/.config/seismic/config.toml.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

fn run_use(args: UseArgs) -> anyhow::Result<ExitCode> {
    let raw = args.selection.ok_or_else(|| {
        anyhow::anyhow!(
            "ctx use needs a target: <network>, <network>/<node>, or `-` for the previous \
             selection — `seismic-tee ctx list` shows what is registered"
        )
    })?;

    let context = Context::load(args.config.as_deref())?;
    let target = resolve_target(&raw, &context)?;
    let selected = context.select(Some(&target.to_string()))?;

    // A network-only selection is legal with no cohort imported: a founder
    // who has not provisioned yet has no node to name. A node half is
    // validated against the table so a context that points at nothing is not
    // storable.
    if selected.selection.node.is_some() {
        selected.node(None)?;
    }

    write::set_current(context.path(), &selected.selection)?;

    println!("Selected {}.", selected.selection);
    print_resolution(&selected);
    Ok(ExitCode::SUCCESS)
}

/// The target `ctx use` resolves to, before it is validated against the
/// network's node table.
fn resolve_target(raw: &str, context: &Context) -> anyhow::Result<Selection> {
    if raw == "-" {
        let previous =
            context.config().previous.clone().ok_or_else(|| {
                anyhow::anyhow!("ctx use -: no previous selection to switch back to")
            })?;
        return previous.parse();
    }
    // A bare word names a network when one is registered under it. Otherwise,
    // with exactly one network registered, there is only one table it could
    // be a node of, so it is read as a node.
    if !raw.contains('/')
        && !context.config().networks.contains_key(raw)
        && context.config().networks.len() == 1
    {
        let network = context
            .config()
            .networks
            .keys()
            .next()
            .expect("len == 1")
            .clone();
        return Ok(Selection {
            network,
            node: Some(raw.to_string()),
        });
    }
    raw.parse()
}

fn run_show(args: ListArgs) -> anyhow::Result<ExitCode> {
    let context = Context::load(args.config.as_deref())?;
    let selected = context.select(None)?;
    println!("{}", selected.selection);
    print_resolution(&selected);
    Ok(ExitCode::SUCCESS)
}

/// What `ctx use` and `ctx show` both print about a resolved selection: one
/// row per thing that resolved.
fn print_resolution(selected: &Selected<'_>) {
    if let Ok(dir) = selected.dir() {
        println!("  dir       {}", dir.display());
    }
    if let Ok(manifest) = selected.manifest() {
        println!("  manifest  {}", manifest.display());
    }
    if selected.selection.node.is_some()
        && let Ok((_, descriptor)) = selected.node(None)
    {
        println!("  rpc       {}", descriptor.eth_rpc_url());
    }
}

fn run_list(args: ListArgs) -> anyhow::Result<ExitCode> {
    let context = Context::load(args.config.as_deref())?;
    for line in list_lines(&context) {
        println!("{line}");
    }
    Ok(ExitCode::SUCCESS)
}

/// One line per selectable context, current one marked with `*`. Opens no
/// file but the config: every field a line needs is already in it.
fn list_lines(context: &Context) -> Vec<String> {
    let current = context.config().current.clone();
    context
        .config()
        .networks
        .keys()
        .flat_map(|name| network_entries(context, name))
        .map(|(selection, display)| {
            let marker = if Some(&selection) == current.as_ref() {
                '*'
            } else {
                ' '
            };
            format!("{marker} {display}")
        })
        .collect()
}

/// `name`'s entries: `(<network>/<node>, <network>/<node>)` per node its
/// table holds, or one `(<network>, "<network> (<reason>)")` pair when it has
/// none to list — a published network awaiting a fetch, or one with no nodes
/// imported yet. Listing must not fail because one entry is incomplete.
fn network_entries(context: &Context, name: &str) -> Vec<(String, String)> {
    let network = &context.config().networks[name];
    if let Shape::Published { .. } = network.shape() {
        return vec![(
            name.to_string(),
            format!("{name} (published; fetching is not implemented)"),
        )];
    }
    if network.nodes.is_empty() {
        return vec![(
            name.to_string(),
            format!(
                "{name} (no nodes; pulumi stack output nodes --json | seismic-tee ctx \
                 set-nodes {name})"
            ),
        )];
    }
    network
        .nodes
        .keys()
        .map(|node| {
            let selection = format!("{name}/{node}");
            (selection.clone(), selection)
        })
        .collect()
}

fn run_unset(args: ListArgs) -> anyhow::Result<ExitCode> {
    let context = Context::load(args.config.as_deref())?;
    write::clear_current(context.path())?;
    println!(
        "Cleared the current context in {}.",
        context.path().display()
    );
    Ok(ExitCode::SUCCESS)
}

fn run_set_network(args: SetNetworkArgs) -> anyhow::Result<ExitCode> {
    let context = Context::load(args.config.as_deref())?;
    // Stored absolute: the file is read from whatever directory the next
    // command runs in, so a path relative to this one would point nowhere.
    let network = Network {
        dir: args.dir.as_deref().map(path::absolute).transpose()?,
        manifest: args.manifest.as_deref().map(path::absolute).transpose()?,
        source: args.source,
        network_id: args.network_id,
        ..Default::default()
    };
    network.validate(&args.name, context.path())?;
    // The file is read before it is written, so a bad map leaves the
    // registration undone too.
    let nodes = args.nodes.as_deref().map(load_descriptors).transpose()?;
    write::set_network(context.path(), &args.name, &network)?;
    if let Some(nodes) = &nodes {
        write::set_nodes(context.path(), &args.name, nodes)?;
    }
    match nodes {
        Some(nodes) => println!(
            "Registered network {} with {} nodes in {}: {}.",
            args.name,
            nodes.len(),
            context.path().display(),
            nodes.keys().cloned().collect::<Vec<_>>().join(", "),
        ),
        None => println!(
            "Registered network {} in {}.",
            args.name,
            context.path().display()
        ),
    }
    Ok(ExitCode::SUCCESS)
}

fn run_set_nodes(args: SetNodesArgs) -> anyhow::Result<ExitCode> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        bail!(
            "set-nodes reads the map on stdin: `pulumi stack output nodes --json | seismic-tee \
             ctx set-nodes {}`, or `< nodes.json`",
            args.name
        );
    }
    let message = import_nodes(&args, &mut stdin.lock())?;
    println!("{message}");
    Ok(ExitCode::SUCCESS)
}

/// [`run_set_nodes`]'s body: read the whole of `input`, parse it as a
/// descriptor map naming `<stdin>` in every failure, and store it as
/// `[networks.<name>.nodes]` — creating the network entry when it is not yet
/// registered. `input` stands in for stdin so a test can hand this a reader
/// of its own bytes.
fn import_nodes(args: &SetNodesArgs, input: &mut impl Read) -> anyhow::Result<String> {
    let mut bytes = Vec::new();
    input
        .read_to_end(&mut bytes)
        .context("reading the descriptor map on stdin")?;
    let nodes = parse_descriptors(&"<stdin>", &bytes)?;

    let context = Context::load(args.config.as_deref())?;
    write::set_nodes(context.path(), &args.name, &nodes)?;

    let names = nodes.keys().cloned().collect::<Vec<_>>().join(", ");
    Ok(format!(
        "Imported {} nodes into network {} in {}: {names}.",
        nodes.len(),
        args.name,
        context.path().display(),
    ))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::{CommandFactory, Parser};

    use super::*;

    /// The group as the binary mounts it.
    #[derive(Parser)]
    struct Probe {
        #[command(subcommand)]
        command: CtxCommand,
    }

    fn parse(argv: &[&str]) -> CtxCommand {
        Probe::try_parse_from(std::iter::once(&"probe").chain(argv))
            .expect("well-formed argv")
            .command
    }

    #[test]
    fn the_command_tree_is_well_formed() {
        Probe::command().debug_assert();
    }

    #[test]
    fn the_commands_are_listed_in_the_documented_order() {
        let names: Vec<_> = Probe::command()
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect();
        assert_eq!(
            names,
            [
                "use",
                "list",
                "show",
                "env",
                "exec",
                "set-network",
                "set-nodes",
                "unset"
            ]
        );
    }

    #[test]
    fn use_takes_exactly_one_positional() {
        assert!(Probe::try_parse_from(["probe", "use", "a"]).is_ok());
        assert!(Probe::try_parse_from(["probe", "use", "a", "b"]).is_err());
    }

    #[test]
    fn set_nodes_takes_exactly_one_positional() {
        assert!(Probe::try_parse_from(["probe", "set-nodes", "a"]).is_ok());
        assert!(Probe::try_parse_from(["probe", "set-nodes"]).is_err());
        assert!(Probe::try_parse_from(["probe", "set-nodes", "a", "b"]).is_err());
    }

    #[test]
    fn set_network_requires_one_of_the_three_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let command = parse(&[
            "set-network",
            "devnet-1",
            "--config",
            config.to_str().unwrap(),
        ]);
        let err = run(command).unwrap_err().to_string();
        assert!(err.contains("is empty"), "{err}");
        assert!(err.contains("ctx set-nodes devnet-1"), "{err}");
    }

    #[test]
    fn set_network_source_without_network_id_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let command = parse(&[
            "set-network",
            "devnet-1",
            "--source",
            "https://example.com/bundle",
            "--config",
            config.to_str().unwrap(),
        ]);
        let err = run(command).unwrap_err().to_string();
        assert!(err.contains("has a source but no network_id"), "{err}");
    }

    #[test]
    fn set_network_writes_a_dir_network() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let command = parse(&[
            "set-network",
            "devnet-1",
            "--dir",
            "/networks/devnet-1",
            "--config",
            config.to_str().unwrap(),
        ]);
        run(command).unwrap();

        let context = Context::load(Some(&config)).unwrap();
        assert_eq!(
            context.config().networks["devnet-1"].dir,
            Some(PathBuf::from("/networks/devnet-1"))
        );
    }

    #[test]
    fn set_network_with_nodes_file_registers_both_halves() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let nodes = dir.path().join("nodes.json");
        std::fs::write(&nodes, TWO_NODE_MAP).unwrap();
        run(parse(&[
            "set-network",
            "partner-net",
            "--manifest",
            "/m/network-manifest.json",
            "--nodes",
            nodes.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ]))
        .unwrap();

        let context = Context::load(Some(&config)).unwrap();
        let network = &context.config().networks["partner-net"];
        assert_eq!(
            network.manifest.as_deref(),
            Some(Path::new("/m/network-manifest.json"))
        );
        assert_eq!(network.nodes.len(), 2);
        assert!(network.nodes.contains_key("alpha"));
    }

    /// A relative `--dir` is stored absolute, with `.` and `..` collapsed:
    /// the file is read from whatever directory the next command runs in.
    #[test]
    fn set_network_stores_a_relative_dir_as_absolute() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        run(parse(&[
            "set-network",
            "devnet-1",
            "--dir",
            "./sub/../networks/devnet-1",
            "--config",
            config.to_str().unwrap(),
        ]))
        .unwrap();

        let context = Context::load(Some(&config)).unwrap();
        let stored = context.config().networks["devnet-1"].dir.clone().unwrap();
        assert_eq!(
            stored,
            std::env::current_dir().unwrap().join("networks/devnet-1")
        );
    }

    const TWO_NODE_MAP: &[u8] = br#"{
        "alpha": {"public_ip": "203.0.113.7", "fqdn": "alpha.example.com"},
        "beta": {"public_ip": "203.0.113.8", "fqdn": "beta.example.com"}
    }"#;

    /// Rewrite the config file: `extra` (e.g. `current = "..."` lines),
    /// followed by `devnet-1` registered with a two-node table.
    fn write_config(config_path: &Path, extra: &str) {
        std::fs::write(
            config_path,
            format!(
                "{extra}[networks.devnet-1]\ndir = \"/x\"\n\n[networks.devnet-1.nodes]\n\
                 alpha = {{ public_ip = \"203.0.113.7\", fqdn = \"alpha.example.com\" }}\n\
                 beta = {{ public_ip = \"203.0.113.8\", fqdn = \"beta.example.com\" }}\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn use_with_network_and_node_writes_current() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        write_config(&config_path, "");

        run(parse(&[
            "use",
            "devnet-1/alpha",
            "--config",
            config_path.to_str().unwrap(),
        ]))
        .unwrap();

        let context = Context::load(Some(&config_path)).unwrap();
        assert_eq!(context.config().current.as_deref(), Some("devnet-1/alpha"));
    }

    #[test]
    fn use_refuses_a_node_the_table_does_not_hold() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        write_config(&config_path, "");

        let err = run(parse(&[
            "use",
            "devnet-1/gamma",
            "--config",
            config_path.to_str().unwrap(),
        ]))
        .unwrap_err()
        .to_string();
        assert!(err.contains("no node `gamma`"), "{err}");
        assert!(err.contains("alpha, beta"), "{err}");

        // Nothing was written.
        let context = Context::load(Some(&config_path)).unwrap();
        assert_eq!(context.config().current, None);
    }

    /// A second network is registered alongside `devnet-1` so the bare name
    /// resolves as a network (the "more than one registered" branch of the
    /// bare-name rule) rather than as a node of the lone network.
    #[test]
    fn use_accepts_a_network_only_selection_with_no_nodes_imported() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[networks.devnet-1]\ndir = \"/x\"\n\n[networks.devnet-2]\ndir = \"/y\"\n",
        )
        .unwrap();

        run(parse(&[
            "use",
            "devnet-2",
            "--config",
            config_path.to_str().unwrap(),
        ]))
        .unwrap();

        let context = Context::load(Some(&config_path)).unwrap();
        assert_eq!(context.config().current.as_deref(), Some("devnet-2"));
    }

    #[test]
    fn dash_swaps_current_and_previous() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        write_config(
            &config_path,
            "current = \"devnet-1/alpha\"\nprevious = \"devnet-1/beta\"\n\n",
        );

        run(parse(&[
            "use",
            "-",
            "--config",
            config_path.to_str().unwrap(),
        ]))
        .unwrap();

        let context = Context::load(Some(&config_path)).unwrap();
        assert_eq!(context.config().current.as_deref(), Some("devnet-1/beta"));
        assert_eq!(context.config().previous.as_deref(), Some("devnet-1/alpha"));
    }

    #[test]
    fn dash_with_no_previous_errors_naming_ctx_use() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        write_config(&config_path, "current = \"devnet-1/alpha\"\n\n");

        let err = run(parse(&[
            "use",
            "-",
            "--config",
            config_path.to_str().unwrap(),
        ]))
        .unwrap_err()
        .to_string();
        assert!(err.contains("ctx use"), "{err}");
    }

    #[test]
    fn a_bare_name_resolves_as_a_node_when_one_network_is_registered() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        write_config(&config_path, "");

        run(parse(&[
            "use",
            "alpha",
            "--config",
            config_path.to_str().unwrap(),
        ]))
        .unwrap();

        let context = Context::load(Some(&config_path)).unwrap();
        assert_eq!(context.config().current.as_deref(), Some("devnet-1/alpha"));
    }

    #[test]
    fn a_bare_name_that_is_a_registered_networks_name_selects_the_network() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        write_config(&config_path, "");

        run(parse(&[
            "use",
            "devnet-1",
            "--config",
            config_path.to_str().unwrap(),
        ]))
        .unwrap();

        let context = Context::load(Some(&config_path)).unwrap();
        assert_eq!(context.config().current.as_deref(), Some("devnet-1"));
    }

    #[test]
    fn a_bare_name_resolves_as_a_network_when_more_than_one_is_registered() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[networks.devnet-1]\ndir = \"/x\"\n\n[networks.partner-net]\ndir = \"/y\"\n",
        )
        .unwrap();

        run(parse(&[
            "use",
            "devnet-1",
            "--config",
            config_path.to_str().unwrap(),
        ]))
        .unwrap();

        let context = Context::load(Some(&config_path)).unwrap();
        assert_eq!(context.config().current.as_deref(), Some("devnet-1"));
    }

    #[test]
    fn use_with_no_argument_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let err = run(parse(&["use", "--config", config.to_str().unwrap()]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("ctx use needs a target"), "{err}");
    }

    #[test]
    fn list_marks_the_current_entry() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        write_config(&config_path, "current = \"devnet-1/alpha\"\n\n");
        let context = Context::load(Some(&config_path)).unwrap();

        let lines = list_lines(&context);
        assert!(lines.contains(&"* devnet-1/alpha".to_string()), "{lines:?}");
        assert!(lines.contains(&"  devnet-1/beta".to_string()), "{lines:?}");
    }

    /// `list` reaches only the config file: a `dir` that does not exist on
    /// disk does not stop its nodes from listing.
    #[test]
    fn list_reads_no_file_but_the_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        write_config(&config_path, "");

        let context = Context::load(Some(&config_path)).unwrap();
        let lines = list_lines(&context);
        assert_eq!(lines.len(), 2, "{lines:?}");
    }

    #[test]
    fn list_lists_a_network_with_no_nodes_as_one_line_naming_ctx_set_nodes() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "[networks.stale-net]\ndir = \"/x\"\n").unwrap();
        let context = Context::load(Some(&config_path)).unwrap();

        let lines = list_lines(&context);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("stale-net"), "{lines:?}");
        assert!(lines[0].contains("ctx set-nodes stale-net"), "{lines:?}");
    }

    #[test]
    fn unset_clears_current_and_leaves_previous_and_networks_intact() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        write_config(
            &config_path,
            "current = \"devnet-1/alpha\"\nprevious = \"devnet-1/beta\"\n\n",
        );

        run(parse(&["unset", "--config", config_path.to_str().unwrap()])).unwrap();

        let context = Context::load(Some(&config_path)).unwrap();
        assert_eq!(context.config().current, None);
        assert_eq!(context.config().previous.as_deref(), Some("devnet-1/beta"));
        assert!(context.config().networks.contains_key("devnet-1"));
    }

    #[test]
    fn set_nodes_imports_a_two_node_map_and_names_both_in_the_success_line() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let args = SetNodesArgs {
            name: "devnet-1".to_string(),
            config: Some(config_path.clone()),
        };

        let message = import_nodes(&args, &mut &TWO_NODE_MAP[..]).unwrap();
        assert!(message.contains("Imported 2 nodes"), "{message}");
        assert!(message.contains("alpha"), "{message}");
        assert!(message.contains("beta"), "{message}");

        let context = Context::load(Some(&config_path)).unwrap();
        assert_eq!(context.config().networks["devnet-1"].nodes.len(), 2);
    }

    #[test]
    fn set_nodes_refuses_a_malformed_map_naming_stdin_and_leaves_the_file_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let original = "current = \"devnet-1\"\n";
        std::fs::write(&config_path, original).unwrap();
        let args = SetNodesArgs {
            name: "devnet-1".to_string(),
            config: Some(config_path.clone()),
        };

        let err = import_nodes(&args, &mut &b"not json"[..])
            .unwrap_err()
            .to_string();
        assert!(err.contains("<stdin>"), "{err}");

        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), original);
    }

    #[test]
    fn set_nodes_creates_an_unregistered_network_with_nodes_only_and_set_network_keeps_them() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let args = SetNodesArgs {
            name: "devnet-1".to_string(),
            config: Some(config_path.clone()),
        };
        import_nodes(&args, &mut &TWO_NODE_MAP[..]).unwrap();

        let context = Context::load(Some(&config_path)).unwrap();
        let network = &context.config().networks["devnet-1"];
        assert_eq!(network.dir, None);
        assert_eq!(network.nodes.len(), 2);

        run(parse(&[
            "set-network",
            "devnet-1",
            "--dir",
            "/networks/devnet-1",
            "--config",
            config_path.to_str().unwrap(),
        ]))
        .unwrap();

        let context = Context::load(Some(&config_path)).unwrap();
        let network = &context.config().networks["devnet-1"];
        assert_eq!(
            network.dir.as_deref(),
            Some(Path::new("/networks/devnet-1"))
        );
        assert_eq!(network.nodes.len(), 2);
    }

    #[test]
    fn a_second_import_with_one_node_fewer_drops_the_missing_node() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let args = SetNodesArgs {
            name: "devnet-1".to_string(),
            config: Some(config_path.clone()),
        };
        import_nodes(&args, &mut &TWO_NODE_MAP[..]).unwrap();

        const ONE_NODE_MAP: &[u8] =
            br#"{"alpha": {"public_ip": "203.0.113.7", "fqdn": "alpha.example.com"}}"#;
        import_nodes(&args, &mut &ONE_NODE_MAP[..]).unwrap();

        let context = Context::load(Some(&config_path)).unwrap();
        assert_eq!(
            context.config().networks["devnet-1"]
                .nodes
                .keys()
                .collect::<Vec<_>>(),
            ["alpha"]
        );
    }
}
