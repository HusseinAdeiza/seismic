# Network directories

One directory per network: the committable identity of a founded
network. The authored inputs live under `inputs/`, joined mid-founding by
the harvested facts (`inputs/harvest/` — the cohort's TEE-born founding
keys and their quotes); `seismic-tee-network assemble` derives
the artifact set from them at the top level. Everything top-level is
hash-pinned by `network-manifest.json` — whose SHA-256 is the network's
`network_id` — and everything under `inputs/` is provenance. What the
manifest's fields mean, what `network_id` transitively commits to, and why it
hashes the exact file bytes:
[the network manifest doc](https://github.com/SeismicSystems/seismic/blob/main/docs/tee/network-manifest.md).

A committed directory is auditable as a whole, by anyone, offline:
`seismic-tee-network verify-harvest <dir>` re-verifies its founding — every
archived quote against its own collateral snapshot and the policy the
manifest pins, and the archive against the validator set the summit
genesis seats.

```text
tee/networks/<name>/
├── inputs/                       provenance (authored + harvested)
│   ├── reth-genesis.json           authored: policy-free EL genesis
│   ├── summit-genesis.toml         authored: consensus parameter choices
│   ├── measurements.json           authored: raw PCRs from `make measure`,
│   │                               carrying its measurement_id
│   ├── founder-withdrawal-credentials.json
│   │                               authored: one address per founding
│   │                               node, in node-name order
│   └── harvest/                    written by `network harvest`
│       ├── <node>.json             founding pubkeys + quote + verification
│       └── dcap-collateral/
│           └── <node>.json         the DCAP collateral that verification
│                                   used, so the quote stays verifiable
│                                   once Intel's live collateral ages past it
├── nodes/                        runtime infra state (gitignored)
│   ├── nodes.json                  the cohort's descriptor map: the Pulumi
│   │                               stack's `nodes` output, saved as-is
│   │                               (node name → live IP + fqdn)
│   └── bootnodes.json              founding enode set from `configure`
│
│                                 artifact set: derived by `assemble`, every
│                                 file below hash-pinned by the manifest
├── network-manifest.json           SHA-256 of these bytes = network_id
├── reth-genesis.json               input + compiled registry storage
├── summit-genesis.toml             input + eth_genesis_hash + validator set
└── measurement-policy-bootstrap.json
                                    allowlist promoted from measurements
```

The committed `summit-genesis.toml` is a founding-era snapshot: its
validator entries carry the IPs the cohort had at assemble time, which
are network topology, not identity — summit's config digest (the
manifest's pin) excludes them, and peers authenticate by the pinned
ed25519 keys. `seismic-tee-network configure` therefore splices each
box's current descriptor IP into the copy it delivers, touching no other
field, and then asserts the launch against the pins (reth block 0,
holder keys). The committed file itself never changes after assemble.

![How assemble derives the artifact set, what pins what, and how each
configure run delivers and asserts it](network-dir.svg)

The same founding from each node's side — why keys are born before the
manifest, and how the boot chain is sequenced to allow it — is
[the network founding doc](https://github.com/SeismicSystems/seismic/blob/main/docs/tee/network-founding.md).

Directories are committed because the directory is everything needed to
(re)configure, join, or debug that network later, and its manifest is the
network's immutable identity — a founded network's `network_id` must
never drift. The `nodes/` map is runtime output (live IPs) and stays
gitignored.

Throwaway foundings go in a `tmp-*` directory instead — those are
gitignored wholesale, so a scratch cohort can be founded, torn down, and
`rm -rf`'d without touching git (the copy-pasteable recipe is
[../docs/runbook-devnet.md](../docs/runbook-devnet.md)). If a throwaway
turns out to matter, renaming the directory is enough to commit it —
`network_id` is minted from the manifest bytes, not the path — but the
manifest keeps the `tmp-*` name it was assembled under (the name is part
of those bytes), so a network you already suspect will matter deserves a
real directory name from the start.

## example-devnet

[example-devnet/](example-devnet/) is a committed example of the shape (minus the
gitignored `nodes/` and, having never been founded from a live cohort,
`inputs/harvest/` and the founder credentials — see below).

A **schema example, not a runnable founding** — no cohort runs under this
identity, and none can be brought up from it: `assemble` pins the
founding validator set from a live harvest, so producing an artifact set
takes a provisioned cohort, and this directory's committed artifacts
carry an empty validator set no founding produces. It exists to document
the directory shape — the artifacts are internally consistent (every
manifest pin matches its file), so schema-level tooling can be exercised
against it.

That consistency is enforced, not just claimed: `make test-drift` re-runs
the deploy gates over every committed network directory, so an example
that falls behind the admission compiler or the genesis-header encoding
fails CI instead of misleading a reader.

To found any network, throwaway or real, don't reuse or copy this
directory: run `init <new-dir>`, author fresh inputs, and follow
the founding workflow in the tee README. Start the summit genesis from
[`summit-genesis-starter.toml`](summit-genesis-starter.toml) (in this
directory; a drift test pins its parameter set against summit's).
`namespace` (the BLS signature domain separator) and `chainId` must be
unique per network that matters (cohorts sharing them can cross-replay
signatures).
