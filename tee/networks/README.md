# Network directories

One directory per network: the committable identity of a founded
network. The authored inputs live under `inputs/`, joined mid-founding by
the harvested facts (`inputs/harvest/` — the cohort's TEE-born founding
keys and their quotes); `seismic-tee-network manifest assemble` derives
the artifact set from them at the top level. Everything top-level is
hash-pinned by `network-manifest.json` — whose SHA-256 is the network's
`network_id` — and everything under `inputs/` is provenance.

```text
tee/networks/<name>/
├── inputs/                       provenance (authored + harvested)
│   ├── reth-genesis.json           authored: policy-free EL genesis
│   ├── summit-genesis.toml         authored: consensus parameter choices
│   ├── measurements.json           authored: raw PCRs from `make measure`,
│   │                               measurement_id stamped by `init`
│   ├── founder-withdrawal-credentials.json
│   │                               authored: one address per founding
│   │                               node, in node-name order
│   └── harvest/                    written by `network harvest`
│       └── <node>.json             founding pubkeys + quote + verification
├── nodes/                        runtime infra state (gitignored)
│   ├── <node>.json                 descriptor from `up --network` (live IP)
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

![How assemble derives the artifact set, what pins what, and where the
genesis ceremony picks it up](network-dir.svg)

Directories are committed because the directory is everything needed to
(re)configure, join, or debug that network later, and its manifest is the
network's immutable identity — a founded network's `network_id` must
never drift. The `nodes/` descriptors are runtime output (live IPs) and
stay gitignored.

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

To found any network, throwaway or real, don't reuse or copy this
directory: run `manifest init <new-dir>`, author fresh inputs, and follow
the founding workflow in the tee README. `namespace` (the BLS signature
domain separator) and `chainId` must be unique per network that matters
(cohorts sharing them can cross-replay signatures).
