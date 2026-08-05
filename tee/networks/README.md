# Network directories

One directory per network: the committable identity of a founded (or
foundable) network. The authored inputs live under `inputs/`;
`seismic-tee-network manifest assemble` derives the artifact set from them
at the top level. Everything top-level is hash-pinned by
`network-manifest.json` — whose SHA-256 is the network's `network_id` —
and everything under `inputs/` is provenance. The founding workflow lives
in the tee README ("Creating a new network").

![How assemble derives the artifact set, what pins what, and where the
genesis ceremony picks it up](network-dir.png)

The diagram source is `network-dir.excalidraw`; re-render the PNG when
editing it.

Directories are committed because the directory is everything needed to
(re)configure, join, or debug that network later, and its manifest is the
network's immutable identity — a founded network's `network_id` must
never drift. The `nodes/` descriptors are runtime output (live IPs) and
stay gitignored.

## example-devnet

A **template, not a deployed network** — no cohort runs under this
identity. Two intended uses:

- **Found a throwaway test devnet.** The artifact set is assembled and
  valid, so `up --network … --count N` → `configure` → `genesis-ceremony`
  brings up a working cohort. If two such cohorts might ever run at once,
  give each its own directory with a distinct `namespace` and `chainId`
  (cohorts sharing a `network_id` can cross-replay attestation
  transcripts). Note `inputs/measurements.json` snapshots a specific
  image build — when the deployed VHD moves on, refresh it and
  re-assemble (`up --network` refuses on a pin/policy mismatch).
- **Start a real network.** Don't reuse or copy this directory — run
  `manifest init <new-dir>` and author fresh inputs. `namespace` (the BLS
  signature domain separator) and `chainId` must be unique per network
  that matters.
