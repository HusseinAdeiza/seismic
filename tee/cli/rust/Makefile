# Convenience targets for the Rust deploy CLI. Self-contained on purpose: this
# directory is meant to be liftable — the public operator repo is extracted
# from `common` + `node` — so no recipe here reaches outside the workspace.
#
# Run from anywhere with `make -C tee/cli/rust <target>`.

.PHONY: help check fmt fmt-check lint test locked

help:
	@echo "Targets (the Rust deploy CLI, tee/cli/rust):"
	@echo "  check       fmt-check + lint + test (CI runs this)"
	@echo "  fmt         cargo +nightly fmt (writes changes)"
	@echo "  fmt-check   cargo +nightly fmt --check"
	@echo "  lint        cargo clippy, warnings denied"
	@echo "  test        cargo nextest run"
	@echo "  locked      assert Cargo.lock needs no re-resolve (run before check)"

check: fmt-check lint test

# Nightly, like every other Seismic Rust repo: one `cargo +nightly fmt --all`
# formats any checkout in the workspace, whichever repo you happen to be in.
fmt:
	cargo +nightly fmt --all

fmt-check:
	cargo +nightly fmt --all --check

lint:
	RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --all-features

test:
	cargo nextest run --workspace

# Assert that Cargo.lock already agrees with Cargo.toml: --locked makes cargo
# fail rather than re-resolve and rewrite it. Catches a dependency added
# without committing the regenerated lock, a hand-edited lock, and a bumped
# enclave rev that never reached the lock.
#
# Must run BEFORE `check`, never after: clippy and nextest silently rewrite a
# stale lock, so a trailing run of this always passes and guards nothing. Kept
# out of `check` because locally you usually do want cargo to update the lock;
# CI runs it first, so what gets built there is the committed resolution.
locked:
	cargo metadata --locked --format-version 1 > /dev/null
