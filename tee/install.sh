#!/bin/sh
# Installs a prebuilt `seismic-tee` — the Seismic TEE deploy CLI — from this
# repo's GitHub releases.
#
# While the repo is private, the script and the release assets both need a
# GitHub login, so the one-liner goes through `gh`:
#
#   gh api -H 'Accept: application/vnd.github.raw' \
#       repos/SeismicSystems/deploy/contents/tee/install.sh | sh
#
# The public form is the same script with its `gh` branch idle:
#
#   curl -fsSL https://raw.githubusercontent.com/SeismicSystems/deploy/main/tee/install.sh | sh
#
# The script has one fork. If `gh` is on PATH and logged in (a GH_TOKEN in
# the environment counts, which is how CI runs it), every network request —
# listing the releases, downloading the tarball and SHA256SUMS — goes through
# gh, which is what works while the repo is private. Otherwise the same
# requests go through plain curl against the public API and download URLs,
# for the day the repo is public. After the download the two paths are
# identical.
#
# What it does: picks the release, downloads the tarball for this machine and
# the release's SHA256SUMS, checks the tarball against it, verifies the
# binary's build provenance with `gh attestation` when `gh` can, and installs
# `seismic-tee` into ~/.local/bin. Releases are tagged `seismic-tee/v<X.Y.Z>`
# (versions) and `seismic-tee/main-<sha>` (a prerelease per merge to main);
# the repo hosts other components too, so "Latest" is never consulted — the
# newest release under the prefix is.
#
# Options, as flags or environment variables:
#
#   --version <V>   SEISMIC_TEE_VERSION      X.Y.Z or vX.Y.Z (a release),
#                                            main-<sha> (a prerelease), or
#                                            main (the newest prerelease).
#                                            Default: the newest release.
#   --to <DIR>      SEISMIC_TEE_INSTALL_DIR  Default: ~/.local/bin
#                   SEISMIC_TEE_REPO         Default: SeismicSystems/deploy
#
# Prebuilt for linux_amd64, linux_arm64 and darwin_arm64; anything else is
# told to build from source. POSIX sh: nothing here needs bash.
set -eu

REPO=${SEISMIC_TEE_REPO:-SeismicSystems/deploy}
VERSION=${SEISMIC_TEE_VERSION:-}
INSTALL_DIR=${SEISMIC_TEE_INSTALL_DIR:-$HOME/.local/bin}
PREFIX=seismic-tee/
BIN=seismic-tee

# Color is for a human at a terminal: off when stderr is redirected or piped,
# when NO_COLOR is set, and for a terminal that cannot render it. --no-color
# clears it below, once the arguments are parsed. \033 stays within POSIX
# printf's octal escapes; \e is a GNU extension dash does not read.
if [ -t 2 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != dumb ]; then
    red=$(printf '\033[1;31m')
    plain=$(printf '\033[0m')
else
    red=
    plain=
fi

say() { printf '%s\n' "$*" >&2; }
fail() {
    say "${red}error:${plain} $*"
    exit 1
}
usage() {
    say "usage: install.sh [--version X.Y.Z|vX.Y.Z|main-<sha>|main] [--to DIR] [--no-color]"
    say "  SEISMIC_TEE_VERSION, SEISMIC_TEE_INSTALL_DIR and SEISMIC_TEE_REPO set the same."
}

while [ $# -gt 0 ]; do
    case $1 in
        --version)
            [ $# -ge 2 ] || fail "--version needs a value"
            VERSION=$2
            shift 2
            ;;
        --version=*) VERSION=${1#--version=}; shift ;;
        --to)
            [ $# -ge 2 ] || fail "--to needs a value"
            INSTALL_DIR=$2
            shift 2
            ;;
        --to=*) INSTALL_DIR=${1#--to=}; shift ;;
        --no-color)
            red=
            plain=
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage
            fail "unknown option: $1"
            ;;
    esac
done

# --- Which build -------------------------------------------------------------

os=$(uname -s)
arch=$(uname -m)
case $os in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) fail "unsupported operating system: $os" ;;
esac
case $arch in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) fail "unsupported architecture: $arch" ;;
esac
platform=${os}_${arch}
case $platform in
    linux_amd64 | linux_arm64 | darwin_arm64) ;;
    *) fail "no prebuilt $BIN for $platform; build it from source: cargo install --git https://github.com/$REPO $BIN" ;;
esac

# --- Transport ---------------------------------------------------------------

have_gh=false
if command -v gh > /dev/null 2>&1 && gh auth status > /dev/null 2>&1; then
    have_gh=true
else
    command -v curl > /dev/null 2>&1 || fail "curl is required (or gh, logged in)"
fi

# GET a GitHub API path; JSON on stdout.
api() {
    if $have_gh; then
        gh api "$1"
    else
        curl -fsSL -H 'Accept: application/vnd.github+json' "https://api.github.com/$1"
    fi
}

# Download release asset $1 of $tag into $tmp.
download() {
    if $have_gh; then
        gh release download "$tag" --repo "$REPO" --pattern "$1" --dir "$tmp" ||
            fail "could not download $1 from release $tag of $REPO"
    else
        curl -fsSL -o "$tmp/$1" "https://github.com/$REPO/releases/download/$tag/$1" ||
            fail "could not download $1 from release $tag of $REPO — if the repo is private, log in with \`gh auth login\` and re-run"
    fi
}

# The newest release (the API lists newest first) whose tag starts with $1.
newest_tag() {
    api "repos/$REPO/releases?per_page=100" |
        grep -o "\"tag_name\": *\"$1[^\"]*\"" |
        head -n 1 |
        sed 's/.*"\([^"]*\)"$/\1/'
}

# --- Which release -----------------------------------------------------------

case $VERSION in
    "")
        tag=$(newest_tag "${PREFIX}v") || true
        [ -n "$tag" ] || fail "$REPO has no ${PREFIX}v* release"
        ;;
    main)
        tag=$(newest_tag "${PREFIX}main-") || true
        [ -n "$tag" ] || fail "$REPO has no ${PREFIX}main-* prerelease"
        ;;
    main-*) tag=$PREFIX$VERSION ;;
    v[0-9]*) tag=$PREFIX$VERSION ;;
    [0-9]*) tag=${PREFIX}v$VERSION ;;
    *) fail "unrecognized version: $VERSION (want X.Y.Z, vX.Y.Z, main-<sha> or main)" ;;
esac
version=${tag#"$PREFIX"}
asset=${BIN}_${version}_${platform}.tar.gz
say "installing $BIN $version ($platform) from $REPO release $tag"

# --- Download, check, install ------------------------------------------------

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

download "$asset"
download SHA256SUMS

expected=$(awk -v asset="$asset" '$2 == asset { print $1 }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || fail "SHA256SUMS of $tag lists no $asset"
if command -v sha256sum > /dev/null 2>&1; then
    actual=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
else
    actual=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)
fi
[ "$actual" = "$expected" ] || fail "$asset does not match SHA256SUMS: expected $expected, got $actual"

tar -xzf "$tmp/$asset" -C "$tmp" "$BIN"

# The tarball's checksum says the download is the release's; the attestation
# says the release's binary was built by this repo's workflow from the commit
# the release names. Verified when gh can (gh 2.49+, logged in), skipped with
# a note otherwise — never silently.
if $have_gh && gh attestation --help > /dev/null 2>&1; then
    gh attestation verify "$tmp/$BIN" --repo "$REPO" > /dev/null ||
        fail "$BIN from $tag has no valid build provenance attestation from $REPO"
    say "build provenance verified: attested by $REPO's release workflow"
else
    say "note: build provenance not verified (needs gh 2.49+, logged in); the checksum matched"
fi

mkdir -p "$INSTALL_DIR"
cp "$tmp/$BIN" "$INSTALL_DIR/$BIN.tmp.$$"
chmod 755 "$INSTALL_DIR/$BIN.tmp.$$"
mv -f "$INSTALL_DIR/$BIN.tmp.$$" "$INSTALL_DIR/$BIN"

say "installed $("$INSTALL_DIR/$BIN" --version) to $INSTALL_DIR/$BIN"
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) say "note: $INSTALL_DIR is not on your PATH; add it: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
