#!/usr/bin/env bash
set -euo pipefail

# Publish the already-built public artifacts to a GitHub release.
#
# Invoked by `make github-release` AFTER `make public-release` has produced the
# cross-platform tarballs in build/dist-public/. This script does the GitHub
# half: it creates (and pushes) the git tag if missing, pulls the release notes
# from CHANGELOG.md, and creates the GitHub release, uploading every artifact.
#
# Usage (normally via `make github-release`):
#   github-release.sh
#
# Env / make vars:
#   VERSION          = release tag/title (default: parsed from pkg/cli/version.go)
#   PUBLIC_DIST_DIR  = artifact dir (default: build/dist-public)
#   CHANGELOG        = changelog path (default: CHANGELOG.md)
#   TAG_TARGET       = commit-ish the new tag points at (default: HEAD)
#
# Published versions are immutable: package recipes pin their asset hashes.
# Bump VERSION to ship changed binaries; never replace an existing release.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION_FILE="$ROOT/pkg/cli/version.go"
PUBLIC_DIST_DIR="${PUBLIC_DIST_DIR:-build/dist-public}"
CHANGELOG="${CHANGELOG:-CHANGELOG.md}"
TAG_TARGET="${TAG_TARGET:-HEAD}"

die()  { printf '\033[31m[!] %s\033[0m\n' "$*" >&2; exit 1; }
info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }

command -v gh  >/dev/null 2>&1 || die "gh CLI not found — install GitHub CLI (https://cli.github.com/)."
command -v git >/dev/null 2>&1 || die "git not found."

VERSION="${VERSION:-}"
if [ -z "$VERSION" ]; then
  [ -f "$VERSION_FILE" ] || die "version file not found: $VERSION_FILE"
  VERSION="$(grep -E '^[[:space:]]*Version[[:space:]]*=' "$VERSION_FILE" | head -1 | cut -d '"' -f 2)"
fi
[ -n "$VERSION" ] || die "could not determine VERSION"
if gh release view "$VERSION" >/dev/null 2>&1; then
  die "release $VERSION already exists; bump VERSION instead of replacing package-pinned assets"
fi

# --- Release notes from CHANGELOG.md -----------------------------------------
# Grab the block from the `## [<version>]` header up to (not including) the next
# `## [` section header.
[ -f "$CHANGELOG" ] || die "changelog not found: $CHANGELOG"
notes_file="$(mktemp)"
trap 'rm -f "$notes_file"' EXIT
awk -v ver="$VERSION" '
  index($0, "## [" ver "]") == 1 { grab=1; next }
  grab && /^## \[/ { exit }
  grab { print }
' "$CHANGELOG" > "$notes_file"
[ -s "$notes_file" ] || die "no CHANGELOG.md section found for $VERSION"

# --- Artifacts ----------------------------------------------------------------
# *.zip is as load-bearing as *.tar.gz: `make public-release` archives Windows
# targets as zip (tar.gz needs a third-party tool on older Windows), so a
# tar.gz-only glob publishes a release with no Windows artifact at all - which
# is what happened to v0.4.3.
artifacts=()
while IFS= read -r f; do artifacts+=("$f"); done < <(
  ls "$PUBLIC_DIST_DIR"/*.tar.gz "$PUBLIC_DIST_DIR"/*.zip \
     "$PUBLIC_DIST_DIR"/checksums.txt "$PUBLIC_DIST_DIR"/metadata.json 2>/dev/null
)
[ "${#artifacts[@]}" -gt 0 ] || die "no artifacts in $PUBLIC_DIST_DIR/ — run 'make public-release' first"

# checksums.txt is generated from every archive `make public-release` built, so
# it is the authority on what this release is supposed to carry. Cross-checking
# the upload set against it turns "an entire platform is silently absent" into a
# hard error, whatever archive format a future target introduces.
missing=()
while IFS= read -r name; do
  [ -n "$name" ] || continue
  case " ${artifacts[*]} " in
    *" $PUBLIC_DIST_DIR/$name "*) ;;
    *) missing+=("$name") ;;
  esac
done < <(awk '{ print $NF }' "$PUBLIC_DIST_DIR/checksums.txt" 2>/dev/null)
[ "${#missing[@]}" -eq 0 ] || die "checksums.txt lists artifacts that would not be uploaded: ${missing[*]}"

# --- Git tag (create + push if missing) --------------------------------------
if git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
  info "git tag $VERSION already exists locally"
else
  info "creating annotated git tag $VERSION at $TAG_TARGET..."
  git tag -a "$VERSION" -m "Release $VERSION" "$TAG_TARGET"
fi

if git ls-remote --exit-code --tags origin "refs/tags/$VERSION" >/dev/null 2>&1; then
  info "git tag $VERSION already present on origin"
else
  info "pushing tag $VERSION to origin..."
  git push origin "refs/tags/$VERSION"
fi

# --- GitHub release ---------------------------------------------------------
# If another publisher created the release meanwhile, create fails instead of
# replacing its assets.
info "creating GitHub release $VERSION..."
gh release create "$VERSION" "${artifacts[@]}" --title "$VERSION" --notes-file "$notes_file"

info "GitHub release $VERSION published (${#artifacts[@]} artifacts)."
