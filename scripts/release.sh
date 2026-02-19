#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage:
  ./scripts/release.sh <version> [--push]

examples:
  ./scripts/release.sh 0.2.1
  ./scripts/release.sh v0.2.1 --push

what it does:
  - updates version in plugin/spamblock/plugin.php
  - updates User-Agent version strings in plugin/spamblock/lib/spamcheck.php
  - commits the change
  - creates an annotated git tag v<version>
  - optionally pushes main + the tag (which triggers the GitHub Release workflow)
EOF
}

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 2
fi

version_input="$1"
shift

push=0
if [[ "${1-}" == "--push" ]]; then
  push=1
  shift
fi

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

version="${version_input#v}"
tag="v${version}"

if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: version must look like X.Y.Z (got: $version_input)" >&2
  exit 2
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

branch="$(git branch --show-current)"
if [[ "$branch" != "main" ]]; then
  echo "error: expected to be on branch 'main' (got: $branch)" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is not clean; commit or stash changes first" >&2
  exit 1
fi

if git rev-parse "$tag" >/dev/null 2>&1; then
  echo "error: tag already exists: $tag" >&2
  exit 1
fi

perl -pi -e "s/'version'\s*=>\s*'[^']+'/'version' => '$version'/" plugin/spamblock/plugin.php
perl -pi -e "s/User-Agent: spamblock\/[0-9]+\.[0-9]+\.[0-9]+/User-Agent: spamblock\/$version/g" plugin/spamblock/lib/spamcheck.php

git add plugin/spamblock/plugin.php plugin/spamblock/lib/spamcheck.php

git commit -m "chore(release): ${tag}"

git tag -a "$tag" -m "$tag"

echo "Created release commit + tag: $tag" >&2

echo "Next:" >&2
if [[ $push -eq 1 ]]; then
  git push origin main --follow-tags
else
  echo "  git push origin main --follow-tags" >&2
fi
