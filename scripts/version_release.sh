#!/bin/bash

# Creates a stable release commit and tag.
#
# Yarn 1's `yarn version --message` did four things in one step: bumped the version,
# ran the `version` lifecycle script, created the commit, and created the tag.
# Berry's `yarn version` only rewrites package.json — it runs no lifecycle script and
# performs no git operations at all — so each step is now explicit here.
#
# Usage: yarn version:release [major|minor|patch]

set -euo pipefail

strategy="${1:-}"
# Tolerate the legacy `--patch` flag form that Yarn 1 accepted.
strategy="${strategy#--}"

case "$strategy" in
  major | minor | patch) ;;
  *)
    echo "Usage: yarn version:release [major|minor|patch]" >&2
    exit 1
    ;;
esac

# Add dev dependencies to current path
export PATH="$PATH:node_modules/.bin"

# Refuse to run against uncommitted changes to the files this script rewrites.
# The bump below and the restore on the tag-exists path would otherwise sweep up
# or discard unrelated edits.
dirty=$(git status --porcelain -- package.json CHANGELOG.md)
if [ -n "$dirty" ]; then
  echo "package.json or CHANGELOG.md has uncommitted changes; commit or stash first." >&2
  exit 1
fi

# Bump the version in package.json. Berry never creates a git tag here.
yarn version "$strategy"

new_version=$(node -pe "require('./package.json').version")

# Fail before committing anything if the tag already exists, rather than leaving a
# release commit behind that has no corresponding tag.
if git rev-parse -q --verify "refs/tags/v${new_version}" >/dev/null; then
  echo "Tag v${new_version} already exists; aborting." >&2
  git checkout -- package.json
  exit 1
fi

# Regenerate the changelog. Berry does not run the `version` lifecycle script, so this
# is invoked directly rather than relying on the bump to trigger it.
yarn changelog

# --only limits the commit to these two paths. A bare `git commit` would also pick up
# anything else already staged, which Yarn 1's `yarn version` never did.
git commit --only package.json CHANGELOG.md -m "chore(release): publish"
git tag "v${new_version}"

echo "Created release commit and tag v${new_version}"
