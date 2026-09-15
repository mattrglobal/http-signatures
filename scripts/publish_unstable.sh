#!/bin/bash

# This script handles the publishing of the current
# commit's library as an unstable package
#
# Example if the current package.json version reads 0.1.0
# then the unstable release of 0.1.1-unstable.(current git commit reference)

set -euo pipefail

# Add dev dependencies to current path
export PATH="$PATH:node_modules/.bin"

# Patch version the current package. Berry's `yarn version` never creates a git tag,
# so Yarn 1's `--no-git-tag-version` flag is obsolete rather than renamed.
yarn version patch

# Fetch the current version from the package.json
new_version=$(node -pe "require('./package.json').version")

# Fetch the new unstable version
new_unstable_version=$new_version"-unstable.$(git rev-parse --short HEAD)"

# Write the unstable version, then publish it under the unstable tag.
# `yarn npm publish` has no `--new-version`, so the version is set as its own step.
yarn version "$new_unstable_version"
yarn npm publish --tag unstable

# Reset changes to the package.json
git checkout -- package.json
