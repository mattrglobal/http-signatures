#!/bin/bash

# This script handles the publishing of the current
# commit's library as a stable package
#
# Example if the current package.json version reads 0.1.0
# then the release will be tagged with 0.1.0

set -euo pipefail

# Add dev dependencies to current path
export PATH="$PATH:node_modules/.bin"

# Fetch the current version from the package.json
new_version=$(node -pe "require('./package.json').version")

# The version in package.json is already the one to publish (set by the release
# commit), so no bump happens here. `yarn npm publish` replaces Yarn 1's
# `yarn publish --new-version`, which no longer exists in Berry.
echo "Publishing ${new_version} to the stable tag"
yarn npm publish
