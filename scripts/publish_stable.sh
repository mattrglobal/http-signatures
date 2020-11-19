#!/bin/bash

# This script handling the publishing of the current
# commits library as an unstable package

# Example if the current package.json version reads 0.1.0
# then the release will be tagged with 0.1.0

# Add dev dependencies to current path
export PATH="$PATH:node_modules/.bin"

# Fetch the current version from the package.json
new_version=$(node -pe "require('./package.json').version")

# Version to this new unstable version
yarn publish --new-version $new_version