# Release a version

Run conventional change log generation, manually adjust the changelog if need (this will not be overriten when releasing
next time). Commit, and open a pull request.

```
# Create a new release branch
git checkout -b [initals]/release-[version]

# Bump the version and generate the changelog addtions
yarn version --no-git-tag-version --[major|minor|patch]

# Manually edit the changelog if needed
vim CHANGELOG.md

# Commit package.json and CHANGELOG.md
git commit -a -m "chore(release): publish [version]"

# Push the branch to remote
git push -u origin [initials]/release-[version]

# Open a pull request into master
open https://github.com/mattrglobal/http-signatures/pull/new/[initials]/release-[version]

```

Important: This pull request must be updated if any other pr's are pushed to master before merging.

After merging this PR the release workflow should run automatically and publish to npm.
