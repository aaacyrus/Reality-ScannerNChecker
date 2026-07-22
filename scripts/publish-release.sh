#!/usr/bin/env bash

set -euo pipefail

repo="${RELEASE_REPOSITORY:-aaacyrus/Reality-ScannerNChecker}"
project_name="reality-scanner-checker"
version="${1:-}"
notes_input="${2:-}"

if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]; then
  echo "usage: $0 vMAJOR.MINOR.PATCH path/to/bilingual-notes.md [build-directory]" >&2
  exit 2
fi

if [[ -z "$notes_input" ]]; then
  echo "a bilingual release-notes file is required" >&2
  exit 2
fi

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
version_number="${version#v}"
build_input="${3:-dist/builds/$version}"

if [[ "$notes_input" = /* ]]; then
  notes_file="$notes_input"
else
  notes_file="$project_root/$notes_input"
fi

if [[ "$build_input" = /* ]]; then
  build_dir="$build_input"
else
  build_dir="$project_root/$build_input"
fi

if [[ ! -f "$notes_file" ]]; then
  echo "release-notes file not found: $notes_file" >&2
  exit 1
fi

if ! grep -Eq '^## 繁體中文[[:space:]]*$' "$notes_file"; then
  echo "release notes must contain the heading: ## 繁體中文" >&2
  exit 1
fi

if ! grep -Eq '^## English[[:space:]]*$' "$notes_file"; then
  echo "release notes must contain the heading: ## English" >&2
  exit 1
fi

if [[ "$(head -n 1 "$notes_file")" != "# Reality Scanner & Checker $version" ]]; then
  echo "release notes must start with the versioned title: # Reality Scanner & Checker $version" >&2
  exit 1
fi

cd "$project_root"
if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "refusing to publish: commit all source changes first" >&2
  exit 1
fi

branch="$(git symbolic-ref --quiet --short HEAD || true)"
if [[ -z "$branch" ]]; then
  echo "refusing to publish: detached HEAD is not supported" >&2
  exit 1
fi

upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)"
if [[ -z "$upstream" ]]; then
  echo "refusing to publish: branch $branch has no upstream; push it first" >&2
  exit 1
fi

upstream_remote="$(git config --get "branch.$branch.remote")"
git fetch --quiet "$upstream_remote"
commit_sha="$(git rev-parse HEAD)"
upstream_sha="$(git rev-parse '@{upstream}')"
if [[ "$commit_sha" != "$upstream_sha" ]]; then
  echo "refusing to publish: local HEAD is not identical to $upstream" >&2
  exit 1
fi

assets=(
  "$build_dir/${project_name}_${version_number}_linux_386"
  "$build_dir/${project_name}_${version_number}_linux_amd64"
  "$build_dir/${project_name}_${version_number}_linux_arm64"
  "$build_dir/${project_name}_${version_number}_darwin_amd64"
  "$build_dir/${project_name}_${version_number}_darwin_arm64"
  "$build_dir/${project_name}_${version_number}_windows_386.exe"
  "$build_dir/${project_name}_${version_number}_windows_amd64.exe"
  "$build_dir/${project_name}_${version_number}_windows_arm64.exe"
  "$build_dir/BUILD_INFO.txt"
  "$build_dir/LICENSE"
  "$build_dir/SHA256SUMS"
)

for asset in "${assets[@]}"; do
  if [[ ! -f "$asset" ]]; then
    echo "required build file not found: $asset" >&2
    exit 1
  fi
done

if ! grep -Fqx "Version: $version" "$build_dir/BUILD_INFO.txt"; then
  echo "BUILD_INFO.txt does not match release version $version" >&2
  exit 1
fi

if ! grep -Fqx "Commit: $commit_sha" "$build_dir/BUILD_INFO.txt"; then
  echo "BUILD_INFO.txt was not built from current pushed commit $commit_sha" >&2
  exit 1
fi

(
  cd "$build_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum --check SHA256SUMS
  else
    shasum -a 256 --check SHA256SUMS
  fi
)

gh auth status --hostname github.com >/dev/null
local_repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
if [[ "$local_repo" != "$repo" ]]; then
  echo "refusing to publish: local checkout is $local_repo, expected $repo" >&2
  exit 1
fi

visibility="$(gh repo view "$repo" --json visibility --jq .visibility)"
if [[ "$visibility" != "PRIVATE" ]]; then
  echo "refusing to publish: $repo is $visibility, not PRIVATE" >&2
  exit 1
fi

if gh api "repos/$repo/git/ref/tags/$version" >/dev/null 2>&1; then
  tag_commit="$(gh api "repos/$repo/commits/$version" --jq .sha)"
  if [[ "$tag_commit" != "$commit_sha" ]]; then
    echo "refusing to publish: tag $version points to $tag_commit, not $commit_sha" >&2
    exit 1
  fi
fi

echo "Repository: $repo (PRIVATE)"
echo "Release:    $version"
echo "Notes:      $notes_file"
echo "Files to upload:"
for asset in "${assets[@]}"; do
  echo "  - $(basename "$asset")"
done

read -r -p "Type $version to upload these files to GitHub Release: " confirmation
if [[ "$confirmation" != "$version" ]]; then
  echo "cancelled"
  exit 1
fi

release_flags=()
if [[ "$version" == *-* ]]; then
  release_flags+=(--prerelease)
fi

if gh release view "$version" --repo "$repo" >/dev/null 2>&1; then
  gh release edit "$version" \
    --repo "$repo" \
    --title "$version" \
    --notes-file "$notes_file"
  gh release upload "$version" "${assets[@]}" --repo "$repo" --clobber
else
  gh release create "$version" "${assets[@]}" \
    --repo "$repo" \
    --target "$commit_sha" \
    --title "$version" \
    --notes-file "$notes_file" \
    "${release_flags[@]}"
fi

gh release view "$version" --repo "$repo" --json url --jq .url
