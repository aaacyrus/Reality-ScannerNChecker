#!/usr/bin/env bash

set -euo pipefail

project_name="reality-scanner-checker"
version="${1:-}"

if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]; then
  echo "usage: $0 vMAJOR.MINOR.PATCH [output-directory]" >&2
  exit 2
fi

output_input="${2:-dist/builds/$version}"

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"

cd "$project_root"

if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "refusing to build: commit all source changes first" >&2
  exit 1
fi

branch="$(git symbolic-ref --quiet --short HEAD || true)"
if [[ -z "$branch" ]]; then
  echo "refusing to build: detached HEAD is not supported" >&2
  exit 1
fi

upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)"
if [[ -z "$upstream" ]]; then
  echo "refusing to build: branch $branch has no upstream; push it first" >&2
  exit 1
fi

upstream_remote="$(git config --get "branch.$branch.remote")"
git fetch --quiet "$upstream_remote"

commit_sha="$(git rev-parse HEAD)"
upstream_sha="$(git rev-parse '@{upstream}')"
if [[ "$commit_sha" != "$upstream_sha" ]]; then
  echo "refusing to build: local HEAD is not identical to $upstream; push and synchronize first" >&2
  exit 1
fi

if [[ "$output_input" = /* ]]; then
  output_dir="$output_input"
else
  output_dir="$project_root/$output_input"
fi

mkdir -p "$output_dir"

build_time="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
go_version="$(go version)"
cp LICENSE "$output_dir/LICENSE"
cat > "$output_dir/BUILD_INFO.txt" <<EOF
Project: Reality Scanner & Checker
Version: $version
Commit: $commit_sha
Branch: $branch
Built at: $build_time
Toolchain: $go_version
EOF

targets=(
  "linux 386"
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
  "windows 386"
  "windows amd64"
  "windows arm64"
)
build_files=()
version_number="${version#v}"

for target in "${targets[@]}"; do
  read -r goos goarch <<<"$target"

  binary_name="${project_name}_${version_number}_${goos}_${goarch}"

  if [[ "$goos" == "windows" ]]; then
    binary_name+=".exe"
  fi

  echo "Building $goos/$goarch"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o "$output_dir/$binary_name" .

  build_files+=("$binary_name")
done

(
  cd "$output_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${build_files[@]}" BUILD_INFO.txt LICENSE > SHA256SUMS
  else
    shasum -a 256 "${build_files[@]}" BUILD_INFO.txt LICENSE > SHA256SUMS
  fi
)

echo "Build outputs created in $output_dir"
