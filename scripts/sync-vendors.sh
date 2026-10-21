#!/usr/bin/env bash
# Recreate third-party research clones at auditable pinned commit SHAs.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
manifest="$root/vendors/references.lock.tsv"
command -v git >/dev/null || { echo 'git is required' >&2; exit 1; }

while IFS=$'\t' read -r name repo sha license; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  [[ "$name" =~ ^[a-z0-9][a-z0-9-]+$ ]] || { echo "invalid vendor $name" >&2; exit 1; }
  [[ "$repo" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ]] || { echo "invalid repo $repo" >&2; exit 1; }
  [[ "$sha" =~ ^[a-f0-9]{40}$ ]] || { echo "invalid commit $name: $sha" >&2; exit 1; }
  target="$root/vendors/$name"
  if [[ ! -d "$target/.git" ]]; then
    [[ ! -e "$target" ]] || { echo "refusing to overwrite $target" >&2; exit 1; }
    echo "Cloning $repo into vendors/$name..."
    git clone --quiet --depth=1 --no-checkout --filter=blob:none --sparse "https://github.com/$repo.git" "$target"
  fi
  actual_repo="$(git -C "$target" remote get-url origin)"
  [[ "$actual_repo" == "https://github.com/$repo.git" ]] || { echo "wrong origin: $name" >&2; exit 1; }
  git -C "$target" fetch --quiet --depth=1 --filter=blob:none origin "$sha"
  if [[ -n "$(git -C "$target" status --porcelain --untracked-files=normal)" ]]; then
    echo "Refusing to reset modified reference tree $name" >&2
    exit 1
  fi
  git -C "$target" checkout --quiet --detach "$sha"
  echo "OK $name @ $(git -C "$target" rev-parse --short=12 HEAD) [$license]"
done < "$manifest"
