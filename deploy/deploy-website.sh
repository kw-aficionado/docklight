#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

dry_run=0
if [[ "${1:-}" == "--dry-run" && $# -eq 1 ]]; then
	dry_run=1
elif [[ $# -ne 0 ]]; then
	printf 'Usage: %s [--dry-run]\n' "$0" >&2
	exit 2
fi

target="${DOCKLIGHT_SITE_TARGET:-}"
if [[ -z "$target" ]]; then
	printf 'Set DOCKLIGHT_SITE_TARGET to the rsync destination for the Docklight site.\n' >&2
	exit 2
fi

go run ./cmd/docs-gen
go run ./cmd/apps-gen

generated_paths=(website/docs website/apps website/icons)
if ! git diff --quiet HEAD -- "${generated_paths[@]}"; then
	printf 'Generated website files differ from HEAD; review and commit them before deploying.\n' >&2
	git status --short -- "${generated_paths[@]}"
	exit 1
fi
untracked="$(git ls-files --others --exclude-standard -- "${generated_paths[@]}")"
if [[ -n "$untracked" ]]; then
	printf 'Generated website files are not tracked yet; review and commit them before deploying.\n%s\n' "$untracked" >&2
	exit 1
fi

if ! command -v rsync >/dev/null 2>&1; then
	printf 'rsync is required to publish the static site.\n' >&2
	exit 1
fi

rsync_args=(-av --checksum)
if [[ "$dry_run" -eq 1 ]]; then
	rsync_args+=(--dry-run)
fi
printf 'Publishing website/ to %s\n' "$target"
rsync "${rsync_args[@]}" website/ "$target"
