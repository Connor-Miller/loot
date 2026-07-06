#!/usr/bin/env bash
# Publish the concurrent-agents (CA) epic as GitHub issues.
# Requires an authenticated GitHub CLI (`gh auth login`).
# Creates issues in dependency order so "Blocked by" references real issue numbers.
# Portable to bash 3.2 (macOS system /bin/bash) — no associative arrays.
set -euo pipefail
cd "$(dirname "$0")"

command -v gh >/dev/null || { echo "error: gh CLI not found — https://cli.github.com/"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "error: gh not authenticated — run: gh auth login"; exit 1; }

REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo Connor-Miller/loot)"
echo "Creating issues in $REPO"

# Labels (idempotent)
gh label create concurrent-agents --repo "$REPO" --color 1d76db \
  --description "Concurrent-agent devX epic (docks, harbor, buoys, machine output)" 2>/dev/null || true
gh label create enhancement --repo "$REPO" --color a2eeef 2>/dev/null || true

SLICES=(CA1 CA2 CA3 CA4)

title_for() {
  case "$1" in
    CA1) printf '%s' "CA1 — Docks: isolated working trees over one object store" ;;
    CA2) printf '%s' "CA2 — Local dock merge + harbor convention" ;;
    CA3) printf '%s' "CA3 — Porcelain + JSON output for reconciliation verbs" ;;
    CA4) printf '%s' "CA4 — Buoys: navigational-role resolver over the attestation lane" ;;
  esac
}

file_for() {
  case "$1" in
    CA1) printf '%s' "CA1-docks.md" ;;
    CA2) printf '%s' "CA2-dock-merge-harbor.md" ;;
    CA3) printf '%s' "CA3-porcelain-machine-output.md" ;;
    CA4) printf '%s' "CA4-buoy-resolver.md" ;;
  esac
}

# Space-separated blocker slice ids (empty = none).
blockers_for() {
  case "$1" in
    CA2) printf '%s' "CA1" ;;
    *)   printf '%s' "" ;;
  esac
}

for s in "${SLICES[@]}"; do
  file="$(file_for "$s")"
  # body = file contents with its own "## Blocked by" section stripped...
  body="$(awk 'BEGIN{p=1} /^## Blocked by/{p=0} p{print}' "$file")"
  # ...then regenerated with real issue numbers.
  body+=$'\n\n## Blocked by\n\n'
  blockers="$(blockers_for "$s")"
  if [ -z "$blockers" ]; then
    body+=$'- None — can start immediately.\n'
  else
    for b in $blockers; do
      eval "bnum=\${NUM_$b:-}"
      btitle="$(title_for "$b")"
      body+="- #${bnum} (${b} — ${btitle#* — })"$'\n'
    done
  fi
  url="$(gh issue create --repo "$REPO" \
        --title "$(title_for "$s")" \
        --label concurrent-agents --label enhancement \
        --body "$body")"
  eval "NUM_$s=$(basename "$url")"
  echo "  ${s} -> ${url}"
done

echo "Done. Created ${#SLICES[@]} issues."
