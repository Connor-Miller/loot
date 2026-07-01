#!/usr/bin/env bash
# Publish the loot improvement slices as GitHub issues.
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
gh label create lore-borrow --repo "$REPO" --color 5319e7 \
  --description "Improvement inspired by Epic's lore VCS" 2>/dev/null || true
gh label create enhancement --repo "$REPO" --color a2eeef 2>/dev/null || true

SLICES=(S1 S2 S3 S4 S5 S6 S7 S8 S9)

title_for() {
  case "$1" in
    S1) printf '%s' "S1 — Format versioning + compatibility gate" ;;
    S2) printf '%s' "S2 — Compress public content (Zstd)" ;;
    S3) printf '%s' "S3 — Signed changes: author in id + validity enforcement" ;;
    S4) printf '%s' "S4 — Attestation metadata lane" ;;
    S5) printf '%s' 'S5 — Object-level "wants" negotiation' ;;
    S6) printf '%s' "S6 — Resumable transfer" ;;
    S7) printf '%s' "S7 — Pluggable relay backend + S3 driver" ;;
    S8) printf '%s' "S8 — Sparse views (materialize-only)" ;;
    S9) printf '%s' "S9 — Relay fault-injection test harness" ;;
  esac
}

file_for() {
  case "$1" in
    S1) printf '%s' "S1-format-versioning.md" ;;
    S2) printf '%s' "S2-compress-public-content.md" ;;
    S3) printf '%s' "S3-signed-changes.md" ;;
    S4) printf '%s' "S4-attestation-lane.md" ;;
    S5) printf '%s' "S5-wants-negotiation.md" ;;
    S6) printf '%s' "S6-resumable-transfer.md" ;;
    S7) printf '%s' "S7-pluggable-relay-backend-s3.md" ;;
    S8) printf '%s' "S8-sparse-views.md" ;;
    S9) printf '%s' "S9-relay-fault-injection-tests.md" ;;
  esac
}

# Space-separated blocker slice ids (empty = none).
blockers_for() {
  case "$1" in
    S2) printf '%s' "S1" ;;
    S3) printf '%s' "S1" ;;
    S4) printf '%s' "S3" ;;
    S5) printf '%s' "S1" ;;
    S6) printf '%s' "S5" ;;
    S9) printf '%s' "S5 S6" ;;
    *)  printf '%s' "" ;;
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
        --label lore-borrow --label enhancement \
        --body "$body")"
  eval "NUM_$s=$(basename "$url")"
  echo "  ${s} -> ${url}"
done

echo "Done. Created ${#SLICES[@]} issues."
