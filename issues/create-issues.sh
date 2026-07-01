#!/usr/bin/env bash
# Publish the loot improvement slices as GitHub issues.
# Requires an authenticated GitHub CLI (`gh auth login`).
# Creates issues in dependency order so "Blocked by" references real issue numbers.
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

declare -A TITLE=(
  [S1]="S1 — Format versioning + compatibility gate"
  [S2]="S2 — Compress public content (Zstd)"
  [S3]="S3 — Signed changes: author in id + validity enforcement"
  [S4]="S4 — Attestation metadata lane"
  [S5]='S5 — Object-level "wants" negotiation'
  [S6]="S6 — Resumable transfer"
  [S7]="S7 — Pluggable relay backend + S3 driver"
  [S8]="S8 — Sparse views (materialize-only)"
  [S9]="S9 — Relay fault-injection test harness"
)
declare -A FILE=(
  [S1]="S1-format-versioning.md"
  [S2]="S2-compress-public-content.md"
  [S3]="S3-signed-changes.md"
  [S4]="S4-attestation-lane.md"
  [S5]="S5-wants-negotiation.md"
  [S6]="S6-resumable-transfer.md"
  [S7]="S7-pluggable-relay-backend-s3.md"
  [S8]="S8-sparse-views.md"
  [S9]="S9-relay-fault-injection-tests.md"
)
declare -A BLOCKERS=(
  [S1]="" [S2]="S1" [S3]="S1" [S4]="S3" [S5]="S1"
  [S6]="S5" [S7]="" [S8]="" [S9]="S5 S6"
)

declare -A NUM   # slice -> created issue number

for s in "${SLICES[@]}"; do
  # body = file contents with its own "## Blocked by" section stripped...
  body="$(awk 'BEGIN{p=1} /^## Blocked by/{p=0} p{print}' "${FILE[$s]}")"
  # ...then regenerated with real issue numbers.
  body+=$'\n\n## Blocked by\n\n'
  if [ -z "${BLOCKERS[$s]}" ]; then
    body+=$'- None — can start immediately.\n'
  else
    for b in ${BLOCKERS[$s]}; do
      body+="- #${NUM[$b]} (${b} — ${TITLE[$b]#* — })"$'\n'
    done
  fi
  url="$(gh issue create --repo "$REPO" \
        --title "${TITLE[$s]}" \
        --label lore-borrow --label enhancement \
        --body "$body")"
  NUM[$s]="$(basename "$url")"
  echo "  ${s} -> ${url}"
done

echo "Done. Created ${#SLICES[@]} issues."
