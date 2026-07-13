# Release engineering for the install one-liner
GitHub: #205 · wayfinder:research

## Question

**What machinery turns loot — a repo with no releases or tags today — into
per-platform binaries the install one-liner can fetch?**

The marquee command (`irm https://loot.millerbyte.com/install.ps1 | iex`,
`curl -sSf .../install.sh | sh`) needs a release pipeline behind it. Survey the
prior art (**cargo-dist** first — it likely does 80% of this — plus how rustup,
starship, and uv structure theirs) and pin:

- **cargo-dist vs hand-rolled GitHub Actions.** What does cargo-dist generate
  (workflows, installers, checksums, Releases layout), what does it impose, and
  does its generated installer conflict with or replace our site-served scripts?
- **Target matrix.** Windows x64/arm64, macOS x64/arm64 (universal?), Linux
  x64/arm64 — and the musl-vs-glibc question for Linux. Which targets are v1?
- **Versioning + tagging scheme.** loot has never cut a release. What's v0.1.0,
  and how do tags work in a **loot-first repo** where git `main` is a projection
  (`docs/agents/workflow.md`) — tags and release CI live git-side, downstream of
  the ferry. Does anything about that break a tag-triggered release workflow?
- **Releases layout the scripts rely on.** Artifact naming convention
  (`loot-<version>-<target>.<ext>`), checksums/signatures, `latest` resolution —
  the contract the install scripts (prototype ticket) will code against.

Output: a research summary in `docs/research/` recommending the pipeline, the
v1 target matrix, and the artifact-naming contract.
