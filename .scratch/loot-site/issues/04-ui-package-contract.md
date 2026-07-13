# The @millerbyte/ui package contract
GitHub: #208 · wayfinder:grilling · blocked by #207

## Question

**The shape of `@millerbyte/ui`: exports, theming mechanism, build tooling,
publish flow — and how the atomic extract-and-swap PR sequences against the
TanStack Start migration.**

The audit ticket says *what's in* the package; this grilling pins *how it's
built and consumed*:

- **Theming mechanism** — Tailwind preset (consumers must run Tailwind, both
  do) vs CSS variables (framework-agnostic, heavier refactor) vs both (preset
  emitting vars)? This decides how "pixel-identical across two sites" is
  actually enforced.
- **Exports + API** — component entry points, tree-shaking, whether tokens and
  components are separate subpath exports (`@millerbyte/ui/theme`).
- **Build tooling + toolchain floor** — the millerbyte frontend is on TS7
  (native tsc) and the gateway on TS 6/nodenext; the package must typecheck in
  both consumers. Bundler (tsup? vite lib mode? none — ship TS-compiled ESM?),
  ESM-only per repo convention.
- **Publish flow** — npm public under the existing `@millerbyte` scope
  (`react-logging` precedent), from a private repo; versioning policy;
  workspace layout (`packages/ui/` next to `frontend/`) and whether the repo
  gains npm workspaces.
- **Swap sequencing** — the extract-and-swap PR touches the same files as the
  in-flight migration (collision map from the audit). One PR? Behind the
  migration? Interleaved? Pin the order and the rollback story.

Output: the package contract, recorded here and destined for a millerbyte-repo
ADR (spec ticket assembles it).
