# Presentational-boundary audit of the millerbyte frontend
GitHub: #207 · wayfinder:research

## Question

**Which parts of the millerbyte frontend are pure-presentational and portable
into `@millerbyte/ui` — and which are route/data/auth-coupled and must stay?**

The extract-and-swap bet (map Notes) rests on a boundary claim: presentational
components + theme tokens don't care about the TanStack Start migration
(routing/SSG/data-loading). This audit verifies that claim against the actual
code and produces the package's v1 contents.

In `c:\Users\conno\source\repos\millerbyte\frontend/src`, inventory and
classify:

- **`components/`** — for each: pure-presentational (props in, DOM out) vs
  coupled (TanStack `Link`/router hooks, Clerk auth state, data fetching,
  content-collection types). Note near-misses that become portable with a small
  seam (e.g. a `Link` render-prop).
- **Theme tokens** — `tailwind.config.js`, `index.css`/`styles/`, font loading:
  what is the actual design language (colors, type scale, spacing, dark mode
  mechanism) and in what form does it travel (Tailwind preset? CSS variables?)
- **Collision map with the migration** (millerbyte ADR-0006): which of the
  portable files does the TanStack Start migration also expect to touch? This
  is the list that decides swap sequencing (package-contract ticket).

Output: a classified inventory — proposed `@millerbyte/ui` v1 contents, the
files-that-swap list, and the collision map — linked from the resolution.
