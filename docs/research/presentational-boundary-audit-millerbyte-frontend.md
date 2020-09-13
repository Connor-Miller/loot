# Presentational-boundary audit of the millerbyte frontend

Resolves [loot#207](https://github.com/Connor-Miller/loot/issues/207) (map
[#204](https://github.com/Connor-Miller/loot/issues/204)). Audited
2026-07-12 against `millerbyte@main` (frontend working tree clean;
`frontend/src` read directly).

## Verdict

**The boundary claim holds — and the biggest assumed risk is gone.** The
millerbyte frontend has a clean presentational core (CSS-variable tokens +
handwritten component classes + a dozen props-in/DOM-out components) that
does not touch routing, Clerk, or gateway data. And the TanStack Start
migration (millerbyte ADR-0006) **has already landed** — the "Start 1/7 …
7/7" commit series converted all routes to file-based + SSG, auth/live
routes are client islands, and the frontend working tree is clean. The
"extraction must sequence against an in-flight migration" concern in the map
Notes is stale: **the swap PR is free-standing.**

One surprise that reshapes the theming question: **`tailwind.config.js` is
dead config.** The repo is on Tailwind v4 (`@import "tailwindcss"` +
`@tailwindcss/vite`), which only loads a JS config via an `@config`
directive — and no CSS file has one. The v3-style config (semantic color
mappings, `darkMode: 'class'`) does nothing. What actually styles the site
is plain CSS: `tokens.css` variables + `components.css`/`utilities.css`
classes + stock Tailwind v4 utilities. The design language already travels
as framework-agnostic CSS today.

## Method + a caught flaw

Classified every file under `frontend/src/components/` by its module
imports, then spot-read the borderline files, the three `styles/*.css`
files, `index.css`, `tailwind.config.js`, `package.json`, `__root.tsx`, and
ADR-0006. The first import scan used a single-line regex and missed
multi-line imports — caught when a spot-read of `CharacterLayer` revealed a
`characterSpriteService` import the scan had dropped. Every "pure" verdict
below was re-verified with a `from '...'` scan that catches multi-line
imports.

## Proposed `@millerbyte/ui` v1 contents

### Theme (travels as plain CSS today)

| File | What it holds |
|---|---|
| `styles/tokens.css` | The design language: semantic color vars (surface/text/primary/status + opacity variants), shadows, animation durations/easings, z-index scale, radii, backdrop blurs. Dark-only — light mode is commented out. |
| `styles/components.css` | `.card-glass`, `.card-solid`, `.btn-{primary,secondary,success,danger,ghost}`, `.badge-*`, `.input-field`/`.select-field`/`.checkbox-field`, modal/toast/loading/skeleton, `.link-primary`, `.header-glass`/`.footer-glass`, table classes, `.blog-prose`/`.doc-prose`, `.alert-*`. |
| `styles/utilities.css` | Handwritten semantic utilities (`.text-primary`, `.text-secondary`, `.bg-surface`, `.bg-surface-elevated`, `.border-default`, …) — these, not Tailwind, serve the ~337 semantic-class usages across the app. |

No custom fonts anywhere (system stack via Tailwind defaults); no
`@font-face`, no font links in `__root.tsx`. Brand assets referenced from
components live in `public/` (`/millerbyte_logo.png`, `/avatar.jpg`, sprite
sheets) and are **not** package material.

### Components — pure today, portable as-is

External deps in parentheses become package peer/deps (contract ticket
decides which).

- `CodeBlock` (react-syntax-highlighter) — and `docs/CodeExample`
  (react-syntax-highlighter, lucide) is a near-duplicate with a copy
  button; **consolidate into one component at extraction**.
- `GameToast` (framer-motion)
- `LoadingOverlay` (framer-motion, lucide)
- `RainbowModal` (framer-motion, lucide, `useFocusTrap`)
- `FormModal` (`useFocusTrap`, `types/tableTypes` — types move with it)
- `TanStackTable` (@tanstack/react-table, lucide, `FormModal`,
  `types/tableTypes`)
- `FloatingElements` (framer-motion, lucide)
- `BlogSectionTitle`, `SourceRef` (+`SourceRef.css`),
  `battleReplay/Centered` (generic despite its home), `RouterPendingComponent`
  (lucide only — pure despite the name)
- **`hooks/useFocusTrap`** — leaf hook, no app imports; ships inside the
  package (three portable modals depend on it).

### Near-misses — portable with a small seam

- **`content/` chrome trio** (`ContentNavigation`, `ContentSearch`,
  `ContentSidebar`) — **the highest-value near-miss for the loot site**:
  this is exactly the docs-sidebar/search/prev-next chrome the loot docs
  pages need. Already half-seamed behind `ContentLinker`
  (millerbyte ADR-0008), but the linker's `to` type hardcodes millerbyte
  routes and the components import `Link`/`useNavigate`/`useParams`
  directly. Seam: widen the linker type and inject the link primitive. Both
  consumers are TanStack Start, so a shared `@tanstack/react-router` peer
  is a legitimate alternative to a render-prop — contract ticket's call.
- **`Footer`** — brand chrome, portable but for two `<Link>`s and
  hardcoded nav/social items; seam: items as props. (Inlines GitHub/X SVGs
  because lucide-react v1 removed brand logos — keep that note when
  extracting.)
- **`Header`** — `Link` + `useAuth`; nav items and the auth section must
  become props/slots. Whether a shared header shell is even wanted (the
  loot site has its own nav) is an IA/contract question.
- **`BlogCarousel`** — imports `data/unifiedPosts` + `Link`; seam: items
  as props + link render-prop.
- **`PageErrorBoundary`** (one `<Link>` home button),
  **`RouterErrorBoundary`** (`ErrorComponentProps` type) — small seams, but
  they're app plumbing; probably stay.

### Stays in the app (coupled or domain-specific)

- `arena/` (23 modules + tests) — Arena domain: `types/arena`,
  `types/battleReplay`, services, Clerk in `useArenaMatch`.
- `battleReplay/` (except `Centered`) — replay domain.
- `holoTaco/addPolishModal` — `useCollection` gateway data.
- `docs/`- and `projects/`-specific chrome wrappers (`DocSidebar`,
  `ProjectNavigation`, …) — thin domain bindings over the content chrome;
  they stay and consume the packaged chrome.
- `docs/WideApiEventsExplanation` — content, not a component.
- `ProceduralBackground`, `SpriteSheetDebugger` — sprite services.
- `RetroBackground` (loads `/avatar.jpg`), `CharacterLayer`
  (`characterSpriteService` + carousel-position coupling) — brand art tied
  to public/ assets; stay.

## Files-that-swap list

The atomic swap PR touches: the moved files above (components + 3 CSS files
+ `useFocusTrap` + `types/tableTypes`), `index.css` (imports switch to
`@millerbyte/ui` styles), and every importer of a moved module —
concentrated in `routes/*`, `pages/*`, and the domain chrome wrappers.
Mechanical path rewrites; no behavior change.

## Collision map with the migration: empty

ADR-0006's conversion is **done** (file-based `routes/`, generated
`routeTree.gen.ts`, `@tanstack/react-start` + nitro in deps, clean working
tree). No portable file has a pending migration change waiting on it. The
extraction sequences freely; the only live coordination point is the
gateway-side work in the millerbyte working tree, which doesn't touch
`frontend/`.

## Implied peer surface (input to the contract ticket)

react 19 / react-dom 19, framer-motion 12, lucide-react 1,
react-syntax-highlighter 16 (+@types), @tanstack/react-table 8, and —
only if the chrome trio ships with `Link` imports rather than a render-prop
— @tanstack/react-router. Tailwind is **not** required by the package as
audited: the portable styles are plain CSS.

## Quirks found along the way (millerbyte repo hygiene, not map tickets)

- `tailwind.config.js` is vestigial under Tailwind v4 — delete or port to a
  CSS `@theme` block. Porting would make the semantic utilities real
  Tailwind utilities (variants included) instead of handwritten classes;
  that choice belongs to the contract ticket since it decides the theming
  mechanism.
- `hover:bg-surface-20` in `ContentSearch.tsx` is a **dead class** (no
  generator for it in v4, no handwritten fallback) — the hover style
  silently does nothing. Evidence for the dead-config finding; fix rides
  along with whatever theming mechanism is chosen.
- `docs/CodeExample` duplicates `CodeBlock` (+copy button) — consolidate at
  extraction.
