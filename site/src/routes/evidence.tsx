import type { ReactNode } from 'react';
import { createFileRoute } from '@tanstack/react-router';

export const Route = createFileRoute('/evidence')({
	component: Evidence,
});

const GH = 'https://github.com/Connor-Miller/loot/blob/main/docs/evidence';

// Renders committed run output verbatim, tinting the PASS assertions.
function Verbatim({ text }: { text: string }) {
	return (
		<pre className="verbatim">
			{text.split('\n').map((line, i) => (
				<span key={i} className={line.startsWith('PASS') ? 'pass' : undefined}>
					{line}
					{'\n'}
				</span>
			))}
		</pre>
	);
}

type Proof = {
	title: string;
	proves: ReactNode;
	excerpt: string;
	links: Array<{ label: string; href: string }>;
};

// Each excerpt is an unedited selection of lines from the committed run output
// linked beneath it (docs/evidence/runs/*.txt) — the proof is content in the
// repo the thesis is about. The one run line that echoed the sealed pitch's own
// title is deliberately omitted; docs/pitch/ stays sealed.
const PROOFS: Proof[] = [
	{
		title: 'loot hosts loot — a sealed path is invisible to a non-keyholder',
		proves: (
			<>
				<strong>What this proves:</strong> loot's own private design docs live in
				its public repo and travel through the same relay — a fresh clone
				without the key materializes the public tree and cannot see the sealed
				path, while the keyholder reads it. Visibility is per-content, enforced
				by key custody.
			</>
		),
		excerpt: `      (1 sealed path(s) skipped — request a grant to access them)
PASS: the agent's clone does NOT materialize the sealed path (docs/pitch/zk-host.md absent)
PASS: the agent's clone DOES materialize public content (CONTEXT.md present)
PASS: loot reports sealed path(s) skipped for the agent (it holds the ciphertext, not the key)
PASS: the dev's working tree HAS the sealed path present and readable
ALL CHECKS PASSED -- the sealed path is dev-visible, agent-invisible.`,
		links: [
			{ label: 'run output', href: `${GH}/runs/sealed-path-demo.txt` },
			{ label: 'evidence doc', href: `${GH}/loot-hosts-loot.md` },
		],
	},
	{
		title: 'Hard embargo — no clock, escrow, or patched binary reads it early',
		proves: (
			<>
				<strong>What this proves:</strong> an embargoed change stays unreadable
				until the relay's own clock passes <code>reveal_at</code>. An adversarial
				holder with an advanced clock, direct <code>.loot</code> inspection, and
				a binary with every time gate removed all fail — then the read succeeds
				after release. The key bytes were never on the holder's machine.
			</>
		),
		excerpt: `PASS: advanced holder clock does not release the key (relay clock gates, not the holder's)
PASS: the holder holds only ciphertext: the plaintext secret and key material are absent from .loot
PASS: a client with the time gate removed still cannot read (no key bytes to bypass)
PASS: the relay withholds the grant from its mailbox until its own clock passes reveal_at
PASS: after reveal_at the relay delivers the key and the holder reads the embargoed change normally
ALL CHECKS PASSED -- embargo is holder-adversary-proof against the live relay.`,
		links: [{ label: 'run output', href: `${GH}/runs/attack-demo.txt` }],
	},
	{
		title: 'Concurrent agents converge — no side silently dropped',
		proves: (
			<>
				<strong>What this proves:</strong> two agents editing the same repo
				reconcile through docks and the relay's fork-collapse. Disjoint work
				converges, a same-line edit surfaces as a machine-readable conflict
				(never a silent loss), and a path one side can't decrypt is relayed as
				ciphertext rather than merged.
			</>
		),
		excerpt: `PASS: dock-a's disjoint file converges into the harbor (= row)
PASS: the concurrent same-line edit surfaces as a Conflict (C) -- not silently dropped
PASS: after resolve, no conflicts remain (porcelain is empty)
PASS: agent's apply pulls in dev's concurrent file (fork collapses -- dev's side not dropped)
PASS: the restricted path agent can't open surfaces as RelayedUnmerged (R) -- carried, not merged
ALL CHECKS PASSED -- concurrent convergence proven, both acts.`,
		links: [
			{ label: 'run output', href: `${GH}/runs/concurrent-agents-demo.txt` },
			{ label: 'evidence doc', href: `${GH}/concurrent-agents.md` },
		],
	},
	{
		title: 'Grant then maroon — access is handed out and cut off deliberately',
		proves: (
			<>
				<strong>What this proves:</strong> a restricted path starts unreadable to
				a peer; a sealed, signed grant lets them read it; a hard maroon re-seals
				it so their next pull carries a key they no longer hold. Sharing is a key
				handoff, and revocation is real.
			</>
		),
		excerpt: `PASS: before any grant, the agent cannot read the restricted path (secret.txt absent)
    delivered sealed grant for 'agent' via relay
PASS: after the sealed grant, the agent files the key and reads the restricted content
    hard-marooned agent from secret.txt (new oid: 36683014)
PASS: after the hard maroon, the agent's pull carries a seal it cannot open (no key)`,
		links: [{ label: 'run output', href: `${GH}/runs/grant-maroon-demo.txt` }],
	},
	{
		title: 'Divergence from ordinary work — the ! marker, abandon, and undo',
		proves: (
			<>
				<strong>What this proves:</strong> two identities amending the same change
				produce two live versions under one durable handle — rendered with a{' '}
				<code>!</code> marker, kept flat (no phantom merge), collapsed by{' '}
				<code>loot abandon</code>, and restored by <code>loot undo</code>. Nothing
				is ever destroyed.
			</>
		),
		excerpt: `    mzlxpytq!  57a84e20  add feat                                    7bb5b8c4…
    mzlxpytq!  2f370248  add feat                                    agent
PASS: DIVERGENCE: log renders the ! marker on the divergent change_id
PASS: DIVERGENCE STAYS FLAT (#203): no per-path conflict -- converge minted no merge
PASS: DIVERGENCE: two live versions listed under one durable handle (57a84e20, 2f370248)
    abandoned version 57a84e20 — its change id keeps the remaining live version(s)`,
		links: [
			{ label: 'run output', href: `${GH}/runs/amend-divergence-demo.txt` },
			{ label: 'evidence doc', href: `${GH}/amend-divergence.md` },
		],
	},
	{
		title: 'A working day driven loot-first — git main is a projection',
		proves: (
			<>
				<strong>What this proves:</strong> loot leads its own development. This
				very evidence file originated in loot's working tree, was reviewed on
				GitHub as projected unsigned WIP, and was landed by <code>loot new</code>{' '}
				— with git <code>main</code> projected downstream. No git commit created
				it.
			</>
		),
		excerpt: `The destination proof for wayfinder map #148 ("flip the agentic workflow
loot-first, git downstream"). This document IS the day's unit of work: it
originated in loot's working tree, was reviewed on GitHub as a PR built from
projected unfinalized loot WIP, and landed by \`loot new\` — with git main
projected downstream. If you are reading it on git main, the workflow worked:
no git commit ever created this file.`,
		links: [{ label: 'evidence doc', href: `${GH}/loot-first.md` }],
	},
];

function Evidence() {
	return (
		<div className="doc-prose">
			<section className="hero">
				<p className="eyebrow">Evidence</p>
				<h1>Proof log</h1>
				<p className="tagline">
					Every claim loot makes is backed by a re-runnable script whose captured
					output is committed to the repo — the proof is content in the repo the
					thesis is about. Below is a card per proof over its verbatim run
					output.
				</p>
			</section>

			<section className="section">
				{PROOFS.map((p) => (
					<div className="proof" key={p.title}>
						<h3>{p.title}</h3>
						<p className="proves">{p.proves}</p>
						<Verbatim text={p.excerpt} />
						<div className="links">
							{p.links.map((l, i) => (
								<span key={l.href}>
									{i > 0 ? ' · ' : ''}
									<a className="run-link" href={l.href}>
										{l.label} ↗
									</a>
								</span>
							))}
						</div>
					</div>
				))}
			</section>
		</div>
	);
}
