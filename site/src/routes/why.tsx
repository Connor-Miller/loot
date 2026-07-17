import { Link, createFileRoute } from '@tanstack/react-router';

export const Route = createFileRoute('/why')({
	component: Why,
});

// Fresh, sell-only copy (spec §4). The argument is built from what loot actually
// does — CONTEXT.md's relay/visibility model and the committed evidence — never
// from the sealed docs/pitch/, which is not read or quoted here.
function Why() {
	return (
		<div className="doc-prose">
			<section className="hero">
				<p className="eyebrow">Why loot</p>
				<h1>Every host reads your code. loot's relay physically cannot.</h1>
				<p className="tagline">
					GitHub, GitLab, your CI, your self-hosted box — every one of them
					stores your source as plaintext it can read at will. Their privacy is
					a <em>permission bit</em>: a promise, enforced by policy, revocable by
					anyone with access to the database. loot replaces the promise with
					math.
				</p>
			</section>

			<section className="section">
				<h2>The claim</h2>
				<p className="lede">
					Content is encrypted before it ever leaves your machine, and the key
					never travels with it.
				</p>
				<p>
					In loot, visibility is a property of the <strong>content</strong>, not
					of the repository. A private file is sealed under a key that only its
					holders possess. Push it to a relay and the relay stores ciphertext it
					has no key for — a host can forward your private code without ever
					being able to read it. There is no admin override, no "just this once"
					database query, no breach that leaks what was never legible. The
					difference between a permission bit and a withheld key is the
					difference between a locked door and a wall.
				</p>
			</section>

			<section className="section">
				<h2>Why now</h2>
				<p className="lede">
					AI agents turned code custody from a background worry into a live
					hazard.
				</p>
				<p>
					A year ago your source sat in a handful of trusted systems. Now it
					flows through agents, tool runners, review bots, and hosted sandboxes
					— each a new place your plaintext lands, each a new party you have to
					trust not to retain it. The old model answers this with more policy:
					more scopes, more audit logs, more promises. loot answers it with
					custody. If an agent, a relay, or a service was never handed the key,
					it holds ciphertext and nothing else — and that's provable, not
					assured.
				</p>
			</section>

			<section className="section">
				<h2>Plaintext access is an explicit, audited grant</h2>
				<p className="lede">
					The services that genuinely need to read your code ask for the key —
					on the record.
				</p>
				<p>
					CI, server-side search, a diffing service: some tools really do need
					plaintext. In loot that isn't an ambient property of "having repo
					access." It's a <strong>grant</strong> — one content key, sealed to
					one identity's public key, signed by you, and written to an
					append-only manifest anyone can audit. Access is something you hand
					out deliberately and can cut off with <code>loot maroon</code>, not a
					default everyone inherits by being on the host.
				</p>
			</section>

			<section className="section">
				<h2>It isn't a pitch — it's a proof</h2>
				<p className="lede">
					loot hosts its own development on exactly this model.
				</p>
				<p>
					The private design docs behind this project live in loot's own repo,
					sealed, and travel through the same relay that serves the public code
					— which cannot read them. That's not an assertion; it's a re-runnable
					demo with committed output. So is the embargo that no advanced clock
					or patched binary can beat, and the two-agent convergence where no
					side is ever silently dropped.
				</p>
				<div className="cta-row">
					<Link to="/evidence" className="btn btn-primary">
						See the proof log
					</Link>
					<Link to="/install" className="btn btn-ghost">
						Install loot
					</Link>
				</div>
			</section>
		</div>
	);
}
