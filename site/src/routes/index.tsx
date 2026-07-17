import { Link, createFileRoute } from '@tanstack/react-router';
import { CodeBlock } from '@millerbyte/ui';
import { INSTALL_SH_ONELINER } from '../lib/install';

export const Route = createFileRoute('/')({
	component: Landing,
});

// The loop loot can run end to end today (README §"what works today").
const LOOP: Array<{ label: string; verbs: string }> = [
	{ label: 'local', verbs: 'init · status · describe · new · log · surface' },
	{ label: 'docks', verbs: 'dock · docks · dock merge' },
	{ label: 'file', verbs: 'bundle · apply' },
	{ label: 'relay', verbs: 'serve · push · pull' },
	{ label: 'grants', verbs: 'grant · grant --relay · grants · pull-grants' },
	{ label: 'identity', verbs: 'keygen · whoami · peer add · id export/import' },
];

function Landing() {
	return (
		<div className="doc-prose">
			<section className="hero">
				<p className="eyebrow">Source control, reimagined</p>
				<h1>Version control where the host cannot read your code.</h1>
				<p className="tagline">
					loot makes visibility and permissions properties of{' '}
					<strong>content and changes</strong>, not of the repository. Commit
					your <code>.env</code>. Keep files private inside a shared repo.
					Embargo a security fix, cut the release, and reveal the source later.
				</p>
				<CodeBlock language="bash">{INSTALL_SH_ONELINER}</CodeBlock>
				<p className="hint">
					macOS · Linux · Windows — see <Link to="/install">all install
					options</Link>. Installs to <code>~/.loot/bin</code>; verify with{' '}
					<code>loot --version</code>.
				</p>
				<div className="cta-row">
					<Link to="/install" className="btn btn-primary">
						Install loot
					</Link>
					<Link to="/why" className="btn btn-ghost">
						Why loot
					</Link>
					<Link to="/evidence" className="btn btn-ghost">
						See the proof
					</Link>
				</div>
			</section>

			<section className="section">
				<h2>What works today</h2>
				<p className="lede">
					loot is a from-scratch, encrypted-DAG source-control system that hosts
					its own development. The full loop, from first <code>init</code> to
					relay-based collaboration, runs now.
				</p>
				<div className="loop-grid">
					{LOOP.map((row) => (
						<div className="loop" key={row.label}>
							<div className="loop-label">{row.label}</div>
							<div className="loop-verbs">{row.verbs}</div>
						</div>
					))}
				</div>
			</section>

			<section className="section">
				<h2>Three things git can't do</h2>
				<p className="lede">
					Each is one command. Full walkthroughs live in the docs.
				</p>
				<div className="card-grid">
					<div className="card">
						<h3>Commit a private <code>.env</code></h3>
						<p>
							Declare per-file privacy in <code>.lootattributes</code>. The
							secret is sealed in a shared repo; non-keyholders carry the
							ciphertext and can never read it.
						</p>
						<CodeBlock language="bash">{'.env restricted=alice'}</CodeBlock>
						<Link to="/docs" hash="private-env" className="card-link">
							Walkthrough →
						</Link>
					</div>
					<div className="card">
						<h3>Embargo a security fix</h3>
						<p>
							Merge the patch and cut the release now; the source stays
							encrypted to everyone until the reveal timestamp, then unlocks
							for anyone who pulls.
						</p>
						<CodeBlock language="bash">
							{'security-fix.txt embargoed=1800000000'}
						</CodeBlock>
						<Link to="/docs" hash="embargo" className="card-link">
							Walkthrough →
						</Link>
					</div>
					<div className="card">
						<h3>Grant a key to a teammate</h3>
						<p>
							Hand one content key to one identity over the relay — sealed to
							their public key, signed by you, recorded in the audit manifest.
							Permissioning is key management.
						</p>
						<CodeBlock language="bash">
							{'loot grant --relay origin .env bob'}
						</CodeBlock>
						<Link to="/docs" hash="grant-a-key" className="card-link">
							Walkthrough →
						</Link>
					</div>
				</div>
			</section>

			<section className="section">
				<h2>Built with loot</h2>
				<p className="lede">
					loot leads its own development; git <code>main</code> is a downstream
					projection. The relay that hosts it physically cannot read the private
					code it stores — that claim is backed by re-runnable, committed
					proofs.
				</p>
				<div className="cta-row">
					<Link to="/evidence" className="btn btn-primary">
						Read the proof log
					</Link>
					<Link to="/why" className="btn btn-ghost">
						Why this matters
					</Link>
				</div>
			</section>
		</div>
	);
}
