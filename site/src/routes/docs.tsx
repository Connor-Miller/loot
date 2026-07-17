import type { ReactNode } from 'react';
import { createFileRoute } from '@tanstack/react-router';
import { CodeBlock } from '@millerbyte/ui';

export const Route = createFileRoute('/docs')({
	component: Docs,
});

// Hand-written CLI reference (spec §4 — generation from clap is a fast-follow).
// Grouped local / docks / sync / grants / identity / setup, sourced from the
// binary's own usage text so flags and behavior can't drift into fiction.
type Verb = { cmd: string; desc: string };
const CLI: Array<{ id: string; group: string; verbs: Verb[] }> = [
	{
		id: 'cli-setup',
		group: 'Setup',
		verbs: [
			{ cmd: 'loot init [--identity <name>]', desc: 'Initialize a repo here (identity from global config if omitted).' },
			{ cmd: 'loot clone <url> <dir> [--identity <name>]', desc: 'Clone a relay into <dir>; ends with a materialized working tree.' },
			{ cmd: 'loot config set|unset|list', desc: 'Manage global config (~/.config/loot/config) — e.g. a default identity.' },
		],
	},
	{
		id: 'cli-local',
		group: 'Local',
		verbs: [
			{ cmd: 'loot status [--porcelain|--json]', desc: 'Show the working change, read-only — no snapshot, no ceremony.' },
			{ cmd: 'loot describe -m <message>', desc: 'Record the working tree and name the change. Your first verb on new edits.' },
			{ cmd: 'loot new [-m <message>]', desc: 'Finalize (sign) the working change and start a fresh one on top.' },
			{ cmd: 'loot edit <change-id>', desc: 'Reopen a finalized change to amend it; supersedes it on finalize (ADR 0032).' },
			{ cmd: 'loot log', desc: 'Show change history with visibility hints; a divergent change is marked !.' },
			{ cmd: 'loot surface', desc: 'Materialize what the current identity may see; sealed paths are skipped.' },
			{ cmd: 'loot gc [--dry-run]', desc: 'Prune loose objects no change references.' },
			{ cmd: 'loot undo  ·  loot op log  ·  loot op restore <n>', desc: 'Step the view back / list / jump the operation log (redo included).' },
			{ cmd: 'loot abandon <version-id> [--head]', desc: 'Drop one version of a divergent change, or a whole fork tip; undoable.' },
			{ cmd: 'loot adopt [<version-id>] [--discard-wip]', desc: 'Catch this working tree up to landed history.' },
		],
	},
	{
		id: 'cli-docks',
		group: 'Docks (concurrency)',
		verbs: [
			{ cmd: 'loot dock <name> --at <dir>', desc: 'Bind a separate worktree over the same shared store — no second clone.' },
			{ cmd: 'loot dock merge <name>', desc: "Merge another dock's finalized tip into the current one, in-process." },
			{ cmd: 'loot docks', desc: 'List docks with their working tip and visibility.' },
			{ cmd: 'loot lane new / loot lanes', desc: 'Spawn / observe sealed ephemeral lanes — the isolation unit for concurrent agents.' },
		],
	},
	{
		id: 'cli-sync',
		group: 'Sync',
		verbs: [
			{ cmd: 'loot bundle <file>  ·  loot apply <file>', desc: 'Offline sync: write a sync bundle (ciphertext, no private keys) / merge a peer’s.' },
			{ cmd: 'loot remote add|remove|list', desc: 'Register named relay URLs (origin is the conventional default).' },
			{ cmd: 'loot push [<url>]  ·  loot pull [<url>]', desc: 'Publish changes to a relay / fetch, merge, and converge from one.' },
			{ cmd: 'loot serve [--dir <path>] [--addr <host:port>]', desc: 'Run a relay: stores and forwards ciphertext it cannot read.' },
			{ cmd: 'loot conflicts  ·  loot resolve <path> <file>', desc: 'List paths needing human resolution / resolve one from a file.' },
		],
	},
	{
		id: 'cli-grants',
		group: 'Grants & visibility',
		verbs: [
			{ cmd: 'loot grant <path> <identity> <file>', desc: 'Write a targeted grant bundle for file delivery.' },
			{ cmd: 'loot grant --relay <name> <path> <identity>', desc: "Seal and deliver a content key via the relay’s mailbox." },
			{ cmd: 'loot grants [<url>]  ·  loot pull-grants [<url>]', desc: 'Peek the pending grant count / fetch, verify, and apply sealed grants.' },
			{ cmd: 'loot maroon [--hard] <path> <identity>', desc: 'Cut an identity off future access; --hard also purges the held key.' },
			{ cmd: 'loot migrate <path> <vis-spec>', desc: "Change a path’s visibility: public | restricted=a,b | embargoed=<ts>." },
			{ cmd: 'loot manifest', desc: 'Show the grant audit trail (grantor/grantee pubkeys, timestamps).' },
		],
	},
	{
		id: 'cli-identity',
		group: 'Identity',
		verbs: [
			{ cmd: 'loot keygen  ·  loot whoami', desc: 'Generate an identity keypair / show this repo’s public key.' },
			{ cmd: 'loot id export <file>  ·  loot id import <file>', desc: 'Move the same identity between machines (passphrase-encrypted).' },
			{ cmd: 'loot peer add|remove|list', desc: 'Manage the local nickname → public key registry (loot’s known_hosts).' },
		],
	},
];

const CONCEPTS: Array<{ id: string; title: string; body: ReactNode }> = [
	{
		id: 'concept-changes',
		title: 'Changes',
		body: (
			<>
				A <strong>change</strong> is loot's reviewable unit of history — its
				answer to a commit. There is no separate add/commit step: the working
				tree <em>is</em> the change at the tip. <code>loot describe -m</code>{' '}
				records it and names it; <code>loot new</code> finalizes and signs it,
				starting a fresh one. A change carries a set of paths, each with its own
				visibility — which is where permissions live.
			</>
		),
	},
	{
		id: 'concept-visibility',
		title: 'Visibility & .lootattributes',
		body: (
			<>
				Every path is <strong>public</strong>, <strong>restricted</strong> (a
				named set of key holders), or <strong>embargoed</strong> (encrypted to
				all until a reveal time). You declare it in{' '}
				<code>.lootattributes</code>, a gitattributes-style file:{' '}
				<code>.env restricted=alice</code>, <code>*.md public</code>. Unmatched
				paths default to public. The file is versioned like any other, so the
				policy travels to every clone.
			</>
		),
	},
	{
		id: 'concept-identity',
		title: 'Identity & keys',
		body: (
			<>
				An <strong>identity</strong> is a keyholder — an ed25519 keypair minted
				at <code>loot init</code>. Visibility is ultimately enforced by who
				holds the decryption key for a piece of content: "permissioning is key
				management." Names like <code>alice</code> are local nicknames bound to
				a globally-stable public key through the peer registry.
			</>
		),
	},
	{
		id: 'concept-grants',
		title: 'Grants',
		body: (
			<>
				A <strong>grant</strong> hands one content key to one identity. It's
				sealed to the recipient's public key (they can't be granted anything
				they can't unseal), signed by you so the trail is forge-evident, and
				recorded in an append-only manifest. Grants are how restricted content
				is shared after the fact — and <code>loot maroon</code> is how access is
				cut off again.
			</>
		),
	},
	{
		id: 'concept-relays',
		title: 'Relays & hosts',
		body: (
			<>
				A <strong>relay</strong> stores and forwards sealed content it cannot
				read. Restricted keys never travel in a sync bundle, so the relay's
				zero-knowledge property is enforced at the wire level, not by policy. A{' '}
				<em>host is just a relay that never sleeps</em> — which makes a loot
				host a zero-knowledge code host: it physically cannot read your private
				code.
			</>
		),
	},
	{
		id: 'concept-embargo',
		title: 'Embargo',
		body: (
			<>
				An <strong>embargoed</strong> path is encrypted to everyone until a
				reveal timestamp. You can merge a security fix, cut the release, and push
				— the relay holds the ciphertext while withholding the key until{' '}
				<code>reveal_at</code> passes on the relay's own clock. Then anyone who
				pulls can read it. No lying clock, escrow inspection, or patched binary
				reads it early: the key bytes simply aren't there yet.
			</>
		),
	},
	{
		id: 'concept-docks',
		title: 'Docks (for concurrency)',
		body: (
			<>
				A <strong>dock</strong> is an isolated working tree plus its own tip,
				materialized cheaply over one shared object store — loot's answer to a
				git worktree, without a second clone. Docks are the light-touch tool for
				running several agents or workstreams against one repo; concurrent edits
				reconcile through the merge classifier, and conflicts surface as
				machine-readable verdicts rather than being silently dropped.
			</>
		),
	},
];

function Docs() {
	return (
		<div className="doc-prose">
			<section className="hero">
				<p className="eyebrow">Docs</p>
				<h1>Documentation</h1>
				<p className="tagline">
					Everything to go from install to sharing a private key over a relay.
				</p>
			</section>

			<nav className="toc" aria-label="On this page">
				<a href="#getting-started">Getting started</a>
				<a href="#core-concepts">Core concepts</a>
				<a href="#task-guides">Task guides</a>
				<a href="#cli-reference">CLI reference</a>
			</nav>

			<section className="section" id="getting-started">
				<h2>Getting started</h2>
				<p className="lede">
					A private <code>.env</code> living in a shared repo — the shortest
					path to seeing the thesis work.
				</p>
				<CodeBlock language="bash">
					{`# install (or build with: cargo build --release)
curl -sSf https://loot.millerbyte.com/install.sh | sh

loot init --identity alice

printf 'TOKEN=supersecret\\n' > .env
printf '# My Project\\n'      > README.md
printf '.env restricted=alice\\n*.md public\\n' > .lootattributes

loot describe -m "initial work"   # records the tree AND names the change
loot surface                      # alice restores both README.md and .env`}
				</CodeBlock>
				<p>
					The <code>.env</code> ciphertext lives in <code>.loot/</code> the
					whole time. Switch to a non-keyholder and it stays sealed:
				</p>
				<CodeBlock language="bash">
					{`printf mallory > .loot/identity
rm -f .env README.md
loot surface     # mallory: README.md appears; .env stays sealed`}
				</CodeBlock>
				<p>
					If mallory snapshots and re-syncs, the sealed file is carried forward
					untouched — snapshot is visibility-aware, so a non-keyholder can never
					silently drop or expose content they can't read.
				</p>
			</section>

			<section className="section" id="core-concepts">
				<h2>Core concepts</h2>
				<p className="lede">
					The seven ideas the rest of loot is built from.
				</p>
				{CONCEPTS.map((c) => (
					<div className="concept" id={c.id} key={c.id}>
						<h3>{c.title}</h3>
						<p>{c.body}</p>
					</div>
				))}
			</section>

			<section className="section" id="task-guides">
				<h2>Task guides</h2>

				<div id="private-env" className="concept">
					<h3>Keep a file private in a shared repo</h3>
					<p>
						Declare the path restricted before you record it. Only listed
						identities get a key; everyone else carries ciphertext.
					</p>
					<CodeBlock language="bash">
						{`printf '.env restricted=alice\\n' > .lootattributes
loot describe -m "add sealed .env"
loot push          # the relay stores it but cannot read it`}
					</CodeBlock>
				</div>

				<div id="grant-a-key" className="concept">
					<h3>Share a private file with a teammate</h3>
					<p>
						Register their public key (from <code>loot whoami</code> on their
						machine), then deliver a sealed grant over the relay.
					</p>
					<CodeBlock language="bash">
						{`loot peer add bob "ssh-ed25519 AAAA..."
loot grant --relay origin .env bob

# on bob's machine:
loot pull-grants   # verifies alice's signature, checks the peer registry
loot surface       # now bob can read .env`}
					</CodeBlock>
				</div>

				<div id="embargo" className="concept">
					<h3>Embargo a security fix</h3>
					<p>
						Mark the file embargoed until a unix timestamp. Push now; the key is
						withheld by the relay until reveal time.
					</p>
					<CodeBlock language="bash">
						{`echo "VULN_DETAILS=CVE-2025-XXXX" > security-fix.txt
printf 'security-fix.txt embargoed=1800000000\\n' >> .lootattributes

loot describe -m "patch for CVE-2025-XXXX"
loot push          # relay holds ciphertext; key withheld until reveal_at`}
					</CodeBlock>
					<p>
						At <code>reveal_at</code>, the relay releases the key and anyone who
						pulls can read the fix.
					</p>
				</div>

				<div id="sync-relay" className="concept">
					<h3>Sync over a relay</h3>
					<p>
						A relay is the collaboration hub. Run one anywhere; push and pull
						resolve <code>origin</code> by default.
					</p>
					<CodeBlock language="bash">
						{`# terminal 1: run a relay
loot serve --dir /tmp/relay --addr 127.0.0.1:4000

# terminal 2: alice publishes
loot remote add origin http://127.0.0.1:4000
loot push

# terminal 3: bob clones (sees only public content until granted)
loot clone http://127.0.0.1:4000 ./bob-repo --identity bob`}
					</CodeBlock>
				</div>
			</section>

			<section className="section" id="cli-reference">
				<h2>CLI reference</h2>
				<p className="lede">
					The commands that matter, grouped by what you're doing. Every mutating
					verb snapshots the working tree first — no manual{' '}
					<code>loot status</code> needed. Run <code>loot --help</code> for the
					full list.
				</p>
				{CLI.map((g) => (
					<div className="cli-group" id={g.id} key={g.id}>
						<h3>{g.group}</h3>
						<table className="cli-table">
							<tbody>
								{g.verbs.map((v) => (
									<tr key={v.cmd}>
										<td>{v.cmd}</td>
										<td>{v.desc}</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				))}
			</section>
		</div>
	);
}
