import { useEffect, useState } from 'react';
import { createFileRoute } from '@tanstack/react-router';
import { CodeBlock } from '@millerbyte/ui';
import { INSTALL_PS1_ONELINER, INSTALL_SH_ONELINER } from '../lib/install';

export const Route = createFileRoute('/install')({
	component: Install,
});

const RELEASE_TAG = 'v0.1.0';
const DOWNLOAD_BASE =
	'https://github.com/Connor-Miller/loot/releases/latest/download';
const RELEASES_URL = 'https://github.com/Connor-Miller/loot/releases/latest';

// The five native triples shipped in v0.1.0 (spec §5). Windows arm64 is served
// under x64 emulation by the installer, not a native download — #270 — so it is
// deliberately NOT listed as its own platform row.
const PLATFORMS: Array<{ platform: string; asset: string }> = [
	{ platform: 'macOS (Apple Silicon)', asset: 'loot-cli-aarch64-apple-darwin.tar.xz' },
	{ platform: 'macOS (Intel)', asset: 'loot-cli-x86_64-apple-darwin.tar.xz' },
	{ platform: 'Windows (x64)', asset: 'loot-cli-x86_64-pc-windows-msvc.zip' },
	{ platform: 'Linux (x64, gnu)', asset: 'loot-cli-x86_64-unknown-linux-gnu.tar.xz' },
	{ platform: 'Linux (ARM64, gnu)', asset: 'loot-cli-aarch64-unknown-linux-gnu.tar.xz' },
];

type Os = 'unix' | 'windows';

function detectOs(): Os {
	if (typeof navigator === 'undefined') return 'unix';
	const probe = `${navigator.platform ?? ''} ${navigator.userAgent ?? ''}`;
	return /win/i.test(probe) ? 'windows' : 'unix';
}

function Install() {
	// Deterministic first render (unix) so SSR and hydration agree; the client
	// nudges the toggle to the detected OS after mount.
	const [os, setOs] = useState<Os>('unix');
	useEffect(() => {
		setOs(detectOs());
	}, []);

	return (
		<div className="doc-prose">
			<section className="hero">
				<p className="eyebrow">Install</p>
				<h1>Get loot</h1>
				<p className="tagline">
					One command. The installer detects your platform, downloads the
					signed binary from GitHub Releases, unpacks it to{' '}
					<code>~/.loot/bin</code>, and puts it on your <code>PATH</code>.
				</p>

				<div className="os-toggle" role="tablist" aria-label="Operating system">
					<button
						type="button"
						data-active={os === 'unix'}
						onClick={() => setOs('unix')}
					>
						macOS / Linux
					</button>
					<button
						type="button"
						data-active={os === 'windows'}
						onClick={() => setOs('windows')}
					>
						Windows
					</button>
				</div>

				{os === 'unix' ? (
					<CodeBlock language="bash">{INSTALL_SH_ONELINER}</CodeBlock>
				) : (
					<CodeBlock language="powershell">{INSTALL_PS1_ONELINER}</CodeBlock>
				)}
				<p className="hint">
					Then open a fresh shell and run <code>loot --version</code> — it
					should print <code>loot 0.1.0</code>. Re-running the installer is
					idempotent.
				</p>
			</section>

			<section className="section">
				<h2>All platforms</h2>
				<p className="lede">
					Prebuilt binaries for the {RELEASE_TAG} release. Download and unpack
					manually if you'd rather not pipe a script.
				</p>
				<table>
					<thead>
						<tr>
							<th>Platform</th>
							<th>Download</th>
						</tr>
					</thead>
					<tbody>
						{PLATFORMS.map((p) => (
							<tr key={p.asset}>
								<td>{p.platform}</td>
								<td>
									<a href={`${DOWNLOAD_BASE}/${p.asset}`}>{p.asset}</a>
								</td>
							</tr>
						))}
					</tbody>
				</table>
				<div className="note">
					<strong>Windows on ARM:</strong> the PowerShell installer maps ARM64
					Windows onto the x64 build, which runs under emulation. A native
					<code>aarch64-pc-windows-msvc</code> binary is tracked but not yet
					shipped, so there is no separate ARM64 Windows download.
				</div>
			</section>

			<section className="section">
				<h2>Verify your download</h2>
				<p className="lede">
					Every release publishes a unified <code>sha256.sum</code> and GitHub
					Artifact Attestations. Two independent ways to check what you got.
				</p>

				<h3>1. Checksum</h3>
				<p>Hash the archive and compare it against the published sum.</p>
				<CodeBlock language="powershell">
					{'# Windows (PowerShell)\nGet-FileHash .\\loot-cli-x86_64-pc-windows-msvc.zip -Algorithm SHA256'}
				</CodeBlock>
				<CodeBlock language="bash">
					{'# macOS / Linux\nshasum -a 256 loot-cli-x86_64-unknown-linux-gnu.tar.xz\n\n# ...then confirm the hash is the line for that file in:\ncurl -sSfL ' +
						DOWNLOAD_BASE +
						'/sha256.sum'}
				</CodeBlock>

				<h3>2. Provenance (attestation)</h3>
				<p>
					Cryptographically verify the binary was built by loot's release
					workflow, using the{' '}
					<a href="https://cli.github.com/manual/gh_attestation_verify">
						GitHub CLI
					</a>
					:
				</p>
				<CodeBlock language="bash">
					{'gh attestation verify loot-cli-x86_64-unknown-linux-gnu.tar.xz --repo Connor-Miller/loot'}
				</CodeBlock>

				<div className="note">
					<strong>A note on the automated Windows path.</strong> The
					<code>irm | iex</code> one-liner verifies over TLS only — it has no
					embedded checksum, by design (this matches how uv and other
					cargo-dist tools ship). The binary is always fetched GitHub-direct
					over HTTPS; loot.millerbyte.com only proxies the install{' '}
					<em>script</em>, never the binary. For defense in depth on Windows,
					download manually and run the checksum or attestation check above.
				</div>
			</section>

			<section className="section">
				<h2>Build from source</h2>
				<p className="lede">
					loot is a Rust workspace. Building yourself needs a Rust toolchain;
					the binary is <code>loot</code> in the <code>loot-cli</code> crate.
				</p>
				<CodeBlock language="bash">
					{'cargo install --git https://github.com/Connor-Miller/loot loot-cli'}
				</CodeBlock>
				<p className="hint">
					A published <code>cargo install loot-cli</code> from crates.io is a
					deferred fast-follow, not the headline — the hosted one-liner above is
					the supported path.
				</p>
			</section>

			<section className="section">
				<h2>Troubleshooting</h2>
				<div className="doc-prose">
					<ul>
						<li>
							<strong>
								<code>loot</code> not found after install
							</strong>{' '}
							— the installer prepends <code>~/.loot/bin</code> to your{' '}
							<code>PATH</code> (via the user registry on Windows). Open a{' '}
							<em>fresh</em> shell so the change is picked up.
						</li>
						<li>
							<strong>Confirm the version</strong> — <code>loot --version</code>{' '}
							prints the binary's self-reported version; a versioned release and
							the binary can't drift.
						</li>
						<li>
							<strong>Manual install</strong> — grab the archive for your
							platform from the{' '}
							<a href={RELEASES_URL}>releases page</a>, unpack it, and put the{' '}
							<code>loot</code> binary anywhere on your <code>PATH</code>.
						</li>
					</ul>
				</div>
			</section>
		</div>
	);
}
