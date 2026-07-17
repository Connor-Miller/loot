/// <reference types="vite/client" />
import {
	HeadContent,
	Link,
	Scripts,
	createRootRoute,
} from '@tanstack/react-router';
import type { ReactNode } from 'react';
import { INSTALL_SH_ONELINER } from '../lib/install';
import appCss from '../styles.css?url';

// Nav = the five surfaces (spec §4): loot (home) · Install · Docs · Why loot ·
// Evidence · GitHub ↗. Footer repeats the install one-liner + GitHub + license
// + a "built with loot" badge into Evidence.
export const Route = createRootRoute({
	head: () => ({
		meta: [
			{ charSet: 'utf-8' },
			{ name: 'viewport', content: 'width=device-width, initial-scale=1.0' },
			{
				name: 'description',
				content:
					'loot — version control where visibility and permissions are properties of content, not of the repository.',
			},
			{ title: 'loot' },
		],
		links: [{ rel: 'stylesheet', href: appCss }],
	}),
	shellComponent: RootDocument,
});

const GITHUB_URL = 'https://github.com/Connor-Miller/loot';

function RootDocument({ children }: { children: ReactNode }) {
	return (
		<html lang="en">
			<head>
				<HeadContent />
			</head>
			<body>
				<header className="site-header">
					<Link to="/" className="brand">
						loot
					</Link>
					<nav>
						<Link to="/install">Install</Link>
						<Link to="/docs">Docs</Link>
						<Link to="/why">Why loot</Link>
						<Link to="/evidence">Evidence</Link>
						<a href={GITHUB_URL} target="_blank" rel="noreferrer">
							GitHub ↗
						</a>
					</nav>
				</header>
				<main className="site-main">{children}</main>
				<footer className="site-footer">
					<code>{INSTALL_SH_ONELINER}</code>
					<div className="links">
						<a href={GITHUB_URL} target="_blank" rel="noreferrer">
							GitHub
						</a>
						<a href={`${GITHUB_URL}/blob/main/LICENSE`} target="_blank" rel="noreferrer">
							License
						</a>
						<Link to="/evidence">built with loot</Link>
					</div>
				</footer>
				<Scripts />
			</body>
		</html>
	);
}
