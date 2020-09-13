// The install one-liners use `curl -sSf` / `irm` with no redirect-following,
// so these paths must answer 200 with the script bytes. A vercel.json external
// rewrite cannot do this: Vercel proxies GitHub's response as-is, and
// `releases/latest/download/…` (and the versioned asset URL behind it) always
// 302 to GitHub's CDN — the client would see the 302 (falsified live,
// 2026-07-17; the spec's §2 rewrite mechanism doesn't survive contact). This
// server route fetches upstream instead — fetch follows the redirect chain —
// and streams the final bytes back as the response.
const INSTALLER_BASE =
	'https://github.com/Connor-Miller/loot/releases/latest/download';

export async function proxyInstaller(asset: string): Promise<Response> {
	const upstream = await fetch(`${INSTALLER_BASE}/${asset}`);
	return new Response(upstream.body, {
		// Pass upstream failures through un-redirected (a 404 before a release
		// exists stays a 404); never a 3xx.
		status: upstream.status,
		headers: {
			'content-type': 'text/plain; charset=utf-8',
			// Short shared cache: a new release becomes the served installer
			// within minutes without a site redeploy.
			'cache-control': 'public, max-age=300, s-maxage=300',
		},
	});
}
