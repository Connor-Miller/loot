import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import { defineConfig } from 'vite';
import viteReact from '@vitejs/plugin-react';
import { nitro } from 'nitro/vite';

export default defineConfig({
	build: {
		target: 'esnext',
	},
	optimizeDeps: {
		include: ['lucide-react'],
	},
	ssr: {
		// lucide-react ships ESM that misbehaves when pre-bundled for SSR
		// (mirrors millerbyte's frontend, the reference implementation).
		external: ['lucide-react'],
	},
	plugins: [
		// Every page route prerenders — no ssr:false islands, so no prerender
		// deny-list (docs/research/deploy-chain-loot-site.md, Link 1). The two
		// install[.]{sh,ps1} server routes are the deliberate exception to
		// "fully static": nitro functions proxying the installer scripts (see
		// the spec §2 amendment).
		tanstackStart({
			srcDirectory: 'src',
			prerender: {
				enabled: true,
				crawlLinks: true,
			},
			pages: [{ path: '/' }],
		}),
		viteReact(),
		nitro(),
	],
});
