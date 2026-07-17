import { createRouter } from '@tanstack/react-router';
import { routeTree } from './routeTree.gen';

// TanStack Start calls getRouter() on both server and client to build the
// router. Fully static site: no auth context (millerbyte's frontend is the
// reference stack; loot is the all-static subset).
export function getRouter() {
	const router = createRouter({
		routeTree,
		defaultPreload: 'intent',
		scrollRestoration: true,
	});
	return router;
}

declare module '@tanstack/react-router' {
	interface Register {
		router: ReturnType<typeof getRouter>;
	}
}
