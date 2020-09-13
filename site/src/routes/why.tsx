import { createFileRoute } from '@tanstack/react-router';

export const Route = createFileRoute('/why')({
	component: Why,
});

// Placeholder shell — real content lands with the five-surfaces ticket (spec
// §4: sell-only — the claim, why now, grants over permission bits, proof).
function Why() {
	return (
		<>
			<h1>Why loot</h1>
			<p className="placeholder">
				Placeholder shell — the case for content-addressed custody (every host
				reads your code; loot&apos;s relay physically cannot) arrives with the
				content ticket.
			</p>
		</>
	);
}
