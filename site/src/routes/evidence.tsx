import { createFileRoute } from '@tanstack/react-router';

export const Route = createFileRoute('/evidence')({
	component: Evidence,
});

// Placeholder shell — real content lands with the five-surfaces ticket (spec
// §4: a proof-log index — one card per committed, re-runnable demo output).
function Evidence() {
	return (
		<>
			<h1>Evidence</h1>
			<p className="placeholder">
				Placeholder shell — the proof log (loot-hosts-loot, concurrent agents,
				hard-embargo attack demo, loot-first) arrives with the content ticket.
			</p>
		</>
	);
}
