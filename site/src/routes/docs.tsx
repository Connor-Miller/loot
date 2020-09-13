import { createFileRoute } from '@tanstack/react-router';

export const Route = createFileRoute('/docs')({
	component: Docs,
});

// Placeholder shell — real content lands with the five-surfaces ticket (spec
// §4: Getting started · Core concepts · Task guides · CLI reference).
function Docs() {
	return (
		<>
			<h1>Docs</h1>
			<p className="placeholder">
				Placeholder shell — Getting started, Core concepts, Task guides, and
				the CLI reference arrive with the content ticket.
			</p>
		</>
	);
}
