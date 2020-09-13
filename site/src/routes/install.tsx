import { createFileRoute } from '@tanstack/react-router';
import { CodeBlock } from '@millerbyte/ui';

export const Route = createFileRoute('/install')({
	component: Install,
});

// Placeholder shell — real content lands with the five-surfaces ticket (spec
// §4/§5: platform-detected default, all-platforms listing, verify-your-download).
function Install() {
	return (
		<>
			<h1>Install</h1>
			<p>macOS / Linux:</p>
			<CodeBlock language="bash">
				curl -sSf https://loot.millerbyte.com/install.sh | sh
			</CodeBlock>
			<p>Windows:</p>
			<CodeBlock language="powershell">
				powershell -ExecutionPolicy Bypass -c "irm https://loot.millerbyte.com/install.ps1 | iex"
			</CodeBlock>
			<p className="placeholder">
				Placeholder shell — the all-platforms listing, manual downloads, and
				verify-your-download instructions arrive with the content ticket.
			</p>
		</>
	);
}
