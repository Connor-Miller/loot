import { createFileRoute } from '@tanstack/react-router';
import { CodeBlock } from '@millerbyte/ui';
import { INSTALL_PS1_ONELINER, INSTALL_SH_ONELINER } from '../lib/install';

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
			<CodeBlock language="bash">{INSTALL_SH_ONELINER}</CodeBlock>
			<p>Windows:</p>
			<CodeBlock language="powershell">{INSTALL_PS1_ONELINER}</CodeBlock>
			<p className="placeholder">
				Placeholder shell — the all-platforms listing, manual downloads, and
				verify-your-download instructions arrive with the content ticket.
			</p>
		</>
	);
}
