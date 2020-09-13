import { Link, createFileRoute } from '@tanstack/react-router';
import { CodeBlock } from '@millerbyte/ui';
import { INSTALL_SH_ONELINER } from '../lib/install';

export const Route = createFileRoute('/')({
	component: Landing,
});

// Placeholder shell — real content lands with the five-surfaces ticket (#259,
// spec §4: thesis hook, "what works today", three demo vignettes, CTA row).
function Landing() {
	return (
		<>
			<h1>Version control where the host cannot read your code.</h1>
			<p>
				Visibility and permissions are properties of content and changes, not
				of the repository.
			</p>
			<CodeBlock language="bash">{INSTALL_SH_ONELINER}</CodeBlock>
			<p className="placeholder">
				Placeholder shell — landing content (thesis hook, demo vignettes, CTA
				row) arrives with the content ticket. Meanwhile:{' '}
				<Link to="/install">Install</Link> · <Link to="/why">Why loot</Link> ·{' '}
				<Link to="/evidence">Evidence</Link>
			</p>
		</>
	);
}
