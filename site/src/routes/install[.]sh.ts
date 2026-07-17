import { createFileRoute } from '@tanstack/react-router';
import { proxyInstaller } from '../lib/installerProxy';

export const Route = createFileRoute('/install.sh')({
	server: {
		handlers: {
			GET: () => proxyInstaller('loot-cli-installer.sh'),
		},
	},
});
