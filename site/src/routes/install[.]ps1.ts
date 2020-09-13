import { createFileRoute } from '@tanstack/react-router';
import { proxyInstaller } from '../lib/installerProxy';

export const Route = createFileRoute('/install.ps1')({
	server: {
		handlers: {
			GET: () => proxyInstaller('loot-cli-installer.ps1'),
		},
	},
});
