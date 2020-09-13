// The hero commands, shared by the landing page, the install page, and the
// footer so they stay in lockstep. (Kept apart from installerProxy.ts — that
// module is the server route's; this one is imported by client components.)
export const INSTALL_SH_ONELINER =
	'curl -sSf https://loot.millerbyte.com/install.sh | sh';

export const INSTALL_PS1_ONELINER =
	'powershell -ExecutionPolicy Bypass -c "irm https://loot.millerbyte.com/install.ps1 | iex"';
