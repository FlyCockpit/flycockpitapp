# Custom shell tools

Configured entries under `tools.*` and the `web.custom.*` commands are shell templates. Each `{name}` marker becomes one required string tool argument. Markers are rendered in one left-to-right pass and values are POSIX single-quoted; a value can never trigger a second placeholder substitution.

Custom commands run with a cleared environment. Only Cockpit's explicit, non-sensitive session environment overlay is supplied; credential-like variables (including `OPENAI_API_KEY` and `GH_TOKEN`) are removed.

When shell sandboxing is available and enabled, custom commands run confined to the same workspace/session boundary as `bash`. If the sandbox is explicitly off (or unavailable only after the user disables it), ordinary configured custom tools require an approval grant keyed by the invoking agent and the tool name before running unconfined. `webfetch` and `websearch` supplied through `web.provider = "custom"` are the intentional exception: configuring those two commands is itself their authorization, so they never prompt, while still receiving the cleared environment and sandbox confinement.
