# 027. The `.agent.toml` config file layer: nearest-up-from-cwd, env-mirrored keys, typos are errors *(2026-07-17)*

**Context.** The engine's configuration resolves through the precedence
`flags > env (AGENT_*) > file > defaults`, and the file layer is the piece that lets a project pin its
engine config beside its code instead of carrying it on every invocation. Three forces shape that layer.
It has to be discoverable the way developers already expect, so the config nearest the work wins. It has
to speak one vocabulary with the environment, so a value reads the same whichever layer supplies it. And
it has to fail loudly on a mistake, because a silently ignored key in a security-sensitive config (kernel,
rootfs, scratch) is worse than no file at all.

**Decision.** The file layer sits between the environment and the defaults as a `.agent.toml` **file**.
Discovery is the **nearest `.agent.toml` walking up from the cwd** (the `.gitignore`/`.editorconfig`
convention), so a project pins its engine config beside its code and a nearer file shadows a farther one.
The file's keys **mirror the `AGENT_*` env names 1:1** (minus the prefix, lowercased: `kernel`, `rootfs`,
`marker`, `scratch_dir`, `firecracker`, `log`; decision 034 later added `signing_key` and
`trusted_keys` on the same pattern), so a value is spelled the same across all three lower
layers, one vocabulary. **Unknown keys are a typed error** (`serde(deny_unknown_fields)`): a typo like
`kernal` fails loudly, naming the valid keys, rather than silently no-opping.

**Consequences.** The layering reuses the engine, it doesn't reimplement it.
`agent-vmm::BootConfig::from_env_with` (made public for this) takes a lookup closure; the CLI composes
`std::env::var_os(key).or_else(|| file.env_value(key))`, which resolves `env > file > defaults` for every
artifact/scratch key with **zero duplication** of the engine's env-key handling or its pinned defaults.
The config values with no `BootConfig` field are resolved by parallel helpers in the CLI: `log` (it
drives `tracing`, not the engine) follows `flag > env > file > default`, and decision 034's
`signing_key` follows `env > file > default` while its `trusted_keys` is a **union** across layers
rather than an override (rotation wants the set, not the winner). This keeps the file layer entirely in the
CLI (the reference embedder); a library embedder builds `BootConfig` programmatically and is unaffected.
Making `from_env_with` public is an additive change to `agent-vmm`, not to the enumerated pinned items
(`Sandbox`/`Limits`/`RunResult`/`VmmError`/`channel`).
