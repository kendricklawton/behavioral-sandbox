# 031. The `.agent.toml` config file layer: nearest-up-from-cwd, env-mirrored keys, typos are errors *(2026-07-17)*

**Decision.** The config precedence `flags > env (AGENT_*) > file > defaults` becomes real by inserting
a `.agent.toml` **file** layer between the environment and the defaults. Discovery is the **nearest
`.agent.toml` walking up from the cwd** (the `.gitignore`/`.editorconfig` convention), so a project
pins its engine config beside its code and a nearer file shadows a farther one. The file's keys
**mirror the `AGENT_*` env names 1:1** (minus the prefix, lowercased: `kernel`, `rootfs`, `marker`,
`scratch_dir`, `firecracker`, `log`), so a value is spelled the same across all three lower layers,
one vocabulary. **Unknown keys are a typed error** (`serde(deny_unknown_fields)`): a typo like
`kernal` fails loudly, naming the valid keys, rather than silently no-opping.

**The layering reuses the engine, it doesn't reimplement it.** `agent-vmm::BootConfig::from_env_with`
(made public for this) takes a lookup closure; the CLI composes `std::env::var_os(key).or_else(|| file.env_value(key))`,
which resolves `env > file > defaults` for every artifact/scratch key with **zero duplication** of the
engine's env-key handling or its pinned defaults. The one config value with no `BootConfig` field,
`log` (it drives `tracing`, not the engine), is resolved by a parallel `flag > env > file > default`
helper in the CLI. This keeps the file layer entirely in the CLI (the reference embedder); a library
embedder builds `BootConfig` programmatically and is unaffected. Making `from_env_with` public is an
additive change to `agent-vmm`, not to the enumerated pinned items (`Sandbox`/`Limits`/`RunResult`/
`VmmError`/`channel`).
