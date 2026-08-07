# Recipes

## One shot: open, run, read the result

```rust,no_run
# extern crate bsx_engine;
use bsx_engine::{BootConfig, Sandbox, VmmError};

fn main() -> Result<(), VmmError> {
    // 1. Resolve boot configuration from environment (BSX_KERNEL, BSX_ROOTFS, etc.)
    let config = BootConfig::from_env();

    // 2. Open a sandbox (confined by default under the jailer)
    let sandbox = Sandbox::open(config)?;

    // 3. Execute a command in the sandbox
    let result = sandbox.exec(&["python3".into(), "-c".into(), "print('Hello from bsx!')".into()], b"")?;

    println!("Exit code: {}", result.exit_code);
    println!("Stdout: {}", String::from_utf8_lossy(&result.stdout));
    println!("Host wall-clock latency: {:?}", result.metrics.wall);

    sandbox.shutdown()?;
    Ok(())
}
```

## Budgets and files on the call

```rust,no_run
# extern crate bsx_engine;
use std::num::{NonZeroU32, NonZeroU8};
use std::time::Duration;
use bsx_engine::{BootConfig, Limits, Sandbox, VmmError};

fn main() -> Result<(), VmmError> {
    // 2 vCPU, 512 MiB RAM, 60s wall. `Limits` is `#[non_exhaustive]`, so a downstream crate
    // starts from `default()` and assigns rather than writing a struct literal.
    let mut limits = Limits::default();
    limits.vcpus = NonZeroU8::new(2).expect("nonzero");
    limits.mem_mib = NonZeroU32::new(512).expect("nonzero");
    limits.wall = Duration::from_secs(60);
    limits.output_cap = 16 * 1024 * 1024;

    // Apply limits onto boot config
    let config = BootConfig::from_env().with_limits(limits);
    let sandbox = Sandbox::open(config)?;

    // Execute with environment variables and input files
    let result = sandbox.exec_with_files(
        &["sh".into(), "-c".into(), "cat input.json && echo $ENV_VAR".into()],
        b"", // stdin
        &[("input.json".into(), b"{\"status\": \"ok\"}".to_vec())], // Injected file
        &[("ENV_VAR".into(), "secret-value".into())],              // Injected env
        &[],                                                       // Artifacts to fetch
    )?;

    println!("Output: {}", String::from_utf8_lossy(&result.stdout));
    sandbox.shutdown()?;
    Ok(())
}
```

## The pre-warmed pool

```rust,no_run
# extern crate bsx_engine;
use bsx_engine::{BootConfig, Jail, Pool, Snapshot, Vm, VmmError, DEFAULT_GUEST_CID};

fn main() -> Result<(), VmmError> {
    // 1. Boot an unjailed source VM to prepare a pre-warmed snapshot. `from_env` leaves the vsock
    // exec channel off, and a snapshot taken without it restores boot-only clones, so turn it on:
    // pre-warmed means exec-ready.
    let mut source_cfg = BootConfig::from_env();
    source_cfg.guest_cid = Some(DEFAULT_GUEST_CID);
    let source_vm = Vm::boot(source_cfg)?;

    // Any directory you own works; a snapshot bundle is just files. `tempfile` would do, but it is
    // not a dependency of `bsx-engine`, so this stays on `std` rather than sending you to add one.
    let snap_dir = std::env::temp_dir().join("bsx-pool-snapshot");
    std::fs::create_dir_all(&snap_dir).expect("create the snapshot dir");
    let snapshot = source_vm.snapshot(&snap_dir)?;

    // 2. Initialize a pool of 4 pre-warmed clones. `jail` on the pool config is what makes every
    // clone restore under the jailer; the `from_env` default (`None`) would restore them unjailed.
    let mut pool_cfg = BootConfig::from_env();
    pool_cfg.jail = Some(Jail::default());
    let mut pool = Pool::new(snapshot, pool_cfg, 4)?;

    // 3. Take a warm clone from the pool: a restore rather than a cold boot
    let warm_vm = pool.take()?;
    let result = warm_vm.exec(&["echo".into(), "warm start".into()], b"")?;
    println!("Execution completed: {}", String::from_utf8_lossy(&result.stdout));

    // 4. Refill pool back to target count
    pool.refill()?;

    pool.shutdown();
    Ok(())
}
```

A pooled clone is a pre-warmed session; entropy is reseeded per clone (VMGenID), and networked clones each
recreate their tap in a private netns, so any number coexist.

**Sizing rule** (stated here so you never meet it as `EMFILE`): each live VM holds up to
`FDS_PER_VM` (8) driver-side fds, so keep

```text
N_live × FDS_PER_VM + headroom (≈64, process baseline)  ≤  ulimit -n (soft)
```

`Pool::new` checks this and logs one warning naming the numbers when a target oversubscribes the
budget, a warning, not a refusal, matching how the engine treats every other best-effort host
resource. The measured steady state is 2
fds per VM on every start path, pinned by test; the constant is deliberately above it so growth is
a visible bump, never drift.

## A minimal reference integration

For the whole lifecycle in one small file, embedding the engine end to end (load the host-side
observers, `open` a jailed sandbox, attach the probes, `exec`, `collect` the audit record,
`shutdown`, then print both the `RunResult` and the JSON record), see the runnable example
[`crates/probes-loader/examples/reference_integration.rs`](https://github.com/kendricklawton/behavioral-sandbox/blob/main/crates/probes-loader/examples/reference_integration.rs).
It composes the driver and the loader the way a downstream host application would.

## The CLI is the reference embedder

`bsx run` is the lifecycle in one command: piped stdin, `--env`, `--put`/`--get`, `--wall`,
`--output-cap`, `--json` (the structured result as one JSON object on stdout, stderr carries the
logs, so pipelines stay clean), `--unjailed` as the loud opt-out. `bsx shell` holds one sandbox
open as an interactive stateful session. If you're writing a client, start from the daemon's
[reference client](./daemon.md#the-reference-client) (`bsx-client`), which exists for exactly that.
