# Recipes

## One shot: open, run, read the result

```rust,no_run
use vmm::{BootConfig, Sandbox, VmmError};

fn main() -> Result<(), VmmError> {
    // 1. Resolve boot configuration from environment (EKVM_KERNEL, EKVM_ROOTFS, etc.)
    let config = BootConfig::from_env();

    // 2. Open a sandbox (confined by default under the jailer)
    let sandbox = Sandbox::open(config)?;

    // 3. Execute a command in the sandbox
    let result = sandbox.exec(&["python3".into(), "-c".into(), "print('Hello from eKVM!')".into()], b"")?;

    println!("Exit code: {}", result.exit_code);
    println!("Stdout: {}", String::from_utf8_lossy(&result.stdout));
    println!("Host wall-clock latency: {:?}", result.metrics.wall);

    sandbox.shutdown()?;
    Ok(())
}
```

## Budgets and files on the call

```rust,no_run
use std::num::{NonZeroU32, NonZeroU8};
use std::time::Duration;
use vmm::{BootConfig, Limits, Sandbox, VmmError};

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
use vmm::{BootConfig, Pool, Snapshot, Vm, VmmError};

fn main() -> Result<(), VmmError> {
    // 1. Boot an unjailed source VM to prepare a pre-warmed snapshot
    let source_cfg = BootConfig::from_env();
    let source_vm = Vm::boot(source_cfg)?;

    let snap_dir = tempfile::tempdir().unwrap();
    let snapshot = source_vm.snapshot(snap_dir.path())?;

    // 2. Initialize a pool of 4 pre-warmed clones (clones will restore jailed)
    let pool_cfg = BootConfig::from_env();
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
recreate their tap in a private netns (014), so any number coexist.

**Sizing rule** (stated here so you never meet it as `EMFILE`): each live VM holds up to
`FDS_PER_VM` (8) driver-side fds, so keep

```
N_live × FDS_PER_VM + headroom (≈64, process baseline)  ≤  ulimit -n (soft)
```

`Pool::new` checks this and logs one warning naming the numbers when a target oversubscribes the
budget, a warning, not a refusal, matching how the engine treats every other best-effort host
resource. The measured steady state is 2
fds per VM on every start path, pinned by test; the constant is deliberately above it so growth is
a visible bump, never drift.

## A minimal reference integration

For the whole lifecycle in one small file, embedding the engine end to end (load the host-side
observers, `open` a jailed sandbox, attach the probes, `exec`, `collect` the audit record, `close`,
then print both the `RunResult` and the JSON record), see the runnable example
[`crates/probes-loader/examples/reference_integration.rs`](../crates/probes-loader/examples/reference_integration.rs).
It composes the driver and the loader the way a downstream host application would.

## The CLI is the reference embedder

`ekvm run` is the lifecycle in one command: piped stdin, `--env`, `--put`/`--get`, `--wall`,
`--output-cap`, `--json` (the structured result as one JSON object on stdout, stderr carries the
logs, so pipelines stay clean), `--unjailed` as the loud opt-out. `ekvm shell` holds one sandbox
open as an interactive stateful session. If you're writing an SDK, start from the daemon's
[reference client](./daemon.md#the-reference-client) (`client`), which exists for exactly that.
