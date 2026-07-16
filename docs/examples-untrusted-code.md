# Running untrusted code

Run a script or a binary you don't trust inside a microVM, feed it input, and read a structured
result back. Every command here is `agent run`, jailed by default; add `--unjailed` on a dev box
without real root and the `jailer` binary (the guest still sits behind the KVM boundary).

Point the CLI at the agent rootfs once:

```console
export AGENT_ROOTFS=artifacts/rootfs-agent.ext4
export AGENT_MARKER=AGENT-GUEST-READY
```

## A script, with stdin

The guest command reads stdin like any process; logs go to stderr, so `2>/dev/null` leaves only
the program's own output:

```console
$ echo 'hello' | cargo run -q -p agent-cli -- run -- \
    python3 -c 'import sys; print(sys.stdin.read().upper())' 2>/dev/null
HELLO
```

## A structured result

`--json` replaces the raw relay with one JSON object on stdout: the exit code, the (lossy-UTF-8)
streams, any returned artifacts, and host-measured metrics. A crash *inside* the guest is a result,
not an error (death by signal comes back as `128 + signal`); exit code `2` from `agent run` itself
means the engine failed to stand the run up.

```console
$ cargo run -q -p agent-cli -- run --json -- python3 -c 'print(2 + 2)' 2>/dev/null
{"exit_code":0,"stdout":"4\n","stderr":"","artifacts":[],"metrics":{"boot_ms":128,"exec_wall_ms":41}}
```

Pipe it straight into `jq`:

```console
$ cargo run -q -p agent-cli -- run --json -- python3 -c 'print(2 + 2)' 2>/dev/null | jq .exit_code
0
```

## Files in, files out

Inject host files into the run's working directory with `--put`, and fetch results with `--get`.
`--get` is deny-by-default: only the paths you name are written back, so a run cannot smuggle out a
file you didn't ask for.

```console
$ echo 'a,b,c' > input.csv
$ cargo run -q -p agent-cli -- run \
    --put input.csv --get output.txt -- \
    python3 -c 'open("output.txt","w").write(open("input.csv").read().count(",").__str__())'
$ cat output.txt
2
```

Secrets ride the call too: `--env KEY=VALUE` sets a variable on the guest command only (never the
agent's own process), and its value never appears in a log line, an error, or the console. For bulk
data, use the block-device input/output paths from [Using the engine API](./embedding.md) rather
than stdin or `--put`, which are bounded to a single frame.

## A static binary

The engine runs any statically-linked Linux binary, not just the interpreters baked into the
rootfs: inject it with `--put`, mark it executable in the command, and run it.

```console
$ cargo run -q -p agent-cli -- run --put ./mytool -- /bin/sh -c 'chmod +x mytool && ./mytool'
```

## Holding a session open

`agent shell` keeps one sandbox open across many commands, each sharing the guest's filesystem, so
state accumulates (install a package on one line, use it on the next). See [Using the agent
CLI](./cli.md#agent-shell).
