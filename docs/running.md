# Running a sandbox

A sandbox with no flags shares nothing: the guest reads its root image, cannot write it, has no
network beyond loopback, and gets one empty directory mounted at `/results` for what it produces.
Everything past that is opted into on the command line, and the posture is printed (`--dry-run`
shows it without booting) because what is shared **is** the policy.

```console
bsx run --root ~/.local/share/bsx/rootfs -- uname -a
```

The guest root falls back to `$BSX_GUEST_ROOT`, then `~/.local/share/bsx/rootfs`, so after one
`export` the `--root` flag can be dropped.

## The verbs

| Verb | What it does |
|---|---|
| `bsx run -- CMD` | Runs one command in a fresh sandbox and exits with its status. |
| `bsx shell` | Opens an interactive session (or any command) on a pty in a fresh sandbox. |
| `bsx up --name NAME` | Starts a sandbox that outlives the command, reachable afterwards by name. |
| `bsx ls` | Lists the sandboxes running on this machine; `--all` adds the ended runs. |
| `bsx exec NAME -- CMD` | Runs a command in a sandbox that is already up; `--tty` attaches a terminal. |
| `bsx stop NAME` | Stops a running sandbox. |
| `bsx show ID\|NAME` | Prints one run's record: what it could touch, what it printed, what it wrote. |
| `bsx rm ID\|NAME` | Removes one run's record and everything it captured. |
| `bsx export ID\|NAME` | Writes one run as a ustar `.tar` (`--to` picks a directory or exact path). |

There is no daemon: a VM is a helper process listening on a control socket in the runtime
directory, so a sandbox started by the CLI is visible to the app and the other way round.

## The posture flags

`run`, `shell` and `up` share these; the record keeps what was granted.

| Flag | Grants | Default |
|---|---|---|
| `--rootfs writable` | The guest writes through to the shared image tree. | `read-only` |
| `--net tsi` | libkrun's socket impersonation: the guest reaches what the host can. | `none` |
| `--mount GUESTDIR=HOSTDIR` | A host directory read-write at a guest path. Repeatable. | nothing |
| `--share TAG=HOSTPATH` | An extra virtiofs device for a guest that mounts by tag. Repeatable. | nothing |
| `--display WIDTHxHEIGHT[@HZ]` | A virtio-gpu display in a window; closing the window stops the sandbox. | none |
| `--sound` | A virtio-snd card on the host's audio server: playback **and** capture. | off |
| `--env KEY=VALUE` | One guest environment entry. Repeatable. | nothing |
| `--vcpus N`, `--mem MIB` | Sizing; also `$BSX_VCPUS` and `$BSX_MEM_MIB`. | 1 vCPU, 512 MiB |
| `--no-results` | Drops the default `/results` mount. | mounted |

## What a run leaves

Every run leaves one directory under `$BSX_RUNS_DIR`, else `$XDG_DATA_HOME/bsx/runs`, else
`~/.local/share/bsx/runs`: the `record` file (the posture as settled, the timings, the end), the
captured output (capped at `$BSX_OUTPUT_CAP_KIB`, 4 MiB by default, with a `.truncated` sidecar
when cut), and `results/`, the directory the guest saw as `/results`. Ended runs beyond
`$BSX_RUNS_KEEP` (200 by default) are pruned oldest-first when a new run starts.

`bsx export` packages that directory as one ustar file a stock `tar` extracts. A symlink a guest
planted inside `results/` is archived as a link entry, never opened:
`a_symlink_is_archived_as_itself_and_never_followed` in `bsx-record` holds it to that. A file that
grows or shrinks mid-export keeps the size its header pinned, so exporting a live run stays
readable.

## The notebook

`bsx-app` opens on a menu that names the `bsx` binary and guest root it found, with the run count.
From there:

- **The list**: every run, newest first, live ones with a thumbnail of their display. `Clear
  history` removes the ended runs behind an inline confirm; live runs stay.
- **One run**: its posture, output and results beside its live display (keyboard and pointer go
  to the guest), with Stop and Shell while it runs, Re-run and Delete after, and Export always.
- **The start form**: every posture flag as a field, summarised in the record's own posture
  sentence ("This sandbox will: ..."), confirmed before anything boots.
- **Settings** (the platform's command with `,`, from any screen): the palette, applied live and
  kept across launches in a file beside the runs directory. `--theme` and `$BSX_THEME` outrank the
  saved pick for one launch.

`bsx-app NAME` opens straight onto a run; `--new` opens the form. Starting and stopping go through
the `bsx` binary beside the app (`$BSX_CLI` overrides which one).

## Platform notes

On macOS ARM64 the same verbs work, but this platform's libkrun builds no `--sound` and no guest
input backend, and a display is viewed in `bsx-app` rather than a window of the helper's own; sign
the binary again after any build (`cargo xtask sign`). The [Architecture](./architecture.md) page
carries the fuller status.
