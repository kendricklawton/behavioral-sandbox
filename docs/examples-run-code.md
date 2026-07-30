# Run untrusted code

Run a script or binary inside a microVM, feed it input, and receive a structured result.

## A script, with stdin

Logs go to stderr, so `2>/dev/null` leaves only the program's own output:

```console
$ echo 'hello' | ekvm run --unjailed -- python3 -c 'import sys; print(sys.stdin.read().upper())' 2>/dev/null
HELLO
```

## A structured result

`--json` replaces the raw relay with one JSON object on stdout: the exit code, streams, artifacts, and
host-measured metrics.

```console
$ ekvm run --unjailed --json -- python3 -c 'print(2 + 2)' 2>/dev/null | jq .exit_code
0
```

A crash *inside* the guest comes back as a result (`exit_code`), not an engine error. The engine
reserves exit code 2 for its own operational failures, so a caller can tell "your code failed" from
"the sandbox failed to run your code". See
[Streams and exit codes](./cli-commands.md#streams-and-exit-codes).

## Files in, files out

Inject host files into the run's working directory with `--put`, and fetch results with `--get`.
`--get` is **deny-by-default**: only paths you explicitly name come back, so a run cannot quietly
hand you more than you asked for.

```console
$ echo 'a,b,c' > input.csv
$ ekvm run --unjailed --put input.csv --get output.txt -- \
    python3 -c 'open("output.txt","w").write(open("input.csv").read().count(",").__str__())'
$ cat output.txt
2
```

`--put` and `--get` are for small, bounded files, since each rides a single exec frame. Whole
directories and large files belong on the block-device path (`input_dir`/`output_dir` in the
[engine API](./embedding.md)).
