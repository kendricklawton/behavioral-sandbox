# Run a CI job from a fork

Execute an untrusted pull request's scripts without giving them the runner.

```console
$ ekvm run \
    --put project.tar --put ci-job.sh --get report.txt \
    --record-summary ci.json -- /bin/sh ci-job.sh
```

Note the absence: **no `--net`**, so the sandbox has no NIC at all, and `ci.json` records
`"network": null`. That is the record's proof of it, rather than an assurance that the job did not
try. A fork's test suite cannot exfiltrate what it cannot reach.

This example is jailed (no `--unjailed`), because a CI runner executing fork code is exactly the case
where the VMM's own confinement is worth having rather than a dev-box convenience to skip.

## A runnable job script

[`docs/examples/ci-job.sh`](./examples/ci-job.sh) is a minimal job of this shape: unpack the submitted
sources, run their test suite, leave a report behind. It needs nothing installed at run time, since
`python3` is baked into the guest rootfs.

```console
tar cf project.tar my-project/
ekvm run --put project.tar --put docs/examples/ci-job.sh --get report.txt \
    --record-summary ci.json -- /bin/sh ci-job.sh
```

## Making the record load-bearing

On a shared runner, the useful step is to stop trusting that whoever invokes the engine passes the
right flags. `require_record` refuses any run that would leave no audit record, `require_jail`
withdraws the `--unjailed` opt-out, and `allow_net = false` refuses `--net` outright. Those are host
posture rather than per-run knobs, and they deliberately sit outside the flags-over-env-over-file
precedence, since a ceiling a caller can override is not a ceiling. See
[Operator policy](./cli-config.md#operator-policy).
