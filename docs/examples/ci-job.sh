#!/bin/sh
# A minimal CI job, of the kind you'd run for an untrusted fork's pull request: unpack the submitted
# sources and run their test suite, leaving a report behind. It reaches no network — with no `--net`
# the sandbox is deny-by-default, and the host record proves the job couldn't phone home even if a
# test tried. Run it with:
#
#   agent run --put project.tar --put ci-job.sh --get report.txt \
#       --record-summary ci.json -- /bin/sh ci-job.sh
#
# python3 is baked into the guest rootfs, so this needs nothing installed at run time.
set -eu

# The run's working directory: where `--put` landed the files and where `--get` reads from.
start=$(pwd)
work=$(mktemp -d)

echo "== unpacking submitted sources =="
tar xf "$start/project.tar" -C "$work"
cd "$work"

echo "== running the test suite =="
if python3 -m unittest discover -v >"$start/report.txt" 2>&1; then
    echo "status=pass" >>"$start/report.txt"
    result=0
else
    echo "status=fail" >>"$start/report.txt"
    result=1
fi

tail -n 3 "$start/report.txt"
exit "$result"
