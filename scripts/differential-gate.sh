#!/usr/bin/env bash
# The differential gate, plus a check that it ran anything at all.
#
# This was a bare `swift test --filter Differential` in two places, in
# scripts/check.sh and in the CI workflow. A filter matching nothing exits 0 and
# prints "Test run with 0 tests in 0 suites passed", so had the suite been
# renamed both callers would have gone green having compared no sequences.
#
# The differential's own comment warns about this shape one level down, where an
# absent harness is made a failure rather than a skip: "a run of ten thousand
# sequences and a run of none are reported identically". The filter selecting
# that test had no such floor, in the gate that certifies the milestone.
#
# Pass or fail is the exit status, never the output -- output contains whatever
# the code under test chose to print. The count is only the floor.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

SEQUENCES="${NETSTACK_DIFFERENTIAL_SEQUENCES:-10000}"

output="$(mktemp)"
trap 'rm -f "$output"' EXIT INT TERM

NETSTACK_DIFFERENTIAL_SEQUENCES="$SEQUENCES" swift test --filter Differential 2>&1 | tee "$output"
outcome=${PIPESTATUS[0]}
[[ $outcome -ne 0 ]] && exit "$outcome"

# At least one, rather than the exact four that match today: adding a
# differential test should not fail this, and zero is the whole hazard.
ran="$(sed -n 's/.*Test run with \([0-9][0-9]*\) test.*/\1/p' "$output" | tail -1)"
if [[ -z "$ran" ]]; then
    echo "could not tell how many tests ran, so this gate proved nothing" >&2
    exit 1
fi
if [[ "$ran" -lt 1 ]]; then
    echo "the Differential filter selected no tests, so this gate compared nothing" >&2
    exit 1
fi

echo "ok: differential  $ran tests over $SEQUENCES sequences"
