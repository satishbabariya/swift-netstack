#!/usr/bin/env bash
# The README states how many tests there are. Keep it true.
#
# A number maintained by hand in prose drifts every time anything is added, and
# it was updated fifteen times in a single day of work here -- by hand, from
# memory of what the last run printed. It is a small claim, but it is the first
# concrete one a reader meets and it is trivially checkable.
#
# Takes the count from a `swift test` log rather than running the suite again,
# so CI does not pay for it twice.

set -uo pipefail
cd "$(dirname "$0")/.."

log="${1:-}"
if [[ -z "$log" || ! -f "$log" ]]; then
    echo "usage: $0 <swift-test-log>" >&2
    exit 2
fi

actual=$(grep -oE 'Test run with [0-9]+ tests' "$log" | grep -oE '[0-9]+' | tail -1)
if [[ -z "$actual" ]]; then
    echo "✘ could not find a test count in $log" >&2
    exit 2
fi

stated=$(grep -oE '^[0-9]+ tests, plus a differential harness' README.md | grep -oE '^[0-9]+')
if [[ -z "$stated" ]]; then
    echo "✘ README.md no longer states a test count in the expected form" >&2
    exit 1
fi

if [[ "$stated" != "$actual" ]]; then
    echo "✘ README says $stated tests; the suite has $actual" >&2
    exit 1
fi
echo "✔ README's test count is $actual"
