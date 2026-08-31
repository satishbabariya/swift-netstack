#!/usr/bin/env bash
# Everything CI runs, in one command.
#
# The gates were seven separate scripts plus a handful of bare `swift`
# invocations spread across five CI jobs, and the difference between "I ran the
# gates" and "I ran the ones I remembered" was a matter of memory. It went wrong
# in the cheapest possible way: CI builds with -warnings-as-errors and nothing
# local did, so a `try` on a call that does not throw passed here and failed
# there, after the branch was already pushed.
#
# `scripts/conventions.sh` checks that every script CI invokes is invoked here
# too, so a gate added to CI cannot quietly stop being runnable locally.
#
#   --quick   skip the two slow ones (falsify, the 10,000-sequence differential
#             gate). Everything else still runs. Use it while iterating; run the
#             whole thing before pushing.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

quick=0
[[ "${1:-}" == "--quick" ]] && quick=1

status=0
failed=()

# Output is held and printed only when the step fails. A gate runner whose
# passing output is four thousand lines of green is one whose summary nobody
# reads, which defeats the point of collecting the gates in the first place.
step() {
    local name="$1"
    shift
    local held
    held="$(mktemp)"
    if "$@" >"$held" 2>&1; then
        echo "✔ $name"
    else
        echo "✘ $name"
        sed 's/^/    /' "$held"
        failed+=("$name")
        status=1
    fi
    rm -f "$held"
}

# CI's own first build. Warnings are errors there and were not here, which is
# the whole reason this file exists.
step "build with warnings as errors" \
    swift build --build-tests -Xswiftc -warnings-as-errors

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
# `tee` rather than a redirect: the log is what check-test-count.sh reads, and
# `step` needs the same text to have something to print if the suite fails.
step "tests" bash -c 'set -o pipefail; swift test 2>&1 | tee "$0"' "$log"
step "the README's test count" ./scripts/check-test-count.sh "$log"

step "formatting" ./scripts/format.sh
step "conventions" ./scripts/conventions.sh
step "interop with upstream's client" ./scripts/interop.sh
step "frames through the built executable" ./scripts/frame-smoke.sh
# Says "skipped" and passes where the platform has no seqpacket, which is every
# Mac. CI's Linux job is where this one actually runs.
step "a frame through the seqpacket wire" ./scripts/bess-smoke.sh

if [[ $quick -eq 1 ]]; then
    echo
    echo "skipped (--quick): falsify the guards, the full differential gate"
else
    step "the full differential gate" \
        env NETSTACK_DIFFERENTIAL_SEQUENCES=10000 swift test --filter Differential
    step "falsify the guards" ./scripts/falsify.sh --all
fi

echo
if [[ $status -eq 0 ]]; then
    echo "✔ every gate holds"
else
    # Named again, at the end, because the detail is printed where it happened
    # and a long run is read from the bottom. "something above did not hold" is
    # true and useless: it sent me back to search a few thousand lines three
    # times in one day, and twice I did not search far enough and pushed anyway.
    echo "✘ these did not hold:"
    for name in "${failed[@]}"; do
        echo "    - $name"
    done
fi
exit $status
