#!/usr/bin/env bash
# Delete a guard and find out whether anything notices.
#
# This repository's tests are written on the premise that a guard with no test
# that fails when it is removed is not guarded, only described. Checking that has
# been done by hand all along, with a shell function that got two things wrong
# often enough to matter:
#
#   - It reported "not caught" when the mutation simply had not applied, because
#     the anchor text had drifted. A replacement that matches nothing changes
#     nothing and every test still passes, which reads exactly like a guard that
#     nothing depends on.
#   - It decided a build had failed by looking for "error:" anywhere in the
#     output -- and `netstack-gateway` prints its own errors with that prefix, so
#     a mutation that WAS caught got reported as a compile failure.
#
# Both make a falsification say the opposite of what happened, which is worse
# than not running one. So: the anchor must match, the build is judged by its own
# exit status, and the three outcomes are kept apart.
#
#   CAUGHT     the tests failed. The guard is guarded.
#   SURVIVED   the tests passed with the guard gone. Nothing depends on it.
#   NOT-BUILT  the mutation does not compile. Says nothing either way; write a
#              mutation that builds.
#
# Usage:
#   scripts/falsify.sh <file> <anchor-file> <replacement-file> [test-filter]
#   scripts/falsify.sh --all
#
# The anchor and replacement are read from files rather than argv so that
# quoting, newlines and backslashes survive -- which is the other thing that kept
# going wrong by hand.

set -uo pipefail
cd "$(dirname "$0")/.."

restore() {
    if [[ -n "${TARGET:-}" && -f "${BACKUP:-/nonexistent}" ]]; then
        cp "$BACKUP" "$TARGET"
        rm -f "$BACKUP"
        BACKUP=""
    fi
}
trap restore EXIT INT TERM

# Measures one mutation and puts the file back before returning.
#
# The restore is here rather than only in the EXIT trap, and that is not a
# refinement: with it only at exit, `--all` left every file it had touched
# mutated except the last, because each row overwrote the trap's idea of what to
# put back. It corrupted the working tree of the repository it was checking.
run_one() {
    TARGET="$1"; ANCHOR_FILE="$2"; REPLACEMENT_FILE="$3"; FILTER="${4:-}"
    BACKUP="$(mktemp)"
    cp "$TARGET" "$BACKUP"

    if ! python3 - "$TARGET" "$ANCHOR_FILE" "$REPLACEMENT_FILE" <<'PY'
import sys
target, anchor_file, replacement_file = sys.argv[1:4]
source = open(target).read()
anchor = open(anchor_file).read()
replacement = open(replacement_file).read()
if anchor not in source:
    sys.stderr.write("anchor does not appear in %s\n" % target)
    raise SystemExit(3)
open(target, "w").write(source.replace(anchor, replacement, 1))
PY
    then
        restore
        echo "NO-ANCHOR"
        return 3
    fi

    if ! swift build --build-tests >/dev/null 2>&1; then
        restore
        echo "NOT-BUILT"
        return 2
    fi

    if [[ -n "$FILTER" ]]; then
        swift test --filter "$FILTER" >/dev/null 2>&1
    else
        swift test >/dev/null 2>&1
    fi
    # `swift test` exits non-zero when a test fails, which is the whole signal.
    # Judged by status rather than by scraping output, because the output
    # contains whatever the code under test chose to print.
    local outcome=$?
    restore
    if [[ $outcome -ne 0 ]]; then
        echo "CAUGHT"
        return 0
    fi
    echo "SURVIVED"
    return 1
}

if [[ "${1:-}" == "--all" ]]; then
    status=0
    while IFS=$'\t' read -r file filter anchor replacement; do
        [[ -z "${file:-}" || "$file" == \#* ]] && continue
        a="$(mktemp)"; r="$(mktemp)"
        printf '%b' "$anchor" > "$a"
        printf '%b' "$replacement" > "$r"
        outcome="$(run_one "$file" "$a" "$r" "$filter")"
        rm -f "$a" "$r"
        printf '%-10s %s\n' "$outcome" "$filter"
        [[ "$outcome" != "CAUGHT" ]] && status=1
    done < scripts/guards.tsv
    exit $status
fi

if [[ $# -lt 3 ]]; then
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi
run_one "$@"
