#!/usr/bin/env bash
# Run a list of candidate mutations through `falsify.sh`, one at a time.
#
# This is the exploratory half of `guards.tsv`. A row there is a mutation some
# test is known to catch; a row HERE is a mutation nobody has asked about yet,
# and the interesting answer is SURVIVED -- a check the suite would not miss.
#
# ## Why this exists rather than a loop written on the spot
#
# Because the loop written on the spot got it wrong. The scratch version of this
# reimplemented what `falsify.sh` already does -- patch, build, test, restore --
# and did it worse: no verification that the mutation was still in place when
# the test ran, and a restore that could race a killed process. It reported
# SURVIVED for `RTTEstimator.maximumTimeout`, whose sixty-second ceiling is
# asserted twice over by `backingOffDoublesTheTimeoutAndSaturatesAtSixtySeconds`.
# Run through `falsify.sh` the same mutation is CAUGHT.
#
# A false SURVIVED is not a harmless error. It is an instrument saying "nothing
# is watching this" about something that is watched, and the work it invites --
# a test for a property that already has one -- looks productive while it is
# being done. Every survival this session was re-run through `falsify.sh` before
# anything was written down because of that one reading.
#
# So this delegates. It contributes a loop and nothing else, and the thing that
# decides an outcome is the same script CI runs.
#
# Usage:
#   scripts/sweep.sh <candidates.tsv>
#
# The candidates file has `guards.tsv`'s columns:
#
#   file <TAB> test-filter <TAB> anchor <TAB> replacement
#
# with `\n` in the anchor and replacement expanded as newlines, exactly as
# there. A test-filter of `-` runs the WHOLE SUITE, which is what a sweep
# usually wants: the question is whether anything at all notices.
#
# `-` rather than an empty column, because an empty one does not survive the
# read. Tab is IFS whitespace, so `read` folds a run of tabs into one delimiter
# and an empty field between two of them simply disappears -- the filter column
# vanishes and every later field shifts left by one. That fails as NO-ANCHOR on
# every row, which at least fails loudly; a format where it could have shifted
# into something that still matched would not have.
#
# The candidates file is scratch. It is not committed and it is not
# `guards.tsv` -- when a mutation turns out to be caught by a test worth naming,
# the row moves there by hand, with the filter filled in.

set -uo pipefail
cd "$(dirname "$0")/.."

candidates="${1:-}"
if [[ -z "$candidates" || ! -f "$candidates" ]]; then
    echo "usage: scripts/sweep.sh <candidates.tsv>" >&2
    exit 2
fi

anchor_file="$(mktemp)"
replacement_file="$(mktemp)"
trap 'rm -f "$anchor_file" "$replacement_file"' EXIT INT TERM

surviving=0
total=0
unmeasured=0
while IFS=$'\t' read -r file filter anchor replacement extra; do
    [[ -z "${file:-}" || "$file" == \#* ]] && continue
    total=$((total + 1))
    printf '%b' "$anchor" > "$anchor_file"
    printf '%b' "$replacement" > "$replacement_file"

    if [[ -n "${filter:-}" && "$filter" != "-" ]]; then
        outcome="$(./scripts/falsify.sh "$file" "$anchor_file" "$replacement_file" "$filter" | tail -1)"
    else
        outcome="$(./scripts/falsify.sh "$file" "$anchor_file" "$replacement_file" | tail -1)"
    fi

    # The label is the replacement's first line: a sweep's rows have no test to
    # name, so the mutation is the only thing that identifies them.
    label="$(printf '%b' "$replacement" | head -1 | sed 's/^ *//')"
    printf '%-10s %s  [%s]\n' "$outcome" "$file" "$label"
    case "$outcome" in
        SURVIVED) surviving=$((surviving + 1)) ;;
        NO-ANCHOR | NOT-BUILT) unmeasured=$((unmeasured + 1)) ;;
    esac
done < "$candidates"

echo
echo "$total candidates, $surviving survived, $unmeasured not measured"

# Survivals are the point, so they are not a failure. This exits non-zero only
# when a candidate could not be evaluated at all -- an anchor that is not there,
# or a mutation that does not compile -- because those are the two outcomes that
# mean the sweep measured nothing while appearing to have run, which is the
# failure this whole script exists because of.
[[ $unmeasured -eq 0 ]]
