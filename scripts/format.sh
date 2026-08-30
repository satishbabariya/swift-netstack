#!/usr/bin/env bash
# Check, or apply, this repository's own formatting.
#
# `.swift-format` sat here unenforced with 657 findings against it -- because it
# was swift-format's default configuration, saved once and never reconciled with
# the code. A configuration that describes a state the code has never been in is
# not a standard, it is a note somebody left.
#
# It describes the code now: four spaces, 180 columns, indented conditional
# compilation blocks, and the rules this codebase deliberately does not follow
# turned off rather than ignored -- tests force-unwrap on purpose, and an
# if/else is often clearer here than an early exit.
#
#   scripts/format.sh          check, and fail if anything is unformatted
#   scripts/format.sh --fix    format in place

set -uo pipefail
cd "$(dirname "$0")/.."

formatter="$(xcrun --find swift-format 2>/dev/null || command -v swift-format)"
if [[ -z "$formatter" ]]; then
    echo "swift-format not found" >&2
    exit 2
fi

if [[ "${1:-}" == "--fix" ]]; then
    "$formatter" format --recursive --parallel --in-place Sources Tests
    exit $?
fi

# `lint` reports style violations; the diff catches formatting the linter does
# not consider a violation but the formatter would still change. Both, because
# either alone lets something through.
"$formatter" lint --recursive --parallel --strict Sources Tests || exit 1

before="$(mktemp -d)"
cp -R Sources Tests "$before"/
"$formatter" format --recursive --parallel --in-place Sources Tests
if ! diff -rq "$before/Sources" Sources >/dev/null 2>&1 || ! diff -rq "$before/Tests" Tests >/dev/null 2>&1; then
    diff -ru "$before/Sources" Sources | head -40
    diff -ru "$before/Tests" Tests | head -40
    cp -R "$before/Sources" . && cp -R "$before/Tests" .
    rm -rf "$before"
    echo "✘ not formatted. Run scripts/format.sh --fix" >&2
    exit 1
fi
rm -rf "$before"
echo "✔ formatted"
