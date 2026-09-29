#!/usr/bin/env bash
# The checked-in copies of upstream's flags and routes still describe the
# upstream that is pinned.
#
# `scripts/conventions.sh` rules 14 and 15 compare this program against
# `upstream-flags.txt` and `upstream-routes.txt`. Those files are snapshots,
# taken by hand from gvisor-tap-vsock's source, with the commands to regenerate
# them in their headers. Nothing ran those commands again.
#
# So the drift the rules exist to catch has a second door of its own: bump the
# version in `differential/interop/go.mod`, do not regenerate, and rules 14 and
# 15 go on passing against a list that describes the version before. They would
# be checking parity with an upstream nobody is using -- confidently, and in
# CI's own voice.
#
# This closes that door. It reads the pinned module and regenerates both
# snapshots, and a difference is a failure that says what to run.
#
# It is a separate script rather than another rule in `conventions.sh` because
# it needs Go and a network or a populated module cache, and `conventions.sh` is the gate
# that answers in a second on any machine. This one runs beside the interop
# driver, which pins the module it reads.
#
# Usage:
#   scripts/upstream-snapshots.sh          check, and fail on a difference
#   scripts/upstream-snapshots.sh --write  regenerate the snapshots in place

set -uo pipefail
cd "$(dirname "$0")/.."

write=0
[[ "${1:-}" == "--write" ]] && write=1

module="github.com/containers/gvisor-tap-vsock"
# `go list -m` reports where a module is and never fetches it, so on an empty
# cache it answered nothing and this failed before reading a line. CI's cache
# is only as good as setup-go's last restore, and GitHub evicts a cache unused
# for a week: the first push after a quiet week failed here whatever it
# changed. Fetching the pinned version is a no-op on a warm cache. If the fetch
# itself fails, the FAIL below still says so rather than comparing nothing.
(cd differential/interop && go mod download "$module")
upstream="$(cd differential/interop && go list -m -f '{{.Dir}}' "$module" 2>/dev/null)"
if [[ -z "$upstream" || ! -d "$upstream" ]]; then
    echo "FAIL: could not locate $module in the module cache."
    echo "      \`cd differential/interop && go mod download\` puts it there."
    exit 1
fi
version="$(cd differential/interop && go list -m -f '{{.Version}}' "$module" 2>/dev/null)"

config="$upstream/cmd/gvproxy/config.go"
paths="$upstream/pkg/types/paths.go"
for required in "$config" "$paths"; do
    if [[ ! -f "$required" ]]; then
        echo "FAIL: $required does not exist in $module $version."
        echo "      Upstream moved it, so this check is reading nothing. Find where it went"
        echo "      rather than deleting this: the snapshots next door describe a layout that"
        echo "      has changed underneath them."
        exit 1
    fi
done

flags="$(sed -n '/flagSet\./p' "$config" | grep -oE '"[a-z][a-z0-9-]+"' | tr -d '"' | sort -u)"
routes="$(cd "$upstream" && grep -hoE 'mux\.Handle(Func)?\("[^"]+"' \
    pkg/virtualnetwork/mux.go pkg/virtualnetwork/services.go pkg/services/*/*.go | sort -u)"
connect="$(grep -oE 'ConnectPath = "[^"]+"' "$paths")"

# A grep over someone else's source can match nothing, and two empty lists agree
# perfectly. These floors are what stops "upstream reorganised and this pattern
# now matches nothing" being reported as "the snapshots are current".
if [[ "$(printf '%s\n' "$flags" | grep -c .)" -lt 15 ]]; then
    echo "FAIL: only $(printf '%s\n' "$flags" | grep -c .) flags read from $config."
    exit 1
fi
if [[ "$(printf '%s\n' "$routes" | grep -c .)" -lt 10 ]]; then
    echo "FAIL: only $(printf '%s\n' "$routes" | grep -c .) route registrations read from $upstream."
    exit 1
fi
if [[ -z "$connect" ]]; then
    echo "FAIL: types.ConnectPath was not found in $paths."
    exit 1
fi

if [[ $write -eq 1 ]]; then
    # Headers are preserved: they explain where each file came from, and
    # rewriting them from here would put this script's idea of the provenance in
    # place of the one a reader was given.
    for file in scripts/upstream-flags.txt scripts/upstream-routes.raw; do
        grep '^#' "$file" > "$file.new"
        case "$file" in
            *flags.txt) printf '%s\n' "$flags" >> "$file.new" ;;
            *routes.raw) printf '%s\n' "$routes" >> "$file.new" ;;
        esac
        mv "$file.new" "$file"
    done
    echo "wrote the snapshots from $module $version"
    echo "NOTE: scripts/upstream-routes.txt is the ASSEMBLED paths and is not written here."
    echo "      Re-do that assembly by hand if the raw registrations changed; its header says how."
    exit 0
fi

status=0
compare() {
    local name="$1" file="$2" fresh="$3"
    local stored
    stored="$(grep -v '^#' "$file" | grep . || true)"
    if [[ "$stored" != "$fresh" ]]; then
        echo "✘ $file does not match $module $version"
        diff <(printf '%s\n' "$stored") <(printf '%s\n' "$fresh") | sed 's/^/    /'
        echo "    Run scripts/upstream-snapshots.sh --write, then check what changed:"
        echo "    a new $name upstream is a decision for this port, not a diff to accept."
        status=1
    fi
}
compare "flag" scripts/upstream-flags.txt "$flags"
compare "route" scripts/upstream-routes.raw "$routes"

# The one path upstream registers through a constant rather than a literal, so
# the grep above cannot see it and rule 15's list would keep asserting a path
# that had been renamed.
if ! grep -q -- "$(printf '%s' "$connect" | grep -oE '"[^"]+"' | tr -d '"')" scripts/upstream-routes.txt; then
    echo "✘ upstream's $connect is not in scripts/upstream-routes.txt"
    status=1
fi

if [[ $status -eq 0 ]]; then
    echo "✔ the upstream snapshots describe $module $version"
fi
exit $status
