#!/usr/bin/env bash
# Every flag gvproxy takes is either taken here or listed below as deliberately
# absent.
#
# The README says so in prose: "Everything else gvproxy has is here. Every wire
# ... and every other flag." That sentence was true when it was written and
# nothing was keeping it true. This reads both command lines and compares them.
#
# It is worth having as a check rather than a habit for one reason above the
# rest: the pinned upstream version will be bumped one day, and a version bump
# is exactly the moment a new flag arrives and nobody looks at the command line.
# Reading upstream is also how three things went wrong before -- see
# `interop.sh`, which exists for the same reason from the other end.
#
# Absence is allowed. Absence that nobody decided is not.

set -uo pipefail
cd "$(dirname "$0")/.."

# Flags gvproxy has that this port deliberately does not, each with the reason
# it is not here. A flag missing from BOTH this list and the command line is
# what this check exists to catch.
#
# All five are the SSH forwarding feature, which the README's "What is not here"
# explains at length: it needs an SSH client, a parser for OpenSSH's private key
# format including the KDF for encrypted keys, and the
# `direct-streamlocal@openssh.com` channel extension -- a crypto dependency and
# a protocol implementation, neither checkable the way everything else here is
# without an SSH server to check against.
declared_absent=(
    forward-sock
    forward-dest
    forward-user
    forward-identity
    ssh-port
)

module="github.com/containers/gvisor-tap-vsock"
upstream_dir="$(cd differential/interop && go list -m -f '{{.Dir}}' "$module" 2>/dev/null)"
if [[ -z "$upstream_dir" || ! -d "$upstream_dir" ]]; then
    echo "FAIL: could not locate $module in the module cache."
    echo "      \`cd differential/interop && go mod download\` puts it there."
    exit 1
fi

config="$upstream_dir/cmd/gvproxy/config.go"
if [[ ! -f "$config" ]]; then
    echo "FAIL: $config does not exist."
    echo "      Upstream moved its flag definitions, so this check is reading nothing."
    echo "      That is a real failure: find where they went rather than deleting this."
    exit 1
fi

# `flagSet.StringVar(&args.x, "name", ...)`, and the Var/BoolVar/IntVar forms.
theirs="$(grep -oE '(StringVar|BoolVar|IntVar|Var)\([^,]+, *"[a-z0-9-]+"' "$config" |
    grep -oE '"[a-z0-9-]+"$' | tr -d '"' | sort -u)"
ours="$(grep -oE 'case "--[a-z0-9-]+"' Sources/netstack-gateway/main.swift |
    sed 's/case "--//;s/"//' | sort -u)"

# Both extractions are greps over source, so both can silently match nothing --
# and a check comparing two empty lists passes. These floors are what stops that
# being reported as parity. They are not tight: the point is "this read
# something", not "this read exactly twenty".
#
# The digit in `[a-z0-9-]` is not decoration. Without it the pattern misses
# `ec2-metadata-access` on both sides at once, which cancels out to a clean
# report while the check is reading neither command line properly. That is how
# this script came to be written: the same missing digit, in the same grep, run
# by hand, reported a parity gap that was not there.
their_count=$(printf '%s\n' "$theirs" | grep -c . || true)
our_count=$(printf '%s\n' "$ours" | grep -c . || true)
if [[ "$their_count" -lt 15 ]]; then
    echo "FAIL: only $their_count flags found in upstream's $config, which cannot be right."
    exit 1
fi
if [[ "$our_count" -lt 15 ]]; then
    echo "FAIL: only $our_count flags found in Sources/netstack-gateway/main.swift."
    exit 1
fi

status=0
for flag in $theirs; do
    if printf '%s\n' "$ours" | grep -qx -- "$flag"; then
        continue
    fi
    declared=false
    for absent in ${declared_absent[@]+"${declared_absent[@]}"}; do
        [[ "$flag" == "$absent" ]] && declared=true && break
    done
    if [[ "$declared" == false ]]; then
        echo "✘ gvproxy takes --$flag and this does not, and nothing says that is deliberate."
        echo "    Implement it, or add it to \`declared_absent\` in this script with the reason."
        status=1
    fi
done

# The list is checked in the other direction too. A flag that gets implemented
# and left in `declared_absent` turns this from a check into a comment, and one
# upstream has dropped is a gap that stopped existing without anyone noticing.
for absent in ${declared_absent[@]+"${declared_absent[@]}"}; do
    if printf '%s\n' "$ours" | grep -qx -- "$absent"; then
        echo "✘ --$absent is listed as deliberately absent and is implemented."
        echo "    Remove it from \`declared_absent\`."
        status=1
    fi
    if ! printf '%s\n' "$theirs" | grep -qx -- "$absent"; then
        echo "✘ --$absent is listed as deliberately absent and gvproxy no longer has it."
        echo "    Remove it from \`declared_absent\`: it is not a gap any more."
        status=1
    fi
done

if [[ $status -eq 0 ]]; then
    echo "✔ every one of gvproxy's $their_count flags is taken here or declared absent"
fi
exit $status
