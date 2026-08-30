#!/usr/bin/env bash
# The conventions this package's design rests on, checked instead of read.
#
# Each of these is written down in the README or in a doc comment as something
# that is simply true of `Sources/Netstack`. Each was, at the time it was
# written, and the README said outright that the absence of locks was "checked
# by reading rather than by a test". Reading found a second lock had appeared in
# `WireBootstrap` some changes later, in a package whose whole concurrency
# design is that there are none.
#
# A convention nothing enforces is a convention until somebody is busy.

set -uo pipefail
cd "$(dirname "$0")/.."

status=0

fail() {
    status=1
    echo "✘ $1"
    shift
    printf '    %s\n' "$@"
}

# 1. No locks.
#
# Everything on the datapath is confined to one event loop, which is why there
# is nothing to contend for. `ManualClock` is the exception and is test-only:
# a test drives it from outside the loop deliberately.
locks=$(grep -rn "NIOLock\|NIOLockedValueBox\|DispatchSemaphore\|os_unfair_lock\|pthread_mutex\|DispatchQueue(" \
    Sources/Netstack --include='*.swift' | grep -v "Core/NetstackClock.swift" || true)
if [[ -n "$locks" ]]; then
    fail "a lock in Sources/Netstack, where the design is that there are none" $locks
fi

# 2. No wall-clock reads outside the clock itself.
#
# Every timer reads the injected `NetstackClock`, which is what makes a
# retransmission suite deterministic instead of a race against the machine.
# `RealClock` is where the one real call lives; `PacketCapture` takes its own
# wall clock because a monotonic deadline is useless in a file somebody
# correlates with something outside this process.
now=$(grep -rn "NIODeadline\.now()\|DispatchTime\.now()\|Date()" Sources/Netstack --include='*.swift' \
    | grep -v "Core/NetstackClock.swift" | grep -v "^\S*:[0-9]*: *///" || true)
if [[ -n "$now" ]]; then
    fail "a direct clock read outside NetstackClock" $now
fi

# 3. Nothing writes to the process's own output.
#
# A library that prints has decided for the program that links it. Everything
# diagnostic goes through `RateLimitedLogger`, which is bounded because a guest
# can cause it.
# Anywhere on the line, not just at the start of one: the first version of this
# anchored to `^\s*print(` and a `print` inside braces on a shared line walked
# straight past it. The leading class excludes `sprint(`, `.print(` and the like.
printing=$(grep -rnE "(^|[^A-Za-z_.])print\(|FileHandle\.standard(Error|Output)" \
    Sources/Netstack --include='*.swift' || true)
if [[ -n "$printing" ]]; then
    fail "a library that writes to stdout or stderr" $printing
fi

# 4. The TCP implementation stays behind its own surface.
#
# `Transport/TCP` is a state machine with a lot of parts -- a sender, a
# receiver, a scoreboard, two congestion controllers, a reassembler, four timers
# -- and every one of them that is public is a thing somebody can depend on and
# this package then has to keep working. The allowlist below is the surface, and
# adding to it is meant to be a deliberate act rather than a side effect of
# needing something briefly.
#
# `CongestionControlAlgorithm` is on it because `TCPEndpoint.congestionControl`
# is public and a public property cannot have an internal type. `TCPForwarder`,
# `ForwarderRequest` and `TCPSplice` are on it because the gateway is built out
# of them from another module.
allowed="TCPEndpoint.swift\|CongestionControl.swift\|TCPForwarder.swift\|TCPSplice.swift"
tcp=$(grep -rn "^public \(struct\|class\|enum\|protocol\|func\|var\|let\|final\)" \
    Sources/Netstack/Transport/TCP --include='*.swift' \
    | grep -v "$allowed" || true)
if [[ -n "$tcp" ]]; then
    fail "a public type under Transport/TCP outside the allowed surface" $tcp
fi

# 5. Every recognised differential difference is documented.
#
# The gate asserts an exact set of labels -- a fourth appearing, or a third
# disappearing, fails it. But nothing connected that set to the prose, and
# `differential/README.md` said "the one difference that is recognised" for some
# time after there were three, with `sack-outside-established` described
# nowhere at all.
#
# The labels are read out of the test's own assertion rather than listed here,
# so this cannot drift from what the gate actually enforces.
labels=$(sed -n '/Set(recognisedCounts.keys) == \[/,/\]/p' Tests/NetstackTests/TCPDifferentialTests.swift \
    | grep -oE '"[a-z-]+(\+[a-z-]+)?"' | tr -d '"')
if [[ -z "$labels" ]]; then
    fail "could not read the recognised-difference labels out of TCPDifferentialTests" \
        "the assertion this reads may have been reworded"
else
    for label in $labels; do
        if ! grep -q -- "$label" differential/README.md; then
            fail "the gate recognises '$label' and differential/README.md does not describe it"
        fi
    done
fi

# 6. The harness pins gVisor to this stack's constants, and still does.
#
# `differential/README.md` says the comparison is about algorithms rather than
# about two choices of number, and that rests on three values being the same on
# both sides. Nothing checked it, and the failure would be quiet in the worst
# way: change `RTTEstimator.minimumTimeout` and the gate keeps passing while
# comparing two stacks with different RTO floors -- so it reports fewer real
# differences, not more.
check_pinned() {
    local name="$1" swift_value="$2" go_value="$3"
    if [[ -z "$swift_value" || -z "$go_value" ]]; then
        fail "could not read $name from both sides" "swift='$swift_value' go='$go_value'"
    elif [[ "$swift_value" != "$go_value" ]]; then
        fail "$name is $swift_value here and $go_value in the harness" \
            "the differential would compare two stacks tuned differently"
    fi
}

swift_min=$(grep -oE 'static let minimumTimeout = TimeAmount\.seconds\([0-9]+\)' \
    Sources/Netstack/Transport/TCP/RTTEstimator.swift | grep -oE '[0-9]+')
go_min=$(grep -oE 'TCPMinRTOOption\([0-9]+ \* time\.Second\)' differential/harness/main.go \
    | grep -oE '[0-9]+' | head -1)
check_pinned "the minimum RTO" "$swift_min" "$go_min"

swift_max=$(grep -oE 'static let maximumTimeout = TimeAmount\.seconds\([0-9]+\)' \
    Sources/Netstack/Transport/TCP/RTTEstimator.swift | grep -oE '[0-9]+')
go_max=$(grep -oE 'TCPMaxRTOOption\([0-9]+ \* time\.Second\)' differential/harness/main.go \
    | grep -oE '[0-9]+' | head -1)
check_pinned "the maximum RTO" "$swift_max" "$go_max"

swift_retries=$(grep -oE 'static let maximumFinTransmissions = [0-9]+' \
    Sources/Netstack/Transport/TCP/TCPEndpoint.swift | grep -oE '[0-9]+')
go_retries=$(grep -oE 'TCPMaxRetriesOption\([0-9]+\)' differential/harness/main.go | grep -oE '[0-9]+')
check_pinned "the retry limit" "$swift_retries" "$go_retries"

if [[ $status -eq 0 ]]; then
    echo "✔ conventions hold"
fi
exit $status
