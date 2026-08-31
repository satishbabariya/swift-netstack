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


# 7. Every gate CI runs can be run locally by one command.
#
# The gates live in seven scripts across five CI jobs, and "did I run them"
# used to be a question of memory. scripts/check.sh answers it -- but only for
# as long as it is still the same set. A gate added to ci.yml and not to
# check.sh is one that fails after the push rather than before it, which is the
# situation check.sh exists to end.
for referenced in $(grep -oE './scripts/[a-z-]+\.sh' .github/workflows/ci.yml | sort -u); do
    if ! grep -qF "$referenced" scripts/check.sh; then
        fail "ci.yml runs $referenced and scripts/check.sh does not" \
            "a gate that only exists in CI is one you find out about after pushing"
    fi
done


# 8. The smoke cases share their helpers rather than copying them.
#
# Every case in frame-smoke.sh is a self-contained Python program, so each one
# grew its own copy: five identical checksum routines and the same address
# parsing twenty-seven times. A copy that drifts fails silently -- a case whose
# checksum is wrong does not fail, it stops testing anything, because every
# packet it sends is discarded before it reaches the code the case is about.
for helper in ones_complement; do
    if grep -q "^ *def $helper" scripts/frame-smoke.sh; then
        fail "frame-smoke.sh defines $helper instead of importing it" \
            "a case with its own copy stops testing anything when the copy is wrong"
    fi
done


# 9. Guest-caused logging goes through the rate limiter.
#
# The README says a hostile guest cannot flood the host's disk through the log,
# and unlike the capture file -- which is capped at 64 MiB for the same reason --
# nothing bounds the log's size. What bounds it is that every guest-causable
# event goes through `RateLimitedLogger`, which is keyed on a closed enum and
# emits one line per kind per window.
#
# So a direct `logger.warning(...)` in the library is not a style question. It is
# a line a guest can cause as fast as it can send frames, on a disk nothing else
# is watching. The one allowed exception is the startup path in `Gateway`, which
# runs once before any guest exists.
# Matched on the method rather than on a variable called `logger`, which is the
# narrower rule this started as -- and which a `Logger` stored under any other
# name walked straight past. Checked against the whole library: the broad pattern
# finds exactly one line, and it is the exception below.
direct=$(grep -rnE "\.(debug|info|notice|warning|error|critical)\(" Sources/Netstack \
    | grep -v "Sources/Netstack/Observability/NetstackLog.swift" \
    | grep -v "could not open the capture file")
if [[ -n "$direct" ]]; then
    fail "library logging that does not go through the rate limiter" "$direct"
fi


# 10. Every datagram wire writes through its own descriptor.
#
# NIO closes a datagram channel when a write returns ENOBUFS, and a full unix
# datagram queue returns exactly that on BSD -- so a guest that pauses takes the
# gateway's network down for good unless the link writes to the descriptor
# itself, with a bounded retry.
#
# That fix was made once, for the adopted socket, and three other datagram wires
# did not have it: the LISTENING one, which is --listen-vfkit and the default;
# the dialling one; and bess. The first killed the default wire. Nothing
# connected them, because each is a separate call with its own argument list and
# the missing argument is invisible.
#
# `framed: false` is what makes a wire a datagram wire here -- there is no length
# prefix because the socket carries the boundaries -- so that is what this looks
# for. Per CALL rather than per line: a `configure(...)` spans several lines, so
# a line-by-line version reported every datagram wire as missing the argument
# that was three lines below it, and matched the word in a comment as well.
missing=$(python3 - <<'CHECK'
import re
import sys

source = open("Sources/Netstack/Wire/WireBootstrap.swift").read()
# Comments first: the phrase appears in prose explaining the very rule.
source = re.sub(r"//[^\n]*", "", source)

bad = []
for call in re.finditer(r"configure\(", source):
    depth, i = 0, call.end() - 1
    while i < len(source):
        if source[i] == "(":
            depth += 1
        elif source[i] == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    body = " ".join(source[call.end():i].split())
    if "framed: false" not in body:
        continue
    if "framed: Bool" in body or "rawDescriptor" in body:
        continue
    bad.append(body[:110])

for line in bad:
    print(line)
CHECK
)
if [[ -n "$missing" ]]; then
    fail "a datagram wire that writes through NIO rather than its own descriptor" "$missing"
fi

if [[ $status -eq 0 ]]; then
    echo "✔ conventions hold"
fi
exit $status
