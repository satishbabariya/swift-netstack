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


# 11. Every flag the program takes is named in the README, and every flag the
#     README names either exists or is documented as deliberately absent.
#
# The README said `--listen-bess`, `--listen-stdio` and `--listen-vpnkit` were
# "recognised and refused by name" for most of a day after all three became
# wires. It was true when written, which is what makes this kind of claim
# dangerous: nothing fails when it stops being true, and the only reader who
# finds out is one who believed it.
#
# `[a-zA-Z0-9-]` rather than `[a-zA-Z-]`: gvproxy spells two of them
# `--gatewayIP` and `--hostIP`, and the lowercase-only version this started as
# reported neither of them missing while both were. The version that replaced it
# stopped at the first digit, and the anchoring quote meant a flag containing one
# matched nothing at all -- so `--ec2-metadata-access`, the one flag here with a
# security consequence, was invisible to this rule entirely. It is documented,
# and this rule had nothing to do with that. A check blind to part of its subject
# reports confidently on the part it can see.
flags=$(grep -oE 'case "--[a-zA-Z0-9-]+"' Sources/netstack-gateway/main.swift \
    | grep -oE '\-\-[a-zA-Z0-9-]+' | sort -u)
for flag in $flags; do
    if ! grep -q -- "$flag" README.md; then
        fail "the program takes $flag and the README does not mention it" \
            "a flag nobody has written down is a flag nobody will use"
    fi
done

# The reverse, which was written first and then dropped: the README legitimately
# names flags this program does not take, and a rule fighting its own
# documentation gets answered by weakening the documentation. Naming them
# answers that objection -- each entry below is itself a claim a reader can
# check, and there are eight.
#
#   --ssh-port, --forward-*    SSH forwarding, named in the section that says it
#                              is deliberately absent
#   --quick, --all, --filter   flags of check.sh, falsify.sh and swift test
#
# What it catches: a flag the README offers and the program refuses. The reader
# copies the line and gets an unknown-flag error, which is worse than an
# undocumented flag because it was documented wrongly.
documented_elsewhere="--ssh-port --forward-sock --forward-dest --forward-user"
documented_elsewhere="$documented_elsewhere --forward-identity --quick --all --filter"
for flag in $(grep -oE '\-\-[a-zA-Z][a-zA-Z0-9-]*' README.md | sort -u); do
    case " $documented_elsewhere " in *" $flag "*) continue ;; esac
    if ! echo "$flags" | grep -qx -- "$flag"; then
        fail "the README names $flag and the program does not take it" \
            "a reader copying that line gets an unknown-flag error"
    fi
done


# 13. Every setting the config file parses is one the program applies.
#
# `tcpConnectTimeout` was parsed into `FileConfiguration.dialTimeout` from the
# day the file was added, validated as an integer, and read by nothing. The
# library had the timeout it belonged in and the two were never joined, so
# anyone who set it got the five-second default and no indication otherwise.
#
# A flag the program does not take is refused loudly, and rule 11 keeps the flags
# and the README together. A config *key* has neither: JSON the program does not
# understand is JSON it ignores, so a setting that reaches no code is
# indistinguishable, from outside, from a setting that does nothing.
#
# The struct is the list, because it is what the parser fills in. `[:=]` rather
# than `:`, because `var debug = false` declares its type by inference and an
# earlier version of this rule, written against annotated fields only, would not
# have looked at it.
fields=$(awk '/^struct FileConfiguration \{/{inside=1;next} inside&&/^\}/{exit} \
    inside&&/^    var [a-zA-Z]+[[:space:]]*[:=]/{print $2}' \
    Sources/netstack-gateway/Configuration.swift | tr -d ':')
if [[ -z "$fields" ]]; then
    fail "no fields were found in FileConfiguration" \
        "this rule reads the struct to know what to check, and it read nothing"
fi
for field in $fields; do
    if ! grep -q "file\.$field" Sources/netstack-gateway/main.swift; then
        fail "the config file parses $field and main.swift never reads it" \
            "a setting that reaches no code is one the operator set and did not get"
    fi
done


# 14. Every flag gvproxy takes is one this program takes, or one the README
#     says is deliberately absent.
#
# The README says "Everything else gvproxy has is here". That sentence was true
# of the flags and false of the program: gvproxy also serves the three
# forwarding routes to the guest at <gatewayIP>:80, and this port had nothing
# there for its whole life underneath that claim. Nothing checked it, because
# the claim was prose.
#
# This checks the part that can be checked mechanically. `scripts/upstream-flags.txt`
# is upstream's flagSet, read out of its source and carried here because CI has
# no Go module to read it from; its header says how to regenerate it against a
# newer upstream.
#
# A flag this program does not take passes only if the README names it in a
# sentence about being absent, which is how the SSH family passes: the point is
# that dropping one silently is not possible, not that everything must exist.
absent_section=$(sed -n '/^### What is not here/,/^## /p' README.md)
while read -r flag; do
    [[ -z "$flag" || "$flag" == \#* ]] && continue
    if echo "$flags" | grep -qx -- "--$flag"; then
        continue
    fi
    # Whole token, not substring. Written as a plain grep, a README that had
    # renamed `--ssh-port` to `--ssh-port-renamed` still excused `--ssh-port`,
    # because the old name is a prefix of the new one -- the rule passed while
    # the sentence it depends on had stopped existing.
    if echo "$absent_section" | grep -qE -- "--$flag([^a-zA-Z0-9-]|$)"; then
        continue
    fi
    fail "gvproxy takes --$flag and this program neither takes it nor says why not" \
        "a flag that quietly stopped existing is the drift this file is for"
done < scripts/upstream-flags.txt


# 12. The README's examples compile, and the copy that compiles is the README's.
#
# They are the first thing anybody runs. Every symbol in them has been renamed or
# re-typed at some point in this project's life, and a `Gateway.start` that
# changed shape would have left the page wrong with nothing failing.
#
# `Tests/NetstackTests/READMEExample.swift` holds them inside a function nothing
# calls, so the test build type-checks them. That leaves the copy free to drift
# from the page it stands in for, which this closes.
if ! python3 scripts/smoke/readme_example.py; then
    fail "the compiled copy of the README's examples is not what the README says" \
        "regenerate it from the code blocks, or the page and the check disagree"
fi

if [[ $status -eq 0 ]]; then
    echo "✔ conventions hold"
fi
exit $status
