# Contributing

Thank you for looking at this. The short version: run `./scripts/check.sh`
before you push, and make sure your test can fail.

The rest of this file is the long version, because this repository has a few
conventions that are not the usual ones and a pull request written without them
will get comments that look arbitrary. They are not arbitrary; they are what a
userspace network stack for a hostile guest needs. Knowing them first should
save you a round trip.

## Getting set up

Swift 6.2 or newer, macOS 14 or newer. Go is needed only for the differential
harness and the interop check.

```
git clone https://github.com/satishbabariya/swift-netstack.git
cd swift-netstack
swift build
swift test
```

To run everything CI runs:

```
./scripts/check.sh          # all of it, including the slow gates
./scripts/check.sh --quick  # skips falsify and the full differential gate
```

`--quick` is for iterating. Run the whole thing before you push: the two gates
it skips are the two that take twenty minutes in CI, and finding out there is
the slow way.

## The one rule

**A check that cannot fail is worse than no check**, because it reports
confidence it has not earned. Everything below follows from that.

If you add a test, break the thing it tests and watch it fail. If it still
passes, the test is not testing what its name says. This is not a formality —
it has caught real problems in this repository more than once, including a
fuzzer that had been reaching the TCP parser zero times for weeks while looking
perfectly healthy.

### Tests need controls

Most bugs here would be invisible to an assertion that is also true of a stack
that does nothing. `#expect(x == 0)` passes on a component that never ran.
`#expect(bytes.isEmpty)` passes on a connection that was never established.

So an assertion about something *not* happening is paired with a positive
control showing the thing does happen under different conditions:

```swift
#expect(sender.duplicateAcknowledgements == 0, "an ACK with nothing outstanding is not a duplicate")

// The control, and it is what makes the assertion above mean anything: all of
// it is equally true of a sender that has stopped counting duplicates at all.
// Give the same sender something to lose and the same three acknowledgements
// have to do what RFC 5681 §3.2 says.
```

Write the control *before* the assertion it protects where you can. A control
written afterwards is a control written to suit the result.

### `scripts/guards.tsv`

Each row names a source line, a test, and a mutation of that line. CI applies
every mutation and requires the named test to fail. It is how this repository
knows its tests still test what they used to.

Adding a row:

```
<file>	<test name>	<exact source line>	<replacement>
```

Tab-separated; `\n` in the anchor or replacement is expanded as a newline. Then
prove it:

```
scripts/falsify.sh <file> <anchor-file> <replacement-file> <test-name>
```

It prints `CAUGHT`, `SURVIVED`, `NO-ANCHOR`, or `NOT-BUILT`. Only add the row if
it says `CAUGHT`.

**Do not add a row that reports an outcome it did not earn.** If your mutation
survives because some other check catches it, or because the guard is redundant
with a bounds check one layer down, that is a real and useful finding — write it
in a comment at the site and leave the row out. Several places in this codebase
say exactly that, with the measurement, so the next person does not read a green
run as permission to delete something.

### Exploring with `scripts/sweep.sh`

To ask "would anything notice if this changed?", put candidate mutations in a
TSV and run them:

```
scripts/sweep.sh candidates.tsv
```

Same columns as `guards.tsv`, with `-` in the test column meaning "run the whole
suite". `SURVIVED` is the interesting answer. The candidates file is scratch and
is not committed.

It delegates to `falsify.sh` rather than doing the work itself, and that is
deliberate: an earlier version reimplemented the patch-build-test-restore loop,
got the restore wrong, and reported `SURVIVED` for a constant that two
assertions in one test already covered. Do not write your own loop.

## Conventions the CI enforces

`scripts/conventions.sh` checks seventeen rules and names each one when it
fires. The ones that surprise people:

1. **No locks in `Sources/Netstack`.** Everything is confined to one
   `EventLoop`. The single exception is `ManualClock`, and it is marked as one.
2. **No wall-clock reads outside the clock.** No `NIODeadline.now()` in product
   code — take the time from the injected clock, or a test cannot control it.
3. **Nothing writes to the process's own output.** Logging goes through
   `NetstackLog`; a library that prints to stdout corrupts `--listen-stdio`.
9. **Guest-caused logging is rate-limited.** A guest that can make you log a
   line per frame has found a way to fill a disk.
16. **Every counter a component keeps is exposed in `Statistics`.** A number
   nobody can read is a number that does not exist.
17. **The tree is not sitting in a mutation.** Every `guards.tsv` anchor must be
   present in its file. This exists because a killed `falsify.sh` once left its
   mutation behind and `git add -A` committed it into an open pull request.

Rules 14 and 15 compare this port's flags and API routes against checked-in
snapshots of gvproxy's, and `scripts/upstream-snapshots.sh` checks those
snapshots still describe the pinned upstream. A flag or route that quietly stops
existing is the drift they are for.

## Style

- Four-space indent, 180 columns. `./scripts/format.sh` settles it.
- Tests use Swift Testing (`@Test func`), one flat namespace, no suites.
- `#expect` messages must be a single expression — no `+` concatenation.
- Comments explain *why*, and especially why something is not the obvious
  alternative. The measurement that settled a question is worth more than the
  conclusion: several comments here record what was falsified, what survived,
  and what that means for a future editor.

## Pull requests

- Branch from `main`; `main` is protected and takes merges only through PRs.
- Say what you measured, not only what you changed. If you found a bug, say how
  it would have been observed by someone running this in production.
- Negative results are welcome. "I tried to break X five ways and could not" is
  worth writing down, and this repository has several such notes.

## Reporting a security problem

Do not open an issue. See [SECURITY.md](SECURITY.md).
