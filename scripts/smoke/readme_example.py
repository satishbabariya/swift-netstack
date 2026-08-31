"""What `Tests/NetstackTests/READMEExample.swift` must contain.

The README's Swift examples are the first thing anybody runs, and nothing
checked that they still said something true: every symbol in them has been
renamed or re-typed at some point, and a `Gateway.start` that changed shape
would have left the page wrong with nothing failing.

So they are compiled, as part of the test target. That leaves the copy free to
drift from the page it stands in for, which this closes: the check regenerates
the expected body from the README and compares, so there is one definition of
what the file should hold rather than two that agree today.
"""

import re
import sys


def expected_body(readme: str) -> str:
    """The README's code examples, indented to sit inside a function."""
    blocks = re.findall(r"```swift\n(.*?)```", readme, re.S)
    # The first two are Package.swift fragments, not code that can compile here.
    body = "\n".join(block.rstrip("\n") for block in blocks[2:5])
    lines = [line for line in body.splitlines() if not line.strip().startswith("import ")]
    return "\n".join(("    " + line) if line.strip() else line for line in lines)


def body_in(source: str) -> str:
    """What the file between the markers actually holds."""
    match = re.search(r"// EXAMPLE BEGINS\n.*?\{\n(.*?)\n\}\n// EXAMPLE ENDS", source, re.S)
    return match.group(1) if match else ""


if __name__ == "__main__":
    readme = open("README.md").read()
    source = open("Tests/NetstackTests/READMEExample.swift").read()
    if expected_body(readme) != body_in(source):
        print("Tests/NetstackTests/READMEExample.swift no longer matches the README's examples")
        sys.exit(1)
