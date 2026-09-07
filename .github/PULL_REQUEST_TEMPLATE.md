<!--
Thanks for this. The boxes below are the questions review will ask anyway;
answering them here usually saves a round trip. Delete anything that does not
apply — a one-line documentation fix does not need a falsification report.
-->

## What this changes

<!-- What moved, and why. If it fixes a bug, say how someone running this would
     have noticed it — the failure as experienced, not only the line at fault. -->

## What you measured

<!-- This project's one rule is that a check which cannot fail is worse than no
     check. So: what did you break to prove the new test notices?

     If you added a `guards.tsv` row, paste the falsify.sh outcome:

         ./scripts/falsify.sh <file> <anchor> <replacement> <test>
         CAUGHT

     If a mutation SURVIVED and you decided that is correct — the guard is
     redundant with something one layer down, or two places enforce it — say so
     here and in a comment at the site. That is a useful finding, not a
     shortfall, and this repository has several of them written up. -->

## Checklist

- [ ] `./scripts/check.sh` passes (not just `--quick`)
- [ ] New tests have a **control** — a positive assertion showing the thing does
      happen under different conditions, so "it didn't happen" is not also true
      of a component that never ran
- [ ] Any new `guards.tsv` row prints `CAUGHT`, and no row was added for a
      mutation that survived
- [ ] Comments say *why*, including why not the obvious alternative
- [ ] The README, `--help`, and the config parser agree, if you touched a flag
      or a setting

<!-- If you are changing behaviour that gvproxy also has, mention how upstream
     does it. Parity is the main design constraint, and where this port
     deliberately differs, that difference is written down. -->
