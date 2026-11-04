# Decision log

| ID | Date | Decision | Reason |
|---|---|---|---|
| D-01 | 2026-10-29 | Calibrate on BENIGN only; budget = at most 5 alarm episodes per capture day, judged on the worst day | An analyst-unit budget; the mean hides bad days |
| D-02 | 2026-10-29 | Evaluation unit = (source, window) episodes; primary key (source, target, port), sensitivity key (source, port) | Brute force is one source against one target |
| D-03 | 2026-10-29 | Per-network calibration: 2017 = monday/wednesday/thursday/friday, 2018 = all days except Wednesday-14 | Thresholds do not transfer (0.11% vs 89.2% false positives) |
| D-04 | 2026-10-29 | Acceptance criteria written before any attack measurement; test file run once | Pre-registration |
| D-05 | 2026-10-29 | v1 frozen; any change = v2 after a test | A defined stopping point |
| D-06 | 2026-11 | Rule layer v1: levels normal/borderline/clear, highest over windows, unknown never normal | Contextual standard per network |
| D-07 | 2026-11 | Prolog tool trigger register: CLP, Event Calculus, ASP, tabling, ProbLog, term_expansion; each enters only on its trigger | Flexible without over-building |
| D-08 | 2026-11 | DeLP engine built from scratch, four stages with gates | Specification conformance, explainability, operability |
| D-09 | 2026-11 | Humans decide, machines write: network profiles are generated, not typed | Manual burden and copy errors |
| D-10 | 2026-11 | Simplicity charter: no new file unless it replaces a manual step or decision | Avoid sinking in details |
| D-11 | 2026-11 | Definitions are files in git; small mutable lists via persistency; large records in SQLite on trigger | Match storage to data nature |
| D-12 | 2026-11 | Repository structure and git rules (this repo) | Expandable, reproducible |

## Open items
- Review the six clear_from numbers by eye against calibrate_fine.txt.
- Mutation check on repeat_level: change ">=" to ">" and confirm the tests fail.
- Verify Wazuh 5712 and ET 2001219 thresholds from primary sources.
- Confirm the freeze date of the acceptance criteria is the day they were written.
- Send the delp_lite tests (not its code) as a regression oracle.
- Decide whether to amend the closure record: wording of "one source", add make_slice.py and census.py to its tools, add a note that Wednesday-14 is consumed as the unseen test.