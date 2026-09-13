# Finite continuation input V2

`ag.governed-loop.run-input/v2` adds a bounded continuation sequence to the
existing finite `ag-loopctl run` command. It does not add a scheduler or an
observation producer. The caller supplies an `initial` material object and at
most eight absolute continuation-envelope paths. Each material object names an
occurrence and its exact plan binding, review input, sealed Nightshift request,
and Docket executor configuration. V2 material pins the literal plan-binding
and sealed-request bytes with lowercase `sha256:` identities, so pathname
replacement or content mutation fails closed before the corresponding port use.
AG passes the already-checked sealed-request bytes through an exclusive
campaign-local temporary file for that bounded Nightshift call; it does not
reread the configured request pathname between validation and invocation.

A continuation file uses `ag.governed-loop.run-continuation/v1`. It binds the
campaign, predecessor occurrence and work, successor occurrence and work, and
the four successor material paths. Before opening the successor, AG verifies
that the canonical Maude binding and the binding transported in the canonical
Nightshift request are byte-identical and bind that campaign, occurrence, and
work. AG then retains the exact envelope and `ContinuationOpened` transition in
one SQLite transaction.

On restart, AG selects successor material only from that retained envelope. A
missing next file returns `continuation_input_required`; acquiring a fresh
observation and preparing that file remain external inputs. Exhausting the
declared sequence returns terminal `finite_continuation_bound_complete`.
The declared continuation count may not exceed the run's step bound. Version 1
parsing, identity, and its single continuation behavior are unchanged.
An older schema-V2 database that predates the additive continuation table stays
readable and replayable, but refuses `run-input/v2` before claiming a run.

The review record and Docket executor configuration remain protected by their
existing typed admission gates and deployment permission boundary; V2 does not
claim byte capture for those later-mutating inputs.
