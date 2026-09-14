# Compose one saved check into the objective read view

Status: development example. The real fresh-to-stale journey has been exercised
against public-built components. Public-only reproduction of this exact example
kit and its integration release remains pending. Unit tests are component checks,
not a substitute for that reproduction.

This finite recipe authors and locks one Maude plan through the supported CLI,
runs the released `saved-check-attention/v1` example, maps its exact retained
NQ evaluation to one exact Maude condition through the application-owned
reader, and captures Phosphor's loopback objective detail. The first read
shows the intentionally failed current predicate as `not_satisfied`. After the NQ
definition's actual 120-second currentness interval expires, the second read
shows the same retained evidence as `indeterminate`. The second Maude criterion
stays `unknown`. Finally, the recipe copies only the caller enrollment, changes
its evaluation ID to the all-zero SHA-256 identity after proving that it differs
from the actual ID, and performs one more read against the same NQ store. This
wrong-reference negative control must be `unavailable`, with no owner evidence
or prerequisite assertion.

The source is a disposable SQLite queue and its maintenance declaration is
created explicitly for the example. Maude records the script's submitter as
`synthetic_agent`; no model-generated proposal or independent review is claimed.
The acquisition, evaluation, scheduling, retained state and read interfaces are
real component calls, not substituted responses.

```text
Maude new/save/lock -> Maude objective-read ---------> exact condition ID
Nightshift finite schedule -> Monitor acquisition -> NQ saved evaluation
                                                       |
exact condition ID + retained NQ evaluation -> application reader
                                                       |
                                      Phosphor objective-detail/v2
                                      fresh, stale, missing-reference refusal
```

Nothing here performs AG or Docket work. An empty real campaign directory is
used only because the Phosphor inspector requires that read-side input. The
owner outcome, evidence currentness, maintenance annotation and `authority:
none` remain separate. No HTTP response contains an objective-complete or
permission verdict.

## Exact prerequisites

Use Linux x86-64, Git, a C compiler/linker, Rust/Cargo 1.94.0, and Python 3.12
at both `python3` and `/usr/bin/python3` with SQLite. Obtain these exact public
source revisions:

- constellation-ag `deac918c2ad95b8205f293393874adb8eb12fe26`:
  `ag-operator-ui`, `ag-loopctl`, and
  `examples/phosphor-objective-owner-reader`;
- Maude `abaac51003b29ba8cefddc41ffbdcd018b732212`:
  an installed `maude-plan` supporting `new`, `save`, `lock`, and
  `objective-read`;
- NQ `e259852ed58b8c0bf65a629b3c494afba28d9ce9`: `nq`;
- Nightshift `019e6837565ebf5b0ac244cbd7c3edde28e25aea`:
  `nightshift`, `monitor-concerns`, `runtime/examples/saved-check-recurring.py`,
  and `integrations/monitor-predicate-support/examples/local-queue-attention.py`.

Verify the source revisions and executable hashes in the operator record before
starting. Keep executable pathnames quiescent through launch. This script does
not build, download, or cryptographically bind a pathname after hashing.

`objective-owner-composed.py`, its test, and this guide form a separate example
kit. They are not present in the pinned AG runtime checkout above. Put the
eventually released, digest-pinned example kit in an absolute directory and set
`KIT` to that directory. A release guide must pin the kit revision and file
digests separately from the component revisions.

One direct source setup is:

```sh
SETUP=$(mktemp -d /tmp/objective-owner-composed-setup.XXXXXX)
KIT=/absolute/path/to/objective-owner-composed-example-kit
git clone https://github.com/unpingable/constellation-ag.git "$SETUP/ag"
git -C "$SETUP/ag" checkout --detach deac918c2ad95b8205f293393874adb8eb12fe26
git clone https://github.com/unpingable/maude.git "$SETUP/maude"
git -C "$SETUP/maude" checkout --detach abaac51003b29ba8cefddc41ffbdcd018b732212
git clone https://github.com/unpingable/constellation-nq.git "$SETUP/nq"
git -C "$SETUP/nq" checkout --detach e259852ed58b8c0bf65a629b3c494afba28d9ce9
git clone https://github.com/unpingable/constellation-nightshift.git "$SETUP/nightshift"
git -C "$SETUP/nightshift" checkout --detach 019e6837565ebf5b0ac244cbd7c3edde28e25aea

python3 -m venv "$SETUP/maude-venv"
"$SETUP/maude-venv/bin/pip" install "$SETUP/maude"
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
CARGO_TARGET_DIR="$SETUP/ag-target" cargo +1.94.0 build --locked --manifest-path "$SETUP/ag/Cargo.toml" -p ag-operator-ui -p ag-app --bin ag-operator-ui --bin ag-loopctl
CARGO_TARGET_DIR="$SETUP/nq-target" cargo +1.94.0 build --locked --manifest-path "$SETUP/nq/Cargo.toml" -p nq-app --bin nq
CARGO_TARGET_DIR="$SETUP/nightshift-target" cargo +1.94.0 build --locked --manifest-path "$SETUP/nightshift/runtime/Cargo.toml" -p nightshiftd --bin nightshift
CARGO_TARGET_DIR="$SETUP/monitor-target" cargo +1.94.0 build --locked --manifest-path "$SETUP/nightshift/integrations/monitor-predicate-support/Cargo.toml" --bin monitor-concerns
```

The build needs registry access; the finite runtime needs no network or
provider credential. Check both Python/SQLite installations before use:

```sh
python3 -c 'import sqlite3, sys; print(sys.version); print(sqlite3.sqlite_version)'
/usr/bin/python3 -c 'import sqlite3, sys; print(sys.version); print(sqlite3.sqlite_version)'
```

Hash all seven program pathnames before use. Component versions are independent.

## Start

Choose an absent absolute root and an unused loopback port:

```sh
python3 "$KIT/objective-owner-composed.py" \
  --root /tmp/objective-owner-composed-demo \
  --maude "$SETUP/maude-venv/bin/maude-plan" \
  --nq "$SETUP/nq-target/debug/nq" \
  --nightshift "$SETUP/nightshift-target/debug/nightshift" \
  --monitor "$SETUP/monitor-target/debug/monitor-concerns" \
  --saved-check-example "$SETUP/nightshift/runtime/examples/saved-check-recurring.py" \
  --project-example "$SETUP/nightshift/integrations/monitor-predicate-support/examples/local-queue-attention.py" \
  --reader "$SETUP/ag/examples/phosphor-objective-owner-reader" \
  --operator-ui "$SETUP/ag-target/debug/ag-operator-ui" \
  --ag-loopctl "$SETUP/ag-target/debug/ag-loopctl" \
  --reader-revision deac918c2ad95b8205f293393874adb8eb12fe26 \
  --port 28456
```

The root is create-only. The saved-check producer has a 180-second outer bound;
other commands use 30 seconds, captured command streams use 1 MiB, and HTTP bodies
use 2 MiB. A terminal check requires measured retained regular files to remain
at or below 64 MiB. The supported stale
transition waits at most 121 seconds and uses the reader's actual current UTC
projection time. It does not alter retained timestamps. With setup and HTTP
reads around those bounds, the whole run can approach six minutes. When run
unattended, use a durable supervisor and a recovery checkpoint that identifies
the exact process, source and kit revisions, root, logs, and next inspection.

The script measures retained regular-file bytes at terminal state and refuses
success above 64 MiB. That post-run measurement is not an allocation ceiling;
the operator's launcher must impose and record the actual outer filesystem and
process resource envelope before launch.

## Inspect and retain

Inspect existing files without starting the producer again:

```sh
python3 -m json.tool /tmp/objective-owner-composed-demo/maude-objective.json
python3 -m json.tool /tmp/objective-owner-composed-demo/fresh-objective.json
python3 -m json.tool /tmp/objective-owner-composed-demo/stale-objective.json
python3 -m json.tool /tmp/objective-owner-composed-demo/missing-evaluation-objective.json
python3 -m json.tool /tmp/objective-owner-composed-demo/result.json
```

Also retain `commands.jsonl`, both reader configurations, server identity and
terminal records, the Maude plan/store, and the complete
`nightshift-saved-check-run-objective` directory. A lost final record does not
mean the producer did nothing; reconcile those files and process identity
before considering another occurrence. Do not restart over this root.

Each read retains `<label>-server-stdout.log` and `<label>-server-stderr.log`
(`fresh`, `stale`, or `missing-evaluation`). Each stream retains at most 1 MiB;
excess is drained and discarded so it cannot block the server. The matching
`<label>-server-terminal.json` records byte counts, truncation, capture errors,
and whether the pipe reached EOF. Incomplete diagnostic capture refuses success.
These logs may contain operator-only text: review and redact a minimal excerpt
before reporting it. The reader terminates and reaps its same process group;
this does not establish recovery of a detached process or supervisor-loss safety.

The missing-evaluation result means the caller named no retained evaluation at
that identity. It does not erase or contradict the actual retained evaluation.
Inspect the original `fresh-reader.json`, exact evaluation ID, NQ condition and
owner records before deciding what happened; do not rerun the saved-check
producer to make the negative control succeed. This control does not exercise
execution uncertainty, interrupted delivery, or recovery.

After inspection and only when no evidence, replay, diagnosis, or recovery
dependency remains, an operator may remove exactly the disposable root named on
the original command. Resolve and visually verify that explicit pathname; do
not substitute a variable, glob, parent directory, or repository path:

```sh
rm -rf -- /tmp/objective-owner-composed-demo
```

Retained SQLite custody must not be deleted merely because the foreground
reader exited. This cleanup is not part of the run and cannot be undone.

Run the deterministic helper tests without any product process:

```sh
python3 -m unittest examples/test_objective_owner_composed.py
```

These checks do not qualify public-only installation, a production source,
background monitoring, human receipt, AG/Docket execution, a full objective
consumer migration, or publication of operator-only objective text.
