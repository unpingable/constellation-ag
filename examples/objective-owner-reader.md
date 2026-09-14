# Read one application-owned objective criterion from NQ

Status: public generic example. The reader and its component-only substitution
controls are implemented. Actual NQ-to-AG integration qualification is pending
the root-owned qualification gate.

`phosphor-objective-owner-reader` projects one caller-authored objective
criterion from an existing NQ `saved-check condition` record. It does not read
the saved-check source, create an NQ store, discover objectives, decide that a
plan is complete, or grant permission to run work.

## What the caller owns

The caller supplies one closed enrollment containing:

- the exact Maude-authored plan digest and condition ID;
- the NQ definition ID, stable reference, definition digest, evaluation ID,
  and source identity expected for this criterion;
- the required factual outcome, either `passed` or `failed`;
- the caller-selected maintenance coordinate: component, kind, and subject;
- absolute paths and exact byte digests for a previously configured NQ program
  and NQ configuration;
- optionally, one caller assertion that the exact installed NQ definition is
  the complete prerequisite set for this single criterion.

The mapping is application-owned. NQ establishes retained saved-check facts;
it does not claim that those facts satisfy the application's plan. Likewise,
`owner_source_revision` is declared provenance, not authenticated program
identity.

When this projection is enrolled into the shared assessment capture, its
`plan_digest` must equal the plan digest configured for the Maude assessment,
and its condition ID must be one of that exact plan's authored condition IDs.
A mismatch is unavailable and does not overlay assertions or prerequisites.

## Closed configuration

The configuration is ASCII JSON with no floating-point values and no unknown
fields. Replace every placeholder with the exact enrolled value. Digest values
are lowercase SHA-256 identities.

```json
{
  "schema": "phosphor-ng.objective-owner-reader-config/v1",
  "plan_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "owner_id": "application.saved-check-owner",
  "owner_capability": "nq.saved-check-condition/v1",
  "owner_source_revision": "public-integration-revision-1",
  "nq_program": "/ABS/PATH/TO/nq",
  "nq_program_sha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "nq_config": "/ABS/PATH/TO/nq.toml",
  "nq_config_sha256": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "criterion": {
    "condition_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "definition_id": "definition-001",
    "definition_reference": "application.queue.empty",
    "definition_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "evaluation_id": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "source_identity": "application-queue-source",
    "required_outcome": "passed",
    "component": "queue",
    "kind": "saved-check",
    "subject": "primary"
  },
  "definition_prerequisite": {
    "prerequisite_id": "application.queue.definition-installed",
    "relation": "requires",
    "owner_record_ref": "application:nq-definition:definition-001:application.queue.empty",
    "owner_record_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  }
}
```

The `application:` reference is an opaque application-owned enrollment label;
it is not an NQ-issued custody reference. Set `definition_prerequisite` to
`null` unless the caller explicitly asserts
that this one installed definition is the complete prerequisite coverage for
the criterion. The reader does not infer an empty or complete prerequisite set.

Prepare this configuration from a closed operator setup. Confirm the program
and configuration hashes before use:

```sh
sha256sum /ABS/PATH/TO/nq /ABS/PATH/TO/nq.toml
```

The NQ configuration is read once under its size and digest bounds, copied to
a sealed in-memory file, and supplied to NQ through `/proc/self/fd`. The NQ
program pathname must name a quiescent operator-owned regular executable while
the reader hashes and launches it. This example does not establish immutable
program identity across that hash-to-execute interval or cryptographic
execution provenance. Use an isolated, controlled launch boundary when that
property matters.

## Supported invocation

Use the exact plan digest enrolled in the configuration:

```sh
./examples/phosphor-objective-owner-reader \
  --config /ABS/CONFIG.json \
  objective-projection \
  --plan-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  > /ABS/OBJECTIVE-PROJECTION.json
```

The reader records the actual current UTC second as `projected_at` and passes
that same value to NQ as `saved-check condition --at`. It never changes the
retained source-observation or read-attempt coordinates to make evidence look
current.

Inspect the captured projection without invoking NQ again:

```sh
python3 -m json.tool /ABS/OBJECTIVE-PROJECTION.json
```

The output schema is `phosphor-ng.objective-owner-projection/v1`. Its
`owner_record_ref` and evidence `owner_record_id` are the same exact NQ
evaluation ID, usable with `saved-check condition --evaluation-id`.
`owner_record_digest` covers the exact NQ stdout bytes, including its trailing
newline when present. Parsing that response does not normalize its evidence
identity. `projection_id` is the SHA-256 digest of the sorted, compact ASCII JSON object
with `projection_id` set to the empty string. `authority` is always `none`.

## Reading the condition

A decisive `satisfied` or `not_satisfied` assessment requires all of the
following:

- exact plan, condition, evaluation, definition, source, and caller-coordinate
  bindings;
- an NQ `nq.saved-check-condition/v1` record with `authority: none`;
- a coherent retained `passed` or `failed` original result;
- `read_attempt.state: recorded`, with the same retained read timestamp in the
  original result detail;
- fresh source currentness at the actual projection time.

`satisfied` means the retained NQ outcome equals `required_outcome`.
`not_satisfied` means the other determinate outcome was retained. Neither term
means that the wider plan is complete.

The evidence preserves NQ's factual outcome and maintenance annotation in
separate fields:

```text
owner_outcome          passed | failed
maintenance_annotation covered | overrun | uncovered | unavailable
```

A covered failure remains a failed predicate. Maintenance never rewrites the
comparison.

Stale or future retained evidence becomes `indeterminate`, with its validated
record reference and factual evidence preserved. A coherent NQ claimed result
also remains `indeterminate`; it preserves `owner_outcome: claimed`, its
maintenance annotation, and a null read-attempt time. A missing evaluation,
refused or malformed NQ projection, binding mismatch, contradictory record,
unknown member, unavailable owner, or unusable read record becomes
`unavailable`; its record reference and evidence are null or empty as required
by the shared contract. Missing information is not treated as success.

An available prerequisite result is only the caller's bounded assertion about
the exact definition record. It is not automatic discovery and is not an NQ
claim of application completeness.

## Limits and failure behavior

- Reader configuration: at most 32 KiB.
- NQ configuration: regular file, at most 32 KiB.
- NQ program: regular executable file, at most 128 MiB.
- Combined NQ stdout and stderr: at most 1 MiB.
- NQ read: at most 3 seconds, followed by terminating and reaping that child.
  The exact `saved-check condition` command reads the local store without
  dispatching helpers. It stays in Phosphor's source process group so the
  outer 5-second boundary can also terminate it. This is not an arbitrary
  command runner or a guarantee about detached executors.
- JSON inputs and owner output: ASCII, duplicate-key refusing, no floats.

Help, malformed arguments, invalid configuration, plan mismatch, and failed
file validation stop before NQ is launched. NQ is invoked directly without a
shell and without provider, webhook, or network configuration. Raw NQ errors,
paths, SQL, and saved-check detail are not copied into the reader's operator
projection. This is not a public export: do not publish operator records merely
because this example is public source.

The reader is a factual adapter only. Its output does not establish plan
completion, standing, authorization, Docket custody, execution, human review,
or permission to act. Those remain separate application and governance
boundaries.

The current 18 standard-library tests are deterministic substitution controls
for the reader's component behavior. They are not actual NQ integration
evidence. A separate disposable run used actual Maude, Monitor, Nightshift, NQ,
this reader and Phosphor: the current failed check became `not_satisfied`, the
older result stayed `indeterminate` with stale evidence and overrun maintenance,
and an unassessed criterion stayed `unknown`. The caller explicitly declared
one definition prerequisite. That read-only run did not execute AG/Docket work
or qualify a deployment migration. A pinned public-only integration profile is
still required before claiming the full connected composition is released.
