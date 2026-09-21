# Read a goal alongside the runs associated with it

Phosphor can show an exact Maude-authored goal and acceptance criteria beside
the governed runs linked to that plan. It assembles this read view using
existing owner interfaces. Spine remains a navigation index, not the owner
of objective-state assembly.

This is an experimental, read-only integration. It does not decide whether
the goal is complete. A successful run can appear beside criteria whose
assessment is still unknown.

## Responsibilities and contracts

| Source or view | What it establishes | What it does not establish |
|---|---|---|
| Maude `maude.objective-source/v1` | Goal and criteria from one exact PlanDocument digest, or explicit unavailable/conflicting source result | Completion, current deployment state, permission, or public disclosure approval |
| Nightshift workflow lineage | Explicit plan/campaign/occurrence/proposal/work relationships retained by the owner, either from a supervised Maude authoring handoff or a retained precompiled cycle | Maude session custody when only the precompiled-cycle relationship exists; relationships inferred from time, titles, filenames, or proximity |
| AG campaign projections | Journal states, exact proposals, consumed authorization and retained occurrence history | Success inferred merely from authorization or an issuance |
| Docket inspection | Attempt custody, execution outcome and settlement, with their exact identities | Objective completion or permission for another attempt |
| Optional application-owner projection | Exact owner assertions and prerequisite coverage for exact Maude condition IDs, with separate evidence currentness | Independent proof of the application interpretation, objective completion, permission, or execution |
| Phosphor objective detail (`v1`, or opt-in `v2` with an owner source) | Bounded assembly of those sources, keeping their independent results | A new authority service, scheduler or objective evaluator |

Without an enrolled application-owner projection, conditions have disposition
`unknown` and prerequisites remain unknown. An owner projection can explicitly
assert complete prerequisite coverage, including an empty set; an absent or
unavailable source never implies that no prerequisites exist. Linked campaign detail preserves
execution, authority and evidence source results separately. Failed causal
reads remain visible in `causal_unavailable`; missing configuration is not a
successful empty observation. Historical links use exact retained owner
identities, not the most recent timestamp. Nightshift never backfills a Maude
authoring context from a later plan/proposal resemblance. Its separate
precompiled-workflow export can expose an exact relationship that the original
cycle already retained while keeping absent supervised-session custody explicit.

## Configure the read view

First configure the existing [campaign inspector](operator-ui.md). Add these
arguments to its invocation, using absolute local paths and the exact digest
from your authored plan:

```text
--maude-objective-bin /absolute/path/to/venv/bin/maude-plan
--maude-objective-plan /absolute/path/to/plan-locked.json
--maude-objective-expected-plan-digest sha256:YOUR_EXACT_PLAN_DIGEST
```

These are additional arguments, not a standalone runnable command. The
campaign root and AG CLI remain required. Nightshift is required to establish
the workflow relationships; Docket is required to inspect actual attempt
custody and settlement. Omitting either leaves its contribution unavailable,
not replaced by Maude. Acquisition-ledger inspection is a separate optional
read source for this use case; omitting it loses acquisition-mechanics detail.

An application that owns the interpretation of Maude's authored criteria can
also enroll one fixed bounded reader:

```text
--objective-owner-bin /absolute/path/to/phosphor-objective-owner-reader
--objective-owner-config /absolute/path/to/pinned-reader-config.json
--objective-owner-id APPLICATION_OWNER_ID
--objective-owner-capability CAPABILITY_ID
--objective-owner-source-revision SOURCE_REVISION
--objective-owner-expected-plan-digest sha256:YOUR_EXACT_PLAN_DIGEST
```

Phosphor invokes only `phosphor-objective-owner-reader --config CONFIG
objective-projection --plan-digest DIGEST`. The enrollment declares the reader
and configuration identity; it is not cryptographic proof of their origin.
The closed result must bind the exact plan and Maude condition identifiers.
It retains application-owner assertions, record digests, source currentness,
and source/read/projection timestamps separately. RFC 3339 timestamp strings
are validated but not trimmed, retimed, or normalized before the projection's
JCS identity is checked. Stale, future, refused, or claimed owner facts remain
indeterminate rather than becoming a completion verdict.

The prerequisite list is authoritative only as an application-owner assertion.
An empty list is meaningful solely when accompanied by the explicit
`owner_asserted_complete` coverage value. This read path grants no permission
and does not aggregate the condition assertions into an objective-complete bit.
Enrolling this source explicitly selects `phosphor-ng.objective-detail/v2`.
With no owner source, Phosphor continues to emit the unchanged strict `v1`
shape: no owner-projection member and no new empty evidence members.

Use the 64 hexadecimal characters of that plan digest in these loopback URLs:

```text
GET /objective/PLAN_DIGEST_HEX
GET /api/v1/objectives/PLAN_DIGEST_HEX
```

Both are navigation/read operations. The source invocation is exactly
`maude-plan objective-read --plan FILE --expected-plan-digest DIGEST`.
A changed file cannot silently become the requested plan. Inspect the typed
source result before interpreting the view. A capture time is not a promise
that an underlying deployment is current; multiple owner reads are not an
atomic cross-service snapshot. If relevant state changes, read again and
compare the owner identities rather than merging unlike observations.

## Public summaries are a separate input

The operator view can contain private authored text and raw owner records.
Do not publish it or proxy its operator routes onto a public listener.

A separate `phosphor-ng.public-objective-projection/v1` artifact accepts only
`schema`, `plan_digest`, `approved_summary`, and `approved_receipt_urls`.
An operator must independently approve that summary and each URL. Configure
the artifact with `--public-objective-projection FILE` and repeat
`--public-approved-receipt-url URL` for every allowed receipt link. An HTTPS
URL is not, by itself, approval to disclose a private record. The bounded
reader rejects symbolic links and oversized files; these checks do not replace
human review of the material.

The separate routes are `/public/objectives/PLAN_DIGEST_HEX` and
`/api/v1/public/objectives/PLAN_DIGEST_HEX`. They are still loopback-only.
They do not automatically derive text or links from the operator view.

## Original v1 qualification

The component qualification exercised Linux, Python3.12 and the repository's
locked Rust dependency set. Exact source combination:

| Component | Revision exercised |
|---|---|
| Phosphor source in constellation-ag | `89d72a0e71813fab015acb710701ddf925d33f49` |
| AG owner CLI | `5c8b22b77193798f25298b02758ac3caa3a8fe24` |
| Nightshift owner CLI | `2db475b0bb8be5e3afa7ac6c95e2ab1f73a9ceb4` |
| Docket owner CLI | `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b` |
| Installed Maude objective reader | `e9652983d7c0cfb9c4e57ac93c40d843df335ef3` |

Forty inspector tests passed. A bounded loopback check used an actual authored
plan, a consistent backup of one AG store and supported reads from the
corresponding retained Nightshift/Docket owners. It returned seven criteria
and one exact settled attempt. Criteria remained unknown; settlement did not
become objective completion. A missing-plan control returned unavailable with
no authored content. The public-artifact check used a synthetic allowlisted
URL, not a verified public receipt destination.

This qualified the original local read path, not a reproducible suite release or a full
application migration. External applications still own their presentation
schema, domain interpretation and deployment. The optional source carries an
application-owned interpretation; Phosphor does not independently establish
that interpretation as real-world truth. Cross-repository objective discovery
is not supplied by this contract. See the [Integration guide](https://unpingable.com/constellation/integration.html)
for separately qualified compositions and public prerequisites.

## Application assessments: v2 scope

The optional [NQ condition reader](../examples/objective-owner-reader.md) uses
an explicitly configured application mapping; Maude's criterion text is not
parsed into an implicit rule. Its condition reference is the exact NQ evaluation
ID, and its evidence digest covers the exact response bytes. Missing sources,
changed plan/criterion bindings and incompatible owner records remain visible
as unavailable, with no owner assertions applied.

A disposable integration used real Maude authoring, Monitor acquisition,
Nightshift finite recurrence, NQ saved evaluation/maintenance, this reader and
Phosphor's HTTP and rendered views. It kept a fresh failed result `not_satisfied`,
an old result `indeterminate`, and another criterion `unknown`. Maintenance was
`covered` for the fresh projection and `overrun` for the old one at its later
projection time; the historical attention receipt was not rewritten. One
prerequisite was explicitly application-declared, not discovered by Phosphor.
No AG/Docket execution was needed or substituted in that read-only case.

The source runner bounds same-process-group reads and closes retained pipes on
exit or timeout. Enrolled programs must not detach. The NQ example uses an
inner three-second read deadline inside Phosphor's five-second capture limit;
its exact local read does not start executors. Source bytes and local paths
remain within the operator's deployment trust boundary. Multiple owner reads
are not an atomic snapshot.

This extends component-level read integration; it does not itself qualify the
full application journey, public-only installation, retention rollover, live
notifications or a new suite release. Existing immutable release profiles keep
their documented narrower scope.

## Check an explicit governed occurrence

The objective contract already carries exact owner-minted occurrence links;
no additional objective schema or caller-supplied relationship is needed.  For
a composed qualification, use
[`phosphor-objective-occurrence-check`](../examples/objective-occurrence-read.md)
against a retained objective response produced with AG, Nightshift, Docket and
Maude sources configured.  The checker binds the exact plan, campaign,
occurrence, proposal, work and issuance identities while leaving condition
assessment, evidence currentness, AG projection correspondence, Docket custody
state, present health and future authority separate.

This helper is not evidence that a particular deployment has completed the
journey.  A release profile must still identify the exact participating
revisions and retain one disposable actual-owner result. A precompiled-cycle
relationship remains distinct from a supervised Maude handoff even when both
bind the same plan, proposal and work identities. Fixture-only checks
must remain labeled as such.
