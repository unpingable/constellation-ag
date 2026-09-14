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
| Nightshift authoring lineage | Explicit plan/campaign/occurrence/proposal/work relationships retained by the owner | Relationships inferred from time, titles, filenames, or proximity |
| AG campaign projections | Journal states, exact proposals, consumed authorization and retained occurrence history | Success inferred merely from authorization or an issuance |
| Docket inspection | Attempt custody, execution outcome and settlement, with their exact identities | Objective completion or permission for another attempt |
| Phosphor `phosphor-ng.objective-detail/v1` | Bounded assembly of those sources, keeping their independent results | A new authority service, scheduler or objective evaluator |

The projection's `conditions` currently have disposition `unknown` and no
assessment record. Its `prerequisites` is explicitly `unknown`: an empty list
must not imply that no prerequisites exist. Linked campaign detail preserves
execution, authority and evidence source results separately. Failed causal
reads remain visible in `causal_unavailable`; missing configuration is not a
successful empty observation. Historical links use exact retained owner
identities, not the most recent timestamp.

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
the authoring relationships; Docket is required to inspect actual attempt
custody and settlement. Omitting either leaves its contribution unavailable,
not replaced by Maude. Acquisition-ledger inspection is a separate optional
read source for this use case; omitting it loses acquisition-mechanics detail.

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

## Qualification and remaining work

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

This qualifies a local read path, not a reproducible suite release or a full
application migration. External applications still own their presentation
schema, domain interpretation and deployment. Automatic condition assessment,
prerequisite assembly and cross-repository objective discovery are not supplied
by this contract. See the [Integration guide](https://unpingable.com/constellation/integration.html)
for separately qualified compositions and public prerequisites.
