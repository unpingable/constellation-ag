# Check one occurrence linked to an authored objective

Phosphor assembles objective-to-occurrence relationships from exact Nightshift
workflow lineage checked against AG history. Nightshift may supply either a
supervised Maude authoring-context record or the separate plan/proposal/work
relationship retained by a precompiled cycle. The latter does not claim Maude
session custody. The relationship is not supplied by this checker and is never
inferred from timestamps, labels, filenames, or matching prose.

`phosphor-objective-occurrence-check` is a small read-only caller for a captured
`phosphor-ng.objective-detail/v1` or `v2` response.  It verifies one exact
owner-minted plan/campaign/occurrence/proposal/work relationship and one exact
Docket issuance read.  It keeps objective conditions, evidence currentness,
AG source availability, projection correspondence, Docket custody state, and
unavailable causal reads separate.

## Produce the read

Launch Phosphor as documented in
[`objective-read-projection.md`](../docs/objective-read-projection.md), with all
of these existing sources configured:

```text
--campaign-root /ABS/AG-CAMPAIGNS
--ag-loopctl /ABS/ag-loopctl
--nightshift-bin /ABS/nightshift
--nightshift-store /ABS/nightshift.sqlite
--docket-bin /ABS/docket
--docket-state /ABS/docket-state
--maude-objective-bin /ABS/maude-plan
--maude-objective-plan /ABS/plan-locked.json
--maude-objective-expected-plan-digest sha256:PLAN
```

Add the six `--objective-owner-*` arguments from the objective guide when the
application has an enrolled criterion reader.  Without that source, conditions
remain `unknown`; an occurrence or successful settlement does not change them.

Read the exact objective route and retain the response as a new regular file:

```sh
curl --fail --silent --show-error --max-time 12 \
  http://127.0.0.1:8417/api/v1/objectives/PLAN_HEX \
  --output /ABS/NEW/objective.json
```

This is an operator read.  Do not publish the response: it may contain authored
text, local locators, and raw owner records.

## Check the explicit relationship

Use identities from the actual owner records, not reconstructed values:

```sh
./examples/phosphor-objective-occurrence-check \
  --input /ABS/NEW/objective.json \
  --plan-digest sha256:PLAN \
  --campaign-id sha256:CAMPAIGN \
  --occurrence-id OCCURRENCE-UUID \
  --proposal-id sha256:PROPOSAL \
  --exact-work-id sha256:WORK \
  --issuance-id sha256:ISSUANCE
```

The result reports the retained Docket status as `accepted`, `settled`, or
`indeterminate`.  It also reports `objective_completion: not_determined`,
`current_health: not_derived_from_execution`, and
`authority_for_another_action: none`.  A Docket settlement describes one
attempt.  It is neither an objective verdict nor evidence that the external
condition is current now.

Missing, refused, malformed, stale, future, unavailable, and indeterminate
inputs stay in their existing typed fields.  The checker refuses a changed
relationship, duplicate match, absent Docket issuance, unknown condition
disposition, or evidence without explicit currentness.  It does not modify any
component store or invoke an executor.

This closes the reusable caller/checking seam only.  A profile may claim the
composed path after one disposable run uses actual owner-minted lineage and
actual read interfaces.  Synthetic response tests remain component checks.
