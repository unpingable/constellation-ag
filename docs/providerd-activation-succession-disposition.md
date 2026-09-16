# Providerd activation-identity succession — deferred disposition record

Status: **DEFERRED, 2026-09-16.** This note opens no implementation campaign.

## Motivating witness

Marginalia production is currently pinned to the older providerd image
(`marginalia:generation-policy-d420ba4-candidate`, via
`MARGINALIA_PROVIDERD_IMAGE`) because the newer binary refuses the existing
durable store with `activation identity mismatch`. The mismatch check is
functioning as designed; the missing capability is an authorized
succession/rotation mechanism.

**Do not "fix" this by weakening or bypassing the mismatch check.**

## Semantic gate — answer before implementation

Determine what `activation identity` is intended to name:

1. **logical provider authority**, which should normally remain stable across
   implementation upgrades; or
2. **particular providerd implementation/build identity**, in which case every
   legitimate binary replacement requires an explicit authority-continuity
   transition.

If ordinary binary revision changes activation identity merely because the
executable/revision changed, investigate whether the model is conflating:

- **authority identity** — stable principal holding custody; and
- **implementation identity/revision** — auditable software instance operating
  under that authority.

Do not build a rotation ceremony until this distinction is resolved.

## Candidate required primitive

If identity rotation is genuinely required, introduce an explicit governed
successor operation approximately equivalent to:

```text
providerd activation rotate \
  --expect-current <old-id> \
  --successor <new-id>
```

Requirements:

- explicit operator authorization;
- exact predecessor and successor binding;
- dry-run/preflight;
- store integrity verification;
- exclusive/quiesced custody during transition;
- checkpoint/backup before mutation;
- atomic durable commit;
- retained predecessor→successor lineage / receipt;
- no generic `--force` bypass;
- old identity refuses after successful succession;
- unrelated identity refuses;
- explicit governed rollback/successor-reversal path.

## Qualification target

Before production use, qualify against a copy of Marginalia's real store:

1. current pinned binary opens store;
2. candidate successor refuses before authorization;
3. dry-run succession reports the expected transition;
4. perform succession;
5. candidate successor opens store;
6. readiness and harmless provider operation pass;
7. predecessor now refuses;
8. rollback ceremony restores predecessor authority;
9. interrupted/crash-boundary transitions leave the store recoverable and
   never ambiguously owned.

## Production pickup

Only after upstream qualification:

- take a fresh verified Marginalia backup;
- enter maintenance;
- quiesce providerd;
- execute the qualified authority/implementation succession procedure;
- update `MARGINALIA_PROVIDERD_IMAGE`;
- verify readiness and synthetic provider operation;
- lift maintenance.

**Reopening condition:** fresh bounded ag-ng campaign whose first task is
resolving the activation-identity semantics above.

**Current operational disposition:** keep Marginalia providerd pinned. The
readiness noise is bounded; provider-selection safety is unaffected. Do not
weaken custody semantics merely to permit an upgrade.
