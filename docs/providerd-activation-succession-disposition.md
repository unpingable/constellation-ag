# Providerd build-identity succession

Status: **IMPLEMENTED FOR BUILD-ONLY SUCCESSION, 2026-09-21.** Authority,
configuration, security-profile, catalog, and epoch rotation remain unsupported.

## Motivating witness

Marginalia production is currently pinned to the older providerd image
(`marginalia:generation-policy-d420ba4-candidate`, via
`MARGINALIA_PROVIDERD_IMAGE`) because the newer binary refuses the existing
durable store with `activation identity mismatch`. The mismatch check is
functioning as designed; the missing capability is an authorized
succession/rotation mechanism.

**Do not "fix" this by weakening or bypassing the mismatch check.**

## Semantic disposition

The activation identity names both logical authority inputs and the particular
component build. Ordinary binary replacement therefore requires an explicit,
auditable continuity transition. This contract deliberately does not generalize
that transition into authority rotation.

## Supported primitive

`ag-providerd` has five offline modes:

```console
ag-providerd --config CONFIG --activation-succession-candidate
ag-providerd --config CONFIG --activation-succession-inspect
ag-providerd --config CONFIG --activation-succession-preflight PLAN
ag-providerd --config CONFIG --activation-succession-commit PLAN
ag-providerd --config CONFIG --activation-succession-reverse REVERSAL_PLAN
```

`candidate` prints the exact activation derived from that executable and config;
it does not open the store. `inspect` acquires the offline writer fence, verifies
the store, and prints only its activation, chain head, and lineage revision.
These two outputs provide the exact facts needed to construct a plan.

All plans are strict canonical JSON with schema
`ag-store-activation-succession-plan-v1`. The successor activation is derived
from the executable actually running and the exact descriptor-bound config; an
operator cannot name an arbitrary forward successor build. A reverse plan runs
under the currently enrolled successor executable and may restore only the
immediately recorded predecessor activation from the latest lineage state; it
cannot name an arbitrary target. The modes do not load
credentials, bind a socket, construct provider transport, or call a provider.

The operation requires:

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
- append-only rollback/successor-reversal through a new exact plan.

The plan binds the full predecessor activation and digest, successor activation,
event-chain head, succession-lineage revision, recovery-manifest digest,
operator-authorization-record digest, unique transition ID, reason, and
evidence time. The authorization-record digest is retained evidence; it is not
reinterpreted as a signing authority.

Preflight acquires the daemon's exclusive writer lock, opens SQLite read-only,
and verifies filesystem
custody, SQLite integrity and foreign keys, the entire event/materialized-state
chain, activation identity, exact head, lineage revision, and absence of an
active backup barrier. It does not mutate the store.

Commit repeats every check under an immediate transaction, appends either
`providerd.activation-succeeded.v1` or
`providerd.activation-reversed.v1`, advances the singleton lineage, and updates
the activation record with an exact compare-and-swap. No dispatch, capability,
reservation, acknowledgment, termination, blob, Docket, or application row is
rewritten. A receipt surviving commit is authoritative; retrying the stale plan
fails on activation/head/lineage preconditions.

Only `build_identity` may differ. Any change to authority domain, epoch, config,
security profile, or catalog is refused and needs a separate authority design.

## Qualification target

Before production use, qualify against a copy of Marginalia's real store:

1. current pinned binary opens store;
2. candidate successor refuses before authorization;
3. dry-run succession reports the expected transition;
4. perform succession;
5. candidate successor opens store;
6. daemon health/readiness and content-free endpoint readiness pass;
7. predecessor now refuses;
8. rollback ceremony restores predecessor authority;
9. interrupted/crash-boundary transitions leave the store recoverable and
   never ambiguously owned.

## Production procedure

Only after upstream qualification:

- take a fresh verified Marginalia backup;
- enter maintenance;
- quiesce providerd;
- execute the qualified authority/implementation succession procedure;
- update `MARGINALIA_PROVIDERD_IMAGE`;
- verify readiness and the established bounded synthetic schedule (do not add a
  discretionary billable smoke request);
- lift maintenance.

The currently enrolled successor binary performs the append-only reverse
transition to the exact immediately recorded predecessor. After the reverse
receipt commits, the successor refuses the store and the retained predecessor
binary opens it normally. A reversal plan must bind the post-forward activation,
chain head, and lineage revision. Never restore an older database over a
successfully transitioned store: doing so would discard append-only custody
history and potentially nonterminal provider work.
