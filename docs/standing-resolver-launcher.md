# Standing resolver zero-argument launcher

`tools/seal-standing-resolver-launcher.py` packages the existing canonical
`ag-standing-resolver` for AG's zero-argument process port. It fixes exactly
the mutable mandate-store pathname, resolver identity, and answer TTL. It is
not a standing responder and contains no mandate or signing material.

The enrollment is closed canonical JSON schema
`ag.governed-loop.standing-launcher-enrollment/v1` with fields `schema`,
`resolver_program`, `resolver_sha256`, `mandate_store`, `resolver_id`,
`answer_ttl_ms`, `python_interpreter`, and `python_sha256`. All paths are
absolute. The generated launcher and manifest are created exclusively.

At every invocation the launcher opens the configured resolver with
`O_NOFOLLOW`, validates the opened regular executable's SHA-256, makes that
descriptor inheritable, and executes `/proc/self/fd/FD` with only the three
fixed options. It accepts no argv and passes an empty environment. The
mandate-store pathname remains mutable authority state and is deliberately not
hashed; the canonical resolver rereads it for each request.

The launcher uses an absolute Python shebang. Enrollment records the exact
interpreter hash, and deployment must verify it before AG profile sealing.
Runtime relies on the deployed interpreter and its standard library remaining
within the deployment trust boundary; the launcher itself does not recursively
pin Python's dynamically loaded standard-library files.

After building the actual resolver, qualification must generate a launcher
pinned to that ELF and run the existing real-resolver cases for current,
absent, revoked, expired, and replacement-reread behavior. It must additionally
replace the configured resolver bytes and confirm refusal before the resolver
is executed. AG's existing bounded subprocess port owns timeout and cleanup.
