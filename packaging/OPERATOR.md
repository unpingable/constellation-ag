# Constellation AG installed operator tools

AG independently admits exact work from current evidence and separately enrolled
authority. Installing the tools/executor creates neither standing nor a grant.

The prepared combined candidate targets Ubuntu 22.04 amd64. Use its source-free
[operator guide](https://github.com/unpingable/unpingable-site/blob/dev/operator-beta/constellation/combined-candidate/README.md) for download verification, exact package installation,
separate enrollment, Workbench, currentness and day-two recovery. It is a neutral
owner-review candidate; BC1 is not tagged or published. Component source alone
does not install the composed product or grant authority.

Each packaged tool accepts `--version` (or `-V`) and `--build-info` as its sole
argument before reading configuration, stdin or state. `--version` includes the
declared source commit; `--build-info` emits `ag.build_info.v1` JSON with source
commit, build identity, compiler, target, debug-assertion and systemd-dbus flags.
The executor is installed under `/usr/libexec/agent-governor-ng/ag-effectd`.

Compare that output with `/usr/share/doc/PACKAGE/build-identity.json`, the
package's `.build-identity.json` sidecar, and the candidate checksum manifest.
The receipt lists all four tools across both packages and their exact staged
SHA-256 hashes. The other package's entry describes the build cohort; it does
not assert that package is installed. Missing source/build inputs appear as
JSON null in development builds and cannot be assembled by the package builder.
These are builder declarations, not independent source attestation or evidence
of release promotion.

Use Workbench for current owner state. The documented native API/CLI escape
hatches inspect and advance only the already admitted operation. `ag-loopctl
inspect --database PATH` exposes the bound current snapshot and deterministic
replay; `history` and `refusals` inspect retained outcomes. Choose only the
owner-configured database, runtime profile and exact work.

AG authorization is distinct from Docket attempt custody and from independent
postcondition/recovery evidence. A receipt is not a new grant. Reconcile a pending
attempt before generation changes or removing its executor. These packages own
no systemd service; stop the separately enrolled caller before removal.
