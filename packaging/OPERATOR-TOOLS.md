# Governed-loop runtime packages

`build-operator-tools-deb.sh VERSION ARCH BIN_DIR OUT_DIR` assembles the previously
unpackaged `ag-loopctl`, `ag-standing-resolver` and `ag-operator-ui` surface, plus
the existing target-local executor payload. Build binaries from one exact locked
source export on the intended distribution; build `ag-effectd` with
`systemd-dbus`. Use `SOURCE_DATE_EPOCH` from that source commit. Inspect ELF
interpreter and shared-library/version requirements before declaring compatibility.

Export `AG_SOURCE_COMMIT` as the full lowercase 40-digit source commit and
`AG_BUILD_IDENTITY` as a unique build label (1..256 printable ASCII bytes without
spaces) for both compilation and package assembly. The builder must verify that
the export and locked dependencies actually correspond to that commit; the
binaries do not infer Git state or verify the declaration. Malformed nonempty
values fail compilation. Missing values remain explicitly unknown for local
development and are refused by package assembly.

Build all four tools with those same inputs, for example:

```sh
export AG_SOURCE_COMMIT=FULL_LOWERCASE_COMMIT AG_BUILD_IDENTITY=UNIQUE_BUILD_LABEL
cargo build --locked --release -p ag-app -p ag-operator-ui --features ag-app/systemd-dbus \
  --bin ag-loopctl --bin ag-standing-resolver --bin ag-effectd --bin ag-operator-ui
bash packaging/build-operator-tools-deb.sh 0.1.0+BUILD_LABEL amd64 target/release OUT_DIR
```

Replace the uppercase placeholders first. The assembler probes the copied
staging files, requires matching source/build/version/compiler/target/profile,
checks the executor's `systemd-dbus` feature, and records the cohort and exact
executable hashes in each package and its JSON sidecar before writing either
package. Run `python3 -B -m unittest discover -s packaging -p test_build_identity.py`
for the package correspondence and refusal fixtures. `ag.build_info.v1` is AG's
local reporting format, not a cross-component authority protocol.

These packages install no service, configuration, key or authority state. The
operator tools do not replace the daemon package. The standalone executor
requires systemd >=249: its Manager GetUnit/RefUnit/GetUnitFileState/StartUnit,
JobRemoved signal and Unit ActiveState properties exist in the
[systemd 249 Manager implementation](https://github.com/systemd/systemd/blob/v249/src/core/dbus-manager.c)
and [Unit implementation](https://github.com/systemd/systemd/blob/v249/src/core/dbus-unit.c).
D-Bus Peer GetMachineId and Properties Get are standard interfaces. This package
uses no credential-bearing daemon unit; the daemon package retains its >=252
floor. Source/API and ABI inspection are not a fresh VM effect result.

The Systemd executor verifies signed Docket custody before executing the exact
enrolled plan. Installing these inert packages does not enroll an issuer, runtime
profile, target, work catalog or execution-standing grant. A governed effect
requires those separate owner-controlled enrollments and current evidence.
