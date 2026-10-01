# Governed-loop runtime packages

`build-operator-tools-deb.sh VERSION ARCH BIN_DIR OUT_DIR` assembles the previously
unpackaged `ag-loopctl`, `ag-standing-resolver` and `ag-operator-ui` surface, plus
the existing target-local executor payload. Build binaries from one exact locked
source export on the intended distribution; build `ag-effectd` with
`systemd-dbus`. Use `SOURCE_DATE_EPOCH` from that source commit. Inspect ELF
interpreter and shared-library/version requirements before declaring compatibility.

These packages install no service, configuration, key or authority state. The
operator tools do not replace the daemon package. The standalone executor
requires systemd >=249: its Manager GetUnit/RefUnit/GetUnitFileState/StartUnit,
JobRemoved signal and Unit ActiveState properties exist in the
[systemd 249 Manager implementation](https://github.com/systemd/systemd/blob/v249/src/core/dbus-manager.c)
and [Unit implementation](https://github.com/systemd/systemd/blob/v249/src/core/dbus-unit.c).
D-Bus Peer GetMachineId and Properties Get are standard interfaces. This package
uses no credential-bearing daemon unit; the daemon package retains its >=252
floor. Source/API and ABI inspection are not a fresh VM effect result.

Packaging does not resolve the current signed-dispatch versus Systemd-plan
interface or authorize a governed effect.
