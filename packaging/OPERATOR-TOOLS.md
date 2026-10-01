# Governed-loop runtime packages

`build-operator-tools-deb.sh VERSION ARCH BIN_DIR OUT_DIR` assembles the previously
unpackaged `ag-loopctl`, `ag-standing-resolver` and `ag-operator-ui` surface, plus
the existing target-local executor payload. Build binaries from one exact locked
source export on the intended distribution; build `ag-effectd` with
`systemd-dbus`. Use `SOURCE_DATE_EPOCH` from that source commit. Inspect ELF
interpreter and shared-library/version requirements before declaring compatibility.

These packages install no service, configuration, key or authority state. The
operator tools do not replace the daemon package. The executor deliberately
retains `debian/control`'s systemd >=252 requirement: stock Ubuntu 22.04 (249)
does not satisfy it. Packaging does not resolve the current signed-dispatch
versus Systemd-plan interface or authorize a governed effect.
