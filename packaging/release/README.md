# AG governed-loop release build

`build_release.py` produces the reviewed-local-copy/v1 AG tarball
`ag-0.1.0-linux-amd64.tar.gz` with `bin/ag-loopctl`, `bin/ag-standing-resolver`,
`bin/ag-operator-ui` and `share/seal-standing-resolver-launcher.py`, plus
`SHA256SUMS` and `build-receipt.v1.json`.

The build is offline and pinned:

- the Debian 12 image `rust:1.94.0-bookworm`, pinned by digest, run with
  `--network none`, `--read-only` and `--pull never`;
- dependencies from a `cargo vendor --locked --versioned-dirs` tree, whose
  digest the receipt records;
- the release profile, one codegen unit, path remapping and
  `SOURCE_DATE_EPOCH=1700000000`;
- `AG_SOURCE_COMMIT` set to the built commit, so every executable's
  `--version` and `--build-info` carry it.

Two fresh clones of the pushed commit are built separately and must be
byte-equal, or the build refuses.

```sh
cargo +1.94.0 vendor --locked --versioned-dirs /abs/vendor
python3 packaging/release/build_release.py --commit <40-hex> \
  --require-branch <pushed branch> --vendor /abs/vendor \
  --scratch /abs/scratch --out /abs/out
```

The sealer script answers no `--build-info`. Its identity is its entry in the
tarball's `BUILD-INFO.json` (source path, git blob, sha256) and `SHA256SUMS`.
Run it with `/usr/bin/python3.11 -I -S`.

No agent_gov / agent_governor classic client, RPC path or library is in the
shipped dependency graph. The builder refuses the build if one of those crates
or strings appears in an executable.
