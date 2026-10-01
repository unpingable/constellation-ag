#!/usr/bin/env bash
# Assemble the governed-loop CLI and existing systemd executor payloads.
# This does not promote the composed runtime.
set -euo pipefail
export LC_ALL=C TZ=UTC
umask 022
[[ $# -eq 4 ]] || { echo "usage: $0 VERSION ARCH BIN_DIR OUT_DIR" >&2; exit 2; }
version=$1 arch=$2 bin_dir=$(cd "$3" && pwd -P)
case "$version" in *[!0-9A-Za-z.+:~-]*|'') exit 2;; esac
case "$arch" in amd64|arm64) ;; *) exit 2;; esac
mkdir -p "$4"; out_dir=$(cd "$4" && pwd -P)
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
for b in ag-loopctl ag-standing-resolver ag-operator-ui ag-effectd; do
    [[ -x "$bin_dir/$b" ]] || { echo "missing binary $b" >&2; exit 2; }
done
stage=$(mktemp -d "$out_dir/.stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT
for package in agent-governor-ng-operator-tools agent-governor-ng-systemd-executor; do
    d=$stage/$package
    install -d -m 0755 "$d/DEBIAN" "$d/usr/share/doc/$package"
    install -m 0644 "$root/LICENSE" "$d/usr/share/doc/$package/copyright"
    if [[ $package == agent-governor-ng-operator-tools ]]; then
        install -d -m 0755 "$d/usr/bin"
        install -m 0755 "$bin_dir/ag-loopctl" "$bin_dir/ag-standing-resolver" "$bin_dir/ag-operator-ui" "$d/usr/bin/"
        depends='libc6 (>= 2.35), git'
        description='Agent Governor governed-loop operator tools'
        install -m 0644 "$root/docs/governed-loop-c1.md" "$d/usr/share/doc/$package/"
    else
        install -d -m 0755 "$d/usr/libexec/agent-governor-ng"
        install -m 0755 "$bin_dir/ag-effectd" "$d/usr/libexec/agent-governor-ng/"
        # The standalone executor uses interfaces present in systemd 249.
        # Daemon credential units retain their separate >=252 contract.
        depends='libc6 (>= 2.35), systemd (>= 249)'
        description='Agent Governor target-local systemd effect process adapter'
        install -m 0644 "$root/docs/operator-beta-systemd-dbus-backend-v1.md" "$d/usr/share/doc/$package/"
    fi
    cat > "$d/DEBIAN/control" <<CONTROL
Package: $package
Version: $version
Section: admin
Priority: optional
Architecture: $arch
Maintainer: Constellation contributors
Depends: $depends
Description: $description
 Inert runtime payload. Installs no configuration, credentials or mutable state
 and enables or starts no service. Build and publication do not establish
 release promotion or authorize effects.
CONTROL
    find "$d" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
    dpkg-deb --root-owner-group --build "$d" "$out_dir/${package}_${version}_${arch}.deb" >/dev/null
    (cd "$out_dir" && sha256sum "${package}_${version}_${arch}.deb" > "${package}_${version}_${arch}.deb.sha256")
done
