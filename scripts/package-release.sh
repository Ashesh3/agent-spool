#!/bin/sh
# Run from the repository root. Require a new directory so stale assets cannot ship.
set -eu
out=${1:?Usage: sh scripts/package-release.sh NEW_OUTPUT_DIRECTORY}
mkdir "$out"
out=$(cd "$out" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

cp LICENSE THIRD_PARTY_NOTICES.txt "$stage/"
chmod 644 "$stage/LICENSE" "$stage/THIRD_PARTY_NOTICES.txt"
for os in darwin linux windows; do
    exe=spool-relay
    if [ "$os" = windows ]; then exe=spool-relay.exe; fi
    for arch in amd64 arm64; do
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -mod=readonly -trimpath -ldflags='-s -w' -o "$stage/$exe" ./cmd/spool-relay
        chmod 755 "$stage/$exe"
        base="$out/spool-relay-$os-$arch"
        (
            cd "$stage"
            if [ "$os" = windows ]; then
                zip -q "$base.zip" "$exe" LICENSE THIRD_PARTY_NOTICES.txt
            else
                tar -czf "$base.tar.gz" "$exe" LICENSE THIRD_PARTY_NOTICES.txt
            fi
        )
    done
done
(cd "$out" && sha256sum *.tar.gz *.zip > SHA256SUMS)
