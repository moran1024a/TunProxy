#!/bin/sh
# Run the unit tests together with the integration cases that need the real
# pinned sing-box release.
#
# Usage: tools/run-integration-tests.sh [build-dir]
#
# The archive named in include/tunproxy/core_manifest.hpp is downloaded into
# <build-dir>/integration, verified against the pinned SHA-256, and unpacked.
# The tests then run `sing-box check` on generated configurations and repair a
# core from the archive inside temporary directories. Nothing is installed and
# no TUN interface is created.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=${1:-"$ROOT/build"}
HEADER="$ROOT/include/tunproxy/core_manifest.hpp"

if [ ! -f "$BUILD/CTestTestfile.cmake" ]; then
    echo "error: $BUILD is not a configured build directory (run cmake first)" >&2
    exit 2
fi

# Quoted fields inside kSingBoxRelease, in declaration order.
FIELDS=$(sed -n '/kSingBoxRelease{/,/^};/p' "$HEADER" | grep -o '"[^"]*"' | tr -d '"')
VERSION=$(printf '%s\n' "$FIELDS" | sed -n 1p)
ASSET=$(printf '%s\n' "$FIELDS" | sed -n 3p)
ARCHIVE_SHA256=$(printf '%s\n' "$FIELDS" | grep -m 1 -E '^[0-9a-f]{64}$')
if [ -z "$VERSION" ] || [ -z "$ASSET" ] || [ -z "$ARCHIVE_SHA256" ]; then
    echo "error: cannot parse $HEADER" >&2
    exit 1
fi
URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/${ASSET}"
DIRECTORY="sing-box-${VERSION}-linux-amd64"

WORK="$BUILD/integration"
mkdir -p "$WORK"
ARCHIVE="$WORK/$ASSET"

if [ ! -f "$ARCHIVE" ] || [ "$(sha256sum "$ARCHIVE" | cut -c1-64)" != "$ARCHIVE_SHA256" ]; then
    echo "Downloading $URL"
    curl --fail --location --proto =https --tlsv1.2 --connect-timeout 15 --max-time 600 \
        --output "$ARCHIVE.part" "$URL"
    mv "$ARCHIVE.part" "$ARCHIVE"
fi
ACTUAL=$(sha256sum "$ARCHIVE" | cut -c1-64)
if [ "$ACTUAL" != "$ARCHIVE_SHA256" ]; then
    echo "error: archive SHA-256 mismatch: $ACTUAL" >&2
    exit 1
fi

rm -rf "$WORK/$DIRECTORY"
tar --extract --gzip --file "$ARCHIVE" --directory "$WORK" \
    --no-same-owner --no-same-permissions -- "$DIRECTORY/sing-box"
chmod 0755 "$WORK/$DIRECTORY/sing-box"

TUNPROXY_TEST_SINGBOX="$WORK/$DIRECTORY/sing-box"
TUNPROXY_TEST_SINGBOX_ARCHIVE="$ARCHIVE"
export TUNPROXY_TEST_SINGBOX TUNPROXY_TEST_SINGBOX_ARCHIVE

echo "Using $TUNPROXY_TEST_SINGBOX"
cmake --build "$BUILD"
exec ctest --test-dir "$BUILD" --output-on-failure
