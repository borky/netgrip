#!/bin/sh
# Build deterministic, generic Linux binaries for the Go ABI families used by
# OpenWrt. The frontend must already exist in internal/server/dist.

set -eu

VERSION="${VERSION:-dev}"
OUTPUT_DIR="${OUTPUT_DIR:-dist}"
GO_BIN="${GO_BIN:-go}"
ALL_TARGETS="linux-amd64 linux-arm64 linux-armv7 linux-armv6 linux-armv5 linux-mipsle linux-mips"

[ -f internal/server/dist/index.html ] || {
  echo "ERROR: frontend missing; run 'npm ci && npm run build' in app first" >&2
  exit 1
}

mkdir -p "$OUTPUT_DIR"

build() {
  name=$1
  shift
  release_arch=${name#linux-}
  echo "Building netgrip-${name}"
  env \
    CGO_ENABLED=0 \
    GOOS=linux \
    "$@" \
    "$GO_BIN" build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -buildid= -X main.version=${VERSION} -X github.com/gnacho/netgrip/internal/modules.releaseArch=${release_arch}" \
      -o "${OUTPUT_DIR}/netgrip-${name}" \
      ./cmd/netgrip
}

if [ "$#" -eq 0 ]; then
  set -- $ALL_TARGETS
fi

for target in "$@"; do
  case "$target" in
    linux-amd64)  build "$target" GOARCH=amd64 GOAMD64=v1 ;;
    linux-arm64)  build "$target" GOARCH=arm64 GOARM64=v8.0 ;;
    linux-armv7)  build "$target" GOARCH=arm GOARM=7 ;;
    linux-armv6)  build "$target" GOARCH=arm GOARM=6 ;;
    linux-armv5)  build "$target" GOARCH=arm GOARM=5 ;;
    linux-mipsle) build "$target" GOARCH=mipsle GOMIPS=softfloat ;;
    linux-mips)   build "$target" GOARCH=mips GOMIPS=softfloat ;;
    *)
      echo "ERROR: unsupported binary target: $target" >&2
      echo "Supported targets: $ALL_TARGETS" >&2
      exit 1
      ;;
  esac
done
