#!/bin/sh
# ICEBOX installer: https://raw.githubusercontent.com/Devaretanmay/icebox/main/dist/install.sh | sh
set -eu

REPO="${REPO:-Devaretanmay/icebox}"
BIN="icebox"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux)  OS="linux" ;;
  Darwin) OS="macos" ;;
  *) echo "icebox: unsupported OS: $OS" >&2; exit 1 ;;
esac
case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *) echo "icebox: unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

ASSET="icebox-${OS}-${ARCH}.tar.gz"
if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
else
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "icebox: downloading $URL"
curl -fSL "$URL" -o "$TMP/icebox.tar.gz"
tar -xzf "$TMP/icebox.tar.gz" -C "$TMP"

TARGET="$TMP/$BIN"
if [ ! -f "$TARGET" ]; then
  echo "icebox: binary not found in archive ($ASSET)" >&2
  exit 1
fi

if [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "$TARGET" "$INSTALL_DIR/$BIN"
else
  echo "icebox: $INSTALL_DIR is not writable, trying sudo"
  sudo install -m 0755 "$TARGET" "$INSTALL_DIR/$BIN"
fi

echo "icebox: installed to $INSTALL_DIR/$BIN"
"$INSTALL_DIR/$BIN" --version 2>/dev/null || true
