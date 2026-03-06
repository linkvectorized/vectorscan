#!/usr/bin/env bash
set -euo pipefail

REPO="linkvectorized/vectorscan"
BIN_NAME="vectorscan"
INSTALL_DIR="/usr/local/bin"

# Detect OS and arch
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

case "$OS" in
  darwin) ;;
  *) echo "Unsupported OS: $OS (only macOS is currently supported)" >&2; exit 1 ;;
esac

ASSET="${BIN_NAME}-${OS}-${ARCH}"

# Fetch latest release tag
echo "Fetching latest release..."
TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' \
  | sed 's/.*"tag_name": *"\(.*\)".*/\1/')

if [[ -z "$TAG" ]]; then
  echo "Could not determine latest release tag." >&2
  exit 1
fi

URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"

echo "Downloading ${BIN_NAME} ${TAG} (${OS}/${ARCH})..."
curl -fsSL "$URL" -o "/tmp/${BIN_NAME}"
chmod +x "/tmp/${BIN_NAME}"

echo "Installing to ${INSTALL_DIR}/${BIN_NAME} (may require sudo)..."
sudo mv "/tmp/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"

echo ""
echo "Done. Run: vectorscan --help"
