#!/bin/sh
# One-line installer for kubelogin-daemon (Linux / macOS)
#
# Install:  curl -fsSL https://raw.githubusercontent.com/ZihaoZhou/kubelogin-daemon/daemon-mode/install.sh | sh
# Upgrade:  curl -fsSL https://raw.githubusercontent.com/ZihaoZhou/kubelogin-daemon/daemon-mode/install.sh | sh
#           (same command — detects existing install and runs setup upgrade)
#
# Inspect first: curl -fsSL <URL> -o install.sh && less install.sh && sh install.sh
#
# For Windows, use install.ps1 instead:
#   irm https://raw.githubusercontent.com/ZihaoZhou/kubelogin-daemon/daemon-mode/install.ps1 | iex
set -eu

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)        ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    echo "For Windows, use install.ps1 instead." >&2
    exit 1
    ;;
esac

case "$OS" in
  linux|darwin) ;;
  *)
    echo "Unsupported OS: $OS" >&2
    echo "For Windows, use install.ps1 instead." >&2
    exit 1
    ;;
esac

# Determine latest release
echo "Fetching latest release..."
LATEST=$(curl -fsSL https://api.github.com/repos/ZihaoZhou/kubelogin-daemon/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
if [ -z "$LATEST" ]; then
  echo "Failed to determine latest release" >&2
  exit 1
fi
echo "Latest version: $LATEST"

# Set up paths
BASE_URL="https://github.com/ZihaoZhou/kubelogin-daemon/releases/download/${LATEST}"
BINARY_NAME="kubelogin-daemon_${OS}_${ARCH}"
INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"

# Download binary and checksums to a temp directory
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading kubelogin-daemon ${LATEST} for ${OS}/${ARCH}..."
curl -fsSL --proto '=https' "${BASE_URL}/${BINARY_NAME}" -o "${TMPDIR}/${BINARY_NAME}"
curl -fsSL --proto '=https' "${BASE_URL}/checksums.txt" -o "${TMPDIR}/checksums.txt"

# Verify checksum
EXPECTED=$(grep -F "${BINARY_NAME}" "${TMPDIR}/checksums.txt" | awk '{print $1}' | head -1)
if [ -z "$EXPECTED" ]; then
  echo "ERROR: No checksum entry found for ${BINARY_NAME} in checksums.txt" >&2
  echo "The release may be malformed or tampered with." >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "${TMPDIR}/${BINARY_NAME}" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL=$(shasum -a 256 "${TMPDIR}/${BINARY_NAME}" | awk '{print $1}')
else
  echo "ERROR: Neither sha256sum nor shasum found. Cannot verify download integrity." >&2
  exit 1
fi

if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "CHECKSUM MISMATCH!" >&2
  echo "  Expected: $EXPECTED" >&2
  echo "  Got:      $ACTUAL" >&2
  exit 1
fi
echo "Checksum verified."

# Install: move to install dir
chmod +x "${TMPDIR}/${BINARY_NAME}"

# Check if this is an upgrade (existing binary found)
EXISTING=$(command -v kubelogin-daemon 2>/dev/null || true)
if [ -n "$EXISTING" ] && [ -x "$EXISTING" ]; then
  OLD_VERSION=$("$EXISTING" --version 2>&1 | head -1 || echo "unknown")
  echo "Existing installation found: $OLD_VERSION at $EXISTING"
  # Use the NEW binary's setup upgrade to update kubeconfig & stop old daemon
  mv "${TMPDIR}/${BINARY_NAME}" "${INSTALL_DIR}/kubelogin-daemon"
  echo "Running setup upgrade..."
  "${INSTALL_DIR}/kubelogin-daemon" setup upgrade --yes 2>&1 || true
else
  mv "${TMPDIR}/${BINARY_NAME}" "${INSTALL_DIR}/kubelogin-daemon"
fi

# Verify
if "${INSTALL_DIR}/kubelogin-daemon" --version >/dev/null 2>&1; then
  INSTALLED_VERSION=$("${INSTALL_DIR}/kubelogin-daemon" --version 2>&1 | head -1)
  echo "Installed: $INSTALLED_VERSION"
else
  echo "Installed kubelogin-daemon to ${INSTALL_DIR}/kubelogin-daemon"
fi

echo ""

# Check PATH
IN_PATH=true
case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    IN_PATH=false
    echo "Add ${INSTALL_DIR} to your PATH:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    echo ""
    ;;
esac

# If this was a fresh install (no existing binary), show setup instructions
if [ -z "$EXISTING" ]; then
  echo "Next steps:"
  echo ""
  echo "  Fresh setup:"
  echo "    kubelogin-daemon setup install \\"
  echo "      --oidc-issuer-url=https://YOUR_ISSUER \\"
  echo "      --oidc-client-id=YOUR_CLIENT_ID"
  echo ""
  echo "  Migrate from kubelogin:"
  echo "    kubelogin-daemon setup migrate"
else
  echo "Upgrade complete."
fi
