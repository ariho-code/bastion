#!/usr/bin/env bash
# Bastionscan CLI installer for macOS and Linux.
# Installs `bastionscan` into ~/.local/bin (or /usr/local/bin if writable).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_NAME="bastionscan"
INSTALL_DIR="${BASTION_INSTALL_DIR:-}"

if [[ -z "${INSTALL_DIR}" ]]; then
  if [[ -w /usr/local/bin ]]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi

mkdir -p "${INSTALL_DIR}"

echo "==> Building bastionscan CLI (Go)…"
if ! command -v go >/dev/null 2>&1; then
  echo "error: Go is required to build the CLI. Install Go 1.21+ from https://go.dev/dl/" >&2
  exit 1
fi

OUT="${INSTALL_DIR}/${BIN_NAME}"
(
  cd "${REPO_ROOT}/engine"
  go build -trimpath -ldflags="-s -w" -o "${OUT}" ./cmd/bastionscan
)

chmod +x "${OUT}"
echo "==> Installed ${OUT}"

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo ""
    echo "Note: ${INSTALL_DIR} is not on your PATH."
    echo "Add this to your shell profile (~/.bashrc, ~/.zshrc):"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac

echo ""
echo "Try:"
echo "  ${BIN_NAME} version"
echo "  export BASTION_ENGINE_URL=https://your-engine.example"
echo "  ${BIN_NAME} verify yourcompany.com"
echo "  ${BIN_NAME} active yourcompany.com --exclude /billing --safe"
echo ""
echo "Ownership-gated Active AppSec never runs without DNS verification on the engine."
