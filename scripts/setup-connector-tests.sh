#!/usr/bin/env bash
# scripts/setup-connector-tests.sh
#
# One-time (idempotent) setup for the connector integration test suite.
#
# What it does:
#   1. Checks that Node ≥18 and npm are available
#   2. Runs `npm install` inside browser-automation-engine/ (skipped if up-to-date)
#   3. Installs Playwright browser binaries (chromium + webkit) if not present
#   4. Checks/installs grpcurl for gRPC backend testing
#   5. Auto-installs Netlify CLI locally if not already available (optional)
#   6. Deploys the GPay/APay token-generator pages to Netlify and writes
#      GPAY_HOSTED_URL to .env.connector-tests (skipped if already deployed)
#   7. Verifies credentials file is present (creds.json)
#   8. Installs test-prism launcher to PATH
#
# Re-running this script is safe — every step checks whether work is needed
# before doing it.
#
# Environment variables (all optional):
#   CONNECTOR_AUTH_FILE_PATH  Path to creds.json (overrides repo default)
#   GPAY_HOSTED_URL           Skip Netlify deploy if already set
#   SKIP_NETLIFY_DEPLOY       Set to 1 to skip the Netlify deploy step (disables Google Pay tests)
#   NETLIFY_AUTH_TOKEN        Required for unattended Netlify deploys (CI/CD environments)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BAE_DIR="${REPO_ROOT}/browser-automation-engine"
ENV_FILE="${REPO_ROOT}/.env.connector-tests"
DEFAULT_CREDS="${REPO_ROOT}/.github/test/creds.json"
UCS_CONFIG_DIR="${HOME}/.config/ucs-connector-tests"
SETUP_SENTINEL="${UCS_CONFIG_DIR}/setup.done"

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Colour

info()    { echo -e "${BLUE}[setup]${NC} $*"; }
success() { echo -e "${GREEN}[setup]${NC} $*"; }
warn()    { echo -e "${YELLOW}[setup]${NC} $*"; }
error()   { echo -e "${RED}[setup]${NC} $*" >&2; }

# ── Step 1: Check Node / npm ───────────────────────────────────────────────────
info "Checking Node.js and npm..."

if ! command -v node &>/dev/null; then
  error "Node.js not found. Install Node ≥18 from https://nodejs.org and re-run."
  exit 1
fi

NODE_VERSION=$(node --version | sed 's/v//')
NODE_MAJOR=$(echo "${NODE_VERSION}" | cut -d. -f1)
if [[ "${NODE_MAJOR}" -lt 18 ]]; then
  error "Node ${NODE_VERSION} is too old. Node ≥18 is required."
  exit 1
fi
success "Node ${NODE_VERSION} OK"

if ! command -v npm &>/dev/null; then
  error "npm not found. It should come with Node — please reinstall Node."
  exit 1
fi
success "npm $(npm --version) OK"

# ── Step 2: npm install ────────────────────────────────────────────────────────
info "Installing browser-automation-engine dependencies..."

LOCK_FILE="${BAE_DIR}/package-lock.json"
NODE_MODULES="${BAE_DIR}/node_modules"

# Check whether node_modules is up-to-date with package-lock.json
needs_install=true
if [[ -d "${NODE_MODULES}" && -f "${LOCK_FILE}" ]]; then
  # node_modules newer than package-lock.json → already installed
  if [[ "${NODE_MODULES}" -nt "${LOCK_FILE}" ]]; then
    needs_install=false
  fi
fi

if "${needs_install}"; then
  (cd "${BAE_DIR}" && npm install --prefer-offline 2>&1)
  success "npm install complete"
else
  success "node_modules up-to-date, skipping npm install"
fi

# ── Step 3: Install Playwright browsers ───────────────────────────────────────
info "Checking Playwright browser binaries..."

# Use a sentinel file to avoid re-installing on every run
PLAYWRIGHT_SENTINEL="${NODE_MODULES}/.playwright-browsers-installed"

if [[ ! -f "${PLAYWRIGHT_SENTINEL}" ]]; then
  info "Installing Playwright browsers (chromium + webkit)..."
  (cd "${BAE_DIR}" && npm run install:browsers 2>&1)
  touch "${PLAYWRIGHT_SENTINEL}"
  success "Playwright browsers installed"
else
  success "Playwright browsers already installed"
fi

# ── Step 3.5: Check/Install grpcurl ───────────────────────────────────────────
info "Checking grpcurl..."

if command -v grpcurl &>/dev/null; then
  success "grpcurl already installed ($(grpcurl --version 2>&1 | head -1))"
else
  warn "grpcurl not found — attempting to install..."

  # Detect platform
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "${OS}" in
    Darwin)
      if command -v brew &>/dev/null; then
        info "Installing grpcurl via Homebrew..."
        brew install grpcurl && success "grpcurl installed via Homebrew"
      else
        warn "Homebrew not found. Please install grpcurl manually:"
        warn "  brew install grpcurl"
        warn "  OR download from: https://github.com/fullstorydev/grpcurl/releases"
        warn ""
        warn "grpcurl is required for gRPC backend testing."
      fi
      ;;
    Linux)
      info "Installing grpcurl from GitHub releases..."
      GRPCURL_VERSION="1.9.1"
      DOWNLOAD_URL="https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/grpcurl_${GRPCURL_VERSION}_linux_x86_64.tar.gz"

      TEMP_DIR=$(mktemp -d)
      if curl -L -o "${TEMP_DIR}/grpcurl.tar.gz" "${DOWNLOAD_URL}" 2>&1; then
        tar -xzf "${TEMP_DIR}/grpcurl.tar.gz" -C "${TEMP_DIR}"

        # Try to install to /usr/local/bin or ~/bin
        if [[ -w "/usr/local/bin" ]]; then
          mv "${TEMP_DIR}/grpcurl" /usr/local/bin/
          success "grpcurl installed to /usr/local/bin/grpcurl"
        elif mkdir -p "${HOME}/bin" 2>/dev/null; then
          mv "${TEMP_DIR}/grpcurl" "${HOME}/bin/"
          success "grpcurl installed to ~/bin/grpcurl"

          # Check if ~/bin is in PATH
          if [[ ":${PATH}:" != *":${HOME}/bin:"* ]]; then
            warn "~/bin is not in your PATH. Add it to your shell profile:"
            warn "  echo 'export PATH=\"\${HOME}/bin:\${PATH}\"' >> ~/.bashrc"
            warn "  source ~/.bashrc"
          fi
        else
          warn "Could not install grpcurl to system path."
          warn "Binary available at: ${TEMP_DIR}/grpcurl"
          warn "Move it manually: sudo mv ${TEMP_DIR}/grpcurl /usr/local/bin/"
        fi
      else
        warn "Failed to download grpcurl. Please install manually:"
        warn "  https://github.com/fullstorydev/grpcurl/releases"
      fi
      rm -rf "${TEMP_DIR}"
      ;;
    *)
      warn "Unsupported OS: ${OS}. Please install grpcurl manually:"
      warn "  https://github.com/fullstorydev/grpcurl/releases"
      warn ""
      warn "grpcurl is required for gRPC backend testing."
      ;;
  esac
fi

# ── Step 4: Install Netlify CLI (if needed) ───────────────────────────────────
info "Checking Netlify CLI..."

# Check if Netlify CLI is already installed globally or can run via npx
NETLIFY_AVAILABLE=false
if command -v netlify &>/dev/null; then
  NETLIFY_AVAILABLE=true
  success "Netlify CLI already installed (global)"
elif (cd "${BAE_DIR}" && npx --no -- netlify --version &>/dev/null 2>&1); then
  NETLIFY_AVAILABLE=true
  success "Netlify CLI available via npx"
fi

# If not available and user hasn't explicitly skipped, offer to install
if [[ "${NETLIFY_AVAILABLE}" == "false" && "${SKIP_NETLIFY_DEPLOY:-0}" != "1" ]]; then
  echo ""
  warn "Netlify CLI is not installed."
  echo ""
  echo "  Netlify CLI is used to deploy Google Pay token generator pages."
  echo "  This enables Google Pay payment testing."
  echo ""
  echo "  Options:"
  echo "    1) Install globally (recommended):  npm install -g netlify-cli"
  echo "    2) Install locally in project:      (auto-installed below)"
  echo "    3) Skip (Google Pay tests disabled): export SKIP_NETLIFY_DEPLOY=1"
  echo ""

  # Auto-install locally in the project for convenience
  info "Installing Netlify CLI locally in browser-automation-engine..."
  if (cd "${BAE_DIR}" && npm install --save-dev netlify-cli 2>&1); then
    success "Netlify CLI installed locally"
    # Add to package.json scripts for easy access
    info "You can now use: cd browser-automation-engine && npx netlify"
  else
    warn "Failed to install Netlify CLI locally"
    warn "Google Pay tests will be skipped unless you install manually:"
    warn "  npm install -g netlify-cli"
  fi
fi

# ── Step 5: Netlify deploy (GPAY_HOSTED_URL) ──────────────────────────────────
# Source .env.connector-tests if it exists so we pick up a previously saved URL
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${ENV_FILE}" || true
fi

SKIP_NETLIFY="${SKIP_NETLIFY_DEPLOY:-0}"

if [[ -n "${GPAY_HOSTED_URL:-}" ]]; then
  success "GPAY_HOSTED_URL already set: ${GPAY_HOSTED_URL}"
  SKIP_NETLIFY=1
fi

if [[ "${SKIP_NETLIFY}" != "1" ]]; then
  info "Deploying GPay token-generator pages to Netlify..."

  # Determine which netlify command to use (global, local, or npx)
  NETLIFY_CMD=""
  if command -v netlify &>/dev/null; then
    NETLIFY_CMD="netlify"
    info "Using global Netlify CLI"
  elif [[ -f "${BAE_DIR}/node_modules/.bin/netlify" ]]; then
    NETLIFY_CMD="npx netlify"
    info "Using locally installed Netlify CLI"
  elif (cd "${BAE_DIR}" && npx --no -- netlify --version &>/dev/null 2>&1); then
    NETLIFY_CMD="npx --no -- netlify"
    info "Using Netlify CLI via npx"
  else
    warn "Netlify CLI not found after installation attempt."
    warn "This is unexpected - please report this issue."
    warn ""
    warn "Manual workaround:"
    warn "  1) Install globally: npm install -g netlify-cli"
    warn "  2) Re-run setup"
    warn ""
    warn "Skipping Netlify deploy — Google Pay tests will be skipped at runtime."
    SKIP_NETLIFY=1
  fi
fi

if [[ "${SKIP_NETLIFY}" != "1" && -n "${NETLIFY_CMD}" ]]; then

  info "Running: netlify deploy --prod (in browser-automation-engine/)"
  DEPLOY_OUTPUT=$(cd "${BAE_DIR}" && ${NETLIFY_CMD} deploy --prod 2>&1) || {
    warn "Netlify deploy failed. Google Pay tests will be skipped at runtime."
    warn "To fix, ensure NETLIFY_AUTH_TOKEN is set and your site is linked."
    warn "Raw output:"
    echo "${DEPLOY_OUTPUT}" | sed 's/^/    /'
    SKIP_NETLIFY=1
  }

  if [[ "${SKIP_NETLIFY}" != "1" ]]; then
    # Extract the deployed URL from netlify output
    # Netlify prints lines like: "Website URL:  https://xxxx.netlify.app"
    DEPLOYED_URL=$(echo "${DEPLOY_OUTPUT}" | grep -Eo 'https://[a-zA-Z0-9._-]+\.netlify\.app' | head -1 || true)
    if [[ -z "${DEPLOYED_URL}" ]]; then
      warn "Could not extract Netlify URL from deploy output."
      warn "Set GPAY_HOSTED_URL manually."
    else
      GPAY_HOSTED_URL="${DEPLOYED_URL}/gpay/gpay-token-gen.html"
      success "Netlify deploy successful: ${GPAY_HOSTED_URL}"

      # Persist to .env.connector-tests
      {
        echo "# Auto-generated by scripts/setup-connector-tests.sh"
        echo "# Re-run 'make setup-connector-tests' to refresh"
        echo "export GPAY_HOSTED_URL=\"${GPAY_HOSTED_URL}\""
      } > "${ENV_FILE}"
      success "Saved GPAY_HOSTED_URL to ${ENV_FILE}"
    fi
  fi
fi

# ── Step 6: Verify credentials ─────────────────────────────────────────────────
info "Checking credentials file..."

CREDS_PATH="${CONNECTOR_AUTH_FILE_PATH:-${UCS_CREDS_PATH:-${DEFAULT_CREDS}}}"

if [[ -f "${CREDS_PATH}" ]]; then
  success "Credentials found: ${CREDS_PATH}"
else
  warn "Credentials file not found at: ${CREDS_PATH}"
  warn ""
  warn "Create it at .github/test/creds.json, or set one of:"
  warn "  export CONNECTOR_AUTH_FILE_PATH=/path/to/creds.json"
  warn "  export UCS_CREDS_PATH=/path/to/creds.json"
  warn ""
  warn "Connector tests that require credentials will be skipped."
fi

# ── Step 7: Install test-prism launcher ───────────────────────────────────────
info "Installing test-prism command..."

LAUNCHER_NAME="test-prism"
LAUNCHER_TARGET="${SCRIPT_DIR}/run-tests"

# Candidate directories — only consider those already on PATH
install_dir=""
candidates=(
  "/usr/local/bin"
  "/opt/homebrew/bin"
  "${HOME}/.local/bin"
  "${HOME}/bin"
)

for candidate in "${candidates[@]}"; do
  # Check if this candidate is on the user's PATH
  if [[ ":${PATH}:" == *":${candidate}:"* ]]; then
    # Create the directory if it doesn't exist (only for user-owned dirs)
    if [[ ! -d "${candidate}" && "${candidate}" == "${HOME}"* ]]; then
      mkdir -p "${candidate}" 2>/dev/null || continue
    fi
    # Check writable
    if [[ -w "${candidate}" ]]; then
      install_dir="${candidate}"
      break
    fi
  fi
done

if [[ -z "${install_dir}" ]]; then
  warn "Could not find a writable directory on your PATH to install ${LAUNCHER_NAME}."
  warn "Checked: ${candidates[*]}"
  warn ""
  warn "To install manually, run one of these after adding a bin dir to your PATH:"
  warn "  sudo cp \"${LAUNCHER_TARGET}\" /usr/local/bin/${LAUNCHER_NAME} && sudo chmod +x /usr/local/bin/${LAUNCHER_NAME}"
  warn "  -- or --"
  warn "  mkdir -p ~/.local/bin && cp \"${LAUNCHER_TARGET}\" ~/.local/bin/${LAUNCHER_NAME} && chmod +x ~/.local/bin/${LAUNCHER_NAME}"
  warn "  (then add ~/.local/bin to your PATH and re-run setup)"
else
  INSTALL_PATH="${install_dir}/${LAUNCHER_NAME}"

  # Write a small launcher that execs the repo script so the repo can be updated
  # independently of the installed command.
  cat > "${INSTALL_PATH}" <<LAUNCHER
#!/usr/bin/env bash
# Auto-generated by scripts/setup-connector-tests.sh — do not edit manually.
# Re-run setup to refresh this launcher after moving the repo.
exec "${LAUNCHER_TARGET}" "\$@"
LAUNCHER
  chmod +x "${INSTALL_PATH}"
  success "Installed ${LAUNCHER_NAME} → ${INSTALL_PATH}"
  success "You can now run:  test-prism"
fi

# ── Done ───────────────────────────────────────────────────────────────────────
# Write setup sentinel so test-prism knows setup has been completed.
mkdir -p "${UCS_CONFIG_DIR}"
echo "{\"repo\": \"${REPO_ROOT}\", \"completed_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
  > "${SETUP_SENTINEL}"

echo ""
success "Setup complete."
echo ""
echo "  To run all connector tests:                test-prism"
echo "  To run tests for a specific connector:     test-prism --connector stripe"
echo "  To run a specific scenario:                test-prism --connector stripe --suite authorize --scenario no3ds_auto_capture_credit_card"
echo "  Interactive wizard:                        test-prism --interactive"
echo "  Full usage:                                test-prism --help"
echo ""

if [[ -n "${GPAY_HOSTED_URL:-}" ]]; then
  echo "  Google Pay support: ENABLED (${GPAY_HOSTED_URL})"
else
  echo "  Google Pay support: DISABLED (GPAY_HOSTED_URL not set)"
  echo "  To enable: set GPAY_HOSTED_URL or allow Netlify deploy during setup"
fi
echo ""
