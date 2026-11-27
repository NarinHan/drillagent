#!/bin/bash
#
# setup_mruby.sh - Install rbenv and the Ruby versions needed to build mruby
#
# DrillAgent switches Ruby automatically before each mruby build
# (see switch_ruby_version in src/drillagent/utils/utils.py):
#   - Ruby 2.7.8 for the older mruby CVE commits (2018 instances)
#   - Ruby 3.0.6 for everything else
# It calls `rbenv global <version>` and `ruby -v` via PATH, so rbenv must be
# initialized in the shell that launches DrillAgent.
#
# Usage: bash scripts/setup_mruby.sh [options]
#
# Options:
#   --skip-deps    Don't apt-get install the Ruby build dependencies
#   -h, --help     Show this help message
#

set -euo pipefail

RUBY_VERSIONS=("2.7.8" "3.0.6")
DEFAULT_VERSION="3.0.6"
RBENV_ROOT="${RBENV_ROOT:-$HOME/.rbenv}"
INSTALL_DEPS=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-deps) INSTALL_DEPS=false; shift ;;
        -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

log() { echo -e "\033[1;34m[setup_mruby]\033[0m $*"; }

# 1. Build dependencies for compiling Ruby (Debian/Ubuntu)
if $INSTALL_DEPS; then
    if command -v apt-get >/dev/null 2>&1; then
        SUDO=""
        [[ $EUID -ne 0 ]] && SUDO="sudo"
        log "Installing Ruby build dependencies via apt-get..."
        $SUDO apt-get update -y
        $SUDO apt-get install -y git curl build-essential autoconf bison \
            libssl-dev libyaml-dev libreadline-dev zlib1g-dev libffi-dev \
            libgdbm-dev libncurses-dev
    else
        log "apt-get not found; skipping dependency install (install Ruby build deps manually)."
    fi
fi

# 2. rbenv
if [[ -d "$RBENV_ROOT/.git" ]]; then
    log "rbenv already present at $RBENV_ROOT; updating..."
    git -C "$RBENV_ROOT" pull --ff-only || log "rbenv update failed; continuing with existing copy."
else
    log "Cloning rbenv into $RBENV_ROOT..."
    git clone https://github.com/rbenv/rbenv.git "$RBENV_ROOT"
fi

# 3. ruby-build plugin (provides `rbenv install`)
RUBY_BUILD_DIR="$RBENV_ROOT/plugins/ruby-build"
if [[ -d "$RUBY_BUILD_DIR/.git" ]]; then
    log "ruby-build already present; updating..."
    git -C "$RUBY_BUILD_DIR" pull --ff-only || log "ruby-build update failed; continuing with existing copy."
else
    log "Cloning ruby-build..."
    git clone https://github.com/rbenv/ruby-build.git "$RUBY_BUILD_DIR"
fi

export PATH="$RBENV_ROOT/bin:$PATH"
eval "$(rbenv init - bash)"

# 4. Shell init lines (idempotent)
add_init() {
    local rc="$1" shell="$2"
    [[ -f "$rc" ]] || return 0
    if grep -q 'rbenv init' "$rc"; then
        log "$rc already initializes rbenv; leaving it."
    else
        log "Adding rbenv init to $rc"
        {
            echo ''
            echo '# rbenv (added by drillagent scripts/setup_mruby.sh)'
            echo "export PATH=\"$RBENV_ROOT/bin:\$PATH\""
            echo "eval \"\$(rbenv init - $shell)\""
        } >> "$rc"
    fi
}
add_init "$HOME/.bashrc" bash
add_init "$HOME/.zshrc" zsh

# 5. Ruby versions
# Ruby 2.7 needs OpenSSL 1.1; recent ruby-build downloads and builds it
# automatically on systems that only ship OpenSSL 3 (e.g. Ubuntu 22.04+).
for v in "${RUBY_VERSIONS[@]}"; do
    if rbenv versions --bare | grep -qx "$v"; then
        log "Ruby $v already installed."
    else
        log "Installing Ruby $v (this takes a few minutes)..."
        rbenv install "$v"
    fi
done

rbenv global "$DEFAULT_VERSION"
rbenv rehash

# 6. Verify
log "Installed Ruby versions:"
rbenv versions
log "Active: $(ruby -v)"
log "Done. Open a new shell (or run: source ~/.bashrc) before launching DrillAgent."
