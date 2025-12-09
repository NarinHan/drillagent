#!/bin/bash
#
# repo_prepare.sh - Initialize all GitHub repositories from SEC-bench CVE instances
#
# This script clones and sets up all 29 GitHub projects listed in the
# DrillAgent/datasets/sec-bench/CVE-instances directory.
#
# Usage: ./repo_prepare.sh [options]
#
# Options:
#   -d, --dest DIR    Destination directory for repositories (default: ./repos)
#   -f, --force       Force re-clone even if repository exists
#   -h, --help        Show this help message
#

set -euo pipefail

# Default configuration
DEST_DIR="./repos"
FORCE_CLONE=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# GitHub repositories to clone (29 projects from SEC-bench)
declare -A REPOS=(
    ["exiv2"]="https://github.com/exiv2/exiv2.git"
    ["faad2"]="https://github.com/knik0/faad2.git"
    ["gpac"]="https://github.com/gpac/gpac.git"
    ["imagemagick"]="https://github.com/imagemagick/imagemagick.git"
    ["jq"]="https://github.com/jqlang/jq.git"
    ["libarchive"]="https://github.com/libarchive/libarchive.git"
    ["libdwarf-code"]="https://github.com/davea42/libdwarf-code.git"
    ["libredwg"]="https://github.com/libredwg/libredwg.git"
    ["matio"]="https://github.com/tbeu/matio.git"
    ["md4c"]="https://github.com/mity/md4c.git"
    ["mruby"]="https://github.com/mruby/mruby.git"
    ["njs"]="https://github.com/nginx/njs.git"
    ["php-src"]="https://github.com/php/php-src.git"
    ["yaml-cpp"]="https://github.com/jbeder/yaml-cpp.git"
    ["openexr"]="https://github.com/academysoftwarefoundation/openexr.git"
    ["openjpeg"]="https://github.com/uclouvain/openjpeg.git"
    ["libheif"]="https://github.com/strukturag/libheif.git"
    ["libiec61850"]="https://github.com/mz-automation/libiec61850.git"
    ["libjpeg-turbo"]="https://github.com/libjpeg-turbo/libjpeg-turbo.git"
    ["liblouis"]="https://github.com/liblouis/liblouis.git"
    ["libmodbus"]="https://github.com/stephane/libmodbus.git"
    ["libplist"]="https://github.com/libimobiledevice/libplist.git"
    ["libsndfile"]="https://github.com/libsndfile/libsndfile.git"
    ["libxls"]="https://github.com/libxls/libxls.git"
    ["qpdf"]="https://github.com/qpdf/qpdf.git"
    ["upx"]="https://github.com/upx/upx.git"
    ["yara"]="https://github.com/virustotal/yara.git"
    ["wabt"]="https://github.com/webassembly/wabt.git"
    ["readstat"]="https://github.com/wizardmac/readstat.git"
)

# Function to print messages
log_info() {
    echo "[INFO] $1"
}

log_success() {
    echo "[SUCCESS] $1"
}

log_warning() {
    echo "[WARNING] $1"
}

log_error() {
    echo "[ERROR] $1"
}

# Function to show usage
show_help() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--dest)
                DEST_DIR="$2"
                shift 2
                ;;
            -f|--force)
                FORCE_CLONE=true
                shift
                ;;
            -h|--help)
                show_help
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                ;;
        esac
    done
}

# Function to clone a single repository
clone_repo() {
    local name="$1"
    local url="$2"
    local dest="$DEST_DIR/$name"
    
    if [[ -d "$dest" ]]; then
        if [[ "$FORCE_CLONE" == "true" ]]; then
            log_warning "Removing existing repository: $name"
            rm -rf "$dest"
        else
            log_info "Repository already exists, skipping: $name"
            return 0
        fi
    fi
    
    log_info "Cloning $name from $url..."
    if git clone --depth 1 "$url" "$dest" > /dev/null 2>&1; then
        log_success "Successfully cloned: $name"
        return 0
    else
        log_error "Failed to clone: $name"
        return 1
    fi
}

# Function to clone repositories sequentially
clone_repos() {
    local count=0
    local total=${#REPOS[@]}
    local failed=0
    
    log_info "Cloning $total repositories to: $DEST_DIR"
    echo ""
    
    # Create destination directory
    mkdir -p "$DEST_DIR"
    
    # Clone repositories one by one
    for name in $(echo "${!REPOS[@]}" | tr ' ' '\n' | sort); do
        url="${REPOS[$name]}"
        count=$((count + 1))
        printf "[%d/%d] Processing: %s\n" "$count" "$total" "$name"
        clone_repo "$name" "$url" || failed=$((failed + 1))
        echo ""
    done
    
    if [[ $failed -eq 0 ]]; then
        log_success "All $total repositories cloned successfully!"
    else
        log_warning "$failed out of $total repositories failed to clone"
        return 1
    fi
}

# Function to verify cloned repositories
verify_repos() {
    log_info "Verifying cloned repositories..."
    local missing=0
    
    for name in "${!REPOS[@]}"; do
        if [[ ! -d "$DEST_DIR/$name/.git" ]]; then
            log_error "Repository missing or invalid: $name"
            ((missing++))
        fi
    done
    
    if [[ $missing -eq 0 ]]; then
        log_success "All repositories verified successfully!"
    else
        log_error "$missing repositories are missing or invalid"
        return 1
    fi
}

# Function to generate repository summary
generate_summary() {
    log_info "Generating repository summary..."
    
    echo ""
    echo "Repository Summary:"
    echo "==================="
    echo "Total repositories: ${#REPOS[@]}"
    echo "Destination: $DEST_DIR"
    echo ""
    echo "Repositories:"
    for name in $(echo "${!REPOS[@]}" | tr ' ' '\n' | sort); do
        printf "  %-20s %s\n" "$name" "${REPOS[$name]}"
    done
}

# Main execution
main() {
    parse_args "$@"
    
    log_info "SEC-bench Repository Preparation Script"
    log_info "========================================"
    echo ""
    
    # Convert relative path to absolute
    if [[ ! "$DEST_DIR" = /* ]]; then
        DEST_DIR="$PROJECT_ROOT/$DEST_DIR"
    fi
    
    clone_repos
    verify_repos
    generate_summary
    
    echo ""
    log_success "Repository initialization complete!"
    log_info "Repositories are available at: $DEST_DIR"
}

# Run main function
main "$@"