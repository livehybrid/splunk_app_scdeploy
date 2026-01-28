#!/bin/bash
#
# Local development test script for Docker-based testing
#
# This script:
# 1. Builds the app locally
# 2. Starts Docker Splunk instance
# 3. Waits for Splunk to be ready
# 4. Configures app destinations (if credentials available)
# 5. Creates test accounts
# 6. Executes token generation searches
# 7. Validates tokens (for local destinations only)
# 8. Optionally cleans up Docker instance
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SPLUNK_HOST="${SPLUNK_HOST:-localhost}"
SPLUNK_PORT="${SPLUNK_PORT:-8089}"
SPLUNK_USER="${SPLUNK_USER:-admin}"
SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-Chang3d!}"
CLEANUP="${CLEANUP:-true}"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        log_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
}

# Build the app
build_app() {
    log_info "Building app..."
    cd "$PROJECT_ROOT"
    make build || {
        log_error "Failed to build app"
        exit 1
    }
    log_info "App built successfully"
}

# Start Docker Splunk instance
start_splunk() {
    log_info "Starting Docker Splunk instance..."
    cd "$PROJECT_ROOT"
    
    # Check if containers are already running
    if docker-compose ps splunk 2>/dev/null | grep -q "Up"; then
        log_warn "Splunk container is already running"
    else
        make up || {
            log_error "Failed to start Splunk"
            exit 1
        }
    fi
    
    log_info "Waiting for Splunk to be ready..."
    
    # Wait for Splunk to be ready
    max_attempts=60
    attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -k -s -u "$SPLUNK_USER:$SPLUNK_PASSWORD" \
           "https://$SPLUNK_HOST:$SPLUNK_PORT/services/server/info" > /dev/null 2>&1; then
            log_info "Splunk is ready"
            break
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    
    if [ $attempt -eq $max_attempts ]; then
        log_error "Splunk did not become ready in time"
        exit 1
    fi
}

# Create test accounts
create_test_accounts() {
    log_info "Creating test accounts..."
    cd "$PROJECT_ROOT"
    
    python3 "$SCRIPT_DIR/create_test_accounts.py" \
        --host "$SPLUNK_HOST" \
        --port "$SPLUNK_PORT" \
        --username "$SPLUNK_USER" \
        --password "$SPLUNK_PASSWORD" \
        --scheme https || {
        log_error "Failed to create test accounts"
        exit 1
    }
    
    log_info "Test accounts created successfully"
}

# Configure app destinations (if credentials available)
configure_destinations() {
    log_info "Configuring app destinations..."
    
    # Check if we have environment variables for destinations
    if [ -n "$GITHUB_REPO" ] && [ -n "$GITHUB_TOKEN" ]; then
        log_info "GitHub credentials found, will configure GitHub destination"
    fi
    
    if [ -n "$GITLAB_PROJECT_URL" ] && [ -n "$GITLAB_TOKEN" ]; then
        log_info "GitLab credentials found, will configure GitLab destination"
    fi
    
    if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
        log_info "AWS credentials found, will configure AWS Secrets Manager destination"
    fi
    
    if [ -n "$OP_SERVICE_ACCOUNT_TOKEN" ]; then
        log_info "1Password credentials found, will configure 1Password destination"
    fi
    
    # Only configure if we have at least one set of credentials
    if [ -n "$GITHUB_REPO" ] || [ -n "$GITLAB_PROJECT_URL" ] || \
       [ -n "$AWS_ACCESS_KEY_ID" ] || [ -n "$OP_SERVICE_ACCOUNT_TOKEN" ]; then
        python3 "$SCRIPT_DIR/configure_app_destinations.py" \
            --host "$SPLUNK_HOST" \
            --port "$SPLUNK_PORT" \
            --username "$SPLUNK_USER" \
            --password "$SPLUNK_PASSWORD" \
            --scheme https \
            --from-env || {
            log_warn "Failed to configure destinations (this is OK if credentials are not available)"
        }
    else
        log_warn "No destination credentials found. Skipping destination configuration."
        log_warn "Set GITHUB_REPO/GITHUB_TOKEN, GITLAB_PROJECT_URL/GITLAB_TOKEN, AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, or OP_SERVICE_ACCOUNT_TOKEN to configure destinations."
    fi
}

# Generate test tokens
generate_tokens() {
    log_info "Generating test tokens..."
    cd "$PROJECT_ROOT"
    
    python3 "$SCRIPT_DIR/generate_test_tokens.py" \
        --host "$SPLUNK_HOST" \
        --port "$SPLUNK_PORT" \
        --username "$SPLUNK_USER" \
        --password "$SPLUNK_PASSWORD" \
        --scheme https || {
        log_error "Failed to generate tokens"
        exit 1
    }
    
    log_info "Tokens generated successfully"
}

# Validate tokens (basic validation only for local)
validate_tokens() {
    log_info "Validating tokens..."
    
    # For local testing, we can only do basic validation
    # Full validation requires external service access
    if [ -n "$GITHUB_REPO" ] || [ -n "$GITLAB_PROJECT_URL" ] || \
       [ -n "$AWS_ACCESS_KEY_ID" ] || [ -n "$OP_SERVICE_ACCOUNT_TOKEN" ]; then
        python3 "$SCRIPT_DIR/validate_tokens.py" \
            --from-env \
            --no-trigger || {
            log_warn "Some token validations failed (this may be expected in local testing)"
        }
    else
        log_warn "Skipping token validation (no credentials available)"
    fi
}

# Cleanup
cleanup() {
    if [ "$CLEANUP" = "true" ]; then
        log_info "Cleaning up Docker containers..."
        cd "$PROJECT_ROOT"
        make down || {
            log_warn "Failed to clean up containers"
        }
    else
        log_info "Skipping cleanup (set CLEANUP=false to keep containers running)"
    fi
}

# Main execution
main() {
    log_info "Starting local test workflow..."
    
    check_docker
    build_app
    start_splunk
    create_test_accounts
    configure_destinations
    generate_tokens
    validate_tokens
    
    log_info "Local test workflow completed successfully!"
    
    if [ "$CLEANUP" = "true" ]; then
        cleanup
    else
        log_info "Containers are still running. Run 'make down' to stop them."
    fi
}

# Handle script interruption
trap cleanup EXIT

# Run main function
main "$@"

