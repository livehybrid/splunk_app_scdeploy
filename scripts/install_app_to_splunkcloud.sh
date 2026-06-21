#!/bin/bash
#
# Install the app to Splunk Cloud via ACS
#
# This script:
# 1. Builds the app
# 2. Packages the app
# 3. Gets ACS token from Splunk Cloud
# 4. Uploads the app via ACS CLI
#

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== Installing App to Splunk Cloud ==="

# Check if credentials are set
if [ -z "$SPLUNKCLOUD_STACK_URL" ] || [ -z "$SPLUNKCLOUD_ADMIN_USER" ] || [ -z "$SPLUNKCLOUD_ADMIN_PASSWORD" ]; then
    echo -e "${RED}Error: Splunk Cloud credentials not set${NC}"
    echo "Please source the secrets first:"
    echo "  source scripts/get_secrets_from_1password.sh"
    exit 1
fi

if [ -z "$ACS_STACK" ]; then
    echo -e "${RED}Error: ACS_STACK not set${NC}"
    exit 1
fi

# Check if acs CLI is available
if ! command -v acs &> /dev/null; then
    echo -e "${RED}Error: acs CLI not found${NC}"
    echo "Install it from: https://docs.splunk.com/Documentation/SplunkCloud/latest/Admin/InstallACS"
    exit 1
fi

# Check for required system tools
if ! command -v crudini &> /dev/null; then
    echo -e "${YELLOW}Warning: crudini not found${NC}"
    echo "Install with: brew install crudini (macOS) or apt-get install crudini (Linux)"
fi

if ! command -v slim &> /dev/null; then
    echo -e "${YELLOW}Warning: slim not found${NC}"
    echo "Install with: pip install slim-splunk-add-on or ensure it's in PATH"
fi

# Check if poetry is available and dependencies are installed
if ! command -v poetry &> /dev/null; then
    echo -e "${YELLOW}Warning: Poetry not found. Attempting to use make directly...${NC}"
else
    echo ""
    echo -e "${GREEN}Checking Poetry dependencies...${NC}"
    if [ ! -f "poetry.lock" ]; then
        echo "Installing Poetry dependencies..."
        poetry install --no-root || {
            echo -e "${YELLOW}Warning: Poetry install failed, continuing anyway...${NC}"
        }
    fi
fi

# Step 1: Build the app
echo ""
echo -e "${GREEN}Step 1:${NC} Building app..."
# Clear PYTHONPATH to ensure Poetry's virtual environment takes precedence
# (lib/ directory may contain incomplete packages from previous manual installs)
if [ -n "$PYTHONPATH" ]; then
    echo -e "${YELLOW}Note: Clearing PYTHONPATH ($PYTHONPATH) to use Poetry's virtual environment${NC}"
    unset PYTHONPATH
fi
make build || {
    echo -e "${RED}Failed to build app${NC}"
    echo "Make sure Poetry dependencies are installed: poetry install"
    echo "Note: If you previously set PYTHONPATH to lib/, unset it before building"
    exit 1
}

# Step 2: Package the app
echo ""
echo -e "${GREEN}Step 2:${NC} Packaging app..."
make dist || {
    echo -e "${RED}Failed to package app${NC}"
    echo "Make sure Poetry dependencies are installed: poetry install"
    exit 1
}

# Step 3: Configure ACS authentication
echo ""
echo -e "${GREEN}Step 3:${NC} Configuring ACS authentication..."
echo "  Stack: ${ACS_STACK}"
echo "  Stack URL: ${SPLUNKCLOUD_STACK_URL}"
echo "  Username: ${SPLUNKCLOUD_ADMIN_USER}"
echo "  Password: [REDACTED]"

# Set ACS environment variables for authentication
# ACS CLI uses STACK_USERNAME and STACK_PASSWORD for Splunk Cloud Platform deployment
export STACK_USERNAME="${SPLUNKCLOUD_ADMIN_USER}"
export STACK_PASSWORD="${SPLUNKCLOUD_ADMIN_PASSWORD}"

# If SPLUNK_USERNAME/SPLUNK_PASSWORD are set (for splunk.com account), use them
# Otherwise, ACS will use STACK_USERNAME/STACK_PASSWORD
if [ -n "$SPLUNK_USERNAME" ] && [ -n "$SPLUNK_PASSWORD" ]; then
    echo "  Using splunk.com credentials for authentication"
    export SPLUNK_USERNAME="${SPLUNK_USERNAME}"
    export SPLUNK_PASSWORD="${SPLUNK_PASSWORD}"
else
    echo "  Using stack credentials for authentication"
fi

# Step 4: Upload via ACS
echo ""
echo -e "${GREEN}Step 4:${NC} Uploading app via ACS..."
scripts/acscli_upload.sh || {
    echo -e "${RED}Failed to upload app via ACS${NC}"
    exit 1
}

echo ""
echo -e "${GREEN}=== App Installation Complete ===${NC}"
echo ""
echo "Waiting 30 seconds for app to be fully installed..."
sleep 30

echo ""
echo "Next steps:"
echo "  1. Configure app destinations:"
echo "     python3 scripts/configure_app_destinations.py --host \$SPLUNKCLOUD_STACK_URL --port 8089 --username \$SPLUNKCLOUD_ADMIN_USER --password \"\$SPLUNKCLOUD_ADMIN_PASSWORD\" --scheme https --from-env"
echo ""
echo "  2. Generate test tokens:"
echo "     python3 scripts/generate_test_tokens.py --host \$SPLUNKCLOUD_STACK_URL --port 8089 --username \$SPLUNKCLOUD_ADMIN_USER --password \"\$SPLUNKCLOUD_ADMIN_PASSWORD\" --scheme https"

