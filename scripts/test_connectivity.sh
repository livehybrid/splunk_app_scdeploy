#!/bin/bash
#
# Test connectivity to Splunk Cloud and verify credentials
#

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== Testing Splunk Cloud Connectivity ==="

# Check if credentials are set
if [ -z "$SPLUNKCLOUD_STACK_URL" ] || [ -z "$SPLUNKCLOUD_ADMIN_USER" ] || [ -z "$SPLUNKCLOUD_ADMIN_PASSWORD" ]; then
    echo -e "${RED}Error: Splunk Cloud credentials not set${NC}"
    echo "Please source the secrets first:"
    echo "  source scripts/get_secrets_from_1password.sh"
    echo "  # or"
    echo "  eval \$(scripts/get_secrets_from_1password.sh)"
    exit 1
fi

echo -e "${GREEN}✓${NC} Credentials loaded"
echo "  Stack URL: ${SPLUNKCLOUD_STACK_URL:0:20}..." # Show only first 20 chars
echo "  Admin User: ${SPLUNKCLOUD_ADMIN_USER}"
echo "  Stack Name: ${ACS_STACK:-not set}"

# Test Splunk connection
echo ""
echo "Testing Splunk Cloud connection..."
if curl -k -s -u "$SPLUNKCLOUD_ADMIN_USER:$SPLUNKCLOUD_ADMIN_PASSWORD" \
   "https://${SPLUNKCLOUD_STACK_URL}:8089/services/server/info" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Successfully connected to Splunk Cloud"
else
    echo -e "${RED}✗${NC} Failed to connect to Splunk Cloud"
    echo "  Check your credentials and network connectivity"
    exit 1
fi

# Test Python dependencies
echo ""
echo "Checking Python dependencies..."
if python3 -c "import splunklib.client" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} splunklib installed"
else
    echo -e "${YELLOW}⚠${NC} splunklib not found - install with: pip install splunk-sdk"
fi

if python3 -c "import solnlib" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} solnlib installed"
else
    echo -e "${YELLOW}⚠${NC} solnlib not found - install with: pip install solnlib"
fi

echo ""
echo -e "${GREEN}=== Connectivity Test Complete ===${NC}"
echo ""
echo "Next steps (in order):"
echo ""
echo "  1. Install the app to Splunk Cloud (REQUIRED before configuring destinations):"
echo "     scripts/install_app_to_splunkcloud.sh"
echo ""
echo "  2. Create test accounts:"
echo "     python3 scripts/create_test_accounts.py --host \$SPLUNKCLOUD_STACK_URL --port 8089 --username \$SPLUNKCLOUD_ADMIN_USER --password \"\$SPLUNKCLOUD_ADMIN_PASSWORD\" --scheme https"
echo ""
echo "  3. Configure app destinations (requires app to be installed first):"
echo "     python3 scripts/configure_app_destinations.py --host \$SPLUNKCLOUD_STACK_URL --port 8089 --username \$SPLUNKCLOUD_ADMIN_USER --password \"\$SPLUNKCLOUD_ADMIN_PASSWORD\" --scheme https --from-env"
echo ""
echo "  4. Generate test tokens:"
echo "     python3 scripts/generate_test_tokens.py --host \$SPLUNKCLOUD_STACK_URL --port 8089 --username \$SPLUNKCLOUD_ADMIN_USER --password \"\$SPLUNKCLOUD_ADMIN_PASSWORD\" --scheme https"
echo ""
echo "  5. Validate tokens (if destinations are configured):"
echo "     python3 scripts/validate_tokens.py --from-env"

