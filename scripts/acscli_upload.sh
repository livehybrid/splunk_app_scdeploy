#!/bin/bash

set -e
set -x

# Validate required environment variables
if [ -z "$ACS_STACK" ]; then
    echo "Error: ACS_STACK environment variable not set" >&2
    exit 1
fi

# Check for authentication credentials
# ACS can authenticate using either:
# 1. STACK_USERNAME/STACK_PASSWORD (for Splunk Cloud Platform deployment)
# 2. SPLUNK_USERNAME/SPLUNK_PASSWORD (for splunk.com account)
# 3. ACS_TOKEN/STACK_TOKEN (JWT token, if already obtained)
if [ -z "$STACK_USERNAME" ] && [ -z "$SPLUNK_USERNAME" ] && [ -z "$ACS_TOKEN" ] && [ -z "$STACK_TOKEN" ]; then
    echo "Error: ACS authentication credentials not set" >&2
    echo "Set one of:" >&2
    echo "  - STACK_USERNAME and STACK_PASSWORD (for Splunk Cloud Platform)" >&2
    echo "  - SPLUNK_USERNAME and SPLUNK_PASSWORD (for splunk.com account)" >&2
    echo "  - ACS_TOKEN or STACK_TOKEN (JWT token)" >&2
    exit 1
fi

# Use STACK_TOKEN if ACS_TOKEN is not set (for backward compatibility)
if [ -z "$ACS_TOKEN" ] && [ -n "$STACK_TOKEN" ]; then
    export ACS_TOKEN=$STACK_TOKEN
fi

# Check if dist directory exists
if [ ! -d "dist" ]; then
    echo "Error: dist directory not found. Run 'make dist' first." >&2
    exit 1
fi

# Check if acs CLI is available
if ! command -v acs &> /dev/null; then
    echo "Error: acs CLI not found. Install it first." >&2
    exit 1
fi

echo "Configuring ACS stack: $ACS_STACK"
acs config add-stack "$ACS_STACK" || {
    echo "Warning: Stack may already be configured"
}

acs config use-stack "$ACS_STACK"

echo "Logging into ACS..."
# ACS login will use STACK_USERNAME/STACK_PASSWORD or SPLUNK_USERNAME/SPLUNK_PASSWORD
# from environment variables, or ACS_TOKEN if set
if [ -n "$ACS_TOKEN" ] || [ -n "$STACK_TOKEN" ]; then
    echo "  Using token-based authentication"
    export STACK_TOKEN="${ACS_TOKEN:-$STACK_TOKEN}"
else
    echo "  Using username/password authentication"
    if [ -n "$STACK_USERNAME" ]; then
        echo "    Stack Username: ${STACK_USERNAME}"
    elif [ -n "$SPLUNK_USERNAME" ]; then
        echo "    Splunk.com Username: ${SPLUNK_USERNAME}"
    fi
fi

acs login --token-user ${STACK_USERNAME} || {
    echo "Error: Failed to login to ACS" >&2
    echo "Check your credentials and ensure ACS CLI is properly configured" >&2
    exit 1
}

echo "Checking ACS status..."
acs status current-stack || {
    echo "Error: Failed to get ACS status" >&2
    exit 1
}

echo "Installing private app from dist/..."
APP_PKG=$(ls -t dist/*.tar.gz dist/*.tgz 2>/dev/null | head -1)
if [ -z "$APP_PKG" ]; then
    echo "Error: no app package (.tar.gz/.tgz) found in dist/" >&2
    exit 1
fi
echo "  Package: $APP_PKG"
if ! acs apps install private --app-package "$APP_PKG" --acs-legal-ack=Y; then
    echo ""
    echo "Error: Failed to install apps via ACS" >&2
    echo ""
    
    # Try to find and display the appinspect report
    ACS_REPORT_DIR="${HOME}/.acs/reports/${ACS_STACK}"
    if [ -d "$ACS_REPORT_DIR" ]; then
        # Find the most recent report file
        LATEST_REPORT=$(ls -t "${ACS_REPORT_DIR}"/apps_install_private_*.json "${ACS_REPORT_DIR}"/apps_bulk_install_private_*.json 2>/dev/null | head -1)
        if [ -n "$LATEST_REPORT" ] && [ -f "$LATEST_REPORT" ]; then
            echo "=== AppInspect Report ==="
            echo "Report location: $LATEST_REPORT"
            echo ""
            
            # Extract and display failures
            if command -v jq &> /dev/null; then
                echo "=== AppInspect Failures ==="
                # Try to extract failures from the report structure
                # The report structure may vary, so try multiple paths
                FAILURES=$(jq -r '
                    if .reports then
                        .reports[] | select(.status == "failure" or .status == "error") | 
                        "\(.name // .check_name // "Unknown"): \(.message // .description // .result_message // "No message")"
                    elif .info then
                        "Summary: errors=\(.info.error // 0), failures=\(.info.failure // 0)"
                    else
                        "Report structure: \(keys | join(", "))"
                    end
                ' "$LATEST_REPORT" 2>/dev/null)
                
                if [ -n "$FAILURES" ]; then
                    echo "$FAILURES"
                else
                    # Try to get summary info
                    SUMMARY=$(jq -r '.info // empty' "$LATEST_REPORT" 2>/dev/null)
                    if [ -n "$SUMMARY" ]; then
                        echo "$SUMMARY" | jq '.'
                    else
                        echo "Could not extract failures. Showing report structure:"
                        jq 'keys' "$LATEST_REPORT" 2>/dev/null || cat "$LATEST_REPORT"
                    fi
                fi
                echo ""
                echo "Full report available at: $LATEST_REPORT"
                echo ""
                echo "To view full report:"
                echo "  cat $LATEST_REPORT | jq '.'"
            else
                echo "Full report available at: $LATEST_REPORT"
                echo "Install 'jq' to view formatted report: brew install jq"
                echo ""
                echo "Report preview (first 50 lines):"
                head -50 "$LATEST_REPORT"
            fi
        else
            echo "AppInspect report not found in $ACS_REPORT_DIR"
        fi
    else
        echo "ACS report directory not found: $ACS_REPORT_DIR"
    fi
    
    exit 1
fi

echo "App installation completed successfully"
