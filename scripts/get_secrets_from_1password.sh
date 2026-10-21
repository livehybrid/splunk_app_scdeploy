#!/bin/bash
#
# Retrieve secrets from 1Password and export as environment variables
#
# Usage:
#   source scripts/get_secrets_from_1password.sh
#   # or
#   eval $(scripts/get_secrets_from_1password.sh)
#
# Requires:
#   - OP_SERVICE_ACCOUNT_TOKEN environment variable set
#   - Python with onepassword_client.py module available
#

set -e

# Determine if script is being sourced or executed directly
# This allows us to suppress informational messages when executed directly
IS_SOURCED=false
if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
    IS_SOURCED=true
fi

# Determine script directory without using cd/pwd to avoid permission prompts
# Use relative paths when possible to minimize file system access
if [ -n "${BASH_SOURCE[0]}" ]; then
    SCRIPT_RELATIVE_DIR="$(dirname "${BASH_SOURCE[0]}")"
    # Normalize: remove leading ./ and trailing /
    SCRIPT_RELATIVE_DIR="${SCRIPT_RELATIVE_DIR#./}"
    SCRIPT_RELATIVE_DIR="${SCRIPT_RELATIVE_DIR%/}"
    
    # If we're already in scripts directory or script path is relative, use it directly
    if [[ "${SCRIPT_RELATIVE_DIR}" == scripts ]] || [[ "${SCRIPT_RELATIVE_DIR}" == "scripts" ]] || [[ "${PWD}" == *"/scripts" ]]; then
        SCRIPT_DIR="."
    elif [[ "${SCRIPT_RELATIVE_DIR}" == "." ]] || [[ -z "${SCRIPT_RELATIVE_DIR}" ]]; then
        SCRIPT_DIR="."
    else
        # Use relative path from current directory
        SCRIPT_DIR="${SCRIPT_RELATIVE_DIR}"
    fi
else
    SCRIPT_DIR="."
fi

# Determine the correct path to the Python script ONCE to avoid multiple permission prompts
OP_CLIENT_SCRIPT="onepassword_client.py"
OP_CLIENT_PATH=""

# Try to find the script path (only check once to minimize file system access)
for test_path in "${SCRIPT_DIR}/${OP_CLIENT_SCRIPT}" "scripts/${OP_CLIENT_SCRIPT}" "./scripts/${OP_CLIENT_SCRIPT}"; do
    if [ -f "$test_path" ] 2>/dev/null; then
        OP_CLIENT_PATH="$test_path"
        break
    fi
done

# If still not found, default to scripts/onepassword_client.py (will fail gracefully if wrong)
if [ -z "$OP_CLIENT_PATH" ]; then
    OP_CLIENT_PATH="scripts/${OP_CLIENT_SCRIPT}"
fi

VAULT_NAME="${OP_VAULT_NAME:-cicd}"

# Check if token is set
if [ -z "$OP_SERVICE_ACCOUNT_TOKEN" ]; then
    echo "Error: OP_SERVICE_ACCOUNT_TOKEN environment variable not set" >&2
    exit 1
fi

# Resolve the vault NAME to its UUID ONCE. Subsequent `op item get --vault <uuid>` calls
# then skip per-call vault-name resolution, cutting the 1Password requests per run.
# Falls back to the name if resolution fails, so this is safe.
if command -v op >/dev/null 2>&1; then
    _VAULT_UUID=$(op vault get "$VAULT_NAME" --format json 2>/dev/null | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")
    if [ -n "$_VAULT_UUID" ]; then
        VAULT_NAME="$_VAULT_UUID"
    fi
fi

# Function to retrieve secret from 1Password
# Use the cached path to avoid multiple permission prompts
get_op_secret() {
    local item="$1"
    local field="$2"
    python3 "$OP_CLIENT_PATH" "$VAULT_NAME" "$item" --field "$field" 2>/dev/null || echo ""
}

# Function to retrieve login item
# Use the cached path to avoid multiple permission prompts
get_op_login() {
    local item="$1"
    python3 "$OP_CLIENT_PATH" "$VAULT_NAME" "$item" || echo "{}"
}

# Retrieve Splunk Cloud Stack credentials
if [ "$IS_SOURCED" = true ]; then
    echo "Retrieving Splunk Cloud Stack credentials..." >&2
fi
# Single Python call using cached path to minimize permission prompts
SPLUNK_STACK_RESULT=$(python3 "$OP_CLIENT_PATH" "$VAULT_NAME" "splunk-cloud-stack" || echo "{}")

if [ -n "$SPLUNK_STACK_RESULT" ] && [ "$SPLUNK_STACK_RESULT" != "{}" ]; then
    # Single Python call to parse all fields at once
    eval $(echo "$SPLUNK_STACK_RESULT" | python3 -c "
import sys, json, os
try:
    data = json.load(sys.stdin)
    url = data.get('url', '')
    username = data.get('username', '')
    password = data.get('password', '')
    print(f'export SPLUNKCLOUD_STACK_URL=\"{url}\"')
    print(f'export SPLUNKCLOUD_ADMIN_USER=\"{username}\"')
    print(f'export SPLUNKCLOUD_ADMIN_PASSWORD=\"{password}\"')
    if url:
        # Extract stack name from URL (e.g., scde-vl7nc5aea8gxtdoyq.splunkcloud.com -> scde-vl7nc5aea8gxtdoyq)
        stack = url.replace('.splunkcloud.com', '')
        print(f'export ACS_STACK=\"{stack}\"')
except:
    pass
")
else
    if [ "$IS_SOURCED" = true ]; then
        echo "Warning: Could not retrieve Splunk Cloud Stack credentials" >&2
    fi
fi

# Retrieve Splunkbase credentials
if [ "$IS_SOURCED" = true ]; then
    echo "Retrieving Splunkbase credentials..." >&2
fi
# Single fetch (was 2 separate per-field op calls)
SPLUNKBASE_RESULT=$(get_op_login "splunkbase-credentials")
if [ -n "$SPLUNKBASE_RESULT" ] && [ "$SPLUNKBASE_RESULT" != "{}" ]; then
    eval $(echo "$SPLUNKBASE_RESULT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f'export SPLUNKBASE_USERNAME=\"{data.get(\"username\", \"\")}\"')
    print(f'export SPLUNKBASE_PASSWORD=\"{data.get(\"password\", \"\")}\"')
except Exception:
    pass
")
fi

if [ -n "$SPLUNKBASE_USERNAME" ] && [ -n "$SPLUNKBASE_PASSWORD" ]; then
    # Also set SPLUNK_USERNAME/SPLUNK_PASSWORD for ACS authentication (splunk.com account)
    export SPLUNK_USERNAME="$SPLUNKBASE_USERNAME"
    export SPLUNK_PASSWORD="$SPLUNKBASE_PASSWORD"

    # Create base64 auth for Splunkbase API
    export SPLUNKBASE_AUTH=$(echo -n "${SPLUNKBASE_USERNAME}:${SPLUNKBASE_PASSWORD}" | base64)
else
    if [ "$IS_SOURCED" = true ]; then
        echo "Warning: Could not retrieve Splunkbase credentials" >&2
    fi
fi

# Retrieve GitHub test repo credentials (optional, single fetch — was CHECK + DATA)
GITHUB_DATA=$(get_op_login "github-test-repo")
if [ -n "$GITHUB_DATA" ] && [ "$GITHUB_DATA" != "{}" ]; then
    if [ "$IS_SOURCED" = true ]; then
        echo "Retrieving GitHub test repo credentials..." >&2
    fi
    eval $(echo "$GITHUB_DATA" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if data.get('password'):
        print(f'export GITHUB_TOKEN=\"{data.get(\"password\", \"\")}\"')
        print(f'export GITHUB_REPO=\"{data.get(\"url\", \"\")}\"')
except:
    pass
")
fi

# Retrieve GitLab test project credentials (optional, single fetch — was CHECK + DATA)
GITLAB_DATA=$(get_op_login "gitlab-test-project")
if [ -n "$GITLAB_DATA" ] && [ "$GITLAB_DATA" != "{}" ]; then
    if [ "$IS_SOURCED" = true ]; then
        echo "Retrieving GitLab test project credentials..." >&2
    fi
    eval $(echo "$GITLAB_DATA" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if data.get('password'):
        print(f'export GITLAB_TOKEN=\"{data.get(\"password\", \"\")}\"')
        print(f'export GITLAB_PROJECT_URL=\"{data.get(\"url\", \"\")}\"')
except:
    pass
")
fi

# Retrieve 1Password Connect server (optional; for the in-Splunk 1Password destination — single fetch)
OPCONNECT_DATA=$(get_op_login "1password-connect")
if [ -n "$OPCONNECT_DATA" ] && [ "$OPCONNECT_DATA" != "{}" ]; then
    eval $(echo "$OPCONNECT_DATA" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if data.get('url'):
        print(f'export OP_CONNECT_HOST=\"{data.get(\"url\", \"\")}\"')
        if data.get('password'):
            print(f'export OP_CONNECT_TOKEN=\"{data.get(\"password\", \"\")}\"')
except:
    pass
")
    if [ -n "$OP_CONNECT_HOST" ] && [ "$IS_SOURCED" = true ]; then
        echo "Retrieving 1Password Connect URL..." >&2
    fi
fi

# Retrieve AWS Secrets Manager credentials (optional, single fetch — was CHECK + DATA)
AWS_DATA=$(get_op_login "aws-secrets-manager")
if [ -n "$AWS_DATA" ] && [ "$AWS_DATA" != "{}" ]; then
    eval $(echo "$AWS_DATA" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if data.get('username'):
        print(f'export AWS_ACCESS_KEY_ID=\"{data.get(\"username\", \"\")}\"')
        print(f'export AWS_SECRET_ACCESS_KEY=\"{data.get(\"password\", \"\")}\"')
        print(f'export AWS_DEFAULT_REGION=\"{data.get(\"url\", \"\")}\"')
        # secretpath from custom fields (get_login_item returns no 'fields', so this defaults)
        secret_name = 'splunk/test-token'
        for field in data.get('fields', []):
            field_id = (field.get('id') or '').lower()
            field_label = (field.get('label') or '').lower()
            if 'secretpath' in field_id or 'secretpath' in field_label or 'secret_name' in field_id or 'secret_name' in field_label:
                secret_name = field.get('value', 'splunk/test-token')
                break
        print(f'export AWS_SECRET_NAME=\"{secret_name}\"')
except:
    print('export AWS_SECRET_NAME=\"splunk/test-token\"')
")
    if [ -n "$AWS_ACCESS_KEY_ID" ] && [ "$IS_SOURCED" = true ]; then
        echo "Retrieving AWS Secrets Manager credentials..." >&2
    fi
fi

# Validate required variables
if [ -z "$SPLUNKCLOUD_STACK_URL" ] || [ -z "$SPLUNKCLOUD_ADMIN_USER" ] || [ -z "$SPLUNKCLOUD_ADMIN_PASSWORD" ]; then
    echo "Error: Required Splunk Cloud credentials not found in 1Password" >&2
    exit 1
fi

if [ -z "$SPLUNKBASE_USERNAME" ] || [ -z "$SPLUNKBASE_PASSWORD" ]; then
    echo "Error: Required Splunkbase credentials not found in 1Password" >&2
    exit 1
fi

if [ "$IS_SOURCED" = true ]; then
    echo "Successfully retrieved secrets from 1Password vault: $VAULT_NAME" >&2
fi

# If script is sourced, export variables to parent shell
# If executed directly, output export commands
if [ "$IS_SOURCED" = true ]; then
    # Script is being sourced
    echo "Secrets loaded into environment" >&2
else
    # Script is being executed - output export commands
    echo "export SPLUNKCLOUD_STACK_URL='${SPLUNKCLOUD_STACK_URL}'"
    echo "export SPLUNKCLOUD_ADMIN_USER='${SPLUNKCLOUD_ADMIN_USER}'"
    echo "export SPLUNKCLOUD_ADMIN_PASSWORD='${SPLUNKCLOUD_ADMIN_PASSWORD}'"
    [ -n "$ACS_STACK" ] && echo "export ACS_STACK='${ACS_STACK}'"
    echo "export SPLUNKBASE_USERNAME='${SPLUNKBASE_USERNAME}'"
    echo "export SPLUNKBASE_PASSWORD='${SPLUNKBASE_PASSWORD}'"
    [ -n "$SPLUNKBASE_AUTH" ] && echo "export SPLUNKBASE_AUTH='${SPLUNKBASE_AUTH}'"
    [ -n "$SPLUNK_USERNAME" ] && echo "export SPLUNK_USERNAME='${SPLUNK_USERNAME}'"
    [ -n "$SPLUNK_PASSWORD" ] && echo "export SPLUNK_PASSWORD='${SPLUNK_PASSWORD}'"
    [ -n "$GITHUB_TOKEN" ] && echo "export GITHUB_TOKEN='${GITHUB_TOKEN}'"
    [ -n "$GITHUB_REPO" ] && echo "export GITHUB_REPO='${GITHUB_REPO}'"
    [ -n "$GITLAB_TOKEN" ] && echo "export GITLAB_TOKEN='${GITLAB_TOKEN}'"
    [ -n "$GITLAB_PROJECT_URL" ] && echo "export GITLAB_PROJECT_URL='${GITLAB_PROJECT_URL}'"
    [ -n "$AWS_ACCESS_KEY_ID" ] && echo "export AWS_ACCESS_KEY_ID='${AWS_ACCESS_KEY_ID}'"
    [ -n "$AWS_SECRET_ACCESS_KEY" ] && echo "export AWS_SECRET_ACCESS_KEY='${AWS_SECRET_ACCESS_KEY}'"
    [ -n "$AWS_DEFAULT_REGION" ] && echo "export AWS_DEFAULT_REGION='${AWS_DEFAULT_REGION}'"
    [ -n "$AWS_SECRET_NAME" ] && echo "export AWS_SECRET_NAME='${AWS_SECRET_NAME}'"
fi

