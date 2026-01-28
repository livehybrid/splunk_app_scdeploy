#!/bin/bash
#
# Get version using dunamai
# For Splunk compliance, returns only Major.Minor.Revision format
# (Splunk requires versions to be in Major.Minor.Revision format)
#

set -e

# Use poetry run dunamai if available, otherwise try dunamai directly
DUNAMAI_CMD="dunamai"
if command -v poetry &> /dev/null; then
    DUNAMAI_CMD="poetry run dunamai"
fi

# Get base version from git tags matching pattern \d+.\d+.\d+
# Splunk requires Major.Minor.Revision format, so we only use the base version
BASE=$(${DUNAMAI_CMD} from git --pattern "(?P<base>\d+\.\d+\.\d+)" --format "{base}" 2>/dev/null || echo "0.0.0")

# If no base version found, try to get the latest tag or default to 0.0.0
if [ "${BASE}" == "0.0.0" ] || [ -z "${BASE}" ]; then
    # Try to get any version-like tag
    LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
    if [ -n "${LATEST_TAG}" ]; then
        # Extract version numbers from tag (remove 'v' prefix if present)
        BASE=$(echo "${LATEST_TAG}" | sed 's/^v//' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || echo "0.0.0")
    fi
fi

# Ensure we have a valid Major.Minor.Revision format
if ! echo "${BASE}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    BASE="0.0.0"
fi

# Return only the base version (Major.Minor.Revision) for Splunk compliance
echo "${BASE}"

