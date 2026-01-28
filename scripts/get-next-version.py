#!/usr/bin/env python3
"""
Get the next version using dunamai.
This script is used for the main branch to calculate the next version.
"""

import subprocess
import sys
import re


def get_version():
    """Get version using dunamai."""
    try:
        # Determine dunamai command (use poetry run if available)
        import shutil
        if shutil.which("poetry"):
            dunamai_cmd = ["poetry", "run", "dunamai"]
        else:
            dunamai_cmd = ["dunamai"]
        
        # Get base version from git tags matching pattern \d+.\d+.\d+
        result = subprocess.run(
            dunamai_cmd + ["from", "git", "--pattern", r"(?P<base>\d+\.\d+\.\d+)", "--format", "{base}"],
            capture_output=True,
            text=True,
            check=True
        )
        base = result.stdout.strip() or "0.0.0"
        
        # Get distance (commits since tag)
        result = subprocess.run(
            dunamai_cmd + ["from", "git", "--pattern", r"(?P<base>\d+\.\d+\.\d+)", "--format", "{distance}"],
            capture_output=True,
            text=True,
            check=True
        )
        distance = result.stdout.strip() or "0"
        
        # Get commit hash
        result = subprocess.run(
            dunamai_cmd + ["from", "git", "--pattern", r"(?P<base>\d+\.\d+\.\d+)", "--format", "{commit}"],
            capture_output=True,
            text=True,
            check=True
        )
        commit = result.stdout.strip() or ""
        
        # Get dirty status
        result = subprocess.run(
            dunamai_cmd + ["from", "git", "--pattern", r"(?P<base>\d+\.\d+\.\d+)", "--format", "{dirty}"],
            capture_output=True,
            text=True,
            check=True
        )
        dirty = result.stdout.strip() or "clean"
        
        # Calculate next version (increment patch version)
        # Splunk requires Major.Minor.Revision format, so we only return the base version
        parts = base.split(".")
        if len(parts) == 3:
            major, minor, patch = parts
            next_patch = str(int(patch) + 1)
            next_version = f"{major}.{minor}.{next_patch}"
        else:
            # If base version is invalid, default to 1.0.0
            next_version = "1.0.0"
        
        # Return only the base version (Major.Minor.Revision) for Splunk compliance
        # Do not add distance, commit hash, or dirty suffix as Splunk requires strict format
        return next_version
        
    except subprocess.CalledProcessError as e:
        print(f"Error running dunamai: {e}", file=sys.stderr)
        if e.stderr:
            print(e.stderr, file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    version = get_version()
    print(version)
