#!/bin/bash
# This script downloads, executes, and cleans up the main gzipped script.
# It's designed to be run via: curl -Ls URL | bash

set -e
GZEXE_SCRIPT_URL="https://raw.githubusercontent.com/Git-think/Salksd/main/frps.sh"

# --- Main Logic ---
# Function to perform cleanup.
cleanup() {
  if [ -n "$TMP_FILE" ] && [ -f "$TMP_FILE" ]; then
    rm -f "$TMP_FILE"
  fi
}

# Trap EXIT signal to ensure cleanup happens even if the script fails.
trap cleanup EXIT

# Create a secure temporary file.
# The file is created in /tmp and its name is unpredictable.
TMP_FILE=$(mktemp /tmp/frps.XXXXXX)

# Download the gzipped script to the temporary file.
# -L: Follow redirects.
# -s: Silent mode (don't show progress).
# -o: Write output to file.
if ! curl -Lso "$TMP_FILE" "$GZEXE_SCRIPT_URL"; then
  echo "Error: Failed to download the main script from $GZEXE_SCRIPT_URL" >&2
  exit 1
fi

# Make the temporary file executable.
chmod +x "$TMP_FILE"

# Execute the temporary file, passing along any arguments provided to this loader script.
# For example: curl ... | bash -s arg1 arg2
"$TMP_FILE" "$@"

# The 'trap' command will handle the cleanup.
exit 0
