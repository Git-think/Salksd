#!/bin/bash

# This script is designed to keep the frps process running.
# It checks every 5 minutes if the process is active, and if not, restarts it.

# The working directory should be passed as the first argument.
WORKDIR_PATH="$1"
if [ -z "$WORKDIR_PATH" ]; then
  echo "Error: Working directory not provided."
  echo "Usage: $0 <workdir_path>"
  exit 1
fi

# The main executable for sing-box
FRPS_EXEC="$WORKDIR_PATH/frps"
# The configuration file
CONFIG_FILE="$WORKDIR_PATH/config.json"
# Log file for the keep-alive script
LOG_FILE="$WORKDIR_PATH/keepalive.log"

# Change to the working directory to ensure paths are correct
cd "$WORKDIR_PATH" || { echo "Error: Cannot cd to $WORKDIR_PATH"; exit 1; }

# Infinite loop to check and restart the process
while true; do
  # Check if the 'frps' process is running
  if ! pgrep -x "frps" > /dev/null; then
    # If not running, log the event and restart it
    echo "$(date): frps process not found. Restarting..." >> "$LOG_FILE"
    nohup "$FRPS_EXEC" run -c "$CONFIG_FILE" >/dev/null 2>&1 &
  else
    # If running, log that it's all good
    echo "$(date): frps process is running." >> "$LOG_FILE"
  fi
  # Wait for 5 minutes (300 seconds) before the next check
  sleep 300
done
