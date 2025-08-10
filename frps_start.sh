#!/bin/bash

# This script is designed to keep the frps process running.

# Determine the script's own directory to use as the working directory.
WORKDIR_PATH=$(cd "$(dirname "$0")" && pwd)

if [ -z "$WORKDIR_PATH" ]; then
  echo "Error: Could not determine working directory." >> "$WORKDIR_PATH/keepalive.log"
  exit 1
fi

# The main executable for frps
FRPS_EXEC="$WORKDIR_PATH/frps"
# The configuration file
CONFIG_FILE="$WORKDIR_PATH/config.json"
# Log file for the keep-alive script
LOG_FILE="$WORKDIR_PATH/keepalive.log"

# Change to the working directory to ensure paths are correct
cd "$WORKDIR_PATH" || { echo "Error: Cannot cd to $WORKDIR_PATH" >> "$LOG_FILE"; exit 1; }

# Log that the keep-alive service has started
echo "$(date): Keep-alive service started." >> "$LOG_FILE"

# Infinite loop to check and restart the process
while true; do
  # Check if the 'frps' process is running by looking for its unique command line signature
  if ! pgrep -f "frps run -c config.json" > /dev/null; then
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
