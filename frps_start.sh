#!/bin/bash

# This script is designed to keep the frps process running.
# It will automatically fork itself into the background.

# Determine the script's own directory to use as the working directory.
WORKDIR_PATH=$(cd "$(dirname "$0")" && pwd)

if [ -z "$WORKDIR_PATH" ]; then
  echo "Error: Could not determine working directory."
  exit 1
fi

# The main executable for sing-box
FRPS_EXEC="$WORKDIR_PATH/frps"
# The configuration file
CONFIG_FILE="$WORKDIR_PATH/config.json"
# Log file for the keep-alive script
LOG_FILE="$WORKDIR_PATH/keepalive.log"
# PID file to manage the background process
PID_FILE="$WORKDIR_PATH/keepalive.pid"

# --- Backgrounding Logic ---
# If the script is not already running in the background (checked by a specific argument)
if [ "$1" != "--background" ]; then
  # Check if a PID file exists, meaning it might already be running
  if [ -f "$PID_FILE" ]; then
    # If the process in the PID file is still running, exit.
    if ps -p $(cat "$PID_FILE") > /dev/null; then
      echo "Keep-alive script is already running."
      exit 0
    fi
  fi
  
  # Start a new instance of this script in the background with a special argument
  # setsid is used to detach it completely from the current terminal
  setsid nohup "$0" --background >/dev/null 2>&1 &
  echo "Keep-alive script started in the background."
  exit 0
fi

# --- Main Logic (runs only in the background instance) ---

# Store the PID of the background process
echo $$ > "$PID_FILE"

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
