#!/bin/bash

# Get the directory where the script is located and cd into it
WORKDIR_PATH=$(cd "$(dirname "$0")" && pwd)
cd "$WORKDIR_PATH" || { echo "FATAL: Cannot cd to $WORKDIR_PATH"; exit 1; }

LOG_FILE="./keepalive.log"
CONFIG_FILE="./config.json"
FRPS_EXEC="./frps"

# --- Logging Function ---
log_message() {
    echo "$(date): $1" >> "$LOG_FILE"
}

# --- Load Configuration ---
# Loads variables from keepalive.conf
load_config() {
    local conf_file="$WORKDIR_PATH/keepalive.conf"
    if [ -f "$conf_file" ]; then
        # Decode the entire file content and evaluate it to export variables
        eval "$(base64 -d < "$conf_file")"
        
        return 0
    else
        log_message "Error: Configuration file not found at $conf_file."
        return 1
    fi
}

# --- Get Available IP ---
# Logic from sb.sh to determine the best IP to use
get_ip() {
  IP_LIST=($(devil vhost list | awk '/^[0-9]+/ {print $1}'))
  API_URL="https://status.eooce.com/api"
  IP=""
  THIRD_IP=${IP_LIST}
  RESPONSE=$(curl -s --max-time 2 "${API_URL}/${THIRD_IP}")
  if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
      IP=$THIRD_IP
  else
      FIRST_IP=${IP_LIST}
      RESPONSE=$(curl -s --max-time 2 "${API_URL}/${FIRST_IP}")
      if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
          IP=$FIRST_IP
      else
          IP=${IP_LIST}
      fi
  fi
  echo "$IP"
}

# --- Download frps Executable ---
# Logic from sb.sh to download the frps binary
download_frps_binary() {
    log_message "frps executable not found. Downloading..."
    ARCH=$(uname -m)
    if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
        BASE_URL="https://github.com/eooce/test/releases/download/freebsd-arm64"
    elif [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "x86" ]; then
        BASE_URL="https://github.com/eooce/test/releases/download/freebsd"
    else
        log_message "Unsupported architecture: $ARCH"
        return 1
    fi
    
    local frps_url="$BASE_URL/sb"
    curl -L -sS --max-time 10 -o "$FRPS_EXEC" "$frps_url" || wget -q -O "$FRPS_EXEC" "$frps_url"
    
    if [ -f "$FRPS_EXEC" ]; then
        chmod +x "$FRPS_EXEC"
        log_message "frps executable downloaded successfully."
        return 0
    else
        log_message "Failed to download frps executable."
        return 1
    fi
}

# --- Generate frps Configuration ---
# Logic from sb.sh to generate config.json
generate_config_file() {
    log_message "config.json not found. Generating..."
    
    # Generate certificates
    
    [[ "$PROXYIP" == "true" ]] && SNI="time.is" || SNI="www.cerebrium.ai"
    
    openssl ecparam -genkey -name prime256v1 -out "private.key" >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=api.$USERNAME.${CURRENT_DOMAIN}" >/dev/null 2>&1
      
    log_message "Getting available IP..."
    available_ip=$(get_ip)
    log_message "Using IP: $available_ip"

    # Create config.json
    cat > "$CONFIG_FILE" << EOF
{
  "log": {
    "disabled": true,
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "address": "8.8.8.8",
        "address_resolver": "local"
      },
      {
        "tag": "local",
        "address": "local"
      }
    ]
  },
  "inbounds": [
    {
       "tag": "hysteria-in",
       "type": "hysteria2",
       "listen": "$available_ip",
       "listen_port": $HY2_PORT,
       "users": [
         {
             "password": "$UUID"
         }
     ],
     "masquerade": "https://bing.com",
     "tls": {
         "enabled": true,
         "alpn": [
             "h3"
         ],
         "certificate_path": "cert.pem",
         "key_path": "private.key"
        }
    },
    {
        "tag": "vless-reality-vesion",
        "type": "vless",
        "listen": "$available_ip",
        "listen_port": $VLESS_PORT,
        "users": [
            {
              "uuid": "$UUID",
              "flow": "xtls-rprx-vision"
            }
        ],
        "tls": {
            "enabled": true,
            "server_name": "$SNI",
            "reality": {
                "enabled": true,
                "handshake": {
                    "server": "$SNI",
                    "server_port": 443
                },
                "private_key": "$private_key",
                "short_id": [
                  ""
                ]
            }
        }
    },
    {
      "tag": "tuic-in",
      "type": "tuic",
      "listen": "$available_ip",
      "listen_port": $TUIC_PORT,
      "users": [
        {
          "uuid": "$UUID",
          "password": "admin"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": [
          "h3"
        ],
        "certificate_path": "cert.pem",
        "key_path": "private.key"
      }
    }
 ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]
}
EOF
    log_message "config.json generated successfully."
}


# --- Main Loop ---
log_message "Keep-alive service started."

while true; do
  if ! pgrep -f "$FRPS_EXEC run" > /dev/null; then

    # 1. Load config. If it fails, we can't proceed.
    if ! load_config; then
        sleep 300
        continue
    fi
    
    log_message "frps process not found. Preparing to restart..."
    # 2. Check for frps executable
    if [ ! -f "$FRPS_EXEC" ]; then
        if ! download_frps_binary; then
            log_message "Will retry download in 5 minutes."
            sleep 300
            continue
        fi
    fi
    
    # 3. Check if the process is running
    # 3a. Generate the config file, as it's needed for restart
    generate_config_file

    # 3b. Start the process
    nohup "$FRPS_EXEC" run -c "$CONFIG_FILE" >/dev/null 2>&1 &
    sleep 2 # Wait a moment for the process to start

    # 3c. Verify and clean up
    if pgrep -f "$FRPS_EXEC run" > /dev/null; then
        log_message "frps process restarted successfully. Cleaning up temporary files."
        rm -rf "$CONFIG_FILE" private.key cert.pem sb.log core fake_useragent_0.2.0.json
        log_message "frps process is running."
    else
        log_message "Error: frps process failed to start after attempt."
    fi
  
  fi
  
  sleep 300
done
