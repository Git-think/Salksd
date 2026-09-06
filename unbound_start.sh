#!/bin/bash

# Get the directory where the script is located and cd into it
WORKDIR_PATH=$(cd "$(dirname "$0")" && pwd)
cd "$WORKDIR_PATH" || { echo "FATAL: Cannot cd to $WORKDIR_PATH"; exit 1; }

LOG_FILE="./keepalive.log"
CONFIG_FILE="./unbound.conf"
UNBOUND_EXEC="./unbound"

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
  THIRD_IP=${IP_LIST[2]}
  RESPONSE=$(curl -s --max-time 2 "${API_URL}/${THIRD_IP}")
  if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
      IP=$THIRD_IP
  else
      FIRST_IP=${IP_LIST[0]}
      RESPONSE=$(curl -s --max-time 2 "${API_URL}/${FIRST_IP}")
      if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
          IP=$FIRST_IP
      else
          IP=${IP_LIST[1]}
      fi
  fi
  echo "$IP"
}

# --- Download unbound Executable ---
# Logic from sb.sh to download the unbound binary
download_unbound_binary() {
    log_message "unbound executable not found. Downloading..."
    ARCH=$(uname -m)
    if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
        BASE_URL="https://github.com/eooce/test/releases/download/freebsd-arm64"
    elif [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "x86" ]; then
        BASE_URL="https://github.com/eooce/test/releases/download/freebsd"
    else
        log_message "Unsupported architecture: $ARCH"
        return 1
    fi
    
    local unbound_url="$BASE_URL/sb"
    curl -L -sS --max-time 10 -o "$UNBOUND_EXEC" "$unbound_url" || wget -q -O "$UNBOUND_EXEC" "$unbound_url"
    
    if [ -f "$UNBOUND_EXEC" ]; then
        chmod +x "$UNBOUND_EXEC"
        log_message "unbound executable downloaded successfully."
        return 0
    else
        log_message "Failed to download unbound executable."
        return 1
    fi
}

# --- Generate unbound Configuration ---
# Logic from sb.sh to generate unbound.conf
generate_config_file() {
    log_message "unbound.conf not found. Generating..."
    
    # Generate certificates
    
    [[ "$PROXYIP" == "true" ]] && SNI="time.is" || SNI="www.cerebrium.ai"
    
    openssl ecparam -genkey -name prime256v1 -out "private.key" >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=api.$USERNAME.${CURRENT_DOMAIN}" >/dev/null 2>&1
      
    log_message "Getting available IP..."
    available_ip=$(get_ip)
    log_message "Using IP: $available_ip"

    # Create unbound.conf
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
    log_message "unbound.conf generated successfully."
}

check_ssl_cert() {
    log_message "Checking SSL certificate..."
    local CERT_INFO=$(devil ssl www list | grep "api.${USERNAME}.${CURRENT_DOMAIN}")
    if [ -n "$CERT_INFO" ]; then
        local EXPIRE_DATE=$(echo "$CERT_INFO" | awk '{print $4}')
        local IP_ADDRESS=$(echo "$CERT_INFO" | awk '{print $6}')
        local DOMAIN=$(echo "$CERT_INFO" | awk '{print $8}')

        local EXPIRE_TIMESTAMP=$(date -j -f "%Y.%m.%d" "$EXPIRE_DATE" "+%s")
        local CURRENT_TIMESTAMP=$(date "+%s")
        local DAYS_TO_EXPIRE=$(( (EXPIRE_TIMESTAMP - CURRENT_TIMESTAMP) / 86400 ))

        if [ "$DAYS_TO_EXPIRE" -lt 30 ]; then
            log_message "Certificate for $DOMAIN is expiring in $DAYS_TO_EXPIRE days. Renewing..."
            devil ssl www del "$IP_ADDRESS" "$DOMAIN" >/dev/null 2>&1
            if devil ssl www add "$IP_ADDRESS" le le "$DOMAIN"; then
                log_message "Certificate for $DOMAIN renewed successfully."
            else
                log_message "Failed to renew certificate for $DOMAIN."
            fi
        else
            log_message "Certificate for $DOMAIN is valid for $DAYS_TO_EXPIRE more days."
        fi
    else
        log_message "No SSL certificate found for api.${USERNAME}.${CURRENT_DOMAIN}."
    fi
}

# --- Ensure Required Ports ---
# Check currently opened ports, remove unnecessary ones,
# and add missing required ports (max 3 ports allowed)
ensure_required_ports() {
    log_message "Checking required ports..."

    # Required ports definition: type:port
    local required_ports=(
        "udp:$HY2_PORT"
        "tcp:$VLESS_PORT"
        "udp:$TUIC_PORT"
    )

    # Build required port set
    declare -A REQUIRED_SET
    local item type port
    for item in "${required_ports[@]}"; do
        type="${item%%:*}"
        port="${item##*:}"
        [ -n "$type" ] && [ -n "$port" ] && REQUIRED_SET["$type:$port"]=1
    done

    # Get currently opened ports
    local CURRENT_PORTS
    CURRENT_PORTS=$(devil port list | awk 'NR>1 && $1 ~ /^[0-9]+$/ && $2 ~ /^(tcp|udp)$/ {print $2 ":" $1}')

    # --- Remove Unnecessary Ports ---
    for item in $CURRENT_PORTS; do
        if [ -z "${REQUIRED_SET[$item]}" ]; then
            type="${item%%:*}"
            port="${item##*:}"
            log_message "Port ${port}/${type} is not required. Deleting..."
            if devil port del "$type" "$port" >/dev/null 2>&1; then
                log_message "Port ${port}/${type} deleted successfully."
            else
                log_message "Failed to delete port ${port}/${type}."
            fi
        fi
    done

    # Refresh current ports after deletion
    CURRENT_PORTS=$(devil port list | awk 'NR>1 && $1 ~ /^[0-9]+$/ && $2 ~ /^(tcp|udp)$/ {print $2 ":" $1}')

    # --- Add Missing Required Ports ---
    for item in "${!REQUIRED_SET[@]}"; do
        if ! echo "$CURRENT_PORTS" | grep -Fxq "$item"; then
            type="${item%%:*}"
            port="${item##*:}"
            log_message "Port ${port}/${type} is missing. Adding..."
            if devil port add "$type" "$port" >/dev/null 2>&1; then
                log_message "Port ${port}/${type} added successfully."
            else
                log_message "Failed to add port ${port}/${type}."
            fi
        else
            log_message "Port ${item##*:}/${item%%:*} already exists."
        fi
    done

    log_message "Port check completed."
}

# --- Main Loop ---
log_message "Keep-alive service started."

while true; do
  check_ssl_cert
  if ! pgrep -f "$UNBOUND_EXEC run" > /dev/null; then

    # 1. Load config. If it fails, we can't proceed.
    if ! load_config; then
        sleep 20
        continue
    fi
    
    log_message "unbound process not found. Preparing to restart..."
    # 2. Check for unbound executable
    if [ ! -f "$UNBOUND_EXEC" ]; then
        if ! download_unbound_binary; then
            log_message "Will retry download in 20s"
            sleep 20
            continue
        fi
    fi
    
    # 3. Check if the process is running
    # 3a. Generate the config file, as it's needed for restart
    generate_config_file

    # 3a.1 Ensure required ports are correctly configured
    ensure_required_ports

    # 3b. Start the process
    nohup "$UNBOUND_EXEC" run -c "$CONFIG_FILE" >/dev/null 2>&1 &
    sleep 2 # Wait a moment for the process to start

    # 3c. Verify and clean up
    if pgrep -f "$UNBOUND_EXEC run" > /dev/null; then
        log_message "unbound process restarted successfully. Cleaning up temporary files."
        rm -rf unbound "$CONFIG_FILE" private.key cert.pem sb.log core fake_useragent_0.2.0.json
        log_message "unbound process is running."
    else
        log_message "Error: unbound process failed to start after attempt."
    fi
  
  fi
  
  sleep 300
done
