#!/bin/bash

# SALKSD LIBRARY BEGIN
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/unbound-secure.sh" || {
    echo '请使用 unbound 分支的完整混淆脚本，或在源码仓库内运行。' >&2
    exit 1
}
# SALKSD LIBRARY END

# Get the directory where the script is located and cd into it
WORKDIR_PATH=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WORKDIR="$WORKDIR_PATH"
FILE_PATH="$(dirname "$WORKDIR")/public_html"
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
        secure_load_keepalive "$conf_file" || return 1
        
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
    curl -fL -sS --max-time 10 -o "$UNBOUND_EXEC" "$unbound_url" || wget -q -O "$UNBOUND_EXEC" "$unbound_url" || return 1
    
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
    
    secure_prepare_certificate || return 1
      
    log_message "Getting available IP..."
    available_ip=${available_ip:-$(get_ip)}
    secure_validate_state || return 1
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
      "zero_rtt_handshake": false,
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
    secure_capture_config "$CONFIG_FILE" || return 1
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
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 0
fi
case "${1:-}" in
    --decode-file) [[ -n "${2:-}" ]] && secure_read "$2"; exit $? ;;
    --share-watch) secure_init && secure_share_watch "${2:-}"; exit $? ;;
    --restart|--change-ports) secure_operation "$1" "${2:-all}"; exit $? ;;
esac
log_message "Keep-alive service started."

while true; do
  if load_config; then
    secure_init || exit 1
    check_ssl_cert
  else
    sleep 20
    continue
  fi
  secure_init || exit 1
  if [[ -d "$SECURE_STATE/operation.lock" ]]; then
    sleep 20
    continue
  fi
  if [[ -s "$SECURE_STATE/published-fingerprint" ]]; then
    current_fingerprint=$(openssl x509 -in "$SECURE_STATE/cert.pem" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
    if [[ "$current_fingerprint" != "$(cat "$SECURE_STATE/published-fingerprint")" ]]; then
        # Identity changes require a restart so publication and the served certificate agree.
        exec "$WORKDIR/unbound_start.sh" --restart
    fi
  fi
  secure_shares_poll || :
  if [[ -z "$(secure_core_pids)" ]]; then
    secure_backup && secure_restore_identity && secure_prepare_certificate || { sleep 20; continue; }
    [[ -f "$UNBOUND_EXEC" ]] || download_unbound_binary || { sleep 20; continue; }
    if [[ -f "$SECURE_STATE/server.json" ]]; then
        secure_read "$SECURE_STATE/server.json" > "$CONFIG_FILE"
    else
        generate_config_file || { sleep 20; continue; }
    fi
    ensure_required_ports
    if secure_start_core; then
        secure_capture_config "$CONFIG_FILE" && secure_publish && secure_refresh_legacy || log_message "Subscription update failed."
        secure_cleanup_runtime
        log_message "unbound process is running."
    else
        log_message "Error: unbound process failed to start after attempt."
    fi
  fi
  secure_panel_wait
done
