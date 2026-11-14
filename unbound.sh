#!/bin/bash

re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }
export LC_ALL=C
HOSTNAME=$(hostname)
USERNAME=$(whoami | tr '[:upper:]' '[:lower:]')
export UUID=${UUID:-$(uuidgen)}
export NEZHA_SERVER=${NEZHA_SERVER:-''}
export NEZHA_PORT=${NEZHA_PORT:-''}
export NEZHA_KEY=${NEZHA_KEY:-''}
export SUB_TOKEN=${SUB_TOKEN:-${UUID:0:8}}
export UPLOAD_URL=${UPLOAD_URL:-''}  # 订阅自动添加到汇聚订阅器，需要先部署Merge-sub项目,环境变量填写部署后的首页地址,例如: UPLOAD_URL=https://merge.serv00.net

if [[ "$HOSTNAME" =~ ct8 ]]; then
    CURRENT_DOMAIN="ct8.pl"
elif [[ "$HOSTNAME" =~ useruno ]]; then
    CURRENT_DOMAIN="useruno.com"
else
    CURRENT_DOMAIN="serv00.net"
fi
WORKDIR="${HOME}/domains/api.${USERNAME}.${CURRENT_DOMAIN}/logs"
FILE_PATH="${HOME}/domains/api.${USERNAME}.${CURRENT_DOMAIN}/public_html"

# 只持久化证书、认证和节点身份；服务器配置/二进制仍按原脚本流程处理。
DATA_DIR="${HOME}/.config/salksd-unbound"
CERT_FILE="${DATA_DIR}/cert.pem"
KEY_FILE="${DATA_DIR}/private.key"
META_FILE="${DATA_DIR}/meta.conf"
CERT_HOST="api.${USERNAME}.${CURRENT_DOMAIN}"
SUB_SCHEMA=2
# 下载的可执行文件只在本次运行期间存在。
trap 'rm -f "${WORKDIR}/unbound"' EXIT

load_meta() {
    [ -s "$META_FILE" ] || return 1
    eval "$(base64 -d < "$META_FILE")" || return 1
    [ -z "${UUID:-}" ] || export UUID
    [ -z "${SUB_TOKEN:-}" ] || export SUB_TOKEN
    private_key="${REALITY_PRIVATE_KEY:-${private_key:-}}"
    public_key="${REALITY_PUBLIC_KEY:-${public_key:-}}"
}

save_meta() {
    mkdir -p "$DATA_DIR" && chmod 700 "$DATA_DIR" || return 1
    local tmp="${META_FILE}.tmp.$$"
    {
        printf 'export UUID=%q\n' "$UUID"
        printf 'export SUB_TOKEN=%q\n' "$SUB_TOKEN"
        printf 'export REALITY_PRIVATE_KEY=%q\n' "${REALITY_PRIVATE_KEY:-$private_key}"
        printf 'export REALITY_PUBLIC_KEY=%q\n' "${REALITY_PUBLIC_KEY:-$public_key}"
        printf 'export AVAILABLE_IP=%q\n' "${AVAILABLE_IP:-$available_ip}"
        printf 'export NODE_NAME=%q\n' "${NODE_NAME:-}"
        printf 'export SUB_SCHEMA=%q\n' "$SUB_SCHEMA"
    } | base64 | tr -d '\r\n' > "$tmp"
    chmod 600 "$tmp" && mv -f "$tmp" "$META_FILE"
}

# 旧安装重启时把原 keepalive.conf 的认证/端口带入新流程。
migrate_old_keepalive() {
    [ -s "${WORKDIR}/keepalive.conf" ] || return 1
    local line value
    while IFS= read -r line; do
        if [[ "$line" =~ ^export\ ([A-Za-z_]+)=\"([^\"]*)\"$ ]]; then
            value="${BASH_REMATCH[2]}"
            case "${BASH_REMATCH[1]}" in
                UUID) UUID="$value" ;;
                VLESS_PORT) VLESS_PORT="$value" ;;
                TUIC_PORT) TUIC_PORT="$value" ;;
                HY2_PORT) HY2_PORT="$value" ;;
                private_key) private_key="$value" ;;
                PROXYIP) PROXYIP="$value" ;;
            esac
        fi
    done < <(base64 -d < "${WORKDIR}/keepalive.conf" 2>/dev/null)
    [ -n "$UUID" ] && export UUID
    if [ -s "${FILE_PATH}/.htaccess" ]; then
        SUB_TOKEN=$(sed -n 's/^RewriteRule \^\([A-Za-z0-9_-]\{1,\}\)\$ .*/\1/p' "${FILE_PATH}/.htaccess" | head -n1)
    fi
    [ -n "$SUB_TOKEN" ] || SUB_TOKEN="${UUID:0:8}"
    export SUB_TOKEN
    REALITY_PRIVATE_KEY="$private_key"
    if [ -s "${FILE_PATH}/list.txt" ]; then
        REALITY_PUBLIC_KEY=$(sed -n '/^vless:/s/.*[?&]pbk=\([^&#]*\).*/\1/p' "${FILE_PATH}/list.txt" | head -n1)
    fi
    return 0
}

cert_pair_ok() {
    local a b
    [ -s "$1" ] && [ -s "$2" ] || return 1
    openssl x509 -in "$1" -noout >/dev/null 2>&1 || return 1
    openssl pkey -in "$2" -noout >/dev/null 2>&1 || return 1
    a=$(openssl x509 -in "$1" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256) || return 1
    b=$(openssl pkey -in "$2" -pubout -outform DER 2>/dev/null | openssl dgst -sha256) || return 1
    [ -n "$a" ] && [ "$a" = "$b" ]
}

cert_ok() {
    local san name subj found=0
    cert_pair_ok "$CERT_FILE" "$KEY_FILE" || return 1
    san=$(openssl x509 -in "$CERT_FILE" -noout -text 2>/dev/null | sed -n '/Subject Alternative Name/{n;p;}') || return 1
    while IFS= read -r name; do
        name="${name//[[:space:]]/}"
        if [[ "${name,,}" == "dns:${CERT_HOST,,}" ]]; then found=1; break; fi
    done < <(printf '%s\n' "$san" | tr ',' '\n')
    [ "$found" -eq 1 ] || return 1
    subj=$(openssl x509 -in "$CERT_FILE" -noout -subject 2>/dev/null)
    printf '%s\n' "$subj" | grep -Fq "CN=$CERT_HOST" || printf '%s\n' "$subj" | grep -Fq "CN = $CERT_HOST" || return 1
    openssl verify -CAfile "$CERT_FILE" -purpose sslserver "$CERT_FILE" >/dev/null 2>&1
}

archive_old_cert() {
    local ts; ts=$(date +%Y%m%d%H%M%S)
    mkdir -p "${DATA_DIR}/legacy" && chmod 700 "${DATA_DIR}/legacy"
    for f in "$CERT_FILE" "$KEY_FILE"; do
        if [ -s "$f" ]; then
            cp -p "$f" "${DATA_DIR}/legacy/$(basename "$f").${ts}" && chmod 600 "${DATA_DIR}/legacy/$(basename "$f").${ts}"
        fi
    done
}

ensure_certificate() {
    ensure_dirs || return 1
    if cert_ok; then
        private_key="${REALITY_PRIVATE_KEY:-$private_key}"
        return 0
    fi
    if [ ! -s "$CERT_FILE" ] && [ -s "${WORKDIR}/cert.pem" ] && [ -s "${WORKDIR}/private.key" ]; then
        cp -f "${WORKDIR}/cert.pem" "$CERT_FILE" && cp -f "${WORKDIR}/private.key" "$KEY_FILE"
        chmod 600 "$CERT_FILE" "$KEY_FILE"
        cert_ok && return 0
    fi
    archive_old_cert
    # 迁移时沿用原私钥；新装按原脚本的 P-256 机制生成。
    if [ ! -s "$KEY_FILE" ]; then
        openssl ecparam -genkey -name prime256v1 -out "$KEY_FILE" >/dev/null 2>&1 || return 1
    fi
    {
        echo "[req]"; echo "prompt = no"; echo "distinguished_name = dn"; echo "x509_extensions = v3"
        echo "[dn]"; echo "CN = $CERT_HOST"
        echo "[v3]"; echo "basicConstraints = critical,CA:FALSE"
        echo "keyUsage = critical,digitalSignature"
        echo "extendedKeyUsage = serverAuth"
        echo "subjectKeyIdentifier = hash"
        echo "authorityKeyIdentifier = keyid:always"
        echo "subjectAltName = DNS:$CERT_HOST"
    } > "${DATA_DIR}/openssl.cnf"
    openssl req -new -x509 -sha256 -days 3650 -key "$KEY_FILE" -out "${CERT_FILE}.new"         -config "${DATA_DIR}/openssl.cnf" >/dev/null 2>&1 || return 1
    mv -f "${CERT_FILE}.new" "$CERT_FILE" && chmod 600 "$CERT_FILE" "$KEY_FILE"
    cert_ok
}

ensure_dirs() {
    mkdir -p "$DATA_DIR" && chmod 700 "$DATA_DIR"
}

cert_sha256() {
    openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':\r\n' | tr 'A-F' 'a-f'
}

ensure_reality_keys() {
    if [ -z "${REALITY_PRIVATE_KEY:-}" ] || [ -z "${REALITY_PUBLIC_KEY:-}" ]; then
        local out
        out=$(./"$(basename "${FILE_MAP[web]:-unbound}")" generate reality-keypair 2>/dev/null) || return 1
        REALITY_PRIVATE_KEY=$(printf '%s\n' "$out" | awk '/PrivateKey:/ {print $2}')
        REALITY_PUBLIC_KEY=$(printf '%s\n' "$out" | awk '/PublicKey:/ {print $2}')
        [ -n "$REALITY_PRIVATE_KEY" ] && [ -n "$REALITY_PUBLIC_KEY" ] || return 1
    fi
    private_key="$REALITY_PRIVATE_KEY"
    public_key="$REALITY_PUBLIC_KEY"
    return 0
}
ensure_dirs
load_meta || migrate_old_keepalive || true
[ -n "${UUID:-}" ] || UUID=$(uuidgen)
[ -n "${SUB_TOKEN:-}" ] || SUB_TOKEN="${UUID:0:8}"
export UUID SUB_TOKEN
private_key="${REALITY_PRIVATE_KEY:-${private_key:-}}"
public_key="${REALITY_PUBLIC_KEY:-${public_key:-}}"
mkdir -p "$FILE_PATH" && chmod 777 "$WORKDIR" "$FILE_PATH" >/dev/null 2>&1
command -v curl &>/dev/null && COMMAND="curl -so" || command -v wget &>/dev/null && COMMAND="wget -qO" || { red "Error: neither curl nor wget found, please install one of them." >&2; exit 1; }

check_port () {
local skip_kill="${1:-}"
port_list=$(devil port list)
tcp_ports=$(echo "$port_list" | grep -c "tcp")
udp_ports=$(echo "$port_list" | grep -c "udp")

if [[ $tcp_ports -ne 1 || $udp_ports -ne 2 ]]; then
    red "端口规则不符合要求，正在调整..."

    if [[ $tcp_ports -gt 1 ]]; then
        tcp_to_delete=$((tcp_ports - 1))
        echo "$port_list" | awk '/tcp/ {print $1, $2}' | head -n $tcp_to_delete | while read port type; do
            devil port del $type $port
            green "已删除TCP端口: $port"
        done
    fi

    if [[ $udp_ports -gt 2 ]]; then
        udp_to_delete=$((udp_ports - 2))
        echo "$port_list" | awk '/udp/ {print $1, $2}' | head -n $udp_to_delete | while read port type; do
            devil port del $type $port
            green "已删除UDP端口: $port"
        done
    fi

    if [[ $tcp_ports -lt 1 ]]; then
        while true; do
            tcp_port=$(shuf -i 10000-65535 -n 1)
            result=$(devil port add tcp $tcp_port 2>&1)
            if [[ $result == *"Ok"* ]]; then
                green "已添加TCP端口: $tcp_port"
                break
            else
                yellow "端口 $tcp_port 不可用，尝试其他端口..."
            fi
        done
    fi

    if [[ $udp_ports -lt 2 ]]; then
        udp_ports_to_add=$((2 - udp_ports))
        udp_ports_added=0
        while [[ $udp_ports_added -lt $udp_ports_to_add ]]; do
            udp_port=$(shuf -i 10000-65535 -n 1)
            result=$(devil port add udp $udp_port 2>&1)
            if [[ $result == *"Ok"* ]]; then
                green "已添加UDP端口: $udp_port"
                if [[ $udp_ports_added -eq 0 ]]; then
                    udp_port1=$udp_port
                else
                    udp_port2=$udp_port
                fi
                udp_ports_added=$((udp_ports_added + 1))
            else
                yellow "端口 $udp_port 不可用，尝试其他端口..."
            fi
        done
    fi
    green "端口已调整完成"
    if [[ "$skip_kill" != "keep" ]]; then
        quick_command
        devil binexec on >/dev/null 2>&1
        green "将断开ssh连接,请重新连接ssh重新执行脚本"
        kill -9 $(ps -o ppid= -p $$) >/dev/null 2>&1
    fi
fi
port_list=$(devil port list)
tcp_port=$(printf '%s\n' "$port_list" | awk '$1 ~ /^[0-9]+$/ && $2 == "tcp" {print $1}')
udp_ports=$(printf '%s\n' "$port_list" | awk '$1 ~ /^[0-9]+$/ && $2 == "udp" {print $1}')
udp_port1=$(printf '%s\n' "$udp_ports" | sed -n '1p')
udp_port2=$(printf '%s\n' "$udp_ports" | sed -n '2p')
[ -n "$tcp_port" ] && [ -n "$udp_port1" ] && [ -n "$udp_port2" ] || return 1
purple "reality使用的端口: $tcp_port"
purple "tuic和hy2分别使用的UDP端口: $udp_port1 和 $udp_port2"
export VLESS_PORT=$tcp_port
export TUIC_PORT=$udp_port1
export HY2_PORT=$udp_port2
}

check_website() {
FULL_DOMAIN="api.${USERNAME}.${CURRENT_DOMAIN}"
CURRENT_SITE=$(devil www list | awk -v domain="$FULL_DOMAIN" '$1 == domain && $2 == "php"')
if [ -n "$CURRENT_SITE" ]; then
    green "已存在 ${FULL_DOMAIN} 的PHP站点，无需修改"
else
    EXIST_SITE=$(devil www list | awk -v domain="$FULL_DOMAIN" '$1 == domain')

    if [ -n "$EXIST_SITE" ]; then
        devil www del "$FULL_DOMAIN" >/dev/null 2>&1
        devil www add "$FULL_DOMAIN" php "$HOME/domains/$FULL_DOMAIN" >/dev/null 2>&1
        green "已删除旧的站点并添加新的php站点"
    else
        devil www add "$FULL_DOMAIN" php "$HOME/domains/$FULL_DOMAIN" >/dev/null 2>&1
        green "已创建新PHP站点 ${FULL_DOMAIN}"
    fi
fi

index_url="https://github.com/eooce/Sing-box/releases/download/00/index.html"
[ -f "${FILE_PATH}/index.html" ] || $COMMAND "${FILE_PATH}/index.html" "$index_url"
}

changge_ports() {
reading "将删除全部端口然后随机开放1个tcp端口和2个udp端口,确定继续吗?(直接回车即确认更换)【y/n】: " choice

if [[ -z "$choice" || "$choice" == "y" || "$choice" == "Y" ]]; then
    devil port list | grep -E "^\s*[0-9]+" | while read -r line; do
        port=$(echo "$line" | awk '{print $1}')
        proto=$(echo "$line" | awk '{print $2}')

        if [[ "$proto" != "tcp" && "$proto" != "udp" ]]; then
            continue
        fi

        if ! [[ "$port" =~ ^[0-9]+$ ]]; then
            continue
        fi

        if devil port del "${proto}" "${port}" > /dev/null 2>&1; then
            green "Port ${port}/${proto} has been removed successfully"
        else
            red "Failed to remove port ${port}/${proto}"
        fi
    done
    check_port keep || return 1
    restart_service
else
    menu
fi
}

read_variables() {
  reading "是否需要开启Proxy_IP功能？(直接回车则不开启)【y/n】: " PROXYIP
  [[ -z $PROXYIP ]] && PROXYIP="false"
  [[ "$PROXYIP" == "y" || "$PROXYIP" == "Y" ]] && PROXYIP="true"

}

install_unbound() {
declare -A FILE_MAP
rm -rf "$WORKDIR" && mkdir -p "$WORKDIR" "$FILE_PATH" && chmod 777 "$WORKDIR" "$FILE_PATH" >/dev/null 2>&1
bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
echo -e "${yellow}本脚本同时三协议共存${purple}(vless-reality,hysteria2,tuic)${re}"
reading "\n确定继续安装吗？(直接回车即确认安装)【y/n】: " choice
  case "${choice:-y}" in
    [Yy]|"")
    	clear
        cd $WORKDIR
        check_port
        check_website
        read_variables
        download_unbound
        get_links
      ;;
    [Nn]) exit 0 ;;
    *) red "无效的选择,请输入y或n" && menu ;;
  esac
}


reset_system() {
reading "\n确定重置系统吗吗？【y/n】: " choice
  case "$choice" in
    [Yy]) yellow "\n初始化系统中,请稍后...\n"
          bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
          find "${HOME}" -mindepth 1 ! -name "domains" ! -name "mail" ! -name "repo" ! -name "backups" ! -name ".*" -exec rm -rf {} + > /dev/null 2>&1
          pkill -f "unbound_start.sh" >/dev/null 2>&1
          devil www del api.${USERNAME}.${CURRENT_DOMAIN} > /dev/null 2>&1
          rm -rf $HOME/domains/api.${USERNAME}.${CURRENT_DOMAIN} > /dev/null 2>&1
          green "\n系统初始化完成!\n"
         ;;
       *) menu ;;
  esac
}

write_server_config() {
  [[ "$PROXYIP" == "true" ]] && SNI="time.is" || SNI="www.cerebrium.ai"
  private_key="${REALITY_PRIVATE_KEY:-$private_key}"
  [ -n "$private_key" ] || { red "缺少 Reality 私钥"; return 1; }
  cat > unbound.conf << EOF
{
  "log": {
    "disabled": true,
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "address": "8.8.8.8"
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
         "alpn": ["h3"],
         "certificate_path": "$CERT_FILE",
         "key_path": "$KEY_FILE"
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
                "short_id": [""]
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
        "alpn": ["h3"],
        "certificate_path": "$CERT_FILE",
        "key_path": "$KEY_FILE"
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
if [[ "$HOSTNAME" =~ s14|s15 ]]; then
  jq '.outbounds += [{
    "type":"wireguard","tag":"wireguard-out","server":"162.159.192.200","server_port":4500,
    "local_address":["172.16.0.2/32","2606:4700:110:8f77:1ca9:f086:846c:5f9e/128"],
    "private_key":"wIxszdR2nMdA7a2Ul3XQcniSfSZqdqjPb6w6opvf5AU=",
    "peer_public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
    "reserved":[126,246,173]
  }] | .route = {
    "rule_set":[
      {"tag":"youtube","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/youtube.srs","download_detour":"direct"},
      {"tag":"google","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/google.srs","download_detour":"direct"},
      {"tag":"spotify","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/spotify.srs","download_detour":"direct"}
    ],
    "rules":[{"rule_set":["google","youtube","spotify"],"outbound":"wireguard-out"}],
    "final":"direct"
  }' unbound.conf > unbound.conf.tmp && mv unbound.conf.tmp unbound.conf || return 1
fi
  jq -e . unbound.conf >/dev/null 2>&1 || { red "服务端 JSON 配置语法检查失败"; return 1; }
  return 0
}

download_unbound() {
ARCH=$(uname -m) && DOWNLOAD_DIR="." && mkdir -p "$DOWNLOAD_DIR" && FILE_INFO=()
if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
    BASE_URL="https://github.com/eooce/test/releases/download/freebsd-arm64"
elif [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "x86" ]; then
    BASE_URL="https://github.com/eooce/test/releases/download/freebsd"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi
FILE_INFO=("$BASE_URL/sb web")
generate_random_name() {
    local chars=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
    local name=""
    for i in {1..6}; do
        name="$name${chars:RANDOM%${#chars}:1}"
    done
    echo "$name"
}

download_with_fallback() {
    local URL=$1
    local NEW_FILENAME=$2

    curl -L -sS --max-time 2 -o "$NEW_FILENAME" "$URL" &
    CURL_PID=$!
    CURL_START_SIZE=$(stat -c%s "$NEW_FILENAME" 2>/dev/null || echo 0)

    sleep 1

    CURL_CURRENT_SIZE=$(stat -c%s "$NEW_FILENAME" 2>/dev/null || echo 0)

    if [ "$CURL_CURRENT_SIZE" -le "$CURL_START_SIZE" ]; then
        kill $CURL_PID 2>/dev/null
        wait $CURL_PID 2>/dev/null
        wget -q -O "$NEW_FILENAME" "$URL"
        green "Downloading $NEW_FILENAME by wget"
    else
        wait $CURL_PID
        green "Downloading $NEW_FILENAME by curl"
    fi
}

for entry in "${FILE_INFO[@]}"; do
    URL=$(echo "$entry" | cut -d ' ' -f 1)
    KEY=$(echo "$entry" | cut -d ' ' -f 2) # 获取代号，例如 'web', 'npm', 'bot'

    # 根据代号KEY来决定文件名
    case "$KEY" in
        web)
            # unbound 主程序
            NEW_FILENAME="$DOWNLOAD_DIR/unbound"
            ;;
        npm|php)
            # 哪吒探针程序 (npm或php两种情况都包含)
            NEW_FILENAME="$DOWNLOAD_DIR/unbound-agent"
            ;;
        bot)
            # 机器人程序
            NEW_FILENAME="$DOWNLOAD_DIR/unbound-bot"
            ;;
        *)
            # 如果有未知的代号，使用随机名作为备用方案，防止出错
            RANDOM_NAME=$(generate_random_name)
            NEW_FILENAME="$DOWNLOAD_DIR/$RANDOM_NAME"
            ;;
    esac

    download_with_fallback "$URL" "$NEW_FILENAME"

    chmod +x "$NEW_FILENAME"
    # 将代号和新的文件名（如unbound, unbound-agent）存入FILE_MAP
    FILE_MAP[$KEY]="$NEW_FILENAME"
done
wait

ensure_reality_keys || { red "Reality 密钥生成失败"; return 1; }
[[ "$PROXYIP" == "true" ]] && SNI="time.is" || SNI="www.cerebrium.ai"
add_ssl_cert
yellow "获取可用IP中,请稍等..."
available_ip=$(get_ip)
AVAILABLE_IP="$available_ip"
purple "当前选择IP为: $available_ip 如安装完后节点不通可尝试重新安装"
ensure_certificate || return 1
write_server_config || return 1
save_meta
if [ -e "$(basename ${FILE_MAP[web]})" ]; then
    nohup ./"$(basename ${FILE_MAP[web]})" run -c unbound.conf >/dev/null 2>&1 &
    sleep 2
    pgrep -x "$(basename ${FILE_MAP[web]})" > /dev/null && green "$(basename ${FILE_MAP[web]}) is running" || { red "$(basename ${FILE_MAP[web]}) is not running, restarting..."; pkill -x "$(basename ${FILE_MAP[web]})" && nohup ./"$(basename ${FILE_MAP[web]})" run -c unbound.conf >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[web]}) restarted"; }
fi



}

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

add_ssl_cert() {
  local IP=$(devil vhost list | awk '/^[0-9]/ {print $1; exit}')
  local DOMAIN="api.${USERNAME}.${CURRENT_DOMAIN}"
  yellow "正在为域名 ${DOMAIN} 申请证书..."
  devil ssl www del "${IP}" "${DOMAIN}" >/dev/null 2>&1
  if devil ssl www add "${IP}" le le "${DOMAIN}"; then
    green "证书申请成功！"
  else
    red "证书申请失败。"
  fi
}

publish_subscriptions () {
    ensure_dirs && ensure_certificate || return 1
    command -v jq >/dev/null 2>&1 || return 1
    ISPF=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F\" '{print $26}' | sed -e 's/ /_/g' || echo "0")
    get_name() { if [ "$HOSTNAME" = "s1.ct8.pl" ]; then SERVER="CT8"; else SERVER=$(echo "$HOSTNAME" | cut -d '.' -f 1); fi; echo "$SERVER"; }
    [ -n "${NODE_NAME:-}" ] || NODE_NAME="$ISPF-$(get_name)"
    NAME="$NODE_NAME"
    available_ip="${AVAILABLE_IP:-$available_ip}"
    CERT_SHA256=$(cert_sha256)
    mkdir -p "$DATA_DIR/data" && chmod 700 "$DATA_DIR/data" || return 1
    local stage; stage=$(mktemp -d "${DATA_DIR}/.s.XXXXXX") || return 1
    openssl x509 -in "$CERT_FILE" -out "$stage/p.pem" || return 1
    CERT_SHA256=$(openssl x509 -in "$stage/p.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':\r\n' | tr 'A-F' 'a-f')
    local cert_pem; cert_pem=$(cat "$stage/p.pem")
    local host="$available_ip" remark; [[ "$host" != *:* ]] || host="[$host]"
    remark=$(jq -rn --arg v "$NAME-reality" '$v|@uri')
    VLESS_LINK="vless://$UUID@$host:$VLESS_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$public_key&type=tcp&headerType=none#$remark"
    cat > "${DATA_DIR}/list.txt" <<EOF
$VLESS_LINK

# hy2/tuic 使用自签名证书，单独链接不携带证书，请使用订阅导入。
EOF

    local vjson hjson tjson
    vjson=$(jq -cn --arg id "$UUID-v" --arg r "$NAME-reality" --arg a "$available_ip" \
      --argjson p "$VLESS_PORT" --arg u "$UUID" --arg s "$SNI" --arg k "$public_key" \
      '{IndexId:$id,ConfigType:5,CoreType:24,ConfigVersion:4,Remarks:$r,Address:$a,Port:$p,Password:$u,Network:"raw",StreamSecurity:"reality",AllowInsecure:"false",Sni:$s,Fingerprint:"chrome",PublicKey:$k,ShortId:"",ProtoExtra:"{\"Flow\":\"xtls-rprx-vision\"}",TransportExtra:""}') || return 1
    hjson=$(jq -cn --arg id "$UUID-h" --arg r "$NAME-hy2" --arg a "$available_ip" \
      --argjson p "$HY2_PORT" --arg w "$UUID" --arg s "$CERT_HOST" --arg c "$cert_pem" \
      '{IndexId:$id,ConfigType:7,CoreType:24,ConfigVersion:4,Remarks:$r,Address:$a,Port:$p,Password:$w,Network:"",StreamSecurity:"tls",AllowInsecure:"false",Sni:$s,Alpn:"",Fingerprint:"",Cert:$c,ProtoExtra:"{}",TransportExtra:""}') || return 1
    tjson=$(jq -cn --arg id "$UUID-t" --arg r "$NAME-tuic" --arg a "$available_ip" \
      --argjson p "$TUIC_PORT" --arg u "$UUID" --arg w admin --arg s "$CERT_HOST" --arg c "$cert_pem" \
      '{IndexId:$id,ConfigType:8,CoreType:24,ConfigVersion:4,Remarks:$r,Address:$a,Port:$p,Username:$u,Password:$w,Network:"",StreamSecurity:"tls",AllowInsecure:"false",Sni:$s,Alpn:"h3",Fingerprint:"",Cert:$c,ProtoExtra:"{\"CongestionControl\":\"bbr\"}",TransportExtra:""}') || return 1
    {
      printf 'v2rayn://vless/%s\n' "$(printf '%s' "$vjson" | base64 | tr -d '\r\n=' | tr '+/' '-_')"
      printf 'v2rayn://hysteria2/%s\n' "$(printf '%s' "$hjson" | base64 | tr -d '\r\n=' | tr '+/' '-_')"
      printf 'v2rayn://tuic/%s\n' "$(printf '%s' "$tjson" | base64 | tr -d '\r\n=' | tr '+/' '-_')"
    } > "$stage/a.dat" || return 1

    jq -cn --arg n "$NAME" --arg a "$available_ip" --arg u "$UUID" --arg s "$CERT_HOST" \
      --arg r "$SNI" --arg k "$public_key" --arg c "$cert_pem" \
      --argjson vp "$VLESS_PORT" --argjson tp "$TUIC_PORT" --argjson hp "$HY2_PORT" \
      '{outbounds:[
        {type:"vless",tag:($n+"-reality"),server:$a,server_port:$vp,uuid:$u,flow:"xtls-rprx-vision",tls:{enabled:true,server_name:$r,insecure:false,reality:{enabled:true,public_key:$k,short_id:""},utls:{enabled:true,fingerprint:"chrome"}}},
        {type:"hysteria2",tag:($n+"-hy2"),server:$a,server_port:$hp,password:$u,tls:{enabled:true,server_name:$s,alpn:["h3"],certificate:$c,insecure:false}},
        {type:"tuic",tag:($n+"-tuic"),server:$a,server_port:$tp,uuid:$u,password:"admin",congestion_control:"bbr",udp_relay_mode:"native",zero_rtt_handshake:false,tls:{enabled:true,server_name:$s,alpn:["h3"],certificate:$c,insecure:false}}
      ]}' > "$stage/b.dat" || return 1

    jq -n --arg n "$NAME" --arg a "$available_ip" --arg u "$UUID" --arg s "$CERT_HOST" \
      --arg r "$SNI" --arg k "$public_key" --arg f "$CERT_SHA256" \
      --argjson vp "$VLESS_PORT" --argjson tp "$TUIC_PORT" --argjson hp "$HY2_PORT" \
      '{"mixed-port":7890,"allow-lan":false,mode:"rule","log-level":"info",
       proxies:[
        {name:($n+"-reality"),type:"vless",server:$a,port:$vp,uuid:$u,network:"tcp",udp:true,tls:true,flow:"xtls-rprx-vision",servername:$r,"client-fingerprint":"chrome","reality-opts":{"public-key":$k,"short-id":""}},
        {name:($n+"-hy2"),type:"hysteria2",server:$a,port:$hp,password:$u,sni:$s,alpn:["h3"],"skip-cert-verify":false,fingerprint:$f,udp:true},
        {name:($n+"-tuic"),type:"tuic",server:$a,port:$tp,uuid:$u,password:"admin",sni:$s,alpn:["h3"],"congestion-controller":"bbr","udp-relay-mode":"native","reduce-rtt":false,"skip-cert-verify":false,fingerprint:$f,udp:true}
       ],
       "proxy-groups":[{name:"PROXY",type:"select",proxies:[($n+"-reality"),($n+"-hy2"),($n+"-tuic")]}],rules:["MATCH,PROXY"]}' > "$stage/c.dat" || return 1

    jq -e . "$stage/b.dat" >/dev/null && jq -e . "$stage/c.dat" >/dev/null || return 1
    local hash; hash=$(printf '%s' "$SUB_TOKEN" | openssl dgst -sha256 -r | awk '{print $1}')
    jq -n --arg h "$hash" --arg f "$CERT_SHA256" --rawfile a "$stage/a.dat" --rawfile b "$stage/b.dat" --rawfile c "$stage/c.dat" --rawfile l "${DATA_DIR}/list.txt" \
      '{schema:2,fingerprint:$f,token:$h,content:{a:$a,b:$b,c:$c,legacy:$l}}' > "$stage/bundle.json" || return 1

    local d64; d64=$(printf '%s' "$DATA_DIR" | base64 | tr -d '\r\n')
    printf '<?php\ndeclare(strict_types=1);\n$d = base64_decode("%s");\n' "$d64" > "$stage/router.php"
    cat >> "$stage/router.php" <<'PHP'
$b = json_decode((string)@file_get_contents($d . '/data/bundle.json'), true);
$p = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
$c = ''; $t = '';
if (preg_match('~^/([A-Za-z0-9_-]{8,128})/(v2rayn|nekobox|mihomo)$~D', (string)$p, $m)) { $t=$m[1]; $c=$m[2]; }
elseif (preg_match('~^/([A-Za-z0-9_-]{8,128})$~D', (string)$p, $m)) { $t=$m[1]; $c='legacy'; }
else { http_response_code(404); exit; }
if (!is_array($b) || !hash_equals($b['token'] ?? '', hash('sha256', $t))) { http_response_code(404); exit; }
if ($c === 'legacy') {
  $u = $_SERVER['HTTP_USER_AGENT'] ?? '';
  if (preg_match('/NekoBox/i', $u)) $c='b';
  elseif (preg_match('/Clash|mihomo|FlClash/i', $u)) $c='c';
  else $c='a';
} else { $c = ['v2rayn'=>'a','nekobox'=>'b','mihomo'=>'c'][$c] ?? ''; }
if (!isset($b['content'][$c])) { http_response_code(404); exit; }
$types=['a'=>'text/plain; charset=utf-8','b'=>'application/json; charset=utf-8','c'=>'text/yaml; charset=utf-8'];
header('Content-Type: '.$types[$c]);
header('Cache-Control: no-store');
echo $b['content'][$c];
PHP
    if command -v php >/dev/null 2>&1; then
        php -l "$stage/router.php" >/dev/null || { rm -rf "$stage"; red "订阅入口语法检查失败"; return 1; }
    fi
    mv -f "$stage/router.php" "$FILE_PATH/${SUB_TOKEN}.php" && chmod 644 "$FILE_PATH/${SUB_TOKEN}.php"
    cat > "$FILE_PATH/.htaccess" <<EOF
RewriteEngine On
DirectoryIndex index.html
RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /(\?|$)
RewriteRule ^\$ /index.html [L]
RewriteRule ^${SUB_TOKEN}$ ${SUB_TOKEN}.php [L]
RewriteRule ^${SUB_TOKEN}/(v2rayn|nekobox|mihomo)$ ${SUB_TOKEN}.php [L]
<FilesMatch "^(list\.txt|v2\.log|clash\.yaml|singbox\.yaml)$">
    Order Allow,Deny
    Deny from all
</FilesMatch>
EOF
    chmod 600 "$stage/a.dat" "$stage/b.dat" "$stage/c.dat" "$stage/bundle.json"
    mv -f "$stage/a.dat" "$DATA_DIR/data/a.dat"
    mv -f "$stage/b.dat" "$DATA_DIR/data/b.dat"
    mv -f "$stage/c.dat" "$DATA_DIR/data/c.dat"
    mv -f "$stage/bundle.json" "$DATA_DIR/data/bundle.json"
    mv -f "$stage/p.pem" "$DATA_DIR/data/p.pem" 2>/dev/null || true
    rm -rf "$stage"
    rm -f "$FILE_PATH/list.txt" "$FILE_PATH/v2.log" "$FILE_PATH/clash.yaml" "$FILE_PATH/singbox.yaml" \
          "$FILE_PATH/sub.php" >/dev/null 2>&1
    SUB_SCHEMA=2
    save_meta
    purple "\n通用订阅: https://${CERT_HOST}/${SUB_TOKEN}"
    green "v2rayN: https://${CERT_HOST}/${SUB_TOKEN}/v2rayn"
    green "NekoBox: https://${CERT_HOST}/${SUB_TOKEN}/nekobox"
    green "Mihomo: https://${CERT_HOST}/${SUB_TOKEN}/mihomo"
    green "证书 SHA-256: ${CERT_SHA256}\n"
}

generate_sub_link () {
    publish_subscriptions
}

install_keepalive () {
    purple "正在安装保活服务中,请稍等......"

    # Create a configuration file for the keep-alive script
    (
    cat << EOF
export UUID="$UUID"
export VLESS_PORT="$VLESS_PORT"
export TUIC_PORT="$TUIC_PORT"
export HY2_PORT="$HY2_PORT"
export PROXYIP="$PROXYIP"
export USERNAME="$USERNAME"
export CURRENT_DOMAIN="$CURRENT_DOMAIN"
export private_key="$private_key"
export SUB_TOKEN="$SUB_TOKEN"
export AVAILABLE_IP="$available_ip"
export SUB_SCHEMA="$SUB_SCHEMA"
EOF
    ) | base64 -w 0 > "${WORKDIR}/keepalive.conf"

    KEEPALIVE_SCRIPT_URL="https://raw.githubusercontent.com/Git-think/Salksd/refs/heads/main/unbound_start.sh"
    KEEPALIVE_SCRIPT_PATH="${WORKDIR}/unbound_start.sh"

    # Download the keep-alive script
    $COMMAND "$KEEPALIVE_SCRIPT_PATH" "$KEEPALIVE_SCRIPT_URL"
    if [ $? -ne 0 ]; then
        red "下载保活脚本失败。"
        exit 1
    fi

    chmod +x "$KEEPALIVE_SCRIPT_PATH"

    # Kill any existing keep-alive script process
    pkill -f "unbound_start.sh" >/dev/null 2>&1

    # Start the new keep-alive script in the background
    nohup "$KEEPALIVE_SCRIPT_PATH" >"${WORKDIR}/keepalive.log" 2>&1 &

    sleep 2
    if pgrep -f "unbound_start.sh" > /dev/null; then
        green "\n全自动保活服务安装成功\n"

        # Create a shortcut command for unbound_start.sh
        local keepalive_command="unbound-start"
        local keepalive_path="$HOME/bin/$keepalive_command"
        mkdir -p "$HOME/bin"
        cat > "$keepalive_path" << EOF
#!/bin/bash

# The path to the actual keep-alive script, derived from WORKDIR
KEEPALIVE_SCRIPT_PATH="${WORKDIR}/unbound_start.sh"

# Check if the keep-alive script is already running
if pgrep -f "unbound_start.sh" > /dev/null; then
    echo "unbound 保活服务已经在运行中。"
    exit 0
fi

# Kill any old instances just in case
pkill -f "unbound_start.sh" >/dev/null 2>&1

# Start the new keep-alive script in the background
nohup "\$KEEPALIVE_SCRIPT_PATH" >/dev/null 2>&1 &

# Wait a moment and check if it started successfully
sleep 2
if pgrep -f "unbound_start.sh" > /dev/null; then
    echo "unbound 保活服务已成功启动到后台。"
else
    echo "unbound 保活服务启动失败。"
fi
EOF
        chmod +x "$keepalive_path"

        if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
            echo "export PATH=\"\$HOME/bin:\$PATH\"" >> "$HOME/.bashrc" 2>/dev/null
            source "$HOME/.bashrc"
        fi
        green "快捷指令 ${keepalive_command} 创建成功, 下次可直接运行 ${keepalive_command} 来启动保活服务。\n"
    else
        red "\n全自动保活服务安装失败\n"
    fi
}

get_links(){
  load_meta || true
  available_ip="${AVAILABLE_IP:-${available_ip:-}}"
  [ -n "$available_ip" ] || available_ip=$(get_ip)
  AVAILABLE_IP="$available_ip"
  publish_subscriptions || return 1
  save_meta
  install_keepalive
  rm -rf "$(basename ${FILE_MAP[web]})" unbound.conf sb.log core fake_useragent_0.2.0.json private.key cert.pem >/dev/null 2>&1
  quick_command
  purple "\n通用订阅: https://${CERT_HOST}/${SUB_TOKEN}"
  green "  v2rayN: https://${CERT_HOST}/${SUB_TOKEN}/v2rayn"
  green "  NekoBox: https://${CERT_HOST}/${SUB_TOKEN}/nekobox"
  green "  Mihomo: https://${CERT_HOST}/${SUB_TOKEN}/mihomo\n"
  green "Running done!\n"
}

quick_command() {
  COMMAND="00"
  SCRIPT_PATH="$HOME/bin/$COMMAND"
  mkdir -p "$HOME/bin"
  echo "#!/bin/bash" > "$SCRIPT_PATH"
  echo "bash <(curl -Ls https://raw.githubusercontent.com/Git-think/Salksd/refs/heads/main/unbound.sh)" >> "$SCRIPT_PATH"
  chmod +x "$SCRIPT_PATH"
  if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
      echo "export PATH=\"\$HOME/bin:\$PATH\"" >> "$HOME/.bashrc" 2>/dev/null
      source "$HOME/.bashrc"
  fi
green "快捷指令00创建成功,下次运行输入00快速进入菜单\n"
}


get_nodes(){
[ -s "${DATA_DIR}/list.txt" ] && cat "${DATA_DIR}/list.txt"
echo ""
purple "通用订阅: https://${CERT_HOST}/${SUB_TOKEN}"
green "  v2rayN: https://${CERT_HOST}/${SUB_TOKEN}/v2rayn"
green "  NekoBox: https://${CERT_HOST}/${SUB_TOKEN}/nekobox"
green "  Mihomo: https://${CERT_HOST}/${SUB_TOKEN}/mihomo\n"
[ ! -x "${WORKDIR}/qrencode" ] || "${WORKDIR}/qrencode" -m 2 -t UTF8 "https://${CERT_HOST}/${SUB_TOKEN}"
}

restart_service() {
  declare -A FILE_MAP
  load_meta || migrate_old_keepalive || true
  mkdir -p "$WORKDIR" && cd "$WORKDIR" || return 1
  bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
  download_unbound || return 1
  get_links
}

publish_only() {
  load_meta || return 1
  available_ip="${AVAILABLE_IP:-$(get_ip)}"
  AVAILABLE_IP="$available_ip"
  publish_subscriptions
}

menu() {
  clear
  echo ""
  purple "=== Serv00|ct8 unbound一键安装脚本 ===\n"
  purple "转载请著名出处，请勿滥用\n"
  yellow "快速启动命令\n"
  green "1. 安装三合一"
  echo  "==============="
  green "2. 查看节点信息"
  echo  "==============="
  yellow "3. 更换节点端口"
  echo  "==============="
  yellow "4. 初始化系统"
  echo  "==============="
  green "5. 重启服务"
  echo  "==============="
  red "0. 退出脚本"
  echo "==========="
  reading "请输入选择(0-5): " choice
  echo ""
  case "${choice:-1}" in
      1) install_unbound ;;
      2) get_nodes ;;
      3) changge_ports ;;
      4) reset_system ;;
      5) restart_service ;;
      0) exit 0 ;;
      *) red "无效的选项，请输入 0 到 5" ;;
  esac
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  if [[ "${1:-}" == "--publish" ]]; then
    publish_only
    exit $?
  fi
  menu
fi
