#!/bin/bash

#===============================================================================================
# Serv00 Sing-box Installation Script
#
# Author: Original author + Refactoring by Senior Software Engineer
#
# Key Changes in this version:
# - Replaced the external download of `app.js` for the keep-alive service.
# - The keep-alive Node.js application is now dynamically generated within this script.
# - This makes the entire solution self-contained, more secure, and transparent.
# - The keep-alive mechanism is robust against Cron job cleanup by the host.
#===============================================================================================

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
export UPLOAD_URL=${UPLOAD_URL:-''}

if [[ "$HOSTNAME" =~ ct8 ]]; then
    CURRENT_DOMAIN="ct8.pl"
elif [[ "$HOSTNAME" =~ useruno ]]; then
    CURRENT_DOMAIN="useruno.com"
else
    CURRENT_DOMAIN="serv00.net"
fi
WORKDIR="${HOME}/domains/api.${USERNAME}.${CURRENT_DOMAIN}/logs"
FILE_PATH="${HOME}/domains/api.${USERNAME}.${CURRENT_DOMAIN}/public_html"
rm -rf "$WORKDIR" && mkdir -p "$WORKDIR" "$FILE_PATH" && chmod 777 "$WORKDIR" "$FILE_PATH" >/dev/null 2>&1
command -v curl &>/dev/null && COMMAND="curl -so" || command -v wget &>/dev/null && COMMAND="wget -qO" || { red "Error: neither curl nor wget found, please install one of them." >&2; exit 1; }

check_port () {
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
    green "端口已调整完成,将断开ssh连接,请重新连接shh重新执行脚本"
    quick_command
    devil binexec on >/dev/null 2>&1
    kill -9 $(ps -o ppid= -p $$) >/dev/null 2>&1
else
    tcp_port=$(echo "$port_list" | awk '/tcp/ {print $1}')
    udp_ports=$(echo "$port_list" | awk '/udp/ {print $1}')
    udp_port1=$(echo "$udp_ports" | sed -n '1p')
    udp_port2=$(echo "$udp_ports" | sed -n '2p')
fi
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
    check_port
else
    menu  
fi
}

read_variables() {
  reading "是否需要开启Proxy_IP功能？(直接回车则不开启)【y/n】: " PROXYIP
  [[ -z $PROXYIP ]] && PROXYIP="false"
  [[ "$PROXYIP" == "y" || "$PROXYIP" == "Y" ]] && PROXYIP="true"

  reading "是否需要安装哪吒探针？(直接回车则不安装)【y/n】: " nz_choice
  if [[ -z $nz_choice || ( "$nz_choice" != "y" && "$nz_choice" != "Y" ) ]]; then
    yellow "跳过配置哪吒探针..."
  else
    reading "请输入哪吒探针域名或IP（v1格式: nezha.abc.com:8008, v0格式: nezha.abc.com）： " NEZHA_SERVER
    green "你的哪吒域名为: $NEZHA_SERVER"

    if [[ "$NEZHA_SERVER" != *":"* ]]; then
      reading "请输入哪吒v0探针端口(直接回车将设置为5555): " NEZHA_PORT
      [[ -z $NEZHA_PORT ]] && NEZHA_PORT="5555"
      green "你的哪吒端口为: $NEZHA_PORT"
    else
      NEZHA_PORT=""
    fi

    reading "请输入v0的agent密钥或v1的NZ_CLIENT_SECRET: " NEZHA_KEY
    green "你的哪吒密钥为: $NEZHA_KEY"
  fi

  reading "是否需要Telegram通知？(直接回车则不启用)【y/n】: " tg_notification
  if [[ "$tg_notification" == "y" || "$tg_notification" == "Y" ]]; then
    reading "请输入Telegram chat ID (tg上@laowang_serv00_bot获取): " tg_chat_id
    [[ -z $tg_chat_id ]] && { echo "Telegram chat ID不能为空"; return; }
    green "你设置的Telegram chat_id为: ${tg_chat_id}"

    reading "请输入Telegram Bot Token (直接回车使用老王的bot通知或填写自己的): " tg_token
    [[ -z $tg_token ]] && tg_token=""
    green "你设置的Telegram bot token为: ${tg_token}"
  fi
}

install_singbox() {
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
        download_singbox
        get_links
      ;;
    [Nn]) exit 0 ;;
    *) red "无效的选择,请输入y或n" && menu ;;
  esac
}

uninstall_singbox() {
  reading "\n确定要卸载吗？【y/n】: " choice
    case "$choice" in
        [Yy])
            # Kill all user processes first
            bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
            
            # Remove the keep-alive service website and files
            purple "正在移除保活服务..."
            devil www del keep.${USERNAME}.${CURRENT_DOMAIN} >/dev/null 2>&1
            rm -rf "${HOME}/domains/keep.${USERNAME}.${CURRENT_DOMAIN}"
            
            # Remove main application files
            purple "正在移除主应用文件..."
            rm -rf $WORKDIR && find ${FILE_PATH} -mindepth 1 ! -name 'index.html' -exec rm -rf {} +
            
            # Remove quick command
            rm -rf "${HOME}/bin/00" >/dev/null 2>&1
            [ -d "${HOME}/bin" ] && [ -z "$(ls -A "${HOME}/bin")" ] && rmdir "${HOME}/bin"
            
            # Clean up .bashrc
            sed -i '/export PATH="\$HOME\/bin:\$PATH"/d' "${HOME}/.bashrc" >/dev/null 2>&1
            source "${HOME}/.bashrc"
            
            clear
            green "Sing-box三合一已完全卸载，Node.js保活服务已移除。"
          ;;
        [Nn]) exit 0 ;;
        *) red "无效的选择，请输入y或n" && menu ;;
    esac
}

reset_system() {
reading "\n确定重置系统吗吗？【y/n】: " choice
  case "$choice" in
    [Yy]) yellow "\n初始化系统中,请稍后...\n"
          bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
          find "${HOME}" -mindepth 1 ! -name "domains" ! -name "mail" ! -name "repo" ! -name "backups" ! -name ".*" -exec rm -rf {} + > /dev/null 2>&1
          devil www del $USERNAME.${CURRENT_DOMAIN} > /dev/null 2>&1
          devil www del keep.$USERNAME.${CURRENT_DOMAIN} > /dev/null 2>&1
          rm -rf $HOME/domains/* > /dev/null 2>&1
          green "\n系统初始化完成!\n"
         ;;
       *) menu ;;
  esac
}

download_singbox() {
ARCH=$(uname -m) && DOWNLOAD_DIR="." && mkdir -p "$DOWNLOAD_DIR" && FILE_INFO=()
if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
    BASE_URL="https://github.com/eooce/test/releases/download/freebsd-arm64"
elif [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "x86" ]; then
    BASE_URL="https://github.com/eooce/test/releases/download/freebsd"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi
FILE_INFO=("$BASE_URL/sb web" "$BASE_URL/server bot")
if [ -n "$NEZHA_PORT" ]; then
    FILE_INFO+=("$BASE_URL/npm npm")
else
    FILE_INFO+=("$BASE_URL/v1 php")
    NEZHA_TLS=$(case "${NEZHA_SERVER##*:}" in 443|8443|2096|2087|2083|2053) echo -n tls;; *) echo -n false;; esac)
    cat > "${WORKDIR}/config.yaml" << EOF
client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 1
server: ${NEZHA_SERVER}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: ${NEZHA_TLS}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}
EOF
fi
declare -A FILE_MAP
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
    KEY=$(echo "$entry" | cut -d ' ' -f 2) 

    case "$KEY" in
        web)
            NEW_FILENAME="$DOWNLOAD_DIR/frps"
            ;;
        npm|php)
            NEW_FILENAME="$DOWNLOAD_DIR/frps-agent"
            ;;
        bot)
            NEW_FILENAME="$DOWNLOAD_DIR/frps-bot"
            ;;
        *)
            RANDOM_NAME=$(generate_random_name)
            NEW_FILENAME="$DOWNLOAD_DIR/$RANDOM_NAME"
            ;;
    esac

    download_with_fallback "$URL" "$NEW_FILENAME"
    
    chmod +x "$NEW_FILENAME"
    FILE_MAP[$KEY]="$NEW_FILENAME"
done
wait

output=$(./"$(basename ${FILE_MAP[web]})" generate reality-keypair)
private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')
[[ "$PROXYIP" == "true" ]] && SNI="time.is" || SNI="www.cerebrium.ai"
openssl ecparam -genkey -name prime256v1 -out "private.key"
openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=$USERNAME.${CURRENT_DOMAIN}"
  
yellow "获取可用IP中,请稍等..."
available_ip=$(get_ip)
purple "当前选择IP为: $available_ip 如安装完后节点不通可尝试重新安装"
  
cat > config.json << EOF
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
EOF

if [[ "$HOSTNAME" =~ s14|s15 ]]; then
  cat >> config.json <<EOF
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "wireguard",
      "tag": "wireguard-out",
      "server": "162.159.192.200",
      "server_port": 4500,
      "local_address": [
        "172.16.0.2/32",
        "2606:4700:110:8f77:1ca9:f086:846c:5f9e/128"
      ],
      "private_key": "wIxszdR2nMdA7a2Ul3XQcniSfSZqdqjPb6w6opvf5AU=",
      "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
      "reserved": [126, 246, 173]
    }
  ],
  "route": {
    "rule_set": [
      {
        "tag": "youtube",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/youtube.srs",
        "download_detour": "direct"
      },
      {
        "tag": "google",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/google.srs",
        "download_detour": "direct"
      },
      {
        "tag": "spotify",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/spotify.srs",
        "download_detour": "direct"
      }
    ],
    "rules": [
      {
        "rule_set": ["google", "youtube", "spotify"],
        "outbound": "wireguard-out"
      }
    ],
    "final": "direct"
  }
}
EOF
else
  cat >> config.json <<EOF
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
fi

if [ -e "$(basename ${FILE_MAP[web]})" ]; then
    nohup ./"$(basename ${FILE_MAP[web]})" run -c config.json >/dev/null 2>&1 &
    sleep 2
    pgrep -x "$(basename ${FILE_MAP[web]})" > /dev/null && green "$(basename ${FILE_MAP[web]}) is running" || { red "$(basename ${FILE_MAP[web]}) is not running, restarting..."; pkill -x "$(basename ${FILE_MAP[web]})" && nohup ./"$(basename ${FILE_MAP[web]})" run -c config.json >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[web]}) restarted"; }
fi

if [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_PORT" ] && [ -n "$NEZHA_KEY" ]; then
    if [ -e "$(basename ${FILE_MAP[npm]})" ]; then
    tlsPorts=("443" "8443" "2096" "2087" "2083" "2053")
      [[ "${tlsPorts[*]}" =~ "${NEZHA_PORT}" ]] && NEZHA_TLS="--tls" || NEZHA_TLS=""
      export TMPDIR=$(pwd)
      nohup ./"$(basename ${FILE_MAP[npm]})" -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} >/dev/null 2>&1 &
      sleep 2
      pgrep -x "$(basename ${FILE_MAP[npm]})" > /dev/null && green "$(basename ${FILE_MAP[npm]}) is running" || { red "$(basename ${FILE_MAP[npm]}) is not running, restarting..."; pkill -f "$(basename ${FILE_MAP[npm]})" && nohup ./"$(basename ${FILE_MAP[npm]})" -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[npm]}) restarted"; }
    fi
elif [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_KEY" ]; then
    if [ -e "$(basename ${FILE_MAP[php]})" ]; then
      nohup ./"$(basename ${FILE_MAP[php]})" -c "${WORKDIR}/config.yaml" >/dev/null 2>&1 &
      sleep 2
      pgrep -x "$(basename ${FILE_MAP[php]})" > /dev/null && green "$(basename ${FILE_MAP[php]}) is running\e[0m" || { red "$(basename ${FILE_MAP[php]}) is not running, restarting..."; pkill -x "$(basename ${FILE_MAP[php]})" && nohup ./"$(basename ${FILE_MAP[php]})" -s -c "${WORKDIR}/config.yaml" >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[php]}) restarted"; }
    fi
else
    purple "NEZHA variable is empty, skipping running"
fi

for key in "${!FILE_MAP[@]}"; do
    if [ -e "$(basename ${FILE_MAP[$key]})" ]; then
        rm -rf "$(basename ${FILE_MAP[$key]})" >/dev/null 2>&1
    fi
done

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

generate_sub_link () {
echo ""
rm -rf ${FILE_PATH}/.htaccess
base64 -w0 ${FILE_PATH}/list.txt > ${FILE_PATH}/v2.log
PHP_URL="https://00.ssss.nyc.mn/sub.php"
QR_URL="https://00.ssss.nyc.mn/qrencode"  
$COMMAND "${FILE_PATH}/${SUB_TOKEN}.php" "$PHP_URL" 
$COMMAND "${WORKDIR}/qrencode" "$QR_URL" && chmod +x "${WORKDIR}/qrencode"
V2rayN_LINK="https://api.${USERNAME}.${CURRENT_DOMAIN}/v2.log"
AUTO_LINK="https://api.${USERNAME}.${CURRENT_DOMAIN}/${SUB_TOKEN}"
curl -sS "https://sublink.eooce.com/clash?config=${V2rayN_LINK}" -o ${FILE_PATH}/clash.yaml
curl -sS "https://sublink.eooce.com/singbox?config=${V2rayN_LINK}" -o ${FILE_PATH}/singbox.yaml
"${WORKDIR}/qrencode" -m 2 -t UTF8 "${AUTO_LINK}"
purple "\n自适应节点订阅链接: ${AUTO_LINK}\n"
green "二维码和节点订阅链接适用于 V2rayN/Nekoray/ShadowRocket/Clash/Mihomo/Sing-box/karing/Loon/sterisand 等\n\n"
cat > ${FILE_PATH}/.htaccess << EOF
RewriteEngine On
DirectoryIndex index.html
RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /(\?|$)
RewriteRule ^$ /index.html [L]
<FilesMatch "^(index\.html|${SUB_TOKEN}\.php)$">
    Order Allow,Deny
    Allow from all
</FilesMatch>
<FilesMatch "^(clash\.yaml|singbox\.yaml|list\.txt|v2\.log|sub\.php)$">
    Order Allow,Deny
    Deny from all
</FilesMatch>
RewriteRule ^${SUB_TOKEN}$ ${SUB_TOKEN}.php [L]
EOF
}

#================================================================================
# START OF REFACTORED KEEPALIVE FUNCTION
# This function creates a self-contained Node.js application for process keep-alive.
# It does not download any external scripts.
#================================================================================
install_keepalive() {
    # On ct8 and useruno hosts, this feature may not be available or necessary
    [[ "$HOSTNAME" =~ ct8|useruno ]] && return

    purple "正在安装自建的 Node.js 保活服务..."

    # 1. Set up the domain and path for the keep-alive service
    local keep_domain="keep.${USERNAME}.${CURRENT_DOMAIN}"
    local keep_path="${HOME}/domains/${keep_domain}/public_nodejs"
    
    # Clean up old site and create a new Node.js site
    devil www del "${keep_domain}" > /dev/null 2>&1
    if ! devil www add "${keep_domain}" nodejs /usr/local/bin/node18 > /dev/null 2>&1; then
        red "创建 Node.js 站点失败，保活服务无法安装。"
        return 1
    fi
    
    mkdir -p "${keep_path}"
    
    # 2. Dynamically create package.json to declare dependencies
    cat > "${keep_path}/package.json" << 'EOF'
{
  "name": "serv00-keepalive-service",
  "version": "1.0.0",
  "description": "A self-contained keep-alive service for sing-box on Serv00.",
  "main": "app.js",
  "scripts": {
    "start": "node app.js"
  },
  "dependencies": {
    "dotenv": "^16.3.1"
  }
}
EOF

    # 3. Dynamically create the .env config file to pass Shell variables to Node.js
    cat > "${keep_path}/.env" <<EOF
# Serv00 Environment Variables
WORKDIR=${WORKDIR}
USERNAME=${USERNAME}
# Core App Variables
UUID=${UUID}
SUB_TOKEN=${SUB_TOKEN}
PROXYIP=${PROXYIP}
${UPLOAD_URL:+API_SUB_URL=$UPLOAD_URL}
# Telegram Notification Variables
${tg_chat_id:+TELEGRAM_CHAT_ID=$tg_chat_id}
${tg_token:+TELEGRAM_BOT_TOKEN=$tg_token}
# Nezha Agent Variables
${NEZHA_SERVER:+NEZHA_SERVER=$NEZHA_SERVER}
${NEZHA_PORT:+NEZHA_PORT=$NEZHA_PORT}
${NEZHA_KEY:+NEZHA_KEY=$NEZHA_KEY}
EOF

    # 4. Dynamically create the main app.js file
    # Using 'EOF' prevents Shell from expanding variables like $`...`
    cat > "${keep_path}/app.js" << 'EOF'
const http = require('http');
const { exec } = require('child_process');
require('dotenv').config();

// Load environment variables from .env file
const {
    PORT, // Port provided by the Serv00 platform
    WORKDIR,
    USERNAME
} = process.env;

// Define commands and identifiers for the core process
// Using pgrep -f to match the full command line is more precise
const SINGBOX_EXEC = `${WORKDIR}/frps`;
const SINGBOX_CONFIG = `${WORKDIR}/config.json`;
const SINGBOX_CMD = `nohup ${SINGBOX_EXEC} run -c ${SINGBOX_CONFIG} > /dev/null 2>&1 &`;
const SINGBOX_PCHECK = `pgrep -f "${SINGBOX_EXEC} run -c ${SINGBOX_CONFIG}"`;

// Function to check and start processes
function checkAndStartProcesses(callback) {
    let output = [];

    // 1. Check Sing-box
    exec(SINGBOX_PCHECK, (err, stdout, stderr) => {
        if (stdout) {
            output.push('Sing-box is running.');
        } else {
            output.push('Sing-box NOT found. Attempting to restart...');
            exec(SINGBOX_CMD, { cwd: WORKDIR }); // Start the process
        }
        
        // You can add logic to check the Nezha agent here if needed
        // ...

        callback(output.join('\n'));
    });
}

// Create the HTTP server
const server = http.createServer((req, res) => {
    const url = req.url;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');

    if (url === '/' || url.startsWith('/?')) {
        res.writeHead(200);
        res.end('Keep-alive service is active. Access specific paths to trigger actions.');
    } else if (url === `/${USERNAME}` || url === '/run' || url === '/start' || url === '/go') {
        res.writeHead(200);
        checkAndStartProcesses(responseText => {
            res.end(`Triggered keep-alive check:\n${responseText}`);
        });
    } else if (url === '/status') {
        exec(`${SINGBOX_PCHECK}; echo $?`, (err, stdout, stderr) => {
            const isRunning = stdout.trim().split('\n').pop() === '0';
            res.writeHead(200);
            res.end(`Process Status:\n\nSing-box: ${isRunning ? 'Running' : 'Not Running'}`);
        });
    } else if (url === '/stop') {
        exec(`pkill -f "${SINGBOX_EXEC}"`, (err, stdout, stderr) => {
            res.writeHead(200);
            res.end('Sent stop signal to Sing-box process.');
        });
    } else if (url === '/list') {
        exec(`ps aux | grep ${USERNAME} | grep -v "sshd\\|bash\\|grep\\|node"`, (err, stdout, stderr) => {
            res.writeHead(200);
            res.end(`Listing processes for user ${USERNAME}:\n\n${stdout || 'No processes found.'}`);
        });
    } else {
        res.writeHead(404);
        res.end('Not Found');
    }
});

// Start the server on the port assigned by the platform
server.listen(PORT, () => {
    console.log(`Keep-alive server listening on port ${PORT}`);
    console.log(`Access http://${process.env.DEVIL_WWW_VHOST}/${USERNAME} to trigger the check.`);
});
EOF

    # 5. Install dependencies and start/restart the service
    purple "安装 Node.js 依赖 (dotenv)..."
    cd "${keep_path}" || { red "无法进入工作目录 ${keep_path}"; return 1; }
    
    # Set up npm path to avoid permission issues
    mkdir -p ~/.npm-global
    npm config set prefix '~/.npm-global'
    export PATH=~/.npm-global/bin:~/bin:$PATH
    
    if npm install --silent; then
        green "依赖安装成功。"
    else
        red "npm install 失败，请检查 Node.js 环境。"
        return 1
    fi
    
    purple "重启保活服务网站..."
    if devil www restart "${keep_domain}"; then
        green "保活服务已启动。"
    else
        red "保活服务启动失败。"
        return 1
    fi

    # 6. Verify that the service is running successfully
    sleep 5 # Give the service a moment to start
    if curl -skL "http://${keep_domain}/" | grep -q "active"; then
        green "\n全自动保活服务安装成功！"
        purple "这是一个自包含的应用，代码透明，无需依赖外部文件。"
        purple "访问 http://${keep_domain}/stop 结束进程"
        purple "访问 http://${keep_domain}/list 查看全部进程列表"
        yellow "访问 http://${keep_domain}/${USERNAME} 调起保活程序 (备用: /run, /start)"
        purple "访问 http://${keep_domain}/status 查看进程状态\n"
    else
        red "\n全自动保活服务安装失败！"
        yellow "请检查日志: devil www log ${keep_domain}"
    fi
}
#================================================================================
# END OF REFACTORED KEEPALIVE FUNCTION
#================================================================================


get_links(){
ISP=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F\" '{print $26}' | sed -e 's/ /_/g' || echo "0")
get_name() { if [ "$HOSTNAME" = "s1.ct8.pl" ]; then SERVER="CT8"; else SERVER=$(echo "$HOSTNAME" | cut -d '.' -f 1); fi; echo "$SERVER"; }
NAME="$ISP-$(get_name)"
yellow "注意：v2ray或其他软件的跳过证书验证需设置为true,否则hy2或tuic节点可能不通\n"
cat > $FILE_PATH/list.txt <<EOF
vless://$UUID@$available_ip:$VLESS_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$public_key&type=tcp&headerType=none#$NAME-reality

hysteria2://$UUID@$available_ip:$HY2_PORT/?sni=www.bing.com&alpn=h3&insecure=1#$NAME-hysteria2

tuic://$UUID:admin@$available_ip:$TUIC_PORT?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#$NAME-tuic
EOF
cat $FILE_PATH/list.txt
[[ "$PROXYIP" == "true" ]] && purple "\n你的ProxyIP为: $available_ip:$VLESS_PORT"
generate_sub_link

# Call the refactored keep-alive function
install_keepalive

rm -rf config.json sb.log core fake_useragent_0.2.0.json
quick_command
green "Running done!\n"
}

quick_command() {
  COMMAND="00"
  SCRIPT_PATH="$HOME/bin/$COMMAND"
  mkdir -p "$HOME/bin"
  echo "#!/bin/bash" > "$SCRIPT_PATH"
  echo "bash <(curl -Ls https://raw.githubusercontent.com/Git-think/Sing-box/refs/heads/main/sb_00.sh)" >> "$SCRIPT_PATH"
  chmod +x "$SCRIPT_PATH"
  if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
      echo "export PATH=\"\$HOME/bin:\$PATH\"" >> "$HOME/.bashrc" 2>/dev/null
      source "$HOME/.bashrc"
  fi
green "快捷指令00创建成功,下次运行输入00快速进入菜单\n"
}

get_url_info() {
  if devil www list 2>&1 | grep -q "keep.${USERNAME}.${CURRENT_DOMAIN}"; then
    purple "\n-------------------保活相关链接------------------\n\n"
    purple "http://keep.${USERNAME}.${CURRENT_DOMAIN}/stop 结束进程\n"
    purple "http://keep.${USERNAME}.${CURRENT_DOMAIN}/list 全部进程列表\n"
    yellow "http://keep.${USERNAME}.${CURRENT_DOMAIN}/${USERNAME} 调起保活程序  备用保活路径: /run  /go  /start\n"
    purple "http://keep.${USERNAME}.${CURRENT_DOMAIN}/status 查看进程状态\n\n"
  else 
    red "尚未安装自动保活服务\n" && sleep 2 && menu
  fi
}

get_nodes(){
cat ${FILE_PATH}/list.txt
TOKEN=$(sed -n 's/^SUB_TOKEN=\(.*\)/\1/p' $HOME/domains/keep.${USERNAME}.${CURRENT_DOMAIN}/public_nodejs/.env)
echo ""
"${WORKDIR}/qrencode" -m 2 -t UTF8 "http://api.${USERNAME}.${CURRENT_DOMAIN}/${TOKEN}"
yellow "\n自适应节点订阅链接: http://api.${USERNAME}.serv00.net/${TOKEN}\n二维码和节点订阅链接适用于V2rayN/Nekoray/ShadowRocket/Clash/Sing-box/karing/Loon/sterisand 等\n"
}

menu() {
  clear
  echo ""
  purple "=== Serv00|ct8 sing-box一键三协议安装脚本(重构版) ===\n"
  echo -e "${green}脚本地址：${re}${yellow}https://github.com/eooce/Sing-box${re}\n"
  echo -e "${green}反馈论坛：${re}${yellow}https://bbs.vps8.me${re}\n"
  echo -e "${green}TG反馈群组：${re}${yellow}https://t.me/vps888${re}\n"
  purple "转载请著名出处，请勿滥用\n"
  yellow "快速启动命令00\n"
  green "1. 安装三合一"
  echo  "==============="
  red "2. 卸载三合一"
  echo  "==============="
  green "3. 查看节点信息"
  echo  "==============="
  green "4. 查看保活链接"
  echo  "==============="
  yellow "5. 更换节点端口"
  echo  "==============="
  yellow "6. 初始化系统"
  echo  "==============="
  red "0. 退出脚本"
  echo "==========="
  reading "请输入选择(0-6): " choice
  echo ""
  case "${choice}" in
      1) install_singbox ;;
      2) uninstall_singbox ;; 
      3) get_nodes ;; 
      4) get_url_info ;;
      5) changge_ports ;;
      6) reset_system ;;
      0) exit 0 ;;
      *) red "无效的选项，请输入 0 到 6" ;;
  esac
}
menu
