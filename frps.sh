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

install_frps() {
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
        download_frps
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
          pkill -f "frps_start.sh" >/dev/null 2>&1
          devil www del api.${USERNAME}.${CURRENT_DOMAIN} > /dev/null 2>&1
          rm -rf $HOME/domains/api.${USERNAME}.${CURRENT_DOMAIN} > /dev/null 2>&1
          green "\n系统初始化完成!\n"
         ;;
       *) menu ;;
  esac
}

download_frps() {
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
    KEY=$(echo "$entry" | cut -d ' ' -f 2) # 获取代号，例如 'web', 'npm', 'bot'

    # 根据代号KEY来决定文件名
    case "$KEY" in
        web)
            # frps 主程序
            NEW_FILENAME="$DOWNLOAD_DIR/frps"
            ;;
        npm|php)
            # 哪吒探针程序 (npm或php两种情况都包含)
            NEW_FILENAME="$DOWNLOAD_DIR/frps-agent"
            ;;
        bot)
            # 机器人程序
            NEW_FILENAME="$DOWNLOAD_DIR/frps-bot"
            ;;
        *)
            # 如果有未知的代号，使用随机名作为备用方案，防止出错
            RANDOM_NAME=$(generate_random_name)
            NEW_FILENAME="$DOWNLOAD_DIR/$RANDOM_NAME"
            ;;
    esac

    download_with_fallback "$URL" "$NEW_FILENAME"
    
    chmod +x "$NEW_FILENAME"
    # 将代号和新的文件名（如frps, frps-agent）存入FILE_MAP
    FILE_MAP[$KEY]="$NEW_FILENAME"
done
wait

output=$(./"$(basename ${FILE_MAP[web]})" generate reality-keypair)
private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')
[[ "$PROXYIP" == "true" ]] && SNI="time.is" || SNI="www.cerebrium.ai"
openssl ecparam -genkey -name prime256v1 -out "private.key"
openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=api.$USERNAME.${CURRENT_DOMAIN}"
  
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

# 如果是s14/s15,google/youtube/spotify相关的服务走warp出站
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
V2rayN_LINK="http://api.${USERNAME}.${CURRENT_DOMAIN}/v2.log"
AUTO_LINK="http://api.${USERNAME}.${CURRENT_DOMAIN}/${SUB_TOKEN}"
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

install_keepalive () {
    purple "正在安装保活服务中,请稍等......"
    
    # Create a configuration file for the keep-alive script
    cat > "${WORKDIR}/keepalive.conf" << EOF
export UUID="$UUID"
export VLESS_PORT="$VLESS_PORT"
export TUIC_PORT="$TUIC_PORT"
export HY2_PORT="$HY2_PORT"
export PROXYIP="$PROXYIP"
export USERNAME="$USERNAME"
export CURRENT_DOMAIN="$CURRENT_DOMAIN"
EOF

    KEEPALIVE_SCRIPT_URL="https://raw.githubusercontent.com/Git-think/Salksd/refs/heads/main/frps_start.sh"
    KEEPALIVE_SCRIPT_PATH="${WORKDIR}/frps_start.sh"

    # Download the keep-alive script
    $COMMAND "$KEEPALIVE_SCRIPT_PATH" "$KEEPALIVE_SCRIPT_URL"
    if [ $? -ne 0 ]; then
        red "下载保活脚本失败。"
        exit 1
    fi

    chmod +x "$KEEPALIVE_SCRIPT_PATH"

    # Kill any existing keep-alive script process
    pkill -f "frps_start.sh" >/dev/null 2>&1

    # Start the new keep-alive script in the background
    nohup "$KEEPALIVE_SCRIPT_PATH" >"${WORKDIR}/keepalive.log" 2>&1 &
    
    sleep 2
    if pgrep -f "frps_start.sh" > /dev/null; then
        green "\n全自动保活服务安装成功\n"
        
        # Create a shortcut command for frps_start.sh
        local keepalive_command="frps-start"
        local keepalive_path="$HOME/bin/$keepalive_command"
        mkdir -p "$HOME/bin"
        cat > "$keepalive_path" << EOF
#!/bin/bash

# The path to the actual keep-alive script, derived from WORKDIR
KEEPALIVE_SCRIPT_PATH="${WORKDIR}/frps_start.sh"

# Check if the keep-alive script is already running
if pgrep -f "frps_start.sh" > /dev/null; then
    echo "frps 保活服务已经在运行中。"
    exit 0
fi

# Kill any old instances just in case
pkill -f "frps_start.sh" >/dev/null 2>&1

# Start the new keep-alive script in the background
nohup "\$KEEPALIVE_SCRIPT_PATH" >/dev/null 2>&1 &

# Wait a moment and check if it started successfully
sleep 2
if pgrep -f "frps_start.sh" > /dev/null; then
    echo "frps 保活服务已成功启动到后台。"
else
    echo "frps 保活服务启动失败。"
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
  echo "bash <(curl -Ls https://raw.githubusercontent.com/Git-think/Salksd/refs/heads/main/frps.sh)" >> "$SCRIPT_PATH"
  chmod +x "$SCRIPT_PATH"
  if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
      echo "export PATH=\"\$HOME/bin:\$PATH\"" >> "$HOME/.bashrc" 2>/dev/null
      source "$HOME/.bashrc"
  fi
green "快捷指令00创建成功,下次运行输入00快速进入菜单\n"
}


get_nodes(){
cat ${FILE_PATH}/list.txt
echo ""
"${WORKDIR}/qrencode" -m 2 -t UTF8 "http://api.${USERNAME}.${CURRENT_DOMAIN}/${SUB_TOKEN}"
yellow "\n自适应节点订阅链接: http://api.${USERNAME}.${CURRENT_DOMAIN}/${SUB_TOKEN}\n二维码和节点订阅链接适用于V2rayN/Nekoray/ShadowRocket/Clash/Sing-box/karing/Loon/sterisand 等\n"
}

menu() {
  clear
  echo ""
  purple "=== Serv00|ct8 frps一键三协议安装脚本 ===\n"
  purple "转载请著名出处，请勿滥用\n"
  yellow "快速启动命令00\n"
  green "1. 安装三合一"
  echo  "==============="
  green "2. 查看节点信息"
  echo  "==============="
  yellow "3. 更换节点端口"
  echo  "==============="
  yellow "4. 初始化系统"
  echo  "==============="
  red "0. 退出脚本"
  echo "==========="
  reading "请输入选择(0-4): " choice
  echo ""
  case "${choice}" in
      1) install_frps ;;
      2) get_nodes ;;
      3) changge_ports ;;
      4) reset_system ;;
      0) exit 0 ;;
      *) red "无效的选项，请输入 0 到 4" ;;
  esac
}
menu
