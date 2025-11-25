#!/bin/sh
# Xray Manager - Tam Yönetim Script
# ZLT X28 - OpenWrt 19.07
# Kurulum | Kaldırma | Güncelleme | URL Import

VERSION="1.1.0"
XRAY_VERSION="1.8.7"
XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-arm64-v8a.zip"

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${BLUE}  $1${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

check_requirements() {
    print_header "Gereksinimler Kontrol Ediliyor"
    
    local missing=""
    
    command -v wget >/dev/null 2>&1 || missing="${missing}wget "
    command -v unzip >/dev/null 2>&1 || missing="${missing}unzip "
    command -v jq >/dev/null 2>&1 || missing="${missing}jq "
    
    if [ -n "$missing" ]; then
        print_error "Eksik paketler: $missing"
        echo ""
        echo "Yüklemek için: opkg update && opkg install $missing"
        return 1
    fi
    
    print_success "Tüm gereksinimler mevcut"
    return 0
}

# URL Decode Fonksiyonu
url_decode() {
    local encoded="$1"
    printf '%b' "${encoded//%/\\x}"
}

# Base64 Decode Fonksiyonu
base64_decode() {
    local encoded="$1"
    # Padding ekle ve decode et
    local padding=$((4 - ${#encoded} % 4))
    if [ $padding -ne 4 ]; then
        encoded="${encoded}$(printf '=%.0s' $(seq 1 $padding))"
    fi
    echo "$encoded" | base64 -d 2>/dev/null
}

# VLESS Link Parser
parse_vless() {
    local vless_url="$1"
    
    print_header "VLESS URL Parse Ediliyor"
    
    # vless:// prefix'i kaldır
    local encoded="${vless_url#vless://}"
    
    # Kullanıcı bilgilerini ve sunucu bilgilerini ayır
    local user_info="${encoded%@*}"
    local server_info="${encoded#*@}"
    
    if [ -z "$user_info" ] || [ -z "$server_info" ]; then
        print_error "Geçersiz VLESS URL formatı!"
        return 1
    fi
    
    # UUID ve parametreleri ayır
    local uuid="${user_info%#*}"
    local params_str="${user_info#*#}"
    
    # Sunucu bilgilerini ayır
    local server="${server_info%/*}"
    local server_host="${server%:*}"
    local server_port="${server#*:}"
    local path_params="${server_info#*/}"
    
    if [ -z "$uuid" ] || [ -z "$server_host" ] || [ -z "$server_port" ]; then
        print_error "Eksik VLESS bilgileri (UUID, sunucu veya port)"
        return 1
    fi
    
    # Parametreleri parse et
    local type="tcp"
    local security="none"
    local path=""
    local host=""
    local sni=""
    local serviceName=""
    local flow=""
    local encryption="none"
    
    # Query parametrelerini parse et
    if echo "$path_params" | grep -q "?"; then
        local query_str="${path_params#*?}"
        
        type=$(echo "$query_str" | grep -oE 'type=[^&]+' | cut -d= -f2 || echo "tcp")
        security=$(echo "$query_str" | grep -oE 'security=[^&]+' | cut -d= -f2 || echo "none")
        path=$(echo "$query_str" | grep -oE 'path=[^&]+' | cut -d= -f2 | sed 's/%2F/\//g' || echo "")
        host=$(echo "$query_str" | grep -oE 'host=[^&]+' | cut -d= -f2 || echo "")
        sni=$(echo "$query_str" | grep -oE 'sni=[^&]+' | cut -d= -f2 || echo "")
        serviceName=$(echo "$query_str" | grep -oE 'serviceName=[^&]+' | cut -d= -f2 || echo "")
        flow=$(echo "$query_str" | grep -oE 'flow=[^&]+' | cut -d= -f2 || echo "")
        encryption=$(echo "$query_str" | grep -oE 'encryption=[^&]+' | cut -d= -f2 || echo "none")
    fi
    
    # Fragment parametrelerini parse et (params_str)
    if [ -n "$params_str" ]; then
        type=$(echo "$params_str" | grep -oE 'type=[^&]+' | cut -d= -f2 || echo "$type")
        security=$(echo "$params_str" | grep -oE 'security=[^&]+' | cut -d= -f2 || echo "$security")
        path=$(echo "$params_str" | grep -oE 'path=[^&]+' | cut -d= -f2 | sed 's/%2F/\//g' || echo "$path")
        host=$(echo "$params_str" | grep -oE 'host=[^&]+' | cut -d= -f2 || echo "$host")
        sni=$(echo "$params_str" | grep -oE 'sni=[^&]+' | cut -d= -f2 || echo "$sni")
        serviceName=$(echo "$params_str" | grep -oE 'serviceName=[^&]+' | cut -d= -f2 || echo "$serviceName")
        flow=$(echo "$params_str" | grep -oE 'flow=[^&]+' | cut -d= -f2 || echo "$flow")
        encryption=$(echo "$params_str" | grep -oE 'encryption=[^&]+' | cut -d= -f2 || echo "$encryption")
    fi
    
    # URL decode uygula
    type=$(url_decode "$type")
    security=$(url_decode "$security")
    path=$(url_decode "$path")
    host=$(url_decode "$host")
    sni=$(url_decode "$sni")
    serviceName=$(url_decode "$serviceName")
    flow=$(url_decode "$flow")
    encryption=$(url_decode "$encryption")
    
    print_success "VLESS parametreleri parse edildi"
    echo "Sunucu: $server_host:$server_port"
    echo "UUID: $uuid"
    echo "Type: $type, Security: $security"
    echo "Path: $path, Host: $host"
    
    # Config oluştur
    cat > /etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "error": "/var/log/xray/error.log",
    "access": "/var/log/xray/access.log"
  },
  "inbounds": [
    {
      "port": 1080,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 1081,
      "protocol": "http",
      "settings": {}
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "$server_host",
            "port": $server_port,
            "users": [
              {
                "id": "$uuid",
                "encryption": "$encryption",
                "flow": "$flow"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "$type",
        "security": "$security",
EOF

    # TLS Settings
    if [ "$security" = "tls" ] || [ "$security" = "reality" ]; then
        cat >> /etc/xray/config.json << EOF
        "tlsSettings": {
          "serverName": "$sni"
        },
EOF
    fi

    # Stream Settings
    cat >> /etc/xray/config.json << EOF
        $(if [ "$type" = "tcp" ]; then
            echo '"tcpSettings": {'
            echo '  "header": {'
            echo '    "type": "none"'
            echo '  }'
            echo '}'
        elif [ "$type" = "ws" ]; then
            echo '"wsSettings": {'
            if [ -n "$path" ]; then
                echo "  \"path\": \"$path\""
            fi
            if [ -n "$host" ]; then
                if [ -n "$path" ]; then
                    echo "  ,\"headers\": {"
                else
                    echo "  \"headers\": {"
                fi
                echo "    \"Host\": \"$host\""
                echo "  }"
            fi
            echo '}'
        elif [ "$type" = "grpc" ]; then
            echo '"grpcSettings": {'
            echo "  \"serviceName\": \"$serviceName\""
            echo '}'
        elif [ "$type" = "kcp" ]; then
            echo '"kcpSettings": {'
            echo '  "mtu": 1350,'
            echo '  "tti": 20,'
            echo '  "uplinkCapacity": 5,'
            echo '  "downlinkCapacity": 20,'
            echo '  "congestion": false,'
            echo '  "readBufferSize": 1,'
            echo '  "writeBufferSize": 1,'
            echo '  "header": {'
            echo '    "type": "none"'
            echo '  }'
            echo '}'
        else
            echo '"tcpSettings": {'
            echo '  "header": {'
            echo '    "type": "none"'
            echo '  }'
            echo '}'
        fi)
      },
      "tag": "proxy"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": []
  }
}
EOF

    print_success "VLESS config oluşturuldu"
    return 0
}

# VMess Link Parser
parse_vmess() {
    local vmess_url="$1"
    
    print_header "VMess URL Parse Ediliyor"
    
    # vmess:// prefix'i kaldır
    local encoded="${vmess_url#vmess://}"
    
    # Base64 decode
    local decoded=$(base64_decode "$encoded")
    
    if [ -z "$decoded" ]; then
        print_error "VMess link decode edilemedi!"
        return 1
    fi
    
    # JSON parse
    local config=$(echo "$decoded" | jq -r '.' 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        print_error "Geçersiz VMess JSON formatı!"
        return 1
    fi
    
    # Config değerlerini al
    local ps=$(echo "$config" | jq -r '.ps // "VMess Connection"')
    local add=$(echo "$config" | jq -r '.add')
    local port=$(echo "$config" | jq -r '.port')
    local id=$(echo "$config" | jq -r '.id')
    local aid=$(echo "$config" | jq -r '.aid // "0"')
    local net=$(echo "$config" | jq -r '.net // "tcp"')
    local type=$(echo "$config" | jq -r '.type // "none"')
    local host=$(echo "$config" | jq -r '.host // ""')
    local path=$(echo "$config" | jq -r '.path // ""')
    local tls=$(echo "$config" | jq -r '.tls // "none"')
    local sni=$(echo "$config" | jq -r '.sni // ""')
    
    print_success "VMess parametreleri parse edildi"
    echo "Açıklama: $ps"
    echo "Sunucu: $add:$port"
    echo "Protocol: $net, TLS: $tls"
    
    # Config oluştur
    cat > /etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "error": "/var/log/xray/error.log",
    "access": "/var/log/xray/access.log"
  },
  "inbounds": [
    {
      "port": 1080,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 1081,
      "protocol": "http",
      "settings": {}
    }
  ],
  "outbounds": [
    {
      "protocol": "vmess",
      "settings": {
        "vnext": [
          {
            "address": "$add",
            "port": $port,
            "users": [
              {
                "id": "$id",
                "alterId": $aid,
                "security": "auto"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "$net",
        "security": "$tls",
EOF

    # TLS Settings
    if [ "$tls" = "tls" ]; then
        cat >> /etc/xray/config.json << EOF
        "tlsSettings": {
          "serverName": "$sni"
        },
EOF
    fi

    # Stream Settings
    cat >> /etc/xray/config.json << EOF
        $(if [ "$net" = "tcp" ]; then
            echo '"tcpSettings": {'
            echo '  "header": {'
            echo "    \"type\": \"$type\""
            if [ "$type" = "http" ] && [ -n "$host" ]; then
                echo '    ,"request": {'
                echo '      "headers": {'
                echo "        \"Host\": [\"$host\"]"
                echo '      }'
                echo '    }'
            fi
            echo '  }'
            echo '}'
        elif [ "$net" = "ws" ]; then
            echo '"wsSettings": {'
            if [ -n "$path" ]; then
                echo "  \"path\": \"$path\""
            fi
            if [ -n "$host" ]; then
                if [ -n "$path" ]; then
                    echo '  ,"headers": {'
                else
                    echo '  "headers": {'
                fi
                echo "    \"Host\": \"$host\""
                echo '  }'
            fi
            echo '}'
        elif [ "$net" = "h2" ]; then
            echo '"httpSettings": {'
            if [ -n "$path" ]; then
                echo "  \"path\": \"$path\""
            fi
            if [ -n "$host" ]; then
                if [ -n "$path" ]; then
                    echo '  ,"host": ['
                else
                    echo '  "host": ['
                fi
                echo "    \"$host\""
                echo '  ]'
            fi
            echo '}'
        elif [ "$net" = "grpc" ]; then
            echo '"grpcSettings": {'
            echo "  \"serviceName\": \"$path\""
            echo '}'
        else
            echo '"tcpSettings": {'
            echo '  "header": {'
            echo '    "type": "none"'
            echo '  }'
            echo '}'
        fi)
      },
      "tag": "proxy"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": []
  }
}
EOF

    print_success "VMess config oluşturuldu: $ps"
    return 0
}

# Ana Parser Fonksiyonu
parse_config_url() {
    local url="$1"
    
    print_header "Config URL Parse Ediliyor"
    
    # jq kontrolü
    if ! command -v jq >/dev/null 2>&1; then
        print_error "jq kurulu değil! Önce yükleyin: opkg update && opkg install jq"
        return 1
    fi
    
    # URL tipini belirle
    if [[ "$url" == vmess://* ]]; then
        parse_vmess "$url"
    elif [[ "$url" == vless://* ]]; then
        parse_vless "$url"
    else
        print_error "Desteklenmeyen link formatı!"
        echo "Desteklenen formatlar: vmess://, vless://"
        return 1
    fi
    
    if [ $? -eq 0 ]; then
        print_success "Config başarıyla oluşturuldu!"
        echo ""
        echo -e "${YELLOW}⚠ Config test ediliyor...${NC}"
        if /usr/bin/xray test -config /etc/xray/config.json; then
            print_success "Config testi başarılı!"
            echo ""
            echo -e "${GREEN}🚀 Servis yeniden başlatılıyor...${NC}"
            /etc/init.d/xray restart
            sleep 2
            show_status
        else
            print_error "Config testi başarısız! Lütfen config'i kontrol edin."
        fi
    else
        print_error "Config oluşturulamadı!"
    fi
}

install_xray() {
    print_header "Xray Kurulumu Başlıyor"
    
    # Gereksinimler
    check_requirements || exit 1
    
    # 1. Xray Binary
    echo ""
    echo "[1/8] Xray-core indiriliyor..."
    cd /tmp
    rm -f xray.zip xray geoip.dat geosite.dat
    
    wget -O xray.zip "$XRAY_URL"
    
    if [ -f xray.zip ] && [ -s xray.zip ]; then
        print_success "İndirme tamamlandı ($(ls -lh xray.zip | awk '{print $5}'))"
    else
        print_error "İndirme başarısız!"
        exit 1
    fi
    
    unzip -q -o xray.zip
    chmod +x xray
    mv xray /usr/bin/xray
    rm -f xray.zip geoip.dat geosite.dat
    
    mkdir -p /etc/xray
    mkdir -p /var/log/xray
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    
    print_success "Xray binary kuruldu: $(xray version | head -n1)"
    
    # 2. UCI Config
    echo ""
    echo "[2/8] UCI config oluşturuluyor..."
    cat > /etc/config/xray << 'EOF'
config xray 'config'
	option enabled '0'
	option config_file '/etc/xray/config.json'
	option log_level 'warning'
EOF
    print_success "UCI config oluşturuldu"
    
    # 3. Init Script
    echo ""
    echo "[3/8] Init script oluşturuluyor..."
    cat > /etc/init.d/xray << 'EOF'
#!/bin/sh /etc/rc.common

START=99
STOP=10
USE_PROCD=1

PROG=/usr/bin/xray
CONF=/etc/xray/config.json

start_service() {
	config_load xray
	local enabled
	config_get_bool enabled config enabled 0
	[ "$enabled" -eq 0 ] && return 1
	
	[ ! -f "$CONF" ] && {
		logger -t xray "Config file not found: $CONF"
		return 1
	}
	
	procd_open_instance
	procd_set_param command $PROG run -config $CONF
	procd_set_param respawn ${respawn_threshold:-3600} ${respawn_timeout:-5} ${respawn_retry:-5}
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_set_param file $CONF
	procd_close_instance
	
	logger -t xray "Xray started"
}

stop_service() {
	killall xray 2>/dev/null
	logger -t xray "Xray stopped"
}

reload_service() {
	stop
	sleep 1
	start
}

service_triggers() {
	procd_add_reload_trigger "xray"
}
EOF
    chmod +x /etc/init.d/xray
    print_success "Init script oluşturuldu"
    
    # 4. Default Config
    echo ""
    echo "[4/8] Varsayılan config oluşturuluyor..."
    cat > /etc/xray/config.json << 'EOF'
{
  "log": {
    "loglevel": "warning",
    "error": "/var/log/xray/error.log",
    "access": "/var/log/xray/access.log"
  },
  "inbounds": [
    {
      "port": 1080,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 1081,
      "protocol": "http",
      "settings": {}
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
    print_success "Varsayılan config oluşturuldu"
    
    # 5. LuCI Controller
    echo ""
    echo "[5/8] LuCI controller oluşturuluyor..."
    mkdir -p /usr/lib/lua/luci/controller
    cat > /usr/lib/lua/luci/controller/xray.lua << 'EOF'
module("luci.controller.xray", package.seeall)

function index()
    if not nixio.fs.access("/etc/config/xray") then
        return
    end

    local page
    
    page = entry({"admin", "services", "xray"}, firstchild(), _("Xray"), 60)
    page.dependent = false
    
    entry({"admin", "services", "xray", "general"}, cbi("xray/general"), _("General Settings"), 1)
    entry({"admin", "services", "xray", "config"}, cbi("xray/config"), _("Configuration"), 2)
    entry({"admin", "services", "xray", "import"}, cbi("xray/import"), _("Import Config"), 3)
    entry({"admin", "services", "xray", "status"}, call("action_status"))
    entry({"admin", "services", "xray", "logs"}, call("action_logs"))
    entry({"admin", "services", "xray", "parse_url"}, call("action_parse_url"))
end

function action_status()
    local sys = require "luci.sys"
    local util = require "luci.util"
    local status = {}
    
    local pid = util.trim(sys.exec("pidof xray 2>/dev/null"))
    if pid ~= "" then
        status.running = true
    else
        status.running = false
    end
    
    if status.running then
        local uptime_cmd = sys.exec("ps -o etime= -p " .. pid .. " 2>/dev/null")
        status.uptime = util.trim(uptime_cmd)
        
        local mem_cmd = sys.exec("cat /proc/" .. pid .. "/status 2>/dev/null | grep VmRSS")
        local mem = mem_cmd:match("(%d+)")
        if mem then
            status.memory = string.format("%.1f MB", tonumber(mem) / 1024)
        else
            status.memory = "N/A"
        end
    else
        status.uptime = "N/A"
        status.memory = "N/A"
    end
    
    local version_cmd = sys.exec("/usr/bin/xray version 2>/dev/null | head -n1")
    status.version = version_cmd:match("Xray ([%d%.]+)") or version_cmd:match("([%d%.]+)") or "Unknown"
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(status)
end

function action_logs()
    local fs = require "nixio.fs"
    local log_content = ""
    
    if fs.access("/var/log/xray/error.log") then
        local f = io.open("/var/log/xray/error.log", "r")
        if f then
            log_content = f:read("*a")
            f:close()
        end
    end
    
    if log_content == "" then
        log_content = "No logs available"
    end
    
    luci.http.prepare_content("text/plain; charset=utf-8")
    luci.http.write(log_content)
end

function action_parse_url()
    local http = require "luci.http"
    local util = require "luci.util"
    local fs = require "nixio.fs"
    local json = require "luci.jsonc"
    
    local result = { success = false, message = "" }
    
    local url = http.formvalue("url")
    if not url or url == "" then
        result.message = "URL cannot be empty!"
        luci.http.prepare_content("application/json")
        luci.http.write_json(result)
        return
    end
    
    -- Sistem komutunu kullanarak parse et
    local tmp_file="/tmp/xray_import_url.txt"
    fs.writefile(tmp_file, url)
    
    local parse_cmd = "/usr/bin/xray_manager.sh import \"" .. url .. "\" 2>&1"
    local parse_result = util.trim(sys.exec(parse_cmd))
    
    if parse_result:find("başarıyla") or parse_result:find("success") then
        result.success = true
        result.message = "Configuration imported successfully!"
    else
        result.message = "Import failed: " .. parse_result
    end
    
    fs.remove(tmp_file)
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end
EOF
    print_success "LuCI controller oluşturuldu"
    
    # 6. LuCI CBI Models
    echo ""
    echo "[6/8] LuCI CBI models oluşturuluyor..."
    mkdir -p /usr/lib/lua/luci/model/cbi/xray
    
    cat > /usr/lib/lua/luci/model/cbi/xray/general.lua << 'EOF'
local sys = require "luci.sys"
local util = require "luci.util"

m = Map("xray", translate("Xray"), translate("Xray is a platform for building proxies to bypass network restrictions."))

s = m:section(TypedSection, "xray", translate("Service Status"))
s.anonymous = true
s.addremove = false

o = s:option(DummyValue, "_status", translate("Current Status"))
o.template = "xray/status"
o.value = translate("Checking...")

s = m:section(TypedSection, "xray", translate("Service Control"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enabled", translate("Enable Xray Service"))
o.rmempty = false
o.default = "0"

o = s:option(Value, "config_file", translate("Configuration File Path"))
o.default = "/etc/xray/config.json"
o.datatype = "file"
o.placeholder = "/etc/xray/config.json"

o = s:option(ListValue, "log_level", translate("Log Level"))
o:value("debug", translate("Debug"))
o:value("info", translate("Info"))
o:value("warning", translate("Warning"))
o:value("error", translate("Error"))
o:value("none", translate("None"))
o.default = "warning"
o.rmempty = false

s = m:section(TypedSection, "xray", translate("Service Actions"))
s.anonymous = true
s.addremove = false

btn_start = s:option(Button, "_start", translate("Start Service"))
btn_start.inputtitle = translate("Start")
btn_start.inputstyle = "apply"
function btn_start.write()
    sys.call("/etc/init.d/xray start >/dev/null 2>&1 &")
end

btn_stop = s:option(Button, "_stop", translate("Stop Service"))
btn_stop.inputtitle = translate("Stop")
btn_stop.inputstyle = "reset"
function btn_stop.write()
    sys.call("/etc/init.d/xray stop >/dev/null 2>&1")
end

btn_restart = s:option(Button, "_restart", translate("Restart Service"))
btn_restart.inputtitle = translate("Restart")
btn_restart.inputstyle = "reload"
function btn_restart.write()
    sys.call("/etc/init.d/xray restart >/dev/null 2>&1 &")
end

btn_logs = s:option(Button, "_logs", translate("View Logs"))
btn_logs.inputtitle = translate("View Logs")
btn_logs.inputstyle = "edit"
btn_logs.template = "xray/logs_button"

return m
EOF
    
    cat > /usr/lib/lua/luci/model/cbi/xray/config.lua << 'EOF'
local fs = require "nixio.fs"
local sys = require "luci.sys"

m = Map("xray", translate("Xray Configuration"), translate("Edit Xray JSON configuration file. Be careful with syntax!"))

s = m:section(TypedSection, "xray", "")
s.anonymous = true
s.addremove = false

o = s:option(TextValue, "_config")
o.rows = 30
o.wrap = "off"
o.rmempty = false

function o.cfgvalue(self, section)
    return fs.readfile("/etc/xray/config.json") or ""
end

function o.write(self, section, value)
    if value then
        value = value:gsub("\r\n?", "\n")
        local tmpfile = "/tmp/xray_config_test.json"
        fs.writefile(tmpfile, value)
        
        local test = sys.call("/usr/bin/xray test -c " .. tmpfile .. " >/dev/null 2>&1")
        if test == 0 then
            fs.writefile("/etc/xray/config.json", value)
            sys.call("/etc/init.d/xray reload >/dev/null 2>&1 &")
            m.message = translate("Configuration saved successfully and service reloaded.")
        else
            m.message = translate("ERROR: Invalid JSON syntax! Configuration NOT saved.")
        end
        fs.remove(tmpfile)
    end
end

return m
EOF

    # YENİ: Import CBI Model
    cat > /usr/lib/lua/luci/model/cbi/xray/import.lua << 'EOF'
local sys = require "luci.sys"
local http = require "luci.http"

m = Map("xray", translate("Import Xray Configuration"), 
        translate("Import configuration from VMess/VLESS URL. The service will be restarted automatically."))

s = m:section(TypedSection, "xray", translate("URL Import"))
s.anonymous = true
s.addremove = false

-- URL input
o = s:option(TextValue, "config_url", translate("Configuration URL"))
o.rows = 3
o.wrap = "off"
o.datatype = "string"
o.placeholder = "vless://uuid@server:port?type=ws&security=tls&path=/path&host=example.com"

-- Help text
help = s:option(DummyValue, "_help", translate("Supported Formats"))
help.rawhtml = true
help.value = [[
<div style="background: #f9f9f9; padding: 10px; border-radius: 5px; font-size: 12px;">
<strong>VMess:</strong> vmess://eyJ2IjoiMiIsInBzIjoiIiw...<br>
<strong>VLESS:</strong> vless://uuid@server:port?type=ws&path=/path&security=tls<br>
<br>
<strong>Supported parameters:</strong><br>
• type: tcp, ws, grpc, kcp<br>
• security: none, tls, reality<br>
• path, host, sni, serviceName, flow, encryption
</div>
]]

-- Import button
btn_import = s:option(Button, "_import", translate("Import Configuration"))
btn_import.inputtitle = translate("Import and Apply")
btn_import.inputstyle = "apply"

function btn_import.write(self, section)
    local url = m:formvalue("cbid.xray._import.config_url") or ""
    
    if url == "" then
        m.message = translate("Error: URL cannot be empty!")
        return
    end
    
    -- AJAX request to parse URL
    local luci_dispatcher = require "luci.dispatcher"
    local import_url = luci_dispatcher.build_url("admin", "services", "xray", "parse_url")
    
    m.message = translate("Importing configuration... Please wait.")
    
    -- JavaScript for AJAX call
    http.write([[<script type="text/javascript">
        var url = ']] .. url .. [[';
        
        fetch(']] .. import_url .. [[', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'url=' + encodeURIComponent(url)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('✅ ' + data.message);
                window.location.href = ']] .. luci_dispatcher.build_url("admin", "services", "xray", "config") .. [[';
            } else {
                alert('❌ ' + data.message);
            }
        })
        .catch(error => {
            alert('❌ Import error: ' + error);
        });
    </script>]])
end

-- Current config preview
s = m:section(TypedSection, "xray", translate("Current Configuration Preview"))
s.anonymous = true

o = s:option(TextValue, "_current_config")
o.rows = 10
o.readonly = true
o.wrap = "off"

function o.cfgvalue(self, section)
    local fs = require "nixio.fs"
    local jsonc = require "luci.jsonc"
    
    local config_content = fs.readfile("/etc/xray/config.json") or "{}"
    local ok, formatted = pcall(jsonc.stringify, jsonc.parse(config_content), true)
    
    if ok then
        return formatted
    else
        return config_content
    end
end

return m
EOF

    print_success "CBI models oluşturuldu"
    
    # 7. LuCI Templates
    echo ""
    echo "[7/8] LuCI templates oluşturuluyor..."
    mkdir -p /usr/lib/lua/luci/view/xray
    
    cat > /usr/lib/lua/luci/view/xray/status.htm << 'EOF'
<%+cbi/valueheader%>

<script type="text/javascript">//<![CDATA[
    XHR.poll(3, '<%=luci.dispatcher.build_url("admin", "services", "xray", "status")%>', null,
        function(x, status) {
            var tb = document.getElementById('xray_status');
            if (tb && status) {
                var html = '';
                if (status.running) {
                    html += '<span style="color:green;font-weight:bold;font-size:14px">● Running</span><br/>';
                    html += '<small>Version: <b>' + status.version + '</b> | ';
                    html += 'Uptime: <b>' + status.uptime + '</b> | ';
                    html += 'Memory: <b>' + status.memory + '</b></small>';
                } else {
                    html += '<span style="color:red;font-weight:bold;font-size:14px">● Stopped</span><br/>';
                    html += '<small>Version: <b>' + status.version + '</b></small>';
                }
                
                // Import quick link
                html += '<br><br><a href="<%=luci.dispatcher.build_url("admin", "services", "xray", "import")%>" class="cbi-button cbi-button-apply" style="font-size:12px">📥 Import Config from URL</a>';
                
                tb.innerHTML = html;
            }
        }
    );
//]]></script>

<div id="xray_status" style="padding:10px;background:#f9f9f9;border-radius:5px">
    <em><%:Checking status...%></em>
</div>

<%+cbi/valuefooter%>
EOF
    
    cat > /usr/lib/lua/luci/view/xray/logs_button.htm << 'EOF'
<%+cbi/valueheader%>

<input class="cbi-button cbi-button-edit" type="button" value="<%:View Logs%>" 
       onclick="window.open('<%=luci.dispatcher.build_url("admin", "services", "xray", "logs")%>', '_blank', 'width=800,height=600,scrollbars=yes')" />

<%+cbi/valuefooter%>
EOF
    print_success "Templates oluşturuldu"
    
    # 8. RPCD ACL
    echo ""
    echo "[8/8] RPCD ACL oluşturuluyor..."
    mkdir -p /usr/share/rpcd/acl.d
    cat > /usr/share/rpcd/acl.d/luci-app-xray.json << 'EOF'
{
    "luci-app-xray": {
        "description": "Grant access to Xray service",
        "read": {
            "ubus": {
                "service": ["list", "signal"]
            },
            "uci": ["xray"],
            "file": {
                "/etc/xray/config.json": ["read"],
                "/var/log/xray/*.log": ["read"]
            }
        },
        "write": {
            "ubus": {
                "service": ["signal"]
            },
            "uci": ["xray"],
            "cgi-io": ["exec"],
            "file": {
                "/etc/xray/config.json": ["write"],
                "/var/log/xray/*.log": ["write"]
            }
        }
    }
}
EOF
    print_success "RPCD ACL oluşturuldu"
    
    # Cleanup & Restart
    echo ""
    echo "Finalizasyon..."
    rm -rf /tmp/luci-indexcache /tmp/luci-modulecache/* /tmp/luci-sessions/*
    /etc/init.d/rpcd restart
    sleep 2
    /etc/init.d/xray enable
    
    print_header "✓ Kurulum Başarıyla Tamamlandı!"
    echo ""
    echo -e "${GREEN}🌐 LuCI Arayüzü:${NC}"
    echo "   http://$(uci get network.lan.ipaddr 2>/dev/null || echo '192.168.1.1')"
    echo ""
    echo -e "${GREEN}📁 Menü:${NC} Services → Xray"
    echo ""
    echo -e "${YELLOW}⚠ Sonraki Adımlar:${NC}"
    echo "   1. LuCI'ye giriş yapın"
    echo "   2. Services → Xray → Import Config"
    echo "   3. VLESS/VMess URL'nizi yapıştırın"
    echo "   4. Import and Apply butonuna basın"
    echo ""
}

uninstall_xray() {
    print_header "Xray Kaldırılıyor"
    
    # Stop service
    echo "Servis durduruluyor..."
    /etc/init.d/xray stop 2>/dev/null
    /etc/init.d/xray disable 2>/dev/null
    
    # Remove files
    echo "Dosyalar siliniyor..."
    rm -f /usr/bin/xray
    rm -rf /etc/xray
    rm -rf /var/log/xray
    rm -f /etc/init.d/xray
    rm -f /etc/config/xray
    rm -f /usr/lib/lua/luci/controller/xray.lua
    rm -rf /usr/lib/lua/luci/model/cbi/xray
    rm -rf /usr/lib/lua/luci/view/xray
    rm -f /usr/share/rpcd/acl.d/luci-app-xray.json
    
    # Clean cache
    rm -rf /tmp/luci-*
    
    # Restart services
    /etc/init.d/rpcd restart 2>/dev/null
    
    print_success "Xray tamamen kaldırıldı!"
    echo ""
    echo "LuCI'yi yenileyip kontrol edin (F5)"
    echo ""
}

update_xray() {
    print_header "Xray Güncelleniyor"
    
    if [ ! -f /usr/bin/xray ]; then
        print_error "Xray kurulu değil! Önce kurulum yapın."
        exit 1
    fi
    
    local current_version=$(xray version 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    echo "Mevcut versiyon: $current_version"
    echo "Yeni versiyon: $XRAY_VERSION"
    echo ""
    
    if [ "$current_version" = "$XRAY_VERSION" ]; then
        print_warning "Zaten güncel versiyondasınız!"
        return 0
    fi
    
    # Stop service
    /etc/init.d/xray stop
    
    # Backup config
    cp /etc/xray/config.json /tmp/xray_config_backup.json
    
    # Download new version
    echo "Yeni versiyon indiriliyor..."
    cd /tmp
    rm -f xray.zip xray
    wget -O xray.zip "$XRAY_URL"
    
    if [ -f xray.zip ] && [ -s xray.zip ]; then
        unzip -q -o xray.zip
        chmod +x xray
        mv xray /usr/bin/xray
        rm -f xray.zip geoip.dat geosite.dat
        
        # Restore config
        cp /tmp/xray_config_backup.json /etc/xray/config.json
        rm /tmp/xray_config_backup.json
        
        # Restart
        /etc/init.d/xray start
        
        print_success "Güncelleme tamamlandı!"
        echo "Yeni versiyon: $(xray version | head -n1)"
    else
        print_error "Güncelleme başarısız!"
        cp /tmp/xray_config_backup.json /etc/xray/config.json
        /etc/init.d/xray start
    fi
    echo ""
}

show_status() {
    print_header "Xray Durum Bilgisi"
    
    if [ ! -f /usr/bin/xray ]; then
        print_error "Xray kurulu değil!"
        return 1
    fi
    
    local version=$(xray version 2>/dev/null | head -n1)
    local pid=$(pidof xray)
    local enabled=$(uci get xray.config.enabled 2>/dev/null)
    
    echo "Versiyon: $version"
    echo "UCI Enabled: $enabled"
    echo ""
    
    if [ -n "$pid" ]; then
        print_success "Durum: Çalışıyor (PID: $pid)"
        local uptime=$(ps -o etime= -p $pid 2>/dev/null | awk '{print $1}')
        local mem=$(cat /proc/$pid/status 2>/dev/null | grep VmRSS | awk '{printf "%.1f MB", $2/1024}')
        echo "Uptime: $uptime"
        echo "Memory: $mem"
    else
        print_error "Durum: Durdurulmuş"
    fi
    
    echo ""
    echo "Config: /etc/xray/config.json"
    echo "Logs: /var/log/xray/error.log"
    echo ""
}

show_menu() {
    clear
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${BLUE}        Xray Manager v${VERSION}${NC}"
    echo -e "${BLUE}        ZLT X28 - OpenWrt 19.07${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  1) Kurulum (Install)"
    echo "  2) Kaldırma (Uninstall)"
    echo "  3) Güncelleme (Update)"
    echo "  4) Durum (Status)"
    echo "  5) Başlat (Start)"
    echo "  6) Durdur (Stop)"
    echo "  7) Yeniden Başlat (Restart)"
    echo "  8) Logları Göster (View Logs)"
    echo "  9) Config URL'den Yükle (From URL)"
    echo "  0) Çıkış (Exit)"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -n "Seçiminiz: "
}

# Main
if [ "$1" = "install" ]; then
    install_xray
    exit 0
elif [ "$1" = "uninstall" ]; then
    uninstall_xray
    exit 0
elif [ "$1" = "update" ]; then
    update_xray
    exit 0
elif [ "$1" = "status" ]; then
    show_status
    exit 0
elif [ "$1" = "import" ]; then
    if [ -n "$2" ]; then
        parse_config_url "$2"
    else
        echo "Kullanım: $0 import <vmess_or_vless_url>"
        exit 1
    fi
    exit 0
elif [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Kullanım: $0 [install|uninstall|update|status|import]"
    echo ""
    echo "  import <url>  - VMess/VLESS URL'den config içe aktar"
    echo ""
    echo "Parametresiz çalıştırırsanız interaktif menü açılır."
    exit 0
fi

# Interactive menu
while true; do
    show_menu
    read choice
    
    case $choice in
        1) install_xray; read -p "Devam etmek için ENTER..."; ;;
        2) uninstall_xray; read -p "Devam etmek için ENTER..."; ;;
        3) update_xray; read -p "Devam etmek için ENTER..."; ;;
        4) show_status; read -p "Devam etmek için ENTER..."; ;;
        5) /etc/init.d/xray start; show_status; read -p "Devam etmek için ENTER..."; ;;
        6) /etc/init.d/xray stop; show_status; read -p "Devam etmek için ENTER..."; ;;
        7) /etc/init.d/xray restart; show_status; read -p "Devam etmek için ENTER..."; ;;
        8) tail -50 /var/log/xray/error.log; read -p "Devam etmek için ENTER..."; ;;
        9) 
            echo -n "VMess/VLESS URL girin: "
            read config_url
            if [ -n "$config_url" ]; then
                parse_config_url "$config_url"
            else
                print_error "URL boş olamaz!"
            fi
            read -p "Devam etmek için ENTER..."; 
            ;;
        0) echo "Çıkış..."; exit 0; ;;
        *) echo "Geçersiz seçim!"; sleep 2; ;;
    esac
done
