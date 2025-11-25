#!/bin/sh
# LuCI Fixer - Tek Script Kurulum
# ZLT X28 için LuCI Onarım - Her boot'ta otomatik çalışır

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "┌──────────────────────────────────────┐"
echo "│         LuCI Fixer Kurulum           │"
echo "│         ZLT X28 - OpenWrt            │"
echo "└──────────────────────────────────────┘"
echo -e "${NC}"

# Ana fix fonksiyonu
luci_fix() {
    echo "🔧 LuCI fix uygulanıyor..."
    
    # 1. uhttpd'yi indir ve kur
    echo -n "📥 uhttpd indiriliyor... "
    wget -q https://raw.githubusercontent.com/EngineerMazid/ZLT-X28/main/uhttpd -O /usr/sbin/uhttpd
    if [ $? -eq 0 ]; then
        chmod +x /usr/sbin/uhttpd
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗ Hata!${NC}"
        return 1
    fi
    
    # 2. LuCI dosyalarını indir ve kur
    echo -n "📦 LuCI dosyaları indiriliyor... "
    wget -q https://raw.githubusercontent.com/EngineerMazid/ZLT-X28/main/luci_fixed.tgz -O /tmp/luci_fixed.tgz
    if [ $? -eq 0 ]; then
        tar xzf /tmp/luci_fixed.tgz -C /tmp
        [ -d "/tmp/www/luci-static" ] && cp -r /tmp/www/luci-static /www/
        [ -d "/tmp/usr/lib/lua/luci" ] && cp -r /tmp/usr/lib/lua/luci /usr/lib/lua/
        [ -d "/tmp/usr/share/luci" ] && cp -r /tmp/usr/share/luci /usr/share/
        rm -f /tmp/luci_fixed.tgz
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗ Hata!${NC}"
        return 1
    fi
    
    # 3. uhttpd'yi başlat
    echo -n "🚀 uhttpd başlatılıyor... "
    killall uhttpd 2>/dev/null
    sleep 2
    /usr/sbin/uhttpd -p 0.0.0.0:4153 -h /www &
    echo -e "${GREEN}✓${NC}"
    
    # 4. Cache temizle
    rm -rf /tmp/luci-*
    echo "🧹 Cache temizlendi"
    
    return 0
}

# Init script oluştur
create_init_script() {
    echo -n "📝 Init script oluşturuluyor... "
    
    cat > /etc/init.d/luci-fixer << 'EOF'
#!/bin/sh /etc/rc.common

START=95
USE_PROCD=1

START=95
STOP=10

start_service() {
    /usr/sbin/luci-fixer start
}

stop_service() {
    /usr/sbin/luci-fixer stop
}
EOF

    chmod +x /etc/init.d/luci-fixer
    echo -e "${GREEN}✓${NC}"
}

# Ana yönetici script oluştur
create_main_script() {
    echo -n "🔧 Ana script oluşturuluyor... "
    
    cat > /usr/sbin/luci-fixer << 'EOF'
#!/bin/sh
# LuCI Fixer - Ana Yönetici Script

case "$1" in
    start)
        # uhttpd'yi indir ve kur
        wget -q https://raw.githubusercontent.com/EngineerMazid/ZLT-X28/main/uhttpd -O /usr/sbin/uhttpd
        chmod +x /usr/sbin/uhttpd
        
        # LuCI dosyalarını indir ve kur
        wget -q https://raw.githubusercontent.com/EngineerMazid/ZLT-X28/main/luci_fixed.tgz -O /tmp/luci_fixed.tgz
        tar xzf /tmp/luci_fixed.tgz -C /tmp
        [ -d "/tmp/www/luci-static" ] && cp -r /tmp/www/luci-static /www/
        [ -d "/tmp/usr/lib/lua/luci" ] && cp -r /tmp/usr/lib/lua/luci /usr/lib/lua/
        [ -d "/tmp/usr/share/luci" ] && cp -r /tmp/usr/share/luci /usr/share/
        rm -f /tmp/luci_fixed.tgz
        
        # uhttpd'yi başlat
        killall uhttpd 2>/dev/null
        sleep 2
        /usr/sbin/uhttpd -p 0.0.0.0:4153 -h /www &
        
        # Cache temizle
        rm -rf /tmp/luci-*
        ;;
    stop)
        killall uhttpd 2>/dev/null
        ;;
    restart)
        killall uhttpd 2>/dev/null
        sleep 2
        /usr/sbin/uhttpd -p 0.0.0.0:4153 -h /www &
        ;;
    *)
        echo "Kullanım: $0 {start|stop|restart}"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/sbin/luci-fixer
    echo -e "${GREEN}✓${NC}"
}

# Kurulumu başlat
echo ""
echo "📦 Kurulum başlatılıyor..."

# 1. Ana script'i oluştur
create_main_script

# 2. Init script oluştur
create_init_script

# 3. İlk fix uygula
echo ""
echo "🎯 İlk fix uygulanıyor..."
luci_fix

# 4. Servisi etkinleştir
echo -n "⚙️  Servis etkinleştiriliyor... "
/etc/init.d/luci-fixer enable
echo -e "${GREEN}✓${NC}"

echo ""
echo -e "${GREEN}"
echo "┌──────────────────────────────────────┐"
echo "│          KURULUM TAMAMLANDI!         │"
echo "└──────────────────────────────────────┘"
echo -e "${NC}"
echo ""
echo -e "${YELLOW}📢 ÖNEMLİ BİLGİLER:${NC}"
echo "   • LuCI: http://$(uci get network.lan.ipaddr 2>/dev/null || echo '192.168.1.1'):4153"
echo "   • Her boot'ta otomatik çalışacak"
echo "   • Manuel kontrol: /usr/sbin/luci-fixer"
echo ""
echo -e "${BLUE}🔧 KULLANIM:${NC}"
echo "   /usr/sbin/luci-fixer start    - Başlat"
echo "   /usr/sbin/luci-fixer stop     - Durdur" 
echo "   /usr/sbin/luci-fixer restart  - Yeniden başlat"
echo "   /etc/init.d/luci-fixer enable - Boot'ta açılmayı etkinleştir"
echo "   /etc/init.d/luci-fixer disable - Boot'ta açılmayı devre dışı bırak"
echo ""

# Servis durumunu kontrol et
sleep 3
echo -e "${YELLOW}🔍 Servis durumu kontrol ediliyor...${NC}"
if pgrep uhttpd > /dev/null; then
    echo -e "${GREEN}✅ uhttpd çalışıyor!${NC}"
else
    echo -e "${RED}❌ uhttpd çalışmıyor!${NC}"
fi

echo ""
echo -e "${GREEN}🎉 İşlem tamam! LuCI artık 4153 portunda erişilebilir.${NC}"
