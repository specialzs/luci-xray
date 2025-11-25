# luci-xray Kurulum Rehberi X28

> OpenWrt veya uyumlu sistemlerde LuCI ve Xray yönetim arayüzünü otomatik kurmak için.

---

## Kurulum Adımları

Aşağıdaki komutları sırayla terminalde çalıştırabilirsiniz:

```bash
# 1. Depoyu klonlayın
git clone https://github.com/specialzs/luci-xray.git
cd luci-xray
```
```bash
# 2. LuCI kurulumunu başlat
chmod +x luci-install.sh
./luci-install.sh
```

```bash
# 3. LuCI kurulumu bitince Xray manager kurulumu ve başlatma
chmod +x xray-manager.sh
./xray-manager.sh
