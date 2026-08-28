#!/bin/bash
set -e
cd "$(dirname "$0")"
APP_NAME="MTProto Finder"
APPIMAGE="$(pwd)/MTProto-Finder-x86_64.AppImage"
AUTOSTART_DIR="$HOME/.config/autostart"
DESKTOP_FILE="$AUTOSTART_DIR/mtproto-finder.desktop"

if [ ! -f "$APPIMAGE" ]; then
    echo "Ошибка: AppImage не найден по пути: $APPIMAGE"
    exit 1
fi

mkdir -p "$AUTOSTART_DIR"

cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=${APP_NAME}
Comment=Find working MTProto proxies for Telegram with real ping
Exec=${APPIMAGE}
Icon=${APPIMAGE}
Terminal=false
Categories=Network;
StartupNotify=false
X-KDE-autostart-after=panel
EOF

chmod +x "$APPIMAGE"
echo "Автозапуск установлен: $DESKTOP_FILE"
echo "Приложение будет запускаться автоматически при входе в систему."
