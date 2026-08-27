#!/bin/bash
# Сборка MTProto Finder в AppImage.
# Зависимости: python-pyqt6, fuse2, appimagetool (или укажите путь к нему в $APPIMAGETOOL)
set -e
cd "$(dirname "$0")"

APPIMAGETOOL="${APPIMAGETOOL:-appimagetool}"

rm -rf build dist AppDir mtproto-finder.spec
python3 -m PyInstaller --noconfirm --windowed --name mtproto-finder \
    --add-data logo.png:. main.py

mkdir -p AppDir/usr/bin AppDir/usr/share/icons/hicolor/256x256/apps
cp -r dist/mtproto-finder/* AppDir/usr/bin/
cp logo.png AppDir/mtproto-finder.png
cp logo.png AppDir/usr/share/icons/hicolor/256x256/apps/mtproto-finder.png

cat > AppDir/mtproto-finder.desktop <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=MTProto Finder
Comment=Поиск рабочих MTProto-прокси для Telegram с реальным пингом
Exec=AppRun
Icon=mtproto-finder
Terminal=false
Categories=Network;
DESKTOP

cat > AppDir/AppRun <<'APPRUN'
#!/bin/bash
SELF="$(readlink -f "$0")"
HERE="${SELF%/*}"
exec "$HERE/usr/bin/mtproto-finder" "$@"
APPRUN
chmod +x AppDir/AppRun
ln -sf usr/bin/mtproto-finder AppDir/.DirIcon

"$APPIMAGETOOL" AppDir MTProto-Finder-x86_64.AppImage
echo "Готово: MTProto-Finder-x86_64.AppImage"
