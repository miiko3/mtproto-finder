#!/bin/bash
set -e
cd "$(dirname "$0")"
APPIMAGETOOL="${APPIMAGETOOL:-appimagetool}"
RUNTIME_FILE="${RUNTIME_FILE-}"
rm -rf build dist AppDir mtproto-finder.spec
python3 -m PyInstaller --noconfirm --windowed --name mtproto-finder --add-data logo.png:. main.py
mkdir -p AppDir/usr/bin AppDir/usr/share/icons/hicolor/256x256/apps
cp -r dist/mtproto-finder/* AppDir/usr/bin/
cp logo.png AppDir/mtproto-finder.png
cp logo.png AppDir/logo.png
cp logo.png AppDir/usr/share/icons/hicolor/256x256/apps/mtproto-finder.png
printf '[Desktop Entry]\nType=Application\nName=MTProto Finder\nComment=Find working MTProto proxies for Telegram with real ping\nExec=AppRun\nIcon=mtproto-finder\nTerminal=false\nCategories=Network;\n' > AppDir/mtproto-finder.desktop
printf '#!/bin/bash\nSELF="$(readlink -f "$0")"\nHERE="${SELF%%/*}"\nexec "$HERE/usr/bin/mtproto-finder" "$@"\n' > AppDir/AppRun
chmod +x AppDir/AppRun
ln -sf usr/bin/mtproto-finder AppDir/.DirIcon
APP_DIR="$(pwd)/AppDir"
OUT="$(pwd)/MTProto-Finder-x86_64.AppImage"
if [ -n "${RUNTIME_FILE:-}" ]; then
  ${APPIMAGETOOL} --runtime-file "$RUNTIME_FILE" "$APP_DIR" "$OUT"
else
  ${APPIMAGETOOL} "$APP_DIR" "$OUT"
fi
echo "Готово: MTProto-Finder-x86_64.AppImage"
