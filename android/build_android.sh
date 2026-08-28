#!/bin/bash
set -e
cd "$(dirname "$0")"
SDK="${ANDROID_HOME:-$HOME/android-sdk}"
BT="$SDK/build-tools/34.0.0"
PLATFORM="$SDK/platforms/android-34/android.jar"
rm -rf build
mkdir -p build/gen build/obj build/out
"$BT/aapt2" compile --dir res -o build/res.zip
"$BT/aapt2" link -o build/base.apk -I "$PLATFORM" --manifest AndroidManifest.xml -R build/res.zip --java build/gen --auto-add-overlay
javac --release 8 -nowarn -classpath "$PLATFORM" -d build/obj build/gen/com/miiko3/mtprotofinder/R.java src/com/miiko3/mtprotofinder/MainActivity.java
"$BT/d8" --release --min-api 24 --lib "$PLATFORM" --output build/out $(find build/obj -name '*.class')
cd build && cp base.apk unsigned.apk && zip -qj unsigned.apk out/classes.dex && cd ..
if [ ! -f keystore.jks ]; then
keytool -genkeypair -v -keystore keystore.jks -alias mtproto -keyalg RSA -keysize 2048 -validity 10000 -storepass mtprotofinder -keypass mtprotofinder -dname "CN=MTProto Finder,OU=miiko3,O=yetilov,C=RU"
fi
"$BT/zipalign" -f 4 build/unsigned.apk build/aligned.apk
"$BT/apksigner" sign --ks keystore.jks --ks-pass pass:mtprotofinder --key-pass pass:mtprotofinder --out MTProto-Finder-v0.1.1.4.apk build/aligned.apk
"$BT/apksigner" verify MTProto-Finder-v0.1.1.4.apk && echo "OK: MTProto-Finder-v0.1.1.4.apk"
