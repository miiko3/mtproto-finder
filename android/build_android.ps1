# Cross-platform build of MTProto Finder for Android.
# Replaces build_android.sh; mirrors it step for step.
#   pwsh -File build_android.ps1
param(
    [string]$VersionName = "0.2.1",
    [int]$VersionCode = 21
)

$ErrorActionPreference = "Stop"

$env:JAVA_HOME = if ($env:JAVA_HOME) { $env:JAVA_HOME } else { "C:\Users\123\AndroidDev\jdk-17.0.20.1+1" }
$sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "C:\Users\123\AndroidDev\sdk" }
$bt = Join-Path $sdk "build-tools\34.0.0"
$platform = Join-Path $sdk "platforms\android-34\android.jar"

$javac = Join-Path $env:JAVA_HOME "bin\javac.exe"
$jar = Join-Path $env:JAVA_HOME "bin\jar.exe"
$keytool = Join-Path $env:JAVA_HOME "bin\keytool.exe"

$aapt2 = Join-Path $bt "aapt2.exe"
$zipalign = Join-Path $bt "zipalign.exe"
$apksigner = Join-Path $bt "apksigner.bat"
$d8 = Join-Path $bt "d8.bat"

$root = $PSScriptRoot
Set-Location $root

foreach ($f in @($javac, $jar, $keytool, $aapt2, $zipalign, $apksigner, $d8, $platform)) {
    if (-not (Test-Path -LiteralPath $f)) { throw "missing: $f" }
}

$build = Join-Path $root "build"
if (Test-Path -LiteralPath $build) { Remove-Item -Recurse -Force -LiteralPath $build }
New-Item -ItemType Directory -Force -Path "$build\gen", "$build\obj", "$build\out" | Out-Null

Write-Host "==> aapt2 compile"
& $aapt2 compile --dir res -o "$build\res.zip"
if ($LASTEXITCODE -ne 0) { throw "aapt2 compile failed" }

Write-Host "==> aapt2 link"
$mf = Get-Content AndroidManifest.xml -Raw
$mf = [regex]::Replace($mf, 'android:versionName="[^"]*"', "android:versionName=`"$VersionName`"")
$mf = [regex]::Replace($mf, 'android:versionCode="\d+"', "android:versionCode=`"$VersionCode`"")
[System.IO.File]::WriteAllText("$build\AndroidManifest.xml", $mf, (New-Object System.Text.UTF8Encoding($false)))

& $aapt2 link -o "$build\base.apk" -I $platform --manifest "$build\AndroidManifest.xml" -R "$build\res.zip" --java "$build\gen" --auto-add-overlay
if ($LASTEXITCODE -ne 0) { throw "aapt2 link failed" }

Write-Host "==> javac"
$sources = Get-ChildItem -Recurse -Filter *.java -Path src, "$build\gen" | ForEach-Object { $_.FullName }
& $javac --release 8 -nowarn -encoding UTF-8 -classpath $platform -d "$build\obj" $sources
if ($LASTEXITCODE -ne 0) { throw "javac failed" }

Write-Host "==> d8"
$classes = Get-ChildItem -Recurse -Filter *.class -Path "$build\obj" | ForEach-Object { $_.FullName }
& $d8 --release --min-api 24 --lib $platform --output "$build\out" $classes
if ($LASTEXITCODE -ne 0) { throw "d8 failed" }

Write-Host "==> package"
Copy-Item "$build\base.apk" "$build\unsigned.apk" -Force
& $jar uf "$build\unsigned.apk" -C "$build\out" classes.dex
if ($LASTEXITCODE -ne 0) { throw "jar failed" }

$keystore = Join-Path $root "keystore.jks"
if (-not (Test-Path -LiteralPath $keystore)) {
    Write-Host "==> generating keystore"
    & $keytool -genkeypair -v -keystore $keystore -alias mtproto -keyalg RSA -keysize 2048 -validity 10000 `
        -storepass mtprotofinder -keypass mtprotofinder -dname "CN=MTProto Finder,OU=miiko3,O=yetilov,C=RU"
    if ($LASTEXITCODE -ne 0) { throw "keytool failed" }
}

Write-Host "==> align + sign"
& $zipalign -f 4 "$build\unsigned.apk" "$build\aligned.apk"
if ($LASTEXITCODE -ne 0) { throw "zipalign failed" }

$apk = Join-Path $root "MTProto-Finder-v$VersionName.apk"
& $apksigner sign --ks $keystore --ks-pass pass:mtprotofinder --key-pass pass:mtprotofinder --out $apk "$build\aligned.apk"
if ($LASTEXITCODE -ne 0) { throw "apksigner failed" }
& $apksigner verify $apk
if ($LASTEXITCODE -ne 0) { throw "apksigner verify failed" }

Write-Host "OK: $apk"
