param(
    [string]$Src = "C:\Users\123\Desktop\Frame 55.png",
    [string]$Res = "C:\Users\123\AppData\Local\Temp\opencode\mtf\android\res"
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

# Палитра фона снята с самого лого: светло-синий радиальный градиент.
$CenterCol = [System.Drawing.Color]::FromArgb(255, 125, 162, 181)   # #7DA2B5
$EdgeCol   = [System.Drawing.Color]::FromArgb(255,  86, 134, 143)   # #56868F

function New-BgBrush([int]$w, [int]$h) {
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddEllipse(-$w * 0.5, -$h * 0.5, $w * 2, $h * 2)
    $br = New-Object System.Drawing.Drawing2D.PathGradientBrush($path)
    $br.CenterColor = $script:CenterCol
    $br.SurroundColors = @($script:EdgeCol)
    $g.FillRectangle($br, 0, 0, $w, $h)
    $br.Dispose(); $path.Dispose(); $g.Dispose()
    return $bmp
}

function Save-Png($bmp, [string]$path) {
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
}

$src0 = New-Object System.Drawing.Bitmap($Src)
$logo = New-Object System.Drawing.Bitmap(1024, 1024)   # upscale once, then downscale per bucket
$gs = [System.Drawing.Graphics]::FromImage($logo)
$gs.InterpolationMode = 'HighQualityBicubic'
$gs.PixelOffsetMode = 'HighQuality'
$gs.DrawImage($src0, 0, 0, 1024, 1024)
$gs.Dispose()
$src0.Dispose()

# ---- adaptive icon foreground: лого на 64% холста (108dp), в безопасной зоне 72dp
$fgScale = 0.64
foreach ($d in @(@('mdpi', 48), @('hdpi', 72), @('xhdpi', 96), @('xxhdpi', 144), @('xxxhdpi', 192))) {
    $dir = $d[0]; $legacy = $d[1]
    $px = [int]($legacy * 108 / 48)   # foreground layer = 108dp
    $bmp = New-Object System.Drawing.Bitmap($px, $px)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.Clear([System.Drawing.Color]::Transparent)
    $g.InterpolationMode = 'HighQualityBicubic'
    $g.PixelOffsetMode = 'HighQuality'
    $g.SmoothingMode = 'AntiAlias'
    $side = [int]($px * $fgScale)
    $off = [int](($px - $side) / 2)
    $g.DrawImage($logo, (New-Object System.Drawing.Rectangle($off, $off, $side, $side)))
    $g.Dispose()
    Save-Png $bmp (Join-Path $Res "drawable-$dir\ic_launcher_foreground.png")
    $bmp.Dispose()
    Write-Host "fg  drawable-$dir/ic_launcher_foreground.png ${px}x${px}"
}

# ---- legacy mipmap: лого во весь квадрат поверх того же градиента (углы не прозрачные)
foreach ($d in @(@('mipmap-mdpi', 48), @('mipmap-hdpi', 72), @('mipmap-xhdpi', 96), @('mipmap-xxhdpi', 144), @('mipmap-xxxhdpi', 192))) {
    $dir = $d[0]; $px = $d[1]
    $bmp = New-BgBrush $px $px
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = 'HighQualityBicubic'
    $g.PixelOffsetMode = 'HighQuality'
    $g.SmoothingMode = 'AntiAlias'
    $side = [int]($px * 0.86)
    $off = [int](($px - $side) / 2)
    $g.DrawImage($logo, (New-Object System.Drawing.Rectangle($off, $off, $side, $side)))
    $g.Dispose()
    Save-Png $bmp (Join-Path $Res "$dir\ic_launcher.png")
    $bmp.Dispose()
    Write-Host "ico $dir/ic_launcher.png ${px}x${px}"
}

# ---- круглый аватар в шапке приложения
$app = New-Object System.Drawing.Bitmap(512, 512)
$g = [System.Drawing.Graphics]::FromImage($app)
$g.InterpolationMode = 'HighQualityBicubic'
$g.PixelOffsetMode = 'HighQuality'
$g.SmoothingMode = 'AntiAlias'
$g.DrawImage($logo, 0, 0, 512, 512)
$g.Dispose()
Save-Png $app (Join-Path $Res "drawable\logo.png")
$app.Dispose()
Write-Host "app res/drawable/logo.png 512x512"

# ---- лого для README / репозитория
Copy-Item (Join-Path $Res "drawable\logo.png") "C:\Users\123\AppData\Local\Temp\opencode\mtf\logo.png" -Force
Write-Host "root logo.png"

$logo.Dispose()
Write-Host "done"
