<#
.SYNOPSIS
    Cong cu bao tri (chay tren may cua ban - chu repo) de tinh SHA256 cho tung
    goi driver va ghi vao manifest.json TRUOC KHI push/publish release moi.

.DESCRIPTION
    Muc dich: dam bao Install-PrinterDrivers.ps1 (chay tren may client, quyen
    Administrator) luon co the xac minh file .zip tai ve khop 100% voi file
    ban da dang len GitHub cua chinh ban - phong truong hop CDN loi, download
    bi cat giua chung, hoac file bi thay doi ngoai y muon sau nay.

    Co 2 che do:
      -Source Local   : quet thu muc chua san cac file .zip, tinh hash truc tiep
      -Source Remote  : tai tung DownloadUrl trong manifest.json ve tam va tinh hash
                         (dung khi ban da upload len GitHub Releases va muon "chot" hash)

.PARAMETER ManifestPath
    Duong dan toi manifest.json can cap nhat. Mac dinh: .\manifest.json

.PARAMETER Source
    'Local' hoac 'Remote'. Mac dinh: Remote.

.PARAMETER LocalFolder
    Khi -Source Local: thu muc chua cac file .zip, ten file phai la
    "<Model>.zip" trung voi truong Model trong manifest (khong bat buoc -
    script se thu doi chieu tu DownloadUrl truoc).

.EXAMPLE
    # Sau khi da upload het release assets len GitHub:
    .\Update-ManifestHashes.ps1 -Source Remote

.EXAMPLE
    # Tinh hash tu file zip dang co san trong thu muc build cuc bo:
    .\Update-ManifestHashes.ps1 -Source Local -LocalFolder "C:\Builds\PrinterDrivers"
#>

[CmdletBinding()]
param(
    [string]$ManifestPath = ".\manifest.json",
    [ValidateSet("Local", "Remote")]
    [string]$Source = "Remote",
    [string]$LocalFolder
)

if (-not (Test-Path $ManifestPath)) {
    Write-Error "Khong tim thay manifest tai: $ManifestPath"
    exit 1
}

$Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
$TempDir  = Join-Path $env:TEMP "ManifestHashCalc"
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

$Updated = 0
$Failed  = @()

foreach ($Entry in $Manifest) {
    Write-Host "==> $($Entry.Model)" -ForegroundColor Cyan
    $ZipPath = $null

    try {
        if ($Source -eq "Remote") {
            $FileName = Split-Path $Entry.DownloadUrl -Leaf
            $ZipPath  = Join-Path $TempDir $FileName
            Write-Host "    Dang tai: $($Entry.DownloadUrl)" -ForegroundColor Gray
            Invoke-WebRequest -Uri $Entry.DownloadUrl -OutFile $ZipPath -UseBasicParsing -TimeoutSec 60
        } else {
            $Candidate = Join-Path $LocalFolder "$($Entry.Model).zip"
            if (-not (Test-Path $Candidate)) {
                $Candidate = Join-Path $LocalFolder (Split-Path $Entry.DownloadUrl -Leaf)
            }
            if (-not (Test-Path $Candidate)) {
                throw "Khong tim thay file zip cuc bo cho '$($Entry.Model)' trong $LocalFolder"
            }
            $ZipPath = $Candidate
        }

        $Hash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLower()
        $Entry.Sha256 = $Hash
        Write-Host "    SHA256: $Hash" -ForegroundColor Green
        $Updated++
    } catch {
        Write-Host "    [X] LOI: $($_.Exception.Message)" -ForegroundColor Red
        $Failed += $Entry.Model
    } finally {
        if ($Source -eq "Remote" -and $ZipPath -and (Test-Path $ZipPath)) {
            Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
        }
    }
}

$Manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $ManifestPath -Encoding UTF8

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " Da cap nhat $Updated / $($Manifest.Count) hash vao $ManifestPath" -ForegroundColor Green
if ($Failed.Count -gt 0) {
    Write-Host " Khong tinh duoc hash cho: $($Failed -join ', ')" -ForegroundColor Yellow
}
Write-Host "============================================================" -ForegroundColor Green
Write-Host " Nho commit + push manifest.json nay len GitHub truoc khi" -ForegroundColor Gray
Write-Host " Install-PrinterDrivers.ps1 chay -RequireHash tren client." -ForegroundColor Gray

Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
