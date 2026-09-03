#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Tu dong phat hien va cai dat driver may in (USB Plug&Play + mang LAN qua SNMP).

.DESCRIPTION
    v2 - Cai tien so voi ban goc:
      - Xac minh SHA256 cua file driver truoc khi nap vao driver store (-RequireHash)
      - Quet nhieu subnet cung luc, tu dong phat hien tren MOI adapter mang dang len
      - Quet port 9100 song song bang RunspacePool (nhanh hon nhieu so voi tuan tu)
      - Khop driver chinh xac hon: uu tien HardwareID/SnmpKeyword khop dai nhat
      - Ghi log co cau truc (CSV + JSON) + Start-Transcript, phu hop audit/Intune
      - Ma thoat (exit code) chuan cho Intune Proactive Remediation / RMM

.PARAMETER ManifestUrl
    URL toi manifest.json. Mac dinh la repo GitHub cua ban.

.PARAMETER Subnets
    Danh sach subnet /24 can quet, dang "192.168.1". Neu bo trong, script tu
    dong lay TAT CA subnet /24 tu cac adapter IPv4 dang hoat dong (khong chi
    subnet dau tien nhu ban cu).

.PARAMETER RequireHash
    Neu bat, driver KHONG co Sha256 trong manifest hoac hash KHONG khop se
    bi TU CHOI cai dat (an toan hon). Mac dinh tat (chi canh bao) de tuong
    thich nguoc voi manifest chua co hash.

.PARAMETER SkipUsbScan / -SkipNetworkScan
    Bo qua tung giai doan neu can chi chay mot phan.

.PARAMETER DryRun
    Chi quet va bao cao thiet bi/driver se duoc cai, KHONG thuc su cai dat gi.

.PARAMETER MaxParallel
    So luong thread song song khi quet mang. Mac dinh 64.

.PARAMETER LogFolder
    Thu muc luu log CSV/JSON + transcript. Mac dinh: $env:ProgramData\PrinterAutoDeploy\Logs

.EXAMPLE
    .\Install-PrinterDrivers.ps1
    # Auto-detect subnet, chay day du, khong bat buoc hash

.EXAMPLE
    .\Install-PrinterDrivers.ps1 -Subnets "10.0.1","10.0.5" -RequireHash -DryRun
    # Quet 2 subnet chi dinh, bat buoc kiem tra hash, khong cai dat that (audit truoc)

.EXAMPLE
    .\Install-PrinterDrivers.ps1 -RequireHash
    # Chay that, tu choi moi driver khong xac minh duoc hash
#>

[CmdletBinding()]
param(
    [string]   $ManifestUrl     = "https://raw.githubusercontent.com/tamtruong90/PrinterDrivers/main/manifest.json",
    [string[]] $Subnets         = @(),
    [switch]   $RequireHash,
    [switch]   $SkipUsbScan,
    [switch]   $SkipNetworkScan,
    [switch]   $DryRun,
    [int]      $MaxParallel     = 64,
    [int]      $PortTimeoutMs   = 200,
    [string]   $LogFolder       = "$env:ProgramData\PrinterAutoDeploy\Logs"
)

# ============================================================
# 0. THIET LAP MOI TRUONG / LOGGING
# ============================================================
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding           = [System.Text.Encoding]::UTF8

New-Item -ItemType Directory -Force -Path $LogFolder | Out-Null
$RunId          = Get-Date -Format "yyyyMMdd_HHmmss"
$TranscriptPath = Join-Path $LogFolder "transcript_$RunId.log"
$ResultCsvPath  = Join-Path $LogFolder "result_$RunId.csv"
$ResultJsonPath = Join-Path $LogFolder "result_$RunId.json"

try { Start-Transcript -Path $TranscriptPath -Force | Out-Null } catch {}

# Danh sach ket qua co cau truc, dung de xuat CSV/JSON va tinh exit code cuoi cung
$script:Results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [string]$Stage,
        [string]$Identifier,
        [string]$Model,
        [string]$Driver,
        [ValidateSet("Success","Skipped","Failed","Detected")]
        [string]$Status,
        [string]$Detail = ""
    )
    $script:Results.Add([PSCustomObject]@{
        Timestamp  = Get-Date -Format "s"
        Stage      = $Stage
        Identifier = $Identifier
        Model      = $Model
        Driver     = $Driver
        Status     = $Status
        Detail     = $Detail
    })
}

$CacheHeaders = @{
    "Cache-Control" = "no-cache, no-store, must-revalidate"
    "Pragma"        = "no-cache"
    "Expires"       = "0"
}

function Get-CacheBustUrl {
    param ([string]$Url)
    $Ticks = (Get-Date).Ticks
    if ($Url.Contains("?")) { return "${Url}&_cb=${Ticks}" } else { return "${Url}?_cb=${Ticks}" }
}

# ============================================================
# 1. KHOP DRIVER CHINH XAC HON (specificity scoring)
# ============================================================
# Tra ve driver co chuoi khop DAI NHAT thay vi driver dau tien tim thay -
# giam rui ro mot rule qua rong (vd "USBPRINT\Canon") nuot mat mot rule cu
# the hon o cung hang.
function Find-BestMatch {
    param(
        [string]  $Needle,
        [object[]]$DriverDatabase,
        [string]  $FieldName   # "HardwareIDs" hoac "SnmpKeywords"
    )
    $Best = $null
    $BestLen = -1
    foreach ($Entry in $DriverDatabase) {
        $Candidates = $Entry.$FieldName
        if (-not $Candidates) { continue }
        foreach ($Cand in $Candidates) {
            if ([string]::IsNullOrWhiteSpace($Cand)) { continue }
            if ($Needle -like "*$Cand*" -and $Cand.Length -gt $BestLen) {
                $Best    = $Entry
                $BestLen = $Cand.Length
            }
        }
    }
    return $Best
}

# ============================================================
# 2. XAC MINH + CAI DAT GOI DRIVER (co kiem tra SHA256)
# ============================================================
function Install-PrinterDriverPackage {
    param($DriverInfo, $TempFolder, $Headers)

    $ExistingDriver = Get-PrinterDriver -Name $DriverInfo.DriverName -ErrorAction SilentlyContinue
    if ($ExistingDriver) {
        Write-Host "  [-] Driver '$($DriverInfo.DriverName)' da co san. Bo qua tai file." -ForegroundColor Gray
        Add-Result -Stage "DriverInstall" -Identifier $DriverInfo.Model -Model $DriverInfo.Model -Driver $DriverInfo.DriverName -Status "Skipped" -Detail "Da ton tai san"
        return $true
    }

    if ($DryRun) {
        Write-Host "  [DRYRUN] Se tai + cai driver: $($DriverInfo.Model)" -ForegroundColor Magenta
        Add-Result -Stage "DriverInstall" -Identifier $DriverInfo.Model -Model $DriverInfo.Model -Driver $DriverInfo.DriverName -Status "Detected" -Detail "DryRun - chua cai"
        return $true
    }

    $ZipPath     = "$TempFolder\$($DriverInfo.Model).zip"
    $ExtractPath = "$TempFolder\$($DriverInfo.Model)"

    if (-not (Test-Path $ExtractPath)) {
        try {
            Write-Host "  [->] Dang tai goi: $($DriverInfo.Model)..." -ForegroundColor Cyan
            $CleanZipUrl = Get-CacheBustUrl -Url $DriverInfo.DownloadUrl
            Invoke-WebRequest -Uri $CleanZipUrl -Headers $Headers -OutFile $ZipPath -UseBasicParsing -TimeoutSec 60

            # --- Xac minh toan ven file (chinh ban up len GitHub cua chinh ban,
            #     nhung van nen kiem tra de bat loi download hong / bi cat giua chung
            #     / thay doi ngoai y muon truoc khi nap vao driver store) ---
            $HasHash = -not [string]::IsNullOrWhiteSpace($DriverInfo.Sha256)
            if ($HasHash) {
                $ActualHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLower()
                $ExpectedHash = $DriverInfo.Sha256.ToLower()
                if ($ActualHash -ne $ExpectedHash) {
                    Write-Host "  [X] SHA256 KHONG KHOP! Expected=$ExpectedHash Actual=$ActualHash" -ForegroundColor Red
                    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
                    Add-Result -Stage "DriverInstall" -Identifier $DriverInfo.Model -Model $DriverInfo.Model -Driver $DriverInfo.DriverName -Status "Failed" -Detail "SHA256 mismatch"
                    return $false
                }
                Write-Host "  [+] SHA256 khop, file toan ven." -ForegroundColor Green
            } elseif ($RequireHash) {
                Write-Host "  [X] Manifest chua co Sha256 cho '$($DriverInfo.Model)' va -RequireHash dang bat. Tu choi cai." -ForegroundColor Red
                Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
                Add-Result -Stage "DriverInstall" -Identifier $DriverInfo.Model -Model $DriverInfo.Model -Driver $DriverInfo.DriverName -Status "Failed" -Detail "Thieu Sha256 trong manifest, RequireHash=true"
                return $false
            } else {
                Write-Host "  [!] Manifest chua co Sha256 - bo qua xac minh (khuyen nghi chay Update-ManifestHashes.ps1)." -ForegroundColor DarkYellow
            }

            Write-Host "  [->] Dang giai nen va dang ky Driver vao Windows Store..." -ForegroundColor Yellow
            Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force
            $InfFiles = Get-ChildItem -Path $ExtractPath -Filter "*.inf" -Recurse
            if (-not $InfFiles) {
                throw "Khong tim thay file .inf nao trong goi da giai nen"
            }
            pnputil.exe /add-driver "$ExtractPath\*.inf" /subdirs /install | Out-Null

            Add-Result -Stage "DriverInstall" -Identifier $DriverInfo.Model -Model $DriverInfo.Model -Driver $DriverInfo.DriverName -Status "Success" -Detail "Da nap vao driver store"
        } catch {
            Write-Host "  [X] Loi khi tai/cai driver '$($DriverInfo.Model)': $($_.Exception.Message)" -ForegroundColor Red
            Add-Result -Stage "DriverInstall" -Identifier $DriverInfo.Model -Model $DriverInfo.Model -Driver $DriverInfo.DriverName -Status "Failed" -Detail $_.Exception.Message
            return $false
        }
    }
    return $true
}

# ============================================================
# 3. SNMP QUERY (giu nguyen tu ban goc, khong doi)
# ============================================================
function Get-PrinterSnmpModel {
    param ([string]$IPAddress)
    try {
        $UdpClient = New-Object System.Net.Sockets.UdpClient
        $UdpClient.Client.ReceiveTimeout = 600
        $UdpClient.Connect($IPAddress, 161)

        [byte[]]$SnmpPacket = @(
            0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
            0xa0, 0x1c, 0x02, 0x04, 0x01, 0x02, 0x03, 0x04, 0x02, 0x01, 0x00, 0x02, 0x01,
            0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
            0x01, 0x00, 0x05, 0x00
        )

        [void]$UdpClient.Send($SnmpPacket, $SnmpPacket.Length)
        $RemoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $Response = $UdpClient.Receive([ref]$RemoteEP)
        $UdpClient.Close()

        $AsciiString = [System.Text.Encoding]::ASCII.GetString($Response)
        return ($AsciiString -replace '[^\x20-\x7E]', ' ').Trim()
    } catch {
        return $null
    }
}

# ============================================================
# 4. TU DONG PHAT HIEN NHIEU SUBNET (khong chi 1 subnet dau tien)
# ============================================================
function Get-LocalSubnets {
    $Addresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $_.IPAddress -notlike "127.*" -and
        $_.IPAddress -notlike "169.254.*" -and
        $_.PrefixLength -ge 20   # bo qua cac dai qua rong (VPN full-tunnel v.v.)
    }
    $Prefixes = $Addresses | ForEach-Object {
        $_.IPAddress.Substring(0, $_.IPAddress.LastIndexOf('.'))
    } | Select-Object -Unique
    return $Prefixes
}

# ============================================================
# 5. QUET PORT 9100 SONG SONG BANG RUNSPACE POOL
#    (tuong thich Windows PowerShell 5.1 lan PowerShell 7)
# ============================================================
function Get-ActivePrinterPorts {
    param([string[]]$SubnetPrefixes, [int]$MaxThreads, [int]$TimeoutMs)

    $Targets = foreach ($Prefix in $SubnetPrefixes) {
        1..254 | ForEach-Object { "$Prefix.$_" }
    }
    $Targets = $Targets | Select-Object -Unique
    Write-Host " [->] Se quet $($Targets.Count) dia chi tren $($SubnetPrefixes.Count) subnet, toi da $MaxThreads luong song song..." -ForegroundColor Cyan

    $ScriptBlock = {
        param($IP, $Timeout)
        $Socket = New-Object System.Net.Sockets.TcpClient
        try {
            $Async = $Socket.BeginConnect($IP, 9100, $null, $null)
            if ($Async.AsyncWaitHandle.WaitOne($Timeout, $false) -and $Socket.Connected) {
                return $IP
            }
        } catch {
        } finally {
            $Socket.Close()
        }
        return $null
    }

    $Pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $Pool.Open()
    $Jobs = foreach ($IP in $Targets) {
        $Ps = [powershell]::Create()
        $Ps.RunspacePool = $Pool
        [void]$Ps.AddScript($ScriptBlock).AddArgument($IP).AddArgument($TimeoutMs)
        [PSCustomObject]@{ Pipe = $Ps; Handle = $Ps.BeginInvoke() }
    }

    $Active = foreach ($Job in $Jobs) {
        $Result = $Job.Pipe.EndInvoke($Job.Handle)
        $Job.Pipe.Dispose()
        if ($Result) { $Result }
    }

    $Pool.Close()
    $Pool.Dispose()
    return $Active
}

# ============================================================
# 6. TAI MANIFEST
# ============================================================
$TempFolder = "$env:TEMP\PrinterSetup"
New-Item -ItemType Directory -Force -Path $TempFolder | Out-Null
$ManifestPath = "$TempFolder\manifest.json"

Write-Host "=== BUOC 1: TAI DANH SACH DRIVER TU GITHUB ===" -ForegroundColor Cyan
try {
    $CleanManifestUrl = Get-CacheBustUrl -Url $ManifestUrl
    Invoke-WebRequest -Uri $CleanManifestUrl -Headers $CacheHeaders -OutFile $ManifestPath -UseBasicParsing -TimeoutSec 10
    $DriverDatabase = Get-Content $ManifestPath | ConvertFrom-Json
    Write-Host " [+] Da tai thanh cong co so du lieu Driver ($($DriverDatabase.Count) muc)." -ForegroundColor Green
} catch {
    Write-Host " [X] LOI: Khong the ket noi toi manifest.json tren GitHub! $($_.Exception.Message)" -ForegroundColor Red
    Add-Result -Stage "Manifest" -Identifier $ManifestUrl -Model "" -Driver "" -Status "Failed" -Detail $_.Exception.Message
    try { Stop-Transcript | Out-Null } catch {}
    $script:Results | Export-Csv -Path $ResultCsvPath -NoTypeInformation -Encoding UTF8
    exit 3   # Loi nghiem trong - khong the tiep tuc
}

# ============================================================
# 7. QUET USB PLUG AND PLAY
# ============================================================
if ($SkipUsbScan) {
    Write-Host "`n=== BUOC 2: BO QUA (SkipUsbScan) ===" -ForegroundColor DarkGray
} else {
    Write-Host "`n=== BUOC 2: QUET MAY IN USB THIEU DRIVER ===" -ForegroundColor Yellow
    $MissingUsbDevices = Get-PnPDevice -Class "Printer", "USB" -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -ne "OK" -and ($_.InstanceId -like "*USBPRINT*" -or $_.Class -eq "Printer") }

    if (-not $MissingUsbDevices) {
        Write-Host " [-] Khong tim thay may in USB nao thieu Driver hoac dang loi." -ForegroundColor Gray
    } else {
        foreach ($Device in $MissingUsbDevices) {
            $DeviceHWIDs = (Get-PnPDeviceProperty -InputObject $Device -KeyName "DEVPKEY_Device_HardwareIds").Data
            $MatchedDriver = $null
            foreach ($HWID in $DeviceHWIDs) {
                $Candidate = Find-BestMatch -Needle $HWID -DriverDatabase $DriverDatabase -FieldName "HardwareIDs"
                if ($Candidate) { $MatchedDriver = $Candidate; break }
            }

            if ($MatchedDriver) {
                Write-Host " [+] Phat hien USB khop voi cau hinh: $($MatchedDriver.Model)" -ForegroundColor Green
                Add-Result -Stage "UsbScan" -Identifier $Device.InstanceId -Model $MatchedDriver.Model -Driver $MatchedDriver.DriverName -Status "Detected" -Detail ""
                Install-PrinterDriverPackage -DriverInfo $MatchedDriver -TempFolder $TempFolder -Headers $CacheHeaders | Out-Null
            } else {
                Write-Host " [!] Phat hien USB nhung chua co Driver phu hop trong Manifest: $($Device.InstanceId)" -ForegroundColor DarkYellow
                Add-Result -Stage "UsbScan" -Identifier $Device.InstanceId -Model "" -Driver "" -Status "Skipped" -Detail "Khong co manifest entry phu hop"
            }
        }
    }
}

# ============================================================
# 8. QUET MANG LAN (DA SUBNET, SONG SONG) TIM MAY IN IP SNMP
# ============================================================
if ($SkipNetworkScan) {
    Write-Host "`n=== BUOC 3: BO QUA (SkipNetworkScan) ===" -ForegroundColor DarkGray
} else {
    Write-Host "`n=== BUOC 3: QUET MANG LAN TIM MAY IN IP SNMP ===" -ForegroundColor Yellow

    $SubnetsToScan = if ($Subnets.Count -gt 0) { $Subnets } else { Get-LocalSubnets }

    if (-not $SubnetsToScan -or $SubnetsToScan.Count -eq 0) {
        Write-Host " [X] Khong tim thay subnet hop le nao de quet!" -ForegroundColor Red
    } else {
        Write-Host " [->] Se quet cac subnet: $($SubnetsToScan -join ', ')" -ForegroundColor Cyan
        $ActiveIPs = Get-ActivePrinterPorts -SubnetPrefixes $SubnetsToScan -MaxThreads $MaxParallel -TimeoutMs $PortTimeoutMs

        if (-not $ActiveIPs -or $ActiveIPs.Count -eq 0) {
            Write-Host " [-] Khong tim thay may in mang nao dang mo cong 9100." -ForegroundColor Gray
        } else {
            Write-Host " [+] Tim thay $($ActiveIPs.Count) dia chi mo cong 9100." -ForegroundColor Green
            foreach ($IP in $ActiveIPs) {
                $SnmpInfo = Get-PrinterSnmpModel -IPAddress $IP
                if (-not $SnmpInfo) { continue }

                Write-Host " [+] Tim thay thiet bi IP: $IP ($SnmpInfo)" -ForegroundColor Green
                $MatchedDriver = Find-BestMatch -Needle $SnmpInfo -DriverDatabase $DriverDatabase -FieldName "SnmpKeywords"

                if (-not $MatchedDriver) {
                    Write-Host "  [!] Khong co Driver phu hop trong Manifest cho thiet bi nay." -ForegroundColor Red
                    Add-Result -Stage "NetworkScan" -Identifier $IP -Model "" -Driver "" -Status "Skipped" -Detail "Khong co manifest entry phu hop ($SnmpInfo)"
                    continue
                }

                $PrinterName = "$($MatchedDriver.Model)_$IP"
                Add-Result -Stage "NetworkScan" -Identifier $IP -Model $MatchedDriver.Model -Driver $MatchedDriver.DriverName -Status "Detected" -Detail $SnmpInfo

                $ExistingPrinter = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
                if ($ExistingPrinter) {
                    Write-Host "  [-] May in '$PrinterName' da duoc cai san. Bo qua." -ForegroundColor Gray
                    Add-Result -Stage "PrinterInstall" -Identifier $IP -Model $MatchedDriver.Model -Driver $MatchedDriver.DriverName -Status "Skipped" -Detail "Da ton tai san"
                    continue
                }

                if ($DryRun) {
                    Write-Host "  [DRYRUN] Se tao printer: $PrinterName" -ForegroundColor Magenta
                    continue
                }

                Write-Host "  -> Khop Driver trong Manifest: $($MatchedDriver.Model)" -ForegroundColor Green
                $DriverOk = Install-PrinterDriverPackage -DriverInfo $MatchedDriver -TempFolder $TempFolder -Headers $CacheHeaders
                if (-not $DriverOk) {
                    Write-Host "  [X] Bo qua tao printer vi cai driver that bai/bi tu choi." -ForegroundColor Red
                    continue
                }

                try {
                    $PortName = "IP_$IP"
                    if (-not (Get-PrinterPort -Name $PortName -ErrorAction SilentlyContinue)) {
                        Add-PrinterPort -Name $PortName -PrinterHostAddress $IP
                        Write-Host "  -> Da tao port in: $PortName" -ForegroundColor Gray
                    }
                    Add-PrinterDriver -Name $MatchedDriver.DriverName -ErrorAction SilentlyContinue
                    Add-Printer -Name $PrinterName -DriverName $MatchedDriver.DriverName -PortName $PortName
                    Write-Host "  [THANH CONG] Da cai dat xong may in IP: $PrinterName" -ForegroundColor Green
                    Add-Result -Stage "PrinterInstall" -Identifier $IP -Model $MatchedDriver.Model -Driver $MatchedDriver.DriverName -Status "Success" -Detail $PrinterName
                } catch {
                    Write-Host "  [X] Loi khi tao printer '$PrinterName': $($_.Exception.Message)" -ForegroundColor Red
                    Add-Result -Stage "PrinterInstall" -Identifier $IP -Model $MatchedDriver.Model -Driver $MatchedDriver.DriverName -Status "Failed" -Detail $_.Exception.Message
                }
            }
        }
    }
}

# ============================================================
# 9. DON DEP + XUAT LOG + MA THOAT
# ============================================================
Remove-Item $TempFolder -Recurse -Force -ErrorAction SilentlyContinue

try {
    $script:Results | Export-Csv -Path $ResultCsvPath -NoTypeInformation -Encoding UTF8
    $script:Results | ConvertTo-Json -Depth 5 | Set-Content -Path $ResultJsonPath -Encoding UTF8
    Write-Host "`n [i] Log ket qua: $ResultCsvPath" -ForegroundColor Gray
    Write-Host " [i] Log JSON   : $ResultJsonPath" -ForegroundColor Gray
} catch {
    Write-Host " [!] Khong the ghi file log ket qua: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "      HOAN TAT QUY TRINH CAI DAT MAY IN TU DONG!            " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

try { Stop-Transcript | Out-Null } catch {}

$FailedCount = ($script:Results | Where-Object { $_.Status -eq "Failed" }).Count
if ($FailedCount -gt 0) {
    Write-Host " Ket thuc voi $FailedCount loi - xem log de biet chi tiet." -ForegroundColor Yellow
    exit 1   # Hoan tat nhung co loi - phu hop "remediation failed" tren Intune
}
exit 0       # Thanh cong hoan toan
