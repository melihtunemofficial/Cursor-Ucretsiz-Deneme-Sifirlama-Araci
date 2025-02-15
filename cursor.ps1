$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$STORAGE_FILE = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
$BACKUP_DIR = "$env:APPDATA\Cursor\User\globalStorage\backups"

function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "[hata] Lütfen bu betiği yönetici olarak çalıştırın."
    Write-Host "Lütfen dosyaya sağ tıklayın ve 'Yönetici olarak çalıştır'a basın'"
    Read-Host "Çıkmak için enter tuşuna basın."
    exit 1
}

Clear-Host
Write-Host @"

    ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ 
   ██╔════╝██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔══██╗
   ██║     ██║   ██║██████╔╝███████╗██║   ██║██████╔╝
   ██║     ██║   ██║██╔══██╗╚════██║██║   ██║██╔══██╗
   ╚██████╗╚██████╔╝██║  ██║███████║╚██████╔╝██║  ██║
    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝

"@
Write-Host "================================"
Write-Host "   Cursor Cihaz Kimliği Değiştirme Aracı         "
Write-Host "  Daha fazla Cursor ve AI bilgisi için takip edin "
Write-Host "  https://github.com/melihtunemofficial  "
Write-Host "================================"
Write-Host ""

function Get-CursorVersion {
    try {
        $packagePath = "$env:LOCALAPPDATA\Programs\cursor\resources\app\package.json"
        
        if (Test-Path $packagePath) {
            $packageJson = Get-Content $packagePath -Raw | ConvertFrom-Json
            if ($packageJson.version) {
                Write-Host "[info] Cursor'ın şu anda yüklü olan sürümü: v$($packageJson.version)"
                return $packageJson.version
            }
        }

        $altPath = "$env:LOCALAPPDATA\cursor\resources\app\package.json"
        if (Test-Path $altPath) {
            $packageJson = Get-Content $altPath -Raw | ConvertFrom-Json
            if ($packageJson.version) {
                Write-Host "[info] Şu anda yüklü Cursor sürümü: v$($packageJson.version)"
                return $packageJson.version
            }
        }

        Write-Host "[hata] Cursor sürümünü algılayamıyor"
        Write-Host "[İpucu] Lütfen Cursor'ın doğru yüklendiğinden emin olun."
        return $null
    }
    catch {
        Write-Host "[hata] Cursor sürümü alınamadı: $_"
        return $null
    }
}

$cursorVersion = Get-CursorVersion
Write-Host ""

Write-Host "[info] Cursor işlemi kontrol ediliyor..."

function Get-ProcessDetails {
    param($processName)
    Write-Host "[debug], $processName işlem ayrıntılarını alıyor:"
    Get-WmiObject Win32_Process -Filter "name='$processName'" | 
        Select-Object ProcessId, ExecutablePath, CommandLine | 
        Format-List
}

$MAX_RETRIES = 5
$WAIT_TIME = 1

function Close-CursorProcess {
    param($processName)
    
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "[UYARI] $processName'in çalıştığını tespit etti"
        Get-ProcessDetails $processName
        
        Write-Host "[hata] $processName kapatılmaya çalışılıyor..."
        Stop-Process -Name $processName -Force
        
        $retryCount = 0
        while ($retryCount -lt $MAX_RETRIES) {
            $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
            if (-not $process) { break }
            
            $retryCount++
            if ($retryCount -ge $MAX_RETRIES) {
                Write-Host "[hata], $MAX_RETRIES denemesinden sonra $processName öğesini kapatamıyor."
                Get-ProcessDetails $processName
                Write-Host "[hata] Lütfen işlemi manuel olarak kapatın ve tekrar deneyin!"
                Read-Host "Çıkmak için enter tuşuna basın"
                exit 1
            }
            Write-Host "[hata] İşlemin kapanması bekleniyor, $retryCount/$MAX_RETRIES deneniyor..."
            Start-Sleep -Seconds $WAIT_TIME
        }
        Write-Host "[info] $processName başarıyla kapatıldı"
    }
}

Close-CursorProcess "Cursor"
Close-CursorProcess "cursor"

if (-not (Test-Path $BACKUP_DIR)) {
    New-Item -ItemType Directory -Path $BACKUP_DIR | Out-Null
}

if (Test-Path $STORAGE_FILE) {
    Write-Host "[info] Yapılandırma dosyaları yedekleniyor..."
    $backupName = "storage.json.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item $STORAGE_FILE "$BACKUP_DIR\$backupName"
}

Write-Host "[info] yeni bir kimlik oluşturuyor..."

function Get-RandomHex {
    param (
        [int]$length
    )
    
    $bytes = New-Object byte[] ($length)
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $rng.GetBytes($bytes)
    $hexString = [System.BitConverter]::ToString($bytes) -replace '-',''
    $rng.Dispose()
    return $hexString
}

function New-StandardMachineId {
    $template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    $result = $template -replace '[xy]', {
        param($match)
        $r = [Random]::new().Next(16)
        $v = if ($match.Value -eq "x") { $r } else { ($r -band 0x3) -bor 0x8 }
        return $v.ToString("x")
    }
    return $result
}

$MAC_MACHINE_ID = New-StandardMachineId
$UUID = [System.Guid]::NewGuid().ToString()
$prefixBytes = [System.Text.Encoding]::UTF8.GetBytes("auth0|user_")
$prefixHex = -join ($prefixBytes | ForEach-Object { '{0:x2}' -f $_ })
$randomPart = Get-RandomHex -length 32
$MACHINE_ID = "$prefixHex$randomPart"
$SQM_ID = "{$([System.Guid]::NewGuid().ToString().ToUpper())}"

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[hata] Lütfen bu betiği yönetici ayrıcalıklarıyla çalıştırın"
    Start-Process powershell "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

function Update-MachineGuid {
    try {
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        if (-not (Test-Path $registryPath)) {
            throw "Kayıt defteri yolu mevcut değil: $registryPath"
        }

        $currentGuid = Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction Stop
        if (-not $currentGuid) {
            throw "Geçerli MachineGuid alınamıyor"
        }

        $originalGuid = $currentGuid.MachineGuid
        Write-Host "[info] Geçerli kayıt defteri değeri:"
        Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" 
        Write-Host "    MachineGuid    REG_SZ    $originalGuid"

        if (-not (Test-Path $BACKUP_DIR)) {
            New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null
        }

        $backupFile = "$BACKUP_DIR\MachineGuid_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
        $backupResult = Start-Process "reg.exe" -ArgumentList "export", "`"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`"", "`"$backupFile`"" -NoNewWindow -Wait -PassThru
        
        if ($backupResult.ExitCode -eq 0) {
            Write-Host "[info] Kayıt defteri girdileri şuraya yedeklendi: $backupFile"
        } else {
            Write-Host "[hata] Yedekleme oluşturma başarısız oldu, devam edin..."
        }

        $newGuid = [System.Guid]::NewGuid().ToString()

        Set-ItemProperty -Path $registryPath -Name MachineGuid -Value $newGuid -Force -ErrorAction Stop
        
        $verifyGuid = (Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction Stop).MachineGuid
        if ($verifyGuid -ne $newGuid) {
            throw "Kayıt defteri doğrulaması başarısız oldu: güncellenen değer ($verifyGuid) beklenen değerle ($newGuid) eşleşmiyor"
        }

        Write-Host "[info] Kayıt defteri güncellemesi başarılı oldu:"
        Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
        Write-Host "    MachineGuid    REG_SZ    $newGuid"
        return $true
    }
    catch {
        Write-Host "[hata] Kayıt işlemi başarısız oldu: $($_.Exception.Message)"
        
        if ($backupFile -and (Test-Path $backupFile)) {
            Write-Host "[info] Yedekten geri yükleme devam ediyor..."
            $restoreResult = Start-Process "reg.exe" -ArgumentList "import", "`"$backupFile`"" -NoNewWindow -Wait -PassThru
            
            if ($restoreResult.ExitCode -eq 0) {
                Write-Host "[başarılı] orijinal kayıt defteri değerlerini geri yükledi"
            } else {
                Write-Host "[hata] Kurtarma başarısız oldu, lütfen yedekleme dosyasını manuel olarak içe aktarın: $backupFile"
            }
        } else {
            Write-Host "[hata] Yedekleme dosyası bulunamadı veya otomatik kurtarma için yedekleme oluşturma başarısız oldu"
        }
        return $false
    }
}

Write-Host "[info] Yapılandırma güncelleniyor..."

try {
    if (-not (Test-Path $STORAGE_FILE)) {
        Write-Host "[hata] Yapılandırma dosyası bulunamadı: $STORAGE_FILE"
        Write-Host "[info] Lütfen bu betiği kullanmadan önce Cursor'ı bir kez yükleyin ve çalıştırın."
        Read-Host "Çıkmak için enter tuşuna basın"
        exit 1
    }

    try {
        $originalContent = Get-Content $STORAGE_FILE -Raw -Encoding UTF8
        
        $config = $originalContent | ConvertFrom-Json 

        $oldValues = @{
            'machineId' = $config.'telemetry.machineId'
            'macMachineId' = $config.'telemetry.macMachineId'
            'devDeviceId' = $config.'telemetry.devDeviceId'
            'sqmId' = $config.'telemetry.sqmId'
        }

        $config.'telemetry.machineId' = $MACHINE_ID
        $config.'telemetry.macMachineId' = $MAC_MACHINE_ID
        $config.'telemetry.devDeviceId' = $UUID
        $config.'telemetry.sqmId' = $SQM_ID

        $updatedJson = $config | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText(
            [System.IO.Path]::GetFullPath($STORAGE_FILE), 
            $updatedJson, 
            [System.Text.Encoding]::UTF8
        )
        Write-Host "[info] Yapılandırma dosyası başarıyla güncellendi"
    } catch {
        if ($originalContent) {
            [System.IO.File]::WriteAllText(
                [System.IO.Path]::GetFullPath($STORAGE_FILE), 
                $originalContent, 
                [System.Text.Encoding]::UTF8
            )
        }
        throw "JSON işlenemedi: $_"
    }
    Update-MachineGuid
    Write-Host ""
    Write-Host "[info] Yapılandırma güncellendi."
    Write-Host "[debug] machineId: $MACHINE_ID"
    Write-Host "[debug] macMachineId: $MAC_MACHINE_ID"
    Write-Host "[debug] devDeviceId: $UUID"
    Write-Host "[debug] sqmId: $SQM_ID"

    Write-Host ""
    Write-Host "[info] Dosya yapısı."
    Write-Host "$env:APPDATA\Cursor\User"
    Write-Host "├── globalStorage"
    Write-Host "│   ├── storage.json (değiştirilmiş)"
    Write-Host "│   └── backups"

    $backupFiles = Get-ChildItem "$BACKUP_DIR\*" -ErrorAction SilentlyContinue
    if ($backupFiles) {
        foreach ($file in $backupFiles) {
            Write-Host "│       └── $($file.Name)"
        }
    } else {
        Write-Host "│       └── (boş)"
    }

    Write-Host ""
    Write-Host "================================"
    Write-Host "Daha fazla Cursor ve yapay zeka hakkında bilgi almak için takip edin."
    Write-Host "https://github.com/melihtunemofficial"
    Write-Host "================================"
    Write-Host ""
    Write-Host "[info] Yeni yapılandırmayı uygulamak için lütfen Cursor'ı yeniden başlatın!"
    Write-Host ""

    Write-Host ""
    Write-Host "[SORU] Cursor otomatik güncelleme özelliğini devre dışı bırakıcak mısınız?"
    Write-Host "0) Hayır - varsayılan ayarları bırakın (enter tuşuna basın)"
    Write-Host "1) Evet - Otomatik güncellemeleri devre dışı bırakın"
    $choice = Read-Host "Lütfen seçenekleri girin (0)"

    if ($choice -eq "1") {
        Write-Host ""
        Write-Host "[info] otomatik güncellemeleri işliyor..."
        $updaterPath = "$env:LOCALAPPDATA\cursor-updater"

        function Show-ManualGuide {
            Write-Host ""
            Write-Host "[hata] Otomatik kurulum başarısız oldu, manuel işlemi deneyin."
            Write-Host "güncellemeleri manuel olarak devre dışı bırakma adımları:"
            Write-Host "1. PowerShell'i yönetici olarak açın"
            Write-Host "2. Aşağıdaki komutu kopyalayıp yapıştırın:"
            Write-Host "Komut 1 - Mevcut bir dizini silme (eğer varsa): "
            Write-Host "Remove-Item -Path `"$updaterPath`" -Force -Recurse -ErrorAction SilentlyContinue"
            Write-Host ""
            Write-Host "Komut 2 - Dosya Oluştur: "
            Write-Host "New-Item -Path `"$updaterPath`" -ItemType File -Force | Out-Null"
            Write-Host ""
            Write-Host "Komut 3 - Salt okunur özniteliğin ayarlanması: "
            Write-Host "Set-ItemProperty -Path `"$updaterPath`" -Name IsReadOnly -Value `$true"
            Write-Host ""
            Write-Host "doğrulama yöntemi: "
            Write-Host "1. Komutu çalıştır:Get-ItemProperty `"$updaterPath`""
            Write-Host "2. IsReadOnly özelliğinin True olduğunu doğrulayın."
            Write-Host "3. Salt okunur erişimi onaylayın."
            Write-Host ""
            Write-Host "[İpucu] İşiniz bittiğinde lütfen Cursoru yeniden başlatın."
        }

        try {
            if (Test-Path $updaterPath) {
                try {
                    Remove-Item -Path $updaterPath -Force -Recurse -ErrorAction Stop
                    Write-Host "[info] Cursor-updater dizini başarıyla silindi."
                }
                catch {
                    Write-Host "[hata] Cursor-updater dizini silinemedi"
                    Show-ManualGuide
                    return
                }
            }

            try {
                New-Item -Path $updaterPath -ItemType File -Force -ErrorAction Stop | Out-Null
                Write-Host "[info] Engelleme dosyası başarıyla oluşturuldu"
            }
            catch {
                Write-Host "[hata] Engelleme dosyası oluşturulamadı"
                Show-ManualGuide
                return
            }

            try {
                Set-ItemProperty -Path $updaterPath -Name IsReadOnly -Value $true -ErrorAction Stop
                
                $result = Start-Process "icacls.exe" -ArgumentList "`"$updaterPath`" /inheritance:r /grant:r `"$($env:USERNAME):(R)`"" -Wait -NoNewWindow -PassThru
                if ($result.ExitCode -ne 0) {
                    throw "icacls komutu başarısız oldu."
                }
                
                Write-Host "[info] Dosya izinleri başarıyla ayarlandı"
            }
            catch {
                Write-Host "[Hata] Dosya izinleri ayarlanamadı"
                Show-ManualGuide
                return
            }

            try {
                $fileInfo = Get-ItemProperty $updaterPath
                if (-not $fileInfo.IsReadOnly) {
                    Write-Host "[Hata] Kimlik doğrulama başarısız oldu: dosya izin ayarları geçerli olmayabilir"
                    Show-ManualGuide
                    return
                }
            }
            catch {
                Write-Host "[Hata] Kimlik doğrulama kurulum hatası"
                Show-ManualGuide
                return
            }

            Write-Host "[info] Otomatik güncelleme başarıyla devre dışı bırakıldı"
        }
        catch {
            Write-Host "[Hata] Bilinmeyen hata oluştu: $_"
            Show-ManualGuide
        }
    }
    else {
        Write-Host "[info] Varsayılan ayarları değiştirmeden bırak"
    }

    Update-MachineGuid

} catch {
    Write-Host "[hata] Büyük işlem başarısız oldu: $_"
    Write-Host "[try] Alternatifini kullanın..."
    
    try {
        $tempFile = [System.IO.Path]::GetTempFileName()
        $config | ConvertTo-Json | Set-Content -Path $tempFile -Encoding UTF8
        Copy-Item -Path $tempFile -Destination $STORAGE_FILE -Force
        Remove-Item -Path $tempFile
        Write-Host "[info] Alternatif yöntem kullanılarak başarılı yapılandırma yazımı"
    } catch {
        Write-Host "[hata] Tüm denemeler başarısız oldu."
        Write-Host "Hata ayrıntıları: $_"
        Write-Host "Hedef dosya: $STORAGE_FILE"
        Write-Host "Dosyaya erişmek için yeterli izinlere sahip olduğunuzdan emin olun"
        Read-Host "Çıkmak için enter tuşuna basın"
        exit 1
    }
}

Write-Host ""
Read-Host "Çıkmak için enter tuşuna basın"
exit 0

function Write-ConfigFile {
    param($config, $filePath)
    
    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        $jsonContent = $config | ConvertTo-Json -Depth 10
        
        $jsonContent = $jsonContent.Replace("`r`n", "`n")
        
        [System.IO.File]::WriteAllText(
            [System.IO.Path]::GetFullPath($filePath),
            $jsonContent,
            $utf8NoBom
        )
        
        Write-Host "[info] Yapılandırma dosyasına başarıyla yazıldı"
    }
    catch {
        throw "Yapılandırma dosyası yazılamadı: $_"
    }
}

function Compare-Version {
    param (
        [string]$version1,
        [string]$version2
    )
    
    try {
        $v1 = [version]($version1 -replace '[^\d\.].*$')
        $v2 = [version]($version2 -replace '[^\d\.].*$')
        return $v1.CompareTo($v2)
    }
    catch {
        Write-Host "[hata] sürüm karşılaştırması başarısız oldu: $_"
        return 0
    }
}

Write-Host "[info] Cursor sürümünü kontrol ediyor..."
$cursorVersion = Get-CursorVersion

if ($cursorVersion) {
    $compareResult = Compare-Version $cursorVersion "0.45.0"
    if ($compareResult -ge 0) {
        Write-Host "[Error] Geçerli sürüm ($cursorVersion) Henüz desteklenmiyor"
        Write-Host "[Önerilen] Lütfen v0.44.11 ve altını kullanın."
        Write-Host "[önerilen] Desteklenen sürümler şu adresten indirilebilir."
        Write-Host "Windows: https://download.todesktop.com/230313mzl4w4u92/Cursor%20Setup%200.44.11%20-%20Build%20250103fqxdt5u9z-x64.exe"
        Write-Host "Mac ARM64: https://dl.todesktop.com/230313mzl4w4u92/versions/0.44.11/mac/zip/arm64"
        Read-Host "Çıkmak için enter tuşuna basın"
        exit 1
    }
    else {
        Write-Host "[info] Geçerli sürüm ($cursorVersion)"
    }
}
else {
    Write-Host "[WARNING] sürümü algılayamadı"
} 