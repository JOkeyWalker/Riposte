#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Riposte.ps1 - Portable SOC Threat Hunting & Forensic Triage Tool (Headless/Remote Shell Edition)
.DESCRIPTION
    100% CLI-native script. Safe for SentinelOne, WinRM, and reverse shells.
    Optimized to prevent console hangs, support multi-line pasting, and handle wildcards.
#>

$ErrorActionPreference = "SilentlyContinue"

# Clear paste debris immediately on execution
Clear-Host
Write-Host "[*] Loading Riposte..." -ForegroundColor DarkGray

# Ensure HKEY_USERS is mapped as a PSDrive for registry scanning
if (-not (Get-PSDrive HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}

function Show-Banner {
    Clear-Host
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    Write-Host "  [ Riposte ] - TACTICAL THREAT HUNTING & TRIAGE TOOLKIT       " -ForegroundColor Cyan
    Write-Host "  * HEADLESS EDITION - SAFE FOR REMOTE SHELLS (S1/RTR/WinRM) * " -ForegroundColor Yellow
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    Write-Host "  Target OS: $((Get-CimInstance Win32_OperatingSystem).Caption)" -ForegroundColor DarkGray
    Write-Host "  User:      $env:USERDOMAIN\$env:USERNAME" -ForegroundColor DarkGray
    Write-Host "  Time:      $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    Write-Host ""
}

function Pause {
    Write-Host "`n[+] Press ENTER to continue..." -ForegroundColor Gray
    $null = Read-Host
}

function Resolve-SidToUsername {
    param([string]$sid)
    if ($sid -eq "S-1-5-18") { return "NT AUTHORITY\SYSTEM" }
    if ($sid -eq "S-1-5-19") { return "NT AUTHORITY\LocalService" }
    if ($sid -eq "S-1-5-20") { return "NT AUTHORITY\NetworkService" }
    
    # Attempt 1: Live LSASS translate (works for active/domain sessions)
    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        return $objUser.Value
    } catch {}

    # Attempt 2: Local SAM account database (works for local accounts even when logged off)
    try {
        $localUser = Get-LocalUser | Where-Object { $_.SID.Value -eq $sid } | Select-Object -First 1
        if ($localUser) { return "$env:COMPUTERNAME\$($localUser.Name)" }
    } catch {}

    # Attempt 3: Registry ProfileList (catches any account that has ever logged on)
    try {
        $profileKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        if (Test-Path $profileKey) {
            $profilePath = (Get-ItemProperty -Path $profileKey -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath
            if ($profilePath -match '\\([^\\]+)$') {
                return $Matches[1]
            }
        }
    } catch {}

    return "SID: $sid"
}

function Get-AssociatedUser {
    param([string]$path)
    if (-not $path) { return "SYSTEM / All Users" }
    
    # If the path is inside a user profile, extract the username directly from the path
    if ($path -match '(?i)^[A-Z]:\\Users\\([^\\]+)') {
        $user = $Matches[1]
        if ($user -notin @("Public", "All Users", "Default", "Default User")) {
            return $user
        }
    }
    
    # Fallback to NTFS Owner
    try {
        $owner = (Get-Acl -Path $path -ErrorAction SilentlyContinue).Owner
        if ($owner) { return $owner }
    } catch {}
    
    return "SYSTEM / All Users"
}

function Resolve-S1Path {
    param([string]$rawPath)
    if (-not $rawPath) { return $null }
    
    # Strip S1 raw device prefix (e.g., \Device\HarddiskVolume3)
    $relativePath = $rawPath -replace '^\\Device\\HarddiskVolume\d+', ''
    
    # Dynamically check active drive letters to find where the file actually lives
    $drives = @($env:SystemDrive, "C:", "D:", "E:", "F:")
    foreach ($drive in $drives) {
        $testPath = Join-Path $drive $relativePath
        if (Test-Path $testPath) {
            return $testPath
        }
    }
    
    # Fallback to system drive if not found
    return Join-Path $env:SystemDrive $relativePath
}

function Convert-WildcardToRegex {
    param([string]$pattern)
    if (-not $pattern) { return ".*" }
    
    if ($pattern -match '\*|\?') {
        $escaped = [regex]::Escape($pattern)
        return $escaped.Replace('\*', '.*').Replace('\?', '.')
    }
    return [regex]::Escape($pattern)
}

function Parse-Keywords {
    param([string]$inputString)
    $inputString = $inputString.Trim()
    $keywords = @()
    
    if ($inputString -match '"') {
        $matches = [regex]::Matches($inputString, '"([^"]+)"')
        foreach ($m in $matches) {
            $keywords += $m.Groups[1].Value.Trim()
        }
    } else {
        $keywords = $inputString -split '[,;]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }
    
    if ($keywords.Count -eq 0 -and $inputString) {
        $keywords += $inputString
    }
    return $keywords
}

function Extract-FilePath {
    param([string]$cmdline)
    if (-not $cmdline) { return $null }
    
    $expanded = [System.Environment]::ExpandEnvironmentVariables($cmdline)
    
    if ($expanded -match '"([^"]+)"') {
        $path = $Matches[1]
        if (Test-Path $path -PathType Leaf) { return $path }
    }
    
    if ($expanded -match '^([^\s]+\.(exe|dll|bat|ps1|vbs|cmd|scr|msi|jar))') {
        $path = $Matches[1]
        if (Test-Path $path -PathType Leaf) { return $path }
    }
    
    $tokens = $expanded.Split(" ")
    foreach ($token in $tokens) {
        $cleanToken = $token.Trim('"', "'", ',', ';')
        if (Test-Path $cleanToken -PathType Leaf) {
            return $cleanToken
        }
    }
    return $null
}

function Get-FileHashes {
    param([string]$filePath)
    $hashes = @{ SHA1 = "N/A"; SHA256 = "N/A" }
    if ($filePath -and (Test-Path $filePath -PathType Leaf)) {
        try {
            $sha1 = (Get-FileHash -Path $filePath -Algorithm SHA1 -ErrorAction Stop).Hash
            $sha256 = (Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop).Hash
            $hashes.SHA1 = $sha1.ToLower()
            $hashes.SHA256 = $sha256.ToLower()
        } catch {}
    }
    return $hashes
}

function Safe-ParseDate {
    param([string]$dateStr)
    $dt = $null
    
    if ([datetime]::TryParse($dateStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) {
        return $dt
    }
    if ([datetime]::TryParse($dateStr, [ref]$dt)) {
        return $dt
    }
    try {
        return Get-Date $dateStr -ErrorAction Stop
    } catch {}
    
    return $null
}

function Parse-Timeframe {
    param([string]$inputString)
    $inputString = $inputString.Trim()
    $endTime = Get-Date
    $startTime = $null

    if ($inputString -match '^(\d+)([mhdD])$') {
        $val = [int]$Matches[1]
        $unit = $Matches[2].ToLower()
        if ($unit -eq 'm') { $startTime = $endTime.AddMinutes(-$val) }
        elseif ($unit -eq 'h') { $startTime = $endTime.AddHours(-$val) }
        elseif ($unit -eq 'd') { $startTime = $endTime.AddDays(-$val) }
        return @{ StartTime = $startTime; EndTime = $endTime }
    }

    if ($inputString -match '(.+)\s+to\s+(.+)') {
        $part1 = $Matches[1].Trim()
        $part2 = $Matches[2].Trim()

        $timeRegex = '^(\d{1,2}):(\d{2})$'
        if ($part1 -match $timeRegex -and $part2 -match $timeRegex) {
            $null = $part1 -match $timeRegex
            $h1 = [int]$Matches[1]
            $m1 = [int]$Matches[2]
            
            $null = $part2 -match $timeRegex
            $h2 = [int]$Matches[1]
            $m2 = [int]$Matches[2]

            $startTime = (Get-Date).Date.AddHours($h1).AddMinutes($m1)
            $endTime = (Get-Date).Date.AddHours($h2).AddMinutes($m2)
            
            if ($endTime -lt $startTime) {
                $startTime = $startTime.AddDays(-1)
            }
            return @{ StartTime = $startTime; EndTime = $endTime }
        }

        $dt1 = Safe-ParseDate -dateStr $part1
        $dt2 = Safe-ParseDate -dateStr $part2

        if ($dt1 -and $dt2) {
            if ($part2 -notmatch '\d{1,2}:\d{2}') {
                $dt2 = $dt2.Date.AddDays(1).AddSeconds(-1)
            }
            return @{ StartTime = $dt1; EndTime = $dt2 }
        }
    }

    $singleDt = Safe-ParseDate -dateStr $inputString
    if ($singleDt) {
        return @{ StartTime = $singleDt; EndTime = $endTime }
    }

    return $null
}

function Get-RegistryRunKeys {
    $results = @()
    $loadedOfflineHives = @()
    
    try {
        # 1. HKLM Run Keys
        $hklmPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        foreach ($path in $hklmPaths) {
            if (Test-Path $path) {
                $keyItem = Get-Item -Path $path
                $lastModified = if ($keyItem -and $keyItem.LastWriteTime) { $keyItem.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                $properties = Get-ItemProperty -Path $path
                foreach ($prop in $properties.psobject.properties) {
                    if ($prop.Name -notmatch "^PS[A-Z]+|^_") {
                        $results += [PSCustomObject]@{
                            Path         = $path
                            User         = "NT AUTHORITY\SYSTEM (All Users)"
                            LastModified = $lastModified
                            Name         = $prop.Name
                            Value        = $prop.Value
                        }
                    }
                }
            }
        }
        
        # 2. Loaded HKU Run Keys (Active Users)
        $loadedSids = Get-ChildItem HKU: | Where-Object { $_.PSChildName -notmatch '_Classes$' -and $_.PSChildName -match '^S-1-5' }
        foreach ($sidObj in $loadedSids) {
            $sid = $sidObj.PSChildName
            $username = Resolve-SidToUsername -sid $sid
            $hkuPaths = @(
                "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Run",
                "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\RunOnce"
            )
            foreach ($path in $hkuPaths) {
                if (Test-Path $path) {
                    $keyItem = Get-Item -Path $path
                    $lastModified = if ($keyItem -and $keyItem.LastWriteTime) { $keyItem.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                    $properties = Get-ItemProperty -Path $path
                    foreach ($prop in $properties.psobject.properties) {
                        if ($prop.Name -notmatch "^PS[A-Z]+|^_") {
                            $results += [PSCustomObject]@{
                                Path         = $path
                                User         = $username
                                LastModified = $lastModified
                                Name         = $prop.Name
                                Value        = $prop.Value
                            }
                        }
                    }
                }
            }
        }
        
        # 3. Offline HKU Run Keys (Logged-off Users)
        $userProfiles = Get-ChildItem "C:\Users" -Directory
        foreach ($profile in $userProfiles) {
            if ($profile.Name -in @("All Users", "Default", "Default User", "Public")) { continue }
            
            $tempHiveName = "S1_Triage_$($profile.Name)"
            if (Test-Path "HKU:\$tempHiveName") { continue }
            
            $ntuserPath = Join-Path $profile.FullName "NTUSER.DAT"
            if (Test-Path $ntuserPath) {
                reg.exe load "HKU\$tempHiveName" "$ntuserPath" 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    $loadedOfflineHives += $tempHiveName
                    $offlinePaths = @(
                        "HKU:\$tempHiveName\Software\Microsoft\Windows\CurrentVersion\Run",
                        "HKU:\$tempHiveName\Software\Microsoft\Windows\CurrentVersion\RunOnce"
                    )
                    foreach ($path in $offlinePaths) {
                        if (Test-Path $path) {
                            $keyItem = Get-Item -Path $path
                            $lastModified = if ($keyItem -and $keyItem.LastWriteTime) { $keyItem.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                            $properties = Get-ItemProperty -Path $path
                            foreach ($prop in $properties.psobject.properties) {
                                if ($prop.Name -notmatch "^PS[A-Z]+|^_") {
                                    $results += [PSCustomObject]@{
                                        Path         = $path
                                        User         = "$($profile.Name) (Offline)"
                                        LastModified = $lastModified
                                        Name         = $prop.Name
                                        Value        = $prop.Value
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } finally {
        foreach ($hive in $loadedOfflineHives) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            reg.exe unload "HKU\$hive" 2>&1 | Out-Null
        }
    }
    return $results
}

function Invoke-Remediation {
    param([PSCustomObject]$item)

    $type = $item.RemediationType
    $path = $item.RemediationPath

    Write-Host ""
    Write-Host "  [!] Selected for removal:" -ForegroundColor Yellow
    Write-Host "      Tool/Name : $($item.Name)" -ForegroundColor White
    Write-Host "      Type      : $type" -ForegroundColor White
    Write-Host "      Target    : $path" -ForegroundColor White
    Write-Host ""
    $confirm = Read-Host "  [?] Confirm removal? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "  [-] Skipped." -ForegroundColor DarkGray
        return $false
    }

    try {
        switch ($type) {

            "Registry" {
                if (Test-Path $path) {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                    Write-Host "  [+] Registry key removed: $path" -ForegroundColor Green
                } else {
                    # Might be a value rather than a key — try parent key
                    $parent = Split-Path $path -Parent
                    $valueName = Split-Path $path -Leaf
                    if (Test-Path $parent) {
                        Remove-ItemProperty -Path $parent -Name $valueName -Force -ErrorAction Stop
                        Write-Host "  [+] Registry value removed: $valueName from $parent" -ForegroundColor Green
                    } else {
                        Write-Host "  [-] Registry path not found: $path" -ForegroundColor Red
                        return $false
                    }
                }
                return $true
            }

            "Task" {
                $task = Get-ScheduledTask -TaskName $path -ErrorAction SilentlyContinue
                if (-not $task) {
                    # Try with wildcards in case path includes task folder
                    $task = Get-ScheduledTask | Where-Object { $_.TaskName -eq $path } | Select-Object -First 1
                }
                if ($task) {
                    Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
                    Write-Host "  [+] Scheduled task removed: $path" -ForegroundColor Green
                } else {
                    Write-Host "  [-] Scheduled task not found: $path" -ForegroundColor Red
                    return $false
                }
                return $true
            }

            "Service" {
                $svc = Get-Service -Name $path -ErrorAction SilentlyContinue
                if ($svc) {
                    Stop-Service -Name $path -Force -ErrorAction SilentlyContinue
                    sc.exe delete $path | Out-Null
                    Write-Host "  [+] Service stopped and deleted: $path" -ForegroundColor Green
                } else {
                    Write-Host "  [-] Service not found: $path" -ForegroundColor Red
                    return $false
                }
                return $true
            }

            "File" {
                if (Test-Path $path) {
                    # Kill any process holding this file first
                    $procs = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like "*$path*" }
                    foreach ($proc in $procs) {
                        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                    }
                    Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                    Write-Host "  [+] File/folder removed: $path" -ForegroundColor Green
                } else {
                    Write-Host "  [-] Path not found: $path" -ForegroundColor Red
                    return $false
                }
                return $true
            }

            "Process" {
                $pid = [int]$path
                $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($proc) {
                    Stop-Process -Id $pid -Force -ErrorAction Stop
                    Write-Host "  [+] Process terminated: PID $pid ($($proc.Name))" -ForegroundColor Green
                } else {
                    Write-Host "  [-] Process PID $pid not found (may have already exited)." -ForegroundColor Red
                    return $false
                }
                return $true
            }

            "WMI" {
                # RemediationPath format: "Filter:<name>" or "Consumer:<name>" or "Binding:<name>"
                if ($path -match '^Filter:(.+)$') {
                    $name = $Matches[1]
                    Get-WMIObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$name'" -ErrorAction Stop | Remove-WmiObject
                    Write-Host "  [+] WMI Event Filter removed: $name" -ForegroundColor Green
                } elseif ($path -match '^Consumer:(.+)$') {
                    $name = $Matches[1]
                    Get-WMIObject -Namespace root\subscription -Class __EventConsumer -Filter "Name='$name'" -ErrorAction Stop | Remove-WmiObject
                    Write-Host "  [+] WMI Event Consumer removed: $name" -ForegroundColor Green
                } elseif ($path -match '^Binding:(.+)$') {
                    $name = $Matches[1]
                    Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -match $name -or $_.Consumer -match $name } | Remove-WmiObject
                    Write-Host "  [+] WMI Binding removed: $name" -ForegroundColor Green
                } else {
                    Write-Host "  [-] Unknown WMI path format: $path" -ForegroundColor Red
                    return $false
                }
                return $true
            }

            "None" {
                Write-Host "  [-] No automated remediation available for this item type." -ForegroundColor DarkGray
                Write-Host "      Manual investigation required." -ForegroundColor DarkGray
                return $false
            }

            default {
                Write-Host "  [-] Unknown remediation type: $type" -ForegroundColor Red
                return $false
            }
        }
    } catch {
        Write-Host "  [!] Remediation failed: $_" -ForegroundColor Red
        return $false
    }
}


function Process-RemediationLoop {
    param(
        [array]$items,
        [string]$title
    )
    
    $activeItems = $items
    if (-not $activeItems) { $activeItems = @() }
    $loop = $true
    $pageSize = 40
    $currentPage = 0
    
    while ($loop -and $activeItems.Count -gt 0) {
        # Only use paging if total results exceed 40
        $usePaging = $activeItems.Count -gt 40
        $totalPages = if ($usePaging) { [Math]::Ceiling($activeItems.Count / $pageSize) } else { 1 }
        
        if ($currentPage -ge $totalPages) { $currentPage = $totalPages - 1 }
        if ($currentPage -lt 0) { $currentPage = 0 }

        Show-Banner
        Write-Host "===============================================================" -ForegroundColor DarkCyan
        Write-Host "  $title" -ForegroundColor Yellow
        Write-Host "===============================================================" -ForegroundColor DarkCyan
        if ($usePaging) {
            Write-Host "  Total Findings: $($activeItems.Count) | Page $($currentPage + 1) of $totalPages" -ForegroundColor DarkGray
            Write-Host "===============================================================" -ForegroundColor DarkCyan
        } else {
            Write-Host "  Total Findings: $($activeItems.Count)" -ForegroundColor DarkGray
            Write-Host "===============================================================" -ForegroundColor DarkCyan
        }
        
        # Re-index remaining active items globally
        $index = 1
        foreach ($item in $activeItems) {
            if ($item.psobject.properties['MenuIndex']) {
                $item.psobject.properties.Remove('MenuIndex')
            }
            $item | Add-Member -MemberType NoteProperty -Name "MenuIndex" -Value $index
            $index++
        }
        
        # Slice active items if paging is active
        $pageItems = $activeItems
        if ($usePaging) {
            $startIndex = $currentPage * $pageSize
            $endIndex = [Math]::Min(($startIndex + $pageSize - 1), ($activeItems.Count - 1))
            $pageItems = $activeItems[$startIndex..$endIndex]
        }

        # Group and Display
        $groupedByType = $pageItems | Group-Object Type
        foreach ($typeGroup in $groupedByType) {
            Write-Host "`n===============================================================" -ForegroundColor DarkCyan
            Write-Host "  CATEGORY: $($typeGroup.Name)" -ForegroundColor Cyan
            Write-Host "===============================================================" -ForegroundColor DarkCyan
            
            $groupedByUser = $typeGroup.Group | Group-Object User
            foreach ($userGroup in $groupedByUser) {
                Write-Host "`n  [+] User/Context: $($userGroup.Name)" -ForegroundColor Magenta
                Write-Host "  ---------------------------------------------------" -ForegroundColor DarkGray
                
                foreach ($item in $userGroup.Group) {
                    Write-Host "   [$($item.MenuIndex)] Name      : $($item.Name)" -ForegroundColor White
                    Write-Host "       Timestamp : $($item.Timestamp)" -ForegroundColor DarkGray
                    
                    if ($typeGroup.Name -match "Scheduled Task|Service|Process|WMI|RunMRU") {
                        Write-Host "       Action    : $($item.Value)" -ForegroundColor Green
                    } else {
                        Write-Host "       Path/Value: $($item.Value)" -ForegroundColor Green
                    }

                    if ($item.SHA1 -and $item.SHA1 -ne "N/A") {
                        Write-Host "       SHA1      : $($item.SHA1)" -ForegroundColor DarkYellow
                        Write-Host "       SHA256    : $($item.SHA256)" -ForegroundColor DarkYellow
                    }
                    Write-Host ""
                }
            }
        }
        
        Write-Host "`n---------------------------------------------------------------" -ForegroundColor DarkCyan
        if ($usePaging) {
            Write-Host "  Navigation: [N] Next Page | [P] Previous Page" -ForegroundColor Cyan
        }
        Write-Host "  Remediation: Enter number(s) (e.g., 1,3,5) | [R] Return to Menu" -ForegroundColor Cyan
        Write-Host "---------------------------------------------------------------" -ForegroundColor DarkCyan
        $remedChoice = Read-Host " [+] Select Option"
        
        if ($remedChoice -eq 'R' -or $remedChoice -eq 'r' -or -not $remedChoice) {
            $loop = $false
            return # Safe return to caller function
        }
        
        if ($usePaging -and ($remedChoice -eq 'N' -or $remedChoice -eq 'n')) {
            if ($currentPage -lt ($totalPages - 1)) { $currentPage++ }
            continue
        }
        
        if ($usePaging -and ($remedChoice -eq 'P' -or $remedChoice -eq 'p')) {
            if ($currentPage -gt 0) { $currentPage-- }
            continue
        }
        
        $choices = $remedChoice -split '[,\s;]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }
        
        if ($choices.Count -eq 0) {
            Write-Host "[-] Invalid selection." -ForegroundColor Red
            Start-Sleep -Seconds 1
            continue
        }
        
        $remediatedIndices = @()
        foreach ($choice in $choices) {
            $selectedItem = $activeItems | Where-Object { $_.MenuIndex -eq $choice }
            if ($selectedItem) {
                $success = Invoke-Remediation -item $selectedItem
                if ($success) {
                    $remediatedIndices += $choice
                }
            } else {
                Write-Host "[-] Index [$choice] not found." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
        
        if ($remediatedIndices.Count -gt 0) {
            $activeItems = $activeItems | Where-Object { $_.MenuIndex -notin $remediatedIndices }
        }
    }
    
    if ($activeItems.Count -eq 0) {
        Write-Host "`n[+] All identified items have been successfully remediated!" -ForegroundColor Green
        Pause
    }
}

function Get-Persistence {
    Show-Banner
    Write-Host "  HUNT FOR PERSISTENCE" -ForegroundColor Yellow
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    $confirm = Read-Host " [?] Press ENTER to begin scan or Q to cancel"
    if ($confirm -eq 'Q' -or $confirm -eq 'q') { return }
    Write-Host ""
    Write-Host "[*] Scanning for common persistence mechanisms..." -ForegroundColor Yellow
    $results = @()

    # --- 1. REGISTRY RUN KEYS (HKLM, Loaded HKU, and Offline HKU) ---
    try {
        $regKeys = Get-RegistryRunKeys
        foreach ($rk in $regKeys) {
            $resolvedPath = Extract-FilePath -cmdline $rk.Value
            $hashes = Get-FileHashes -filePath $resolvedPath
            $results += [PSCustomObject]@{
                Type            = "Registry Run Keys"
                User            = $rk.User
                Timestamp       = "Modified: $($rk.LastModified)"
                Name            = $rk.Name
                Value           = $rk.Value
                SHA1            = $hashes.SHA1
                SHA256          = $hashes.SHA256
                RemediationType = "Registry"
                RemediationPath = $rk.Path
            }
        }
    } catch {
        Write-Host "[-] Error scanning Registry Run Keys: $_" -ForegroundColor Red
    }

    # --- 2. SCHEDULED TASKS ---
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch "^\\Microsoft\\" -and $_.State -ne "Disabled" }
        foreach ($task in $tasks) {
            try {
                $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                $lastRun = if ($taskInfo -and $taskInfo.LastRunTime) { $taskInfo.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                
                $action = ""
                if ($task.Actions -and $task.Actions.Count -gt 0) {
                    $act = $task.Actions[0]
                    if ($act) {
                        if ($act.PSObject.Properties['Execute']) {
                            $action = ($act.Execute + " " + $act.Arguments).Trim()
                        } elseif ($act.PSObject.Properties['ClassId']) {
                            $action = "COM Handler: " + $act.ClassId
                        } else {
                            $action = $act.ToString()
                        }
                    }
                }
                if (-not $action) { $action = "N/A (Custom/COM Handler)" }
                
                $principal = "SYSTEM / Unknown"
                if ($task.Principal) {
                    if ($task.Principal.UserId) { 
                        $principal = $task.Principal.UserId 
                    } elseif ($task.Principal.GroupId) {
                        $principal = $task.Principal.GroupId
                    }
                }

                $resolvedPath = Extract-FilePath -cmdline $action
                $hashes = Get-FileHashes -filePath $resolvedPath

                $results += [PSCustomObject]@{
                    Type            = "Scheduled Tasks"
                    User            = $principal
                    Timestamp       = "Last Run: $lastRun"
                    Name            = $task.TaskName
                    Value           = $action
                    SHA1            = $hashes.SHA1
                    SHA256          = $hashes.SHA256
                    RemediationType = "Task"
                    RemediationPath = $task.TaskName
                }
            } catch {}
        }
    } catch {
        Write-Host "[-] Error scanning Scheduled Tasks: $_" -ForegroundColor Red
    }

    # --- 3. SERVICES ---
    try {
        Write-Host "[*] Scanning System Services..." -ForegroundColor Yellow
        $services = Get-CimInstance Win32_Service | Where-Object {
            $_.StartMode -in @("Auto", "Manual") -and (
                $_.PathName -match "powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin" -or
                $_.PathName -match "C:\\Users\\|C:\\ProgramData\\|C:\\Temp\\|C:\\Windows\\Temp\\" -or
                ($_.PathName -notmatch '^"?C:\\Windows' -and $_.PathName -notmatch '^"?C:\\Program Files')
            )
        }
        foreach ($service in $services) {
            $resolvedPath = Extract-FilePath -cmdline $service.PathName
            $hashes = Get-FileHashes -filePath $resolvedPath

            $results += [PSCustomObject]@{
                Type            = "Services"
                User            = $service.StartName
                Timestamp       = "State: $($service.State) | Start: $($service.StartMode)"
                Name            = $service.Name
                Value           = $service.PathName
                SHA1            = $hashes.SHA1
                SHA256          = $hashes.SHA256
                RemediationType = "Service"
                RemediationPath = $service.Name
            }
        }
    } catch {
        Write-Host "[-] Error scanning System Services: $_" -ForegroundColor Red
    }

    # --- 4. STARTUP FOLDERS ---
    try {
        $publicStartup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
        if (Test-Path $publicStartup) {
            $files = Get-ChildItem -Path $publicStartup -File -Force
            foreach ($file in $files) {
                $hashes = Get-FileHashes -filePath $file.FullName
                $results += [PSCustomObject]@{
                    Type            = "Startup Folders"
                    User            = "NT AUTHORITY\SYSTEM (All Users)"
                    Timestamp       = "Created: $($file.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                    Name            = $file.Name
                    Value           = $file.FullName
                    SHA1            = $hashes.SHA1
                    SHA256          = $hashes.SHA256
                    RemediationType = "File"
                    RemediationPath = $file.FullName
                }
            }
        }

        $userProfiles = Get-ChildItem "C:\Users" -Directory -Force
        foreach ($profile in $userProfiles) {
            $userStartup = "$($profile.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
            if (Test-Path $userStartup) {
                $files = Get-ChildItem -Path $userStartup -File -Force
                foreach ($file in $files) {
                    $hashes = Get-FileHashes -filePath $file.FullName
                    $results += [PSCustomObject]@{
                        Type            = "Startup Folders"
                        User            = $profile.Name
                        Timestamp       = "Created: $($file.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                        Name            = $file.Name
                        Value           = $file.FullName
                        SHA1            = $hashes.SHA1
                        SHA256          = $hashes.SHA256
                        RemediationType = "File"
                        RemediationPath = $file.FullName
                    }
                }
            }
        }
    } catch {
        Write-Host "[-] Error scanning Startup Folders: $_" -ForegroundColor Red
    }

    return $results
}

function Search-GlobalKeyword {
    Write-Host "---------------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host " [+] Enter keyword(s) to hunt for." -ForegroundColor Cyan
    Write-Host "     Single  : OneBrowser" -ForegroundColor DarkGray
    Write-Host "     Multiple: OneBrowser, OB, KitchenCanvas" -ForegroundColor DarkGray
    $keywordInput = Read-Host " [?] (or Q to cancel)"
    if ($keywordInput -eq 'Q' -or $keywordInput -eq 'q') { return }
    
    Write-Host " [+] Enter directory path to restrict file search" -ForegroundColor Gray
    $pathInput = Read-Host "     (Leave blank to scan HIGH-VALUE TRIAGE areas: Users, ProgramData, Temp)"
    
    $parsedKeywords = Parse-Keywords -inputString $keywordInput
    if ($parsedKeywords.Count -eq 0) {
        Write-Host "[-] No valid keywords entered." -ForegroundColor Red
        Pause
        return
    }

    $regexPatterns = @()
    foreach ($kw in $parsedKeywords) {
        $regexPatterns += Convert-WildcardToRegex -pattern $kw
    }
    $regexKeyword = "(" + ($regexPatterns -join '|') + ")"

    Invoke-GlobalHunt -keywords $parsedKeywords -regexPattern $regexKeyword -pathInput $pathInput -directIocs $null
}

function Invoke-GlobalHunt {
    param(
        [array]$keywords,
        [string]$regexPattern,
        [string]$pathInput,
        [hashtable]$directIocs
    )

    Write-Host "`n[*] Initiating Optimized Global Hunt for: $($keywords -join ', ')..." -ForegroundColor Yellow
    $globalResults = @()

    # --- 0. DIRECT ALERT TARGET RESOLUTION ---
    if ($directIocs -and $directIocs.Path) {
        if (Test-Path $directIocs.Path) {
            $fileObj = Get-Item -Path $directIocs.Path
            $owner = Get-AssociatedUser -path $fileObj.FullName
            $hashes = Get-FileHashes -filePath $directIocs.Path
            $globalResults += [PSCustomObject]@{
                Type            = "S1 Alert Target File (Active)"
                User            = $owner
                Timestamp       = "Identified in S1 Alert"
                Name            = $fileObj.Name
                Value           = $fileObj.FullName
                SHA1            = $hashes.SHA1
                SHA256          = $hashes.SHA256
                RemediationType = "File"
                RemediationPath = $fileObj.FullName
            }
            Write-Host "[+] Resolved active S1 alert target file directly on disk!" -ForegroundColor Green
        }
    }

    # --- 1. OPTIMIZED REGISTRY HUNT (HKLM, Loaded HKU, and Offline HKU) ---
    Write-Host "[*] Scanning Registry Run Keys..." -ForegroundColor Yellow
    try {
        $regKeys = Get-RegistryRunKeys
        foreach ($rk in $regKeys) {
            if ($rk.Name -match $regexPattern -or $rk.Value -match $regexPattern) {
                $resolvedPath = Extract-FilePath -cmdline $rk.Value
                $hashes = Get-FileHashes -filePath $resolvedPath
                $globalResults += [PSCustomObject]@{
                    Type            = "Registry Value Match"
                    User            = $rk.User
                    Timestamp       = "Key: $($rk.Path)"
                    Name            = $rk.Name
                    Value           = "[$($rk.Name)] -> $($rk.Value)"
                    SHA1            = $hashes.SHA1
                    SHA256          = $hashes.SHA256
                    RemediationType = "Registry"
                    RemediationPath = $rk.Path
                }
            }
        }
    } catch {
        Write-Host "[-] Error scanning Registry: $_" -ForegroundColor Red
    }

    # --- 2. SCHEDULED TASKS HUNT ---
    Write-Host "[*] Scanning Scheduled Tasks..." -ForegroundColor Yellow
    $tasks = Get-ScheduledTask
    foreach ($task in $tasks) {
        try {
            $action = ""
            if ($task.Actions -and $task.Actions.Count -gt 0) {
                $act = $task.Actions[0]
                if ($act) {
                    if ($act.PSObject.Properties['Execute']) {
                        $action = ($act.Execute + " " + $act.Arguments).Trim()
                    } elseif ($act.PSObject.Properties['ClassId']) {
                        $action = "COM Handler: " + $act.ClassId
                    } else {
                        $action = $act.ToString()
                    }
                }
            }
            if (-not $action) { $action = "N/A" }

            if ($task.TaskName -match $regexPattern -or $task.TaskPath -match $regexPattern -or $action -match $regexPattern) {
                $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                $lastRun = if ($taskInfo -and $taskInfo.LastRunTime) { $taskInfo.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                $principal = "SYSTEM / Unknown"
                if ($task.Principal) {
                    if ($task.Principal.UserId) { 
                        $principal = $task.Principal.UserId 
                    } elseif ($task.Principal.GroupId) {
                        $principal = $task.Principal.GroupId
                    }
                }
                
                $resolvedPath = Extract-FilePath -cmdline $action
                $hashes = Get-FileHashes -filePath $resolvedPath

                $globalResults += [PSCustomObject]@{
                    Type            = "Scheduled Task Match"
                    User            = $principal
                    Timestamp       = "Last Run: $lastRun"
                    Name            = $task.TaskName
                    Value           = $action
                    SHA1            = $hashes.SHA1
                    SHA256          = $hashes.SHA256
                    RemediationType = "Task"
                    RemediationPath = $task.TaskName
                }
            }
        } catch {}
    }

    # --- 3. SERVICES HUNT ---
    Write-Host "[*] Scanning System Services..." -ForegroundColor Yellow
    $services = Get-CimInstance Win32_Service
    foreach ($service in $services) {
        if ($service.Name -match $regexPattern -or $service.DisplayName -match $regexPattern -or $service.PathName -match $regexPattern) {
            $resolvedPath = Extract-FilePath -cmdline $service.PathName
            $hashes = Get-FileHashes -filePath $resolvedPath

            $globalResults += [PSCustomObject]@{
                Type            = "Service Match"
                User            = $service.StartName
                Timestamp       = "State: $($service.State)"
                Name            = $service.Name
                Value           = $service.PathName
                SHA1            = $hashes.SHA1
                SHA256          = $hashes.SHA256
                RemediationType = "Service"
                RemediationPath = $service.Name
            }
        }
    }

    # --- 4. OPTIMIZED FILE SYSTEM HUNT ---
    $searchPaths = @()
    if ($pathInput) {
        if ($pathInput -eq "C:\Users" -or $pathInput -eq "C:\Users\") {
            $userDirs = Get-ChildItem -Path "C:\Users" -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @("All Users", "Default", "Default User", "Public") }
            foreach ($ud in $userDirs) { $searchPaths += $ud.FullName }
            $searchPaths += "C:\Users\Public"
        } else {
            $searchPaths += $pathInput
        }
    } else {
        $userDirs = Get-ChildItem -Path "C:\Users" -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @("All Users", "Default", "Default User", "Public") }
        foreach ($ud in $userDirs) { $searchPaths += $ud.FullName }
        $searchPaths += "C:\Users\Public"
        $searchPaths += @("C:\ProgramData", "C:\Windows\Temp", "C:\Temp")
        
        if ($directIocs -and $directIocs.Path) {
            $alertDir = [System.IO.Path]::GetDirectoryName($directIocs.Path)
            if ($alertDir -and (Test-Path $alertDir) -and ($searchPaths -notcontains $alertDir)) {
                $searchPaths += $alertDir
            }
        }
        Write-Host "[*] No path specified. Defaulting to high-value triage areas to prevent system hang." -ForegroundColor DarkGray
    }

    $excludeDirs = @(
        "C:\Windows\WinSxS",
        "C:\Windows\servicing",
        "C:\Windows\System32\DriverStore",
        "C:\Windows\assembly",
        "C:\$Recycle.Bin",
        "C:\Windows\Microsoft.NET"
    )

    Write-Host "[*] Scanning File System (Names only)..." -ForegroundColor Yellow

    # Build deduplicated keyword filter list once (strips wildcards, removes dupes, skips too-short)
    $cleanKeywords = @()
    foreach ($kw in $keywords) {
        $ck = $kw -replace '\*', ''
        if ($ck.Length -ge 3 -and $cleanKeywords -notcontains $ck) { $cleanKeywords += $ck }
    }

    # Use a HashSet to avoid scanning/hashing the same file path more than once
    $seenFilePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($startPath in $searchPaths) {
        if (-not (Test-Path $startPath)) { continue }
        
        $queue = [System.Collections.Generic.Queue[string]]::new()
        $queue.Enqueue($startPath)

        while ($queue.Count -gt 0) {
            $currentPath = $queue.Dequeue()
            if ($excludeDirs -contains $currentPath) { continue }

            # Collect all files in this directory once, then test against all keywords
            $allFiles = Get-ChildItem -Path $currentPath -File -Force -ErrorAction SilentlyContinue
            foreach ($file in $allFiles) {
                # Skip already-seen paths (prevents duplicate results when multiple keywords match)
                if (-not $seenFilePaths.Add($file.FullName)) { continue }

                # Check if filename matches any keyword
                $matched = $false
                foreach ($ck in $cleanKeywords) {
                    if ($file.Name -like "*$ck*") { $matched = $true; break }
                }
                if (-not $matched) { continue }

                # Secondary regex check for accuracy
                if ($file.Name -notmatch $regexPattern) { continue }

                $associatedUser = Get-AssociatedUser -path $file.FullName
                $hashes = Get-FileHashes -filePath $file.FullName
                $globalResults += [PSCustomObject]@{
                    Type            = "File Name Match"
                    User            = $associatedUser
                    Timestamp       = "Modified: $($file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                    Name            = $file.Name
                    Value           = $file.FullName
                    SHA1            = $hashes.SHA1
                    SHA256          = $hashes.SHA256
                    RemediationType = "File"
                    RemediationPath = $file.FullName
                }
            }

            $subDirs = Get-ChildItem -Path $currentPath -Directory -Force -ErrorAction SilentlyContinue
            foreach ($sd in $subDirs) {
                if ($sd.Attributes -match "ReparsePoint") { continue }
                $queue.Enqueue($sd.FullName)
            }
        }
    }

    # --- 5. RUNNING PROCESS HUNT ---
    Write-Host "[*] Scanning Running Processes..." -ForegroundColor Yellow
    try {
        $runningProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        foreach ($proc in $runningProcs) {
            $procName     = $proc.Name
            $procPath     = $proc.ExecutablePath
            $procCmdLine  = $proc.CommandLine
            $matched      = $false

            if ($procName    -and $procName    -match $regexPattern) { $matched = $true }
            if ($procPath    -and $procPath    -match $regexPattern) { $matched = $true }
            if ($procCmdLine -and $procCmdLine -match $regexPattern) { $matched = $true }

            if ($matched) {
                $procOwner = try {
                    $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue
                    if ($owner.Domain -and $owner.User) { "$($owner.Domain)\$($owner.User)" }
                    elseif ($owner.User) { $owner.User }
                    else { "Unknown" }
                } catch { "Unknown" }

                $hashes = Get-FileHashes -filePath $procPath
                $globalResults += [PSCustomObject]@{
                    Type            = "Running Process Match"
                    User            = $procOwner
                    Timestamp       = "PID: $($proc.ProcessId)"
                    Name            = $procName
                    Value           = if ($procPath) { $procPath } else { $procCmdLine }
                    SHA1            = $hashes.SHA1
                    SHA256          = $hashes.SHA256
                    RemediationType = "Process"
                    RemediationPath = $proc.ProcessId
                }
            }
        }
    } catch {
        Write-Host "[-] Error scanning processes: $_" -ForegroundColor Red
    }

    # --- 6. EVENT LOG HUNT ---
    Write-Host "[*] Scanning Event Logs (last 7 days)..." -ForegroundColor Yellow

    $logLookback = (Get-Date).AddDays(-7)

    # Define logs and event IDs most relevant to SOC triage
    $eventLogTargets = @(
        @{ Log = "Security";                          IDs = @(4688, 4624, 4625, 4648, 4672, 4698, 4702, 4720, 4732) },
        @{ Log = "System";                            IDs = @(7045, 7036, 7040) },
        @{ Log = "Application";                       IDs = @() },
        @{ Log = "Microsoft-Windows-PowerShell/Operational"; IDs = @(4104) },
        @{ Log = "Microsoft-Windows-Sysmon/Operational";     IDs = @(1, 3, 7, 11, 13) }
    )

    # Friendly descriptions for key event IDs
    $eventDesc = @{
        4688 = "Process Created";       4624 = "Logon Success";         4625 = "Logon Failure"
        4648 = "Explicit Logon";        4672 = "Privileged Logon";      4698 = "Scheduled Task Created"
        4702 = "Scheduled Task Updated";4720 = "User Account Created";  4732 = "User Added to Group"
        7045 = "New Service Installed"; 7036 = "Service State Change";  7040 = "Service Start Type Changed"
        4104 = "PS Script Block";       1    = "Sysmon Process Create";  3    = "Sysmon Network Connect"
        7    = "Sysmon Image Loaded";   11   = "Sysmon File Created";    13   = "Sysmon Registry Set"
    }

    foreach ($target in $eventLogTargets) {
        $logName = $target.Log
        $eventIDs = $target.IDs

        # Skip logs that don't exist on this system
        $logExists = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
        if (-not $logExists) { continue }

        try {
            $filter = @{ LogName = $logName; StartTime = $logLookback }
            if ($eventIDs.Count -gt 0) { $filter['Id'] = $eventIDs }

            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 5000 -ErrorAction Stop

            foreach ($evt in $events) {
                # Render full event message and check against keywords
                $msg = try { $evt.Message } catch { "" }
                if (-not $msg) { $msg = ($evt.Properties | ForEach-Object { $_.Value }) -join " " }

                if (-not ($msg -match $regexPattern)) { continue }

                # Resolve user from event
                $evtUser = "N/A"
                if ($evt.UserId) {
                    $evtUser = Resolve-SidToUsername -sid $evt.UserId.ToString()
                } elseif ($msg -match '(?i)Account Name:\s+(\S+)') {
                    $evtUser = $Matches[1]
                }

                # Skip noisy system accounts
                if ($evtUser -match "^NT AUTHORITY\\(SYSTEM|NETWORK SERVICE|LOCAL SERVICE)$") { continue }

                $friendlyDesc = if ($eventDesc.ContainsKey($evt.Id)) { $eventDesc[$evt.Id] } else { "Event" }
                $shortLog = $logName -replace 'Microsoft-Windows-','' -replace '/Operational',''

                # Extract the most relevant line from the message that contains the keyword
                $matchLine = ($msg -split "`n" | Where-Object { $_ -match $regexPattern } | Select-Object -First 1)
                $matchLine = if ($matchLine) { $matchLine.Trim() } else { $msg.Substring(0, [Math]::Min(200, $msg.Length)).Trim() }

                $globalResults += [PSCustomObject]@{
                    Type            = "Event Log: $shortLog (ID $($evt.Id))"
                    User            = $evtUser
                    Timestamp       = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    Name            = "$friendlyDesc (ID $($evt.Id))"
                    Value           = $matchLine
                    SHA1            = "N/A"
                    SHA256          = "N/A"
                    RemediationType = "None"
                    RemediationPath = "N/A"
                }
            }
        } catch {
            # Log not accessible or no events in range — skip silently
        }
    }

    if ($globalResults.Count -gt 0) {
        Process-RemediationLoop -items $globalResults -title "GLOBAL HUNT RESULTS FOR: $($keywords -join ', ')"
    } else {
        Write-Host "`n[-] No matches found across any system vectors." -ForegroundColor Red
        Pause
    }
}

function Get-S1ThreatHunt {
    Show-Banner
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    Write-Host "  SENTINELONE THREAT DETAIL HUNT" -ForegroundColor Yellow
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    Write-Host ""
    
    # HIGH-VISIBILITY INSTRUCTION BOX
    Write-Host "***************************************************************" -ForegroundColor Red
    Write-Host "  INSTRUCTIONS:" -ForegroundColor Yellow
    Write-Host "  1. Copy your full SentinelOne Threat Details block." -ForegroundColor White
    Write-Host "  2. Paste directly into this terminal." -ForegroundColor White
    Write-Host "  3. Hunt begins automatically after the last line." -ForegroundColor White
    Write-Host "     (Detection stops at 'Subscription Time:' line)" -ForegroundColor DarkGray
    Write-Host "  Type Q and press ENTER to cancel." -ForegroundColor DarkGray
    Write-Host "***************************************************************" -ForegroundColor Red
    Write-Host ""
    Write-Host " [+] Paste Threat Details below:" -ForegroundColor Cyan
    Write-Host ""

    $lines = @()
    $pasteLoop = $true
    while ($pasteLoop) {
        $line = Read-Host
        if ($line -eq 'Q' -or $line -eq 'q') { return }
        $lines += $line
        # Auto-detect end of S1 threat detail block by known terminal fields
        if ($line -match '(?i)^\s*Subscription\s*Time:' -or
            $line -match '(?i)^\s*END\s*$') {
            $pasteLoop = $false
        }
    }
    $rawText = $lines -join "`n"

    if (-not $rawText.Trim()) {
        Write-Host "[-] No threat details pasted." -ForegroundColor Red
        Pause
        return
    }

    Write-Host "`n[*] Parsing Threat Details..." -ForegroundColor Yellow
    $iocs = @{}
    
    # Extract fields using case-insensitive regex
    if ($rawText -match '(?i)Name:\s*(.+)')              { $iocs.Name      = $Matches[1].Trim() }
    if ($rawText -match '(?i)Path:\s*(.+)') { 
        $rawPath = $Matches[1].Trim()
        $iocs.Path = Resolve-S1Path -rawPath $rawPath
    }
    if ($rawText -match '(?i)SHA1:\s*([a-fA-F0-9]{40})') { $iocs.SHA1      = $Matches[1].Trim() }
    if ($rawText -match '(?i)SHA256:\s*([a-fA-F0-9]{64})'){ $iocs.SHA256    = $Matches[1].Trim() }
    if ($rawText -match '(?i)Process User:\s*(.+)')       { $iocs.User      = $Matches[1].Trim() }
    if ($rawText -match '(?i)Threat Id:\s*(\d+)')         { $iocs.ThreatId  = $Matches[1].Trim() }
    if ($rawText -match '(?i)Publisher Name:\s*(.+)')     { $iocs.Publisher = $Matches[1].Trim() }
    if ($rawText -match '(?i)Signer Identity:\s*(.+)')    { $iocs.Signer    = $Matches[1].Trim() }
    if ($rawText -match '(?i)Originating Process:\s*(.+)'){ $iocs.Origin    = $Matches[1].Trim() }
    if ($rawText -match '(?i)Computer Name:\s*(.+)')      { $iocs.Computer  = $Matches[1].Trim() }
    if ($rawText -match '(?i)Storyline:\s*([A-F0-9]+)')   { $iocs.Storyline = $Matches[1].Trim() }

    # Display parsed IOCs
    Write-Host "`n=== EXTRACTED THREAT IOCS ===" -ForegroundColor Magenta
    if ($iocs.Name)      { Write-Host "  File Name  : $($iocs.Name)"      -ForegroundColor Cyan }
    if ($iocs.Path)      { Write-Host "  File Path  : $($iocs.Path)"      -ForegroundColor Cyan }
    if ($iocs.SHA1)      { Write-Host "  SHA1 Hash  : $($iocs.SHA1)"      -ForegroundColor Cyan }
    if ($iocs.SHA256)    { Write-Host "  SHA256     : $($iocs.SHA256)"    -ForegroundColor Cyan }
    if ($iocs.User)      { Write-Host "  User       : $($iocs.User)"      -ForegroundColor Cyan }
    if ($iocs.Publisher) { Write-Host "  Publisher  : $($iocs.Publisher)" -ForegroundColor Cyan }
    if ($iocs.Signer)    { Write-Host "  Signer     : $($iocs.Signer)"    -ForegroundColor Cyan }
    if ($iocs.Origin)    { Write-Host "  Origin Proc: $($iocs.Origin)"    -ForegroundColor Cyan }
    if ($iocs.Computer)  { Write-Host "  Computer   : $($iocs.Computer)"  -ForegroundColor Cyan }
    if ($iocs.Storyline) { Write-Host "  Storyline  : $($iocs.Storyline)" -ForegroundColor Cyan }
    if ($iocs.ThreatId)  { Write-Host "  Threat ID  : $($iocs.ThreatId)"  -ForegroundColor Cyan }
    Write-Host "=============================" -ForegroundColor DarkCyan

    # --- DIRECT TARGET RESOLUTION WITH EXPLICIT USER PROMPT ---
    $targetDeleted = $false
    if ($iocs.Path -and (Test-Path $iocs.Path)) {
        Write-Host "`n===============================================================" -ForegroundColor Red
        Write-Host "  [!] DIRECT TARGET DETECTED ON DISK" -ForegroundColor Red
        Write-Host "===============================================================" -ForegroundColor Red
        Write-Host "  Path: $($iocs.Path)" -ForegroundColor Yellow
        Write-Host "---------------------------------------------------------------" -ForegroundColor Red
        
        $immediateDelete = Read-Host " [?] Do you want to immediately delete this file now? (Y/N)"
        if ($immediateDelete -eq 'Y' -or $immediateDelete -eq 'y') {
            try {
                Remove-Item -Path $iocs.Path -Force -ErrorAction Stop
                Write-Host "[+] SUCCESS: Deleted target file '$($iocs.Path)'" -ForegroundColor Green
                $targetDeleted = $true
            } catch {
                Write-Host "[-] ERROR: Failed to delete file: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "[*] Skipping immediate deletion. File will be included in the hunt results." -ForegroundColor Yellow
        }
        Write-Host "===============================================================" -ForegroundColor Red
    }

    # Build search keywords
    $searchKeywords = @()
    if ($iocs.Name) {
        # Exact filename
        $searchKeywords += $iocs.Name

        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($iocs.Name)

        # Always add wildcard of the full base name (e.g. *Shift - PDF_x65q7m*)
        if ($baseName.Length -gt 3) {
            $searchKeywords += "*$baseName*"
        }

        # Generic/noisy tokens that are too broad to be useful as standalone search terms
        $noisyTokens = @(
            'pdf','doc','docx','xls','xlsx','ppt','pptx','exe','msi','zip','rar','7z','iso','img',
            'setup','install','installer','update','updater','patch','new','file','files',
            'windows','win','win32','win64','x86','x64','32bit','64bit',
            'app','application','tool','tools','utility','utilities','program','programs',
            'free','trial','lite','pro','plus','premium','full','final','release','build',
            'tmp','temp','cache','data','log','logs','run','get','set','the','and','for'
        )

        # Split on common separators and extract meaningful word tokens (3+ chars, not pure hex/digits)
        $tokens = $baseName -split '[\s\-_\.\(\)\[\]]+'
        foreach ($token in $tokens) {
            $token = $token.Trim()
            # Skip: short, pure numeric, pure hex hashes, noisy generic words, already added
            if ($token.Length -lt 3)                               { continue }
            if ($token -match '^\d+$')                             { continue }
            if ($token -match '^[a-fA-F0-9]{6,}$')                { continue }
            if ($noisyTokens -contains $token.ToLower())           { continue }
            if ($searchKeywords -contains $token)                  { continue }
            if ($searchKeywords -contains "*$token*")              { continue }
            $searchKeywords += $token
        }

        # Strip trailing random suffix patterns and add cleaned base
        # e.g. "Shift - PDF_x65q7m" -> "Shift - PDF"
        if ($baseName -match '^(.+?)[_-][a-zA-Z0-9]{4,10}$') {
            $cleaned = $Matches[1].Trim()
            if ($cleaned.Length -gt 3 -and $searchKeywords -notcontains "*$cleaned*") {
                $searchKeywords += "*$cleaned*"
            }
        }
    }

    # Publisher / Signer — search for company name tokens (skip generic words)
    $skipWords = @('inc','ltd','llc','corp','co','the','and','technologies','software','systems','group','solutions')
    foreach ($sigField in @($iocs.Publisher, $iocs.Signer)) {
        if (-not $sigField) { continue }
        $sigTokens = $sigField -split '[\s,]+' | Where-Object {
            $_.Length -ge 4 -and ($skipWords -notcontains $_.ToLower()) -and ($searchKeywords -notcontains $_)
        }
        foreach ($tok in $sigTokens) {
            $searchKeywords += $tok
        }
    }

    # Originating Process — add if not a broad/noisy system process
    if ($iocs.Origin) {
        $noisyProcs = @(
            'chrome.exe','firefox.exe','msedge.exe','iexplore.exe','opera.exe','brave.exe','safari.exe',
            'powershell.exe','powershell_ise.exe','pwsh.exe',
            'cmd.exe','conhost.exe','wscript.exe','cscript.exe',
            'explorer.exe','taskhost.exe','taskhostw.exe','sihost.exe',
            'svchost.exe','services.exe','lsass.exe','winlogon.exe','csrss.exe','smss.exe','wininit.exe',
            'msiexec.exe','mshta.exe','rundll32.exe','regsvr32.exe',
            'outlook.exe','winword.exe','excel.exe','powerpnt.exe','onenote.exe','teams.exe',
            'slack.exe','zoom.exe','discord.exe',
            'wmiprvse.exe','wmiapsrv.exe','wsmprovhost.exe',
            'searchindexer.exe','searchhost.exe','runtimebroker.exe','dllhost.exe'
        )
        $originProc = $iocs.Origin.Trim().ToLower()
        if ($noisyProcs -notcontains $originProc -and $searchKeywords -notcontains $iocs.Origin) {
            $searchKeywords += $iocs.Origin
            # Also add the base name without extension as a token
            $originBase = [System.IO.Path]::GetFileNameWithoutExtension($iocs.Origin)
            if ($originBase.Length -gt 3 -and $searchKeywords -notcontains $originBase) {
                $searchKeywords += $originBase
            }
        }
    }

    if ($iocs.SHA1)   { $searchKeywords += $iocs.SHA1 }
    if ($iocs.SHA256) { $searchKeywords += $iocs.SHA256 }

    if ($searchKeywords.Count -eq 0) {
        Write-Host "[-] Could not extract any actionable IOCs (Name or Hashes) from the pasted text." -ForegroundColor Red
        Pause
        return
    }

    # Compile regex pattern
    $regexPatterns = @()
    foreach ($kw in $searchKeywords) {
        $regexPatterns += Convert-WildcardToRegex -pattern $kw
    }
    $regexKeyword = "(" + ($regexPatterns -join '|') + ")"

    # Run the hunt (only pass direct IOCs if the file was NOT already deleted)
    $directIocsToPass = if ($targetDeleted) { $null } else { $iocs }
    Invoke-GlobalHunt -keywords $searchKeywords -regexPattern $regexKeyword -pathInput $null -directIocs $directIocsToPass
}

function Get-PSHistory {
    Write-Host "---------------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host " [+] Enter Timeframe to query PowerShell Execution History:" -ForegroundColor Cyan
    Write-Host "     Examples:" -ForegroundColor DarkGray
    Write-Host "       5m                      = Past 5 minutes" -ForegroundColor DarkGray
    Write-Host "       1h                      = Past hour" -ForegroundColor DarkGray
    Write-Host "       1D                      = Past day" -ForegroundColor DarkGray
    Write-Host "       11:30 to 15:20          = Today's 24hr range" -ForegroundColor DarkGray
    Write-Host "       6/2/2026 to 6/4/2026    = Date range" -ForegroundColor DarkGray
    Write-Host "       6/4/2026 11:30 to 6/5/2026 6:30" -ForegroundColor DarkGray
    Write-Host ""
    
    $timeInput = Read-Host " [?] Enter timeframe (or Q to cancel)"
    if ($timeInput -eq 'Q' -or $timeInput -eq 'q') { return }
    if (-not $timeInput) {
        Write-Host "[-] No input provided. Defaulting to past 1 hour." -ForegroundColor Red
        $timeInput = "1h"
    }

    $parsedTime = Parse-Timeframe -inputString $timeInput
    if (-not $parsedTime) {
        Write-Host "[-] ERROR: Could not parse timeframe format. Defaulting to past 1 hour." -ForegroundColor Red
        $parsedTime = Parse-Timeframe -inputString "1h"
    }

    $startTime = $parsedTime.StartTime
    $endTime = $parsedTime.EndTime

    Write-Host "`n[*] Querying PowerShell Operational Event Log (ID 4104)..." -ForegroundColor Yellow
    Write-Host "    Range: $($startTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkGray
    
    $filter = @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        ID = 4104
        StartTime = $startTime
        EndTime = $endTime
    }

    # Query with a safety cap of 1000 events to prevent terminal spam/hangs
    $events = $null
    try {
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 -ErrorAction Stop
    } catch {}
    
    $results = @()

    if ($events) {
        foreach ($event in $events) {
            # Extract SID string from the SecurityIdentifier object before resolving
            $sidString = if ($event.UserId) { $event.UserId.ToString() } else { $null }
            $resolvedUser = if ($sidString) { Resolve-SidToUsername -sid $sidString } else { "Unknown" }
            
            # Skip SentinelOne remote shell operator activity
            if ($resolvedUser -match "(?i)SentinelRSHUser|SentinelOne") { continue }
            
            # Skip high-noise system accounts with no investigative value in PS history
            if ($resolvedUser -match "^NT AUTHORITY\\(SYSTEM|NETWORK SERVICE|LOCAL SERVICE)$") { continue }
            
            $results += [PSCustomObject]@{
                Time        = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                User        = $resolvedUser
                ScriptBlock = $event.Properties[2].Value
            }
        }
        
        # --- POWERSHELL HISTORY PAGING LOOP (5 events per page) ---
        $pageSize = 5
        $currentPage = 0
        $totalPages = [Math]::Ceiling($results.Count / $pageSize)
        $loop = $true
        
        if ($results.Count -eq 0) {
            Show-Banner
            Write-Host "===============================================================" -ForegroundColor DarkCyan
            Write-Host "  POWERSHELL EXECUTION HISTORY" -ForegroundColor Yellow
            Write-Host "===============================================================" -ForegroundColor DarkCyan
            Write-Host "`n[*] Events were found in the selected timeframe but all were" -ForegroundColor Yellow
            Write-Host "    filtered out (SYSTEM, service accounts, S1 operator)." -ForegroundColor Yellow
            Write-Host "    No user-context PowerShell activity in this window." -ForegroundColor DarkGray
            Write-Host ""
            Pause
            return
        }

        while ($loop -and $results.Count -gt 0) {
            Show-Banner
            Write-Host "===============================================================" -ForegroundColor DarkCyan
            Write-Host "  POWERSHELL EXECUTION HISTORY" -ForegroundColor Yellow
            Write-Host "  Range: $($startTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkGray
            Write-Host "===============================================================" -ForegroundColor DarkCyan
            Write-Host "  Total Events: $($results.Count) | Page $($currentPage + 1) of $totalPages" -ForegroundColor DarkGray
            Write-Host "===============================================================" -ForegroundColor DarkCyan
            
            $startIndex = $currentPage * $pageSize
            $endIndex = [Math]::Min(($startIndex + $pageSize - 1), ($results.Count - 1))
            $pageEvents = $results[$startIndex..$endIndex]
            
            foreach ($res in $pageEvents) {
                Write-Host " [+] Timestamp : $($res.Time)" -ForegroundColor Cyan
                Write-Host "     User      : $($res.User)" -ForegroundColor Yellow
                Write-Host "     Command   :" -ForegroundColor White
                
                $scriptLines = $res.ScriptBlock -split "`r?`n" | Where-Object { $_.Trim() }
                foreach ($line in $scriptLines) {
                    Write-Host "       $line" -ForegroundColor Green
                }
                Write-Host " ---------------------------------------------------" -ForegroundColor DarkGray
            }
            
            Write-Host "`n---------------------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host "  Navigation: [N] Next Page | [P] Previous Page | [R] Return to Menu" -ForegroundColor Cyan
            Write-Host "---------------------------------------------------------------" -ForegroundColor DarkCyan
            $navChoice = Read-Host " [+] Select Option"
            
            if ($navChoice -eq 'R' -or $navChoice -eq 'r' -or -not $navChoice) {
                $loop = $false
                return
            }
            if ($navChoice -eq 'N' -or $navChoice -eq 'n') {
                if ($currentPage -lt ($totalPages - 1)) { $currentPage++ }
                continue
            }
            if ($navChoice -eq 'P' -or $navChoice -eq 'p') {
                if ($currentPage -gt 0) { $currentPage-- }
                continue
            }
        }
    } else {
        Show-Banner
        Write-Host "===============================================================" -ForegroundColor DarkCyan
        Write-Host "  POWERSHELL EXECUTION HISTORY" -ForegroundColor Yellow
        Write-Host "===============================================================" -ForegroundColor DarkCyan
        Write-Host "`n[-] No events found in the selected timeframe." -ForegroundColor Red
        Write-Host "    This may mean:" -ForegroundColor DarkGray
        Write-Host "      - No PowerShell activity occurred in this window" -ForegroundColor DarkGray
        Write-Host "      - Script Block Logging (Event ID 4104) is not enabled" -ForegroundColor DarkGray
        Write-Host "      - The event log has been cleared" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "[*] Falling back to current user PSReadLine history..." -ForegroundColor Yellow
        $historyPath = (Get-PSReadLineOption).HistorySavePath
        if (Test-Path $historyPath) {
            $fileInfo = Get-Item $historyPath
            
            Show-Banner
            Write-Host "===============================================================" -ForegroundColor DarkCyan
            Write-Host "  PSREADLINE HISTORY (LAST 50 COMMANDS)" -ForegroundColor Yellow
            Write-Host "  File Modified: $($fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkGray
            Write-Host "===============================================================" -ForegroundColor DarkCyan
            Write-Host " ---------------------------------------------------" -ForegroundColor DarkGray
            
            $historyContent = Get-Content $historyPath | Select-Object -Last 50
            foreach ($cmd in $historyContent) {
                if ($cmd.Trim()) {
                    Write-Host " [+] Command   : " -NoNewline -ForegroundColor Cyan
                    Write-Host "$($cmd.Trim())" -ForegroundColor Green
                    Write-Host " ---------------------------------------------------" -ForegroundColor DarkGray
                }
            }
            Pause
        } else {
            Write-Host "[-] PSReadLine history file not found." -ForegroundColor Red
            Write-Host "    No PowerShell history available for this user." -ForegroundColor DarkGray
            Write-Host ""
            Pause
        }
    }
}

function Get-ProcessTriage {
    Show-Banner
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    Write-Host "  PROCESS TRIAGE & EXECUTION HUNT" -ForegroundColor Yellow
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    $confirm = Read-Host " [?] Press ENTER to begin scan or Q to cancel"
    if ($confirm -eq 'Q' -or $confirm -eq 'q') { return }
    Write-Host "[*] Scanning running processes for anomalies..." -ForegroundColor Yellow
    
    $results = @()
    try {
        $processes = Get-CimInstance Win32_Process
        foreach ($proc in $processes) {
            try {
                $path = $proc.ExecutablePath
                if (-not $path) { continue }
                
                $isAnomalous = $false
                if ($path -match "C:\\Users\\|C:\\ProgramData\\|C:\\Temp\\|C:\\Windows\\Temp\\") {
                    $isAnomalous = $true
                }
                elseif ($proc.Name -match "powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32") {
                    $isAnomalous = $true
                }
                
                if ($isAnomalous) {
                    $owner = Get-AssociatedUser -path $path
                    $hashes = Get-FileHashes -filePath $path
                    
                    $sigStatus = "Unsigned"
                    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
                    if ($sig -and $sig.Status -eq "Valid") {
                        $sigStatus = "Signed ($($sig.SignerCertificate.Subject))"
                    }

                    $results += [PSCustomObject]@{
                        Type            = "Anomalous Running Process"
                        User            = $owner
                        Timestamp       = "PID: $($proc.ProcessId) | Signature: $sigStatus"
                        Name            = $proc.Name
                        Value           = $proc.CommandLine
                        SHA1            = $hashes.SHA1
                        SHA256          = $hashes.SHA256
                        RemediationType = "Process"
                        RemediationPath = $proc.ProcessId
                    }
                }
            } catch {}
        }
    } catch {
        Write-Host "[-] Error scanning running processes: $_" -ForegroundColor Red
    }

    if ($results.Count -gt 0) {
        Process-RemediationLoop -items $results -title "PROCESS TRIAGE RESULTS"
    } else {
        Write-Host "`n[+] No anomalous running processes detected." -ForegroundColor Green
        Pause
    }
}

function Get-StealthPersistence {
    Show-Banner
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    Write-Host "  STEALTH PERSISTENCE HUNT (WMI & BITS)" -ForegroundColor Yellow
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    $confirm = Read-Host " [?] Press ENTER to begin scan or Q to cancel"
    if ($confirm -eq 'Q' -or $confirm -eq 'q') { return }
    Write-Host "[*] Scanning for WMI Event Subscriptions & BITS Jobs..." -ForegroundColor Yellow
    
    $results = @()

    # --- 1. WMI Event Subscriptions ---
    try {
        $filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
        $consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
        $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding

        foreach ($binding in $bindings) {
            $filterName = $binding.Filter.Name
            $consumerName = $binding.Consumer.Name
            
            $matchedConsumer = $consumers | Where-Object { $_.Name -eq $consumerName }
            $action = "N/A"
            if ($matchedConsumer) {
                if ($matchedConsumer.CommandLineTemplate) { $action = $matchedConsumer.CommandLineTemplate }
                elseif ($matchedConsumer.ScriptText) { $action = "Script Block: " + $matchedConsumer.ScriptText }
            }

            $results += [PSCustomObject]@{
                Type            = "WMI Event Subscription"
                User            = "SYSTEM"
                Timestamp       = "Filter: $filterName | Consumer: $consumerName"
                Name            = $consumerName
                Value           = $action
                SHA1            = "N/A"
                SHA256          = "N/A"
                RemediationType = "WMI"
                RemediationPath = "__FilterToConsumerBinding"
            }
        }
    } catch {
        Write-Host "[-] Error scanning WMI Subscriptions: $_" -ForegroundColor Red
    }

    # --- 2. BITS Jobs ---
    try {
        $bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
        foreach ($job in $bitsJobs) {
            $results += [PSCustomObject]@{
                Type            = "Active BITS Transfer Job"
                User            = Resolve-SidToUsername -sid $job.OwnerIp
                Timestamp       = "State: $($job.JobState) | Priority: $($job.Priority)"
                Name            = $job.DisplayName
                Value           = "Remote: $($job.FileList.RemoteUrl) -> Local: $($job.FileList.LocalName)"
                SHA1            = "N/A"
                SHA256          = "N/A"
                RemediationType = "None"
                RemediationPath = $job.JobId
            }
        }
    } catch {}

    if ($results.Count -gt 0) {
        Process-RemediationLoop -items $results -title "STEALTH PERSISTENCE RESULTS"
    } else {
        Write-Host "`n[+] No stealth WMI or BITS persistence mechanisms found." -ForegroundColor Green
        Pause
    }
}

function Get-RecentlyWrittenFiles {
    Show-Banner
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    Write-Host "  RECENTLY WRITTEN FILES HUNT (CLICKFIX / DRIVE-BY TRIAGE)" -ForegroundColor Yellow
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    Write-Host " [+] Enter Timeframe to check for recently written files:" -ForegroundColor Cyan
    Write-Host "     Examples: '30m' (30 mins), '1h' (1 hour), '2h' (2 hours), '1d' (1 day)" -ForegroundColor DarkGray
    $timeInput = Read-Host "Q to cancel or  [?]"
    if ($timeInput -eq 'Q' -or $timeInput -eq 'q') { return }
    
    if (-not $timeInput) {
        Write-Host "[-] No input provided. Defaulting to past 1 hour." -ForegroundColor Red
        $timeInput = "1h"
    }

    $parsedTime = Parse-Timeframe -inputString $timeInput
    if (-not $parsedTime) {
        Write-Host "[-] ERROR: Could not parse timeframe format. Defaulting to past 1 hour." -ForegroundColor Red
        $parsedTime = Parse-Timeframe -inputString "1h"
    }

    $startTime = $parsedTime.StartTime
    Write-Host "`n[*] Scanning high-value drop directories for files written since: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))..." -ForegroundColor Yellow

    $targetExtensions = @("*.exe", "*.dll", "*.bat", "*.ps1", "*.vbs", "*.js", "*.zip", "*.iso", "*.lnk", "*.msi", "*.hta", "*.scr", "*.cmd", "*.wsf")
    
    $searchPaths = @()
    $userDirs = Get-ChildItem -Path "C:\Users" -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @("All Users", "Default", "Default User", "Public") }
    
    foreach ($ud in $userDirs) {
        $searchPaths += Join-Path $ud.FullName "Downloads"
        $searchPaths += Join-Path $ud.FullName "AppData\Local\Temp"
        $searchPaths += Join-Path $ud.FullName "Desktop"
    }
    $searchPaths += "C:\Users\Public"
    $searchPaths += @("C:\ProgramData", "C:\Windows\Temp", "C:\Temp")

    $results = @()
    foreach ($path in $searchPaths) {
        if (-not (Test-Path $path)) { continue }
        
        $queue = [System.Collections.Generic.Queue[string]]::new()
        $queue.Enqueue($path)

        while ($queue.Count -gt 0) {
            $currentPath = $queue.Dequeue()
            
            foreach ($ext in $targetExtensions) {
                $files = Get-ChildItem -Path $currentPath -Filter $ext -File -Force -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    if ($file.LastWriteTime -ge $startTime -or $file.CreationTime -ge $startTime) {
                        $owner = Get-AssociatedUser -path $file.FullName
                        $hashes = Get-FileHashes -filePath $file.FullName
                        
                        $results += [PSCustomObject]@{
                            Type            = "Recently Written File"
                            User            = $owner
                            Timestamp       = "Written: $($file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                            Name            = $file.Name
                            Value           = $file.FullName
                            SHA1            = $hashes.SHA1
                            SHA256          = $hashes.SHA256
                            RemediationType = "File"
                            RemediationPath = $file.FullName
                        }
                    }
                }
            }

            $subDirs = Get-ChildItem -Path $currentPath -Directory -Force -ErrorAction SilentlyContinue
            foreach ($sd in $subDirs) {
                if ($sd.Attributes -match "ReparsePoint") { continue }
                $queue.Enqueue($sd.FullName)
            }
        }
    }

    if ($results.Count -gt 0) {
        Process-RemediationLoop -items $results -title "RECENTLY WRITTEN FILES (SINCE $($startTime.ToString('HH:mm:ss')))"
    } else {
        Write-Host "`n[+] No recently written files matching target extensions were found." -ForegroundColor Green
        Pause
    }
}

function Get-RunMRU {
    Show-Banner
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    Write-Host "  RUNMRU EXECUTION HUNT (CLICKFIX TRIAGE)" -ForegroundColor Yellow
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    $confirm = Read-Host " [?] Press ENTER to begin scan or Q to cancel"
    if ($confirm -eq 'Q' -or $confirm -eq 'q') { return }
    Write-Host "[*] Scanning RunMRU registry keys across all users..." -ForegroundColor Yellow
    
    $results = @()
    $loadedOfflineHives = @()
    
    try {
        # 1. Loaded HKU RunMRU (Active Users)
        $loadedSids = Get-ChildItem HKU: | Where-Object { $_.PSChildName -notmatch '_Classes$' -and $_.PSChildName -match '^S-1-5' }
        foreach ($sidObj in $loadedSids) {
            $sid = $sidObj.PSChildName
            $username = Resolve-SidToUsername -sid $sid
            $path = "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
            if (Test-Path $path) {
                $properties = Get-ItemProperty -Path $path
                foreach ($prop in $properties.psobject.properties) {
                    if ($prop.Name -match '^[a-z]$') { 
                        $cleanValue = $prop.Value -replace '\\\d+$', '' -replace '\x00', ''
                        $results += [PSCustomObject]@{
                            Type            = "RunMRU Command"
                            User            = $username
                            Timestamp       = "Value: $($prop.Name)"
                            Name            = $prop.Name
                            Value           = $cleanValue
                            SHA1            = "N/A"
                            SHA256          = "N/A"
                            RemediationType = "Registry"
                            RemediationPath = $path
                        }
                    }
                }
            }
        }
        
        # 2. Offline HKU RunMRU (Logged-off Users)
        $userProfiles = Get-ChildItem "C:\Users" -Directory
        foreach ($profile in $userProfiles) {
            if ($profile.Name -in @("All Users", "Default", "Default User", "Public")) { continue }
            
            $tempHiveName = "S1_Triage_MRU_$($profile.Name)"
            if (Test-Path "HKU:\$tempHiveName") { continue }
            
            $ntuserPath = Join-Path $profile.FullName "NTUSER.DAT"
            if (Test-Path $ntuserPath) {
                reg.exe load "HKU\$tempHiveName" "$ntuserPath" 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    $loadedOfflineHives += $tempHiveName
                    $path = "HKU:\$tempHiveName\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
                    if (Test-Path $path) {
                        $properties = Get-ItemProperty -Path $path
                        foreach ($prop in $properties.psobject.properties) {
                            if ($prop.Name -match '^[a-z]$') {
                                $cleanValue = $prop.Value -replace '\\\d+$', '' -replace '\x00', ''
                                $results += [PSCustomObject]@{
                                    Type            = "RunMRU Command"
                                    User            = "$($profile.Name) (Offline)"
                                    Timestamp       = "Value: $($prop.Name)"
                                    Name            = $prop.Name
                                    Value           = $cleanValue
                                    SHA1            = "N/A"
                                    SHA256          = "N/A"
                                    RemediationType = "Registry"
                                    RemediationPath = $path
                                }
                            }
                        }
                    }
                }
            }
        }
    } finally {
        # Always unload offline hives safely
        foreach ($hive in $loadedOfflineHives) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            reg.exe unload "HKU\$hive" 2>&1 | Out-Null
        }
    }
    
    if ($results.Count -gt 0) {
        Process-RemediationLoop -items $results -title "RUNMRU EXECUTION HISTORY (CLICKFIX TRIAGE)"
    } else {
        Write-Host "`n[+] No RunMRU execution history found." -ForegroundColor Green
        Pause
    }
}

function Get-RMMHunt {
    Show-Banner
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    Write-Host "  RMM SOFTWARE HUNT" -ForegroundColor Yellow
    Write-Host "  Scanning for Remote Monitoring & Management tools" -ForegroundColor DarkGray
    Write-Host "  Source: LOLRMM / CISA AA23-025A" -ForegroundColor DarkGray
    Write-Host "===============================================================" -ForegroundColor DarkCyan
    $confirm = Read-Host " [?] Press ENTER to begin scan or Q to cancel"
    if ($confirm -eq 'Q' -or $confirm -eq 'q') { return }
    Write-Host "[*] Scanning processes, services, registry, and disk..." -ForegroundColor Yellow

    $results = @()

    $rmmTools = @(
        @{ Name = "AnyDesk";              Exes = @("anydesk.exe");                                                            Services = @("AnyDesk");                                    RegKeys = @("AnyDesk");                    Paths = @("$env:ProgramFiles\AnyDesk","$env:APPDATA\AnyDesk","C:\ProgramData\AnyDesk") },
        @{ Name = "ScreenConnect";        Exes = @("screenconnect.clientservice.exe","connectwisecontrol.clientservice.exe","screenconnect.exe"); Services = @("ScreenConnect Client","ConnectWiseControl"); RegKeys = @("ScreenConnect","ConnectWise Control"); Paths = @("$env:ProgramFiles\ScreenConnect Client","$env:APPDATA\ScreenConnect Client") },
        @{ Name = "TeamViewer";           Exes = @("teamviewer.exe","teamviewer_service.exe","tv_w32.exe","tv_x64.exe");      Services = @("TeamViewer","TeamViewer12","TeamViewer13","TeamViewer14","TeamViewer15"); RegKeys = @("TeamViewer"); Paths = @("$env:ProgramFiles\TeamViewer","${env:ProgramFiles(x86)}\TeamViewer") },
        @{ Name = "GoTo (LogMeIn)";       Exes = @("logmein.exe","logmeinrescue.exe","goto.exe","g2mainapplication.exe","g2mstart.exe","lmiignition.exe"); Services = @("LogMeIn","LMIGuardianSvc","GoToMeeting"); RegKeys = @("LogMeIn","GoTo"); Paths = @("$env:ProgramFiles\LogMeIn","${env:ProgramFiles(x86)}\LogMeIn") },
        @{ Name = "Atera";                Exes = @("ateraagent.exe","atera_agent.exe");                                        Services = @("AteraAgent");                                 RegKeys = @("Atera Networks");             Paths = @("$env:ProgramFiles\ATERA Networks") },
        @{ Name = "NinjaRMM";             Exes = @("ninjarmmagent.exe","ninjaone.exe");                                        Services = @("Ninja RMM Agent","NinjaRMMAgent");            RegKeys = @("NinjaRMM","NinjaOne");        Paths = @("$env:ProgramFiles\NinjaRMMAgent") },
        @{ Name = "Splashtop";            Exes = @("srserver.exe","splashtopsos.exe","srmanager.exe","sragent.exe");           Services = @("SplashtopRemoteService","SRService");         RegKeys = @("Splashtop");                  Paths = @("$env:ProgramFiles\Splashtop","${env:ProgramFiles(x86)}\Splashtop") },
        @{ Name = "RemotePC";             Exes = @("remotepc.exe","remotepchd.exe","remotepcservice.exe");                     Services = @("RemotePCService","RemotePCUIService");        RegKeys = @("RemotePC");                   Paths = @("$env:ProgramFiles\RemotePC") },
        @{ Name = "Kaseya VSA";           Exes = @("agentmon.exe","kaseyaremotecontrol.exe");                                  Services = @("Kaseya Agent","KaseyaRemoteControl");         RegKeys = @("Kaseya");                     Paths = @("$env:ProgramFiles\Kaseya") },
        @{ Name = "ConnectWise Automate"; Exes = @("ltsvc.exe","ltsvcmon.exe","lttray.exe");                                   Services = @("LTService","LTSvcMon");                       RegKeys = @("LabTech Software");           Paths = @("C:\Windows\LTSvc","$env:ProgramFiles\LabTech") },
        @{ Name = "Datto RMM";            Exes = @("caagent.exe","cagservice.exe");                                            Services = @("CAGService","CentraStageService");            RegKeys = @("CentraStage","Datto RMM");    Paths = @("$env:ProgramFiles\CentraStage") },
        @{ Name = "MeshCentral (MeshAgent)"; Exes = @("meshagent.exe");                                                       Services = @("Mesh Agent");                                 RegKeys = @("Mesh Agent");                 Paths = @("$env:ProgramFiles\Mesh Agent") },
        @{ Name = "NetSupport Manager";   Exes = @("client32.exe","pcictlui.exe","nsm.exe");                                   Services = @("NetSupport Manager");                        RegKeys = @("NetSupport Manager");         Paths = @("$env:ProgramFiles\NetSupport","${env:ProgramFiles(x86)}\NetSupport") },
        @{ Name = "SimpleHelp";           Exes = @("simpleservice.exe","simplegatewayservice.exe");                            Services = @("SimpleService","SimpleGatewayService");      RegKeys = @("SimpleHelp");                 Paths = @("$env:ProgramFiles\SimpleHelp") },
        @{ Name = "Supremo";              Exes = @("supremo.exe","supremoservice.exe");                                        Services = @("SupremoService");                             RegKeys = @("Supremo");                    Paths = @("$env:ProgramFiles\Supremo","$env:APPDATA\Supremo") },
        @{ Name = "Remote Utilities";     Exes = @("rutserv.exe","rfusclient.exe");                                            Services = @("RUT Service");                               RegKeys = @("Remote Utilities");           Paths = @("$env:ProgramFiles\Remote Utilities - Host") },
        @{ Name = "Ammyy Admin";          Exes = @("aa_v3.exe","ammyy_admin.exe");                                             Services = @();                                            RegKeys = @("Ammyy");                      Paths = @() },
        @{ Name = "Action1";              Exes = @("action1_agent.exe","action1_remote.exe");                                  Services = @("Action1 Agent");                             RegKeys = @("Action1");                    Paths = @("$env:ProgramFiles\Action1") },
        @{ Name = "Pulseway";             Exes = @("pulseway.exe","pcmonitor.exe");                                            Services = @("Pulseway","PCMonitor");                      RegKeys = @("Pulseway","MMSOFT Design");   Paths = @("$env:ProgramFiles\Pulseway") },
        @{ Name = "N-able N-sight";       Exes = @("winagent.exe","wr_system_monitor.exe");                                    Services = @("Windows Agent","Advanced Monitoring Agent"); RegKeys = @("Advanced Monitoring Agent");  Paths = @("$env:ProgramFiles\Advanced Monitoring Agent") },
        @{ Name = "Zoho Assist";          Exes = @("zohoassist.exe","zaservice.exe");                                          Services = @("ZohoAssistService","Zoho Assist Unattended Agent"); RegKeys = @("Zoho Assist");       Paths = @("$env:ProgramFiles\ZohoAssist") },
        @{ Name = "Cloudflare Tunnel";    Exes = @("cloudflared.exe");                                                         Services = @("Cloudflared");                               RegKeys = @("Cloudflare");                 Paths = @("$env:ProgramFiles\Cloudflare","$env:APPDATA\cloudflared") },
        @{ Name = "TacticalRMM";          Exes = @("tacticalrmm.exe");                                                         Services = @("tacticalrmm","Mesh Agent");                  RegKeys = @("TacticalRMM");               Paths = @("$env:ProgramFiles\TacticalRMM") },
        @{ Name = "PDQ Deploy";           Exes = @("pdqdeploy.exe","pdqdeployrunner.exe");                                     Services = @("PDQDeployRunner");                           RegKeys = @("PDQ Deploy");                 Paths = @("$env:ProgramFiles\PDQ Deploy") },
        @{ Name = "FleetDeck";            Exes = @("fleetdeck_agent.exe","fleetdeck_agent_svc.exe");                           Services = @("FleetDeck Agent");                           RegKeys = @("FleetDeck");                  Paths = @("$env:ProgramFiles\FleetDeck") }
    )

    # Cache once for performance
    $runningProcs       = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $installedServices  = Get-Service -ErrorAction SilentlyContinue
    $uninstallBases     = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($tool in $rmmTools) {
        $detections = @()

        # Helper: get file creation time as a formatted string
        function Get-InstallDateFromPath {
            param([string]$p)
            if (-not $p) { return "Unknown" }
            try {
                $item = Get-Item -Path $p -ErrorAction Stop
                return $item.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
            } catch { return "Unknown" }
        }

        # 1. Running processes
        foreach ($exe in $tool.Exes) {
            $matches = $runningProcs | Where-Object { $_.Name -like $exe }
            foreach ($proc in $matches) {
                $installDate = Get-InstallDateFromPath -p $proc.ExecutablePath
                $detections += [PSCustomObject]@{
                    DetectionType = "Running Process"
                    Detail        = "PID $($proc.ProcessId) | $($proc.ExecutablePath)"
                    RemType       = "Process"
                    RemPath       = $proc.ProcessId
                    InstallDate   = $installDate
                }
            }
        }

        # 2. Installed services
        foreach ($svcName in $tool.Services) {
            $matches = $installedServices | Where-Object { $_.Name -like "*$svcName*" -or $_.DisplayName -like "*$svcName*" }
            foreach ($svc in $matches) {
                # Get binary path from SCM for file creation time
                $svcBinPath = try {
                    (Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction Stop).PathName
                } catch { $null }
                $svcExePath = if ($svcBinPath) { Extract-FilePath -cmdline $svcBinPath } else { $null }
                $installDate = Get-InstallDateFromPath -p $svcExePath
                $detections += [PSCustomObject]@{
                    DetectionType = "Service"
                    Detail        = "$($svc.DisplayName) [$($svc.Name)] | Status: $($svc.Status)"
                    RemType       = "Service"
                    RemPath       = $svc.Name
                    InstallDate   = $installDate
                }
            }
        }

        # 3. Uninstall registry keys
        foreach ($regBase in $uninstallBases) {
            if (-not (Test-Path $regBase)) { continue }
            $subKeys = Get-ChildItem $regBase -ErrorAction SilentlyContinue
            foreach ($key in $subKeys) {
                $displayName = (Get-ItemProperty -Path $key.PSPath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName
                if (-not $displayName) { continue }
                foreach ($regKw in $tool.RegKeys) {
                    if ($displayName -like "*$regKw*") {
                        $installLoc = (Get-ItemProperty -Path $key.PSPath -Name InstallLocation -ErrorAction SilentlyContinue).InstallLocation
                        # Registry InstallDate is stored as YYYYMMDD string
                        $regDateRaw = (Get-ItemProperty -Path $key.PSPath -Name InstallDate -ErrorAction SilentlyContinue).InstallDate
                        $installDate = if ($regDateRaw -match '^\d{8}$') {
                            try { [datetime]::ParseExact($regDateRaw, "yyyyMMdd", $null).ToString("yyyy-MM-dd") } catch { $regDateRaw }
                        } elseif ($regDateRaw) {
                            $regDateRaw
                        } else {
                            # Fall back to registry key last-write time
                            try { $key.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") } catch { "Unknown" }
                        }
                        $detections += [PSCustomObject]@{
                            DetectionType = "Installed (Registry)"
                            Detail        = "$displayName | Location: $installLoc"
                            RemType       = "Registry"
                            RemPath       = $key.PSPath
                            InstallDate   = $installDate
                        }
                        break
                    }
                }
            }
        }

        # 4. Known paths on disk
        foreach ($path in $tool.Paths) {
            if ($path -and (Test-Path $path)) {
                $installDate = Get-InstallDateFromPath -p $path
                $detections += [PSCustomObject]@{
                    DetectionType = "Path on Disk"
                    Detail        = $path
                    RemType       = "File"
                    RemPath       = $path
                    InstallDate   = $installDate
                }
            }
        }

        foreach ($det in $detections) {
            $dateStr = if ($det.InstallDate) { $det.InstallDate } else { "Unknown" }
            $results += [PSCustomObject]@{
                Type            = "RMM: $($tool.Name)"
                User            = $det.DetectionType
                Timestamp       = "Installed: $dateStr"
                Name            = $tool.Name
                Value           = $det.Detail
                SHA1            = "N/A"
                SHA256          = "N/A"
                RemediationType = $det.RemType
                RemediationPath = $det.RemPath
            }
        }
    }

    if ($results.Count -gt 0) {
        Process-RemediationLoop -items $results -title "RMM SOFTWARE HUNT RESULTS"
    } else {
        Write-Host "`n[+] No known RMM software detected on this endpoint." -ForegroundColor Green
        Pause
    }
}

function Get-SystemInfo {
    Show-Banner
    $confirm = Read-Host " [?] Press ENTER to begin scan or Q to cancel"
    if ($confirm -eq 'Q' -or $confirm -eq 'q') { return }
    Write-Host "=== SYSTEM & OS BASELINE ===" -ForegroundColor Magenta
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $uptime = (Get-Date) - $os.LastBootUpTime

    Write-Host " Hostname      : $($cs.Name)" -ForegroundColor Cyan
    Write-Host " Domain/WG     : $($cs.Domain)" -ForegroundColor Cyan
    Write-Host " OS Version    : $($os.Caption) ($($os.OSArchitecture))" -ForegroundColor Cyan
    Write-Host " Build Number  : $($os.BuildNumber)" -ForegroundColor Cyan
    Write-Host " Install Date  : $($os.InstallDate.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
    Write-Host " System Uptime : $($uptime.Days) Days, $($uptime.Hours) Hours, $($uptime.Minutes) Minutes" -ForegroundColor Cyan

    Write-Host "`n=== SECURITY POSTURE ===" -ForegroundColor Magenta
    $av = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
    if ($av) {
        foreach ($product in $av) { Write-Host " Antivirus     : $($product.displayName)" -ForegroundColor Green }
    } else {
        Write-Host " Antivirus     : No WMI SecurityCenter AV found (Check Defender/EDR manually)" -ForegroundColor DarkGray
    }
    
    $fw = Get-NetFirewallProfile | Where-Object Enabled -eq $true
    $fwActive = if ($fw) { ($fw.Name -join ", ") } else { "ALL DISABLED" }
    $fwColor = if ($fw) { "Green" } else { "Red" }
    Write-Host " Active FW     : $fwActive" -ForegroundColor $fwColor

    Write-Host "`n=== NETWORK CONFIGURATION ===" -ForegroundColor Magenta
    $netAdapters = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    foreach ($adapter in $netAdapters) {
        Write-Host " Adapter       : $($adapter.Description)" -ForegroundColor Cyan
        Write-Host "   IP Address  : $($adapter.IPAddress -join ', ')" -ForegroundColor DarkGray
        Write-Host "   MAC Address : $($adapter.MACAddress)" -ForegroundColor DarkGray
        Write-Host "   Gateway     : $($adapter.DefaultIPGateway -join ', ')" -ForegroundColor DarkGray
    }

    Write-Host "`n=== PRIVILEGED ACCOUNTS (LOCAL ADMINS) ===" -ForegroundColor Magenta
    $adminGroup = Get-LocalGroup | Where-Object SID -eq 'S-1-5-32-544'
    $admins = Get-LocalGroupMember -Group $adminGroup.Name -ErrorAction SilentlyContinue
    if ($admins) {
        foreach ($admin in $admins) {
            Write-Host " User/Group    : $($admin.Name) ($($admin.ObjectClass))" -ForegroundColor Yellow
        }
    } else {
        Write-Host " [!] Could not enumerate Local Administrators." -ForegroundColor Red
    }

    Write-Host "`n=== ACTIVE USER SESSIONS ===" -ForegroundColor Magenta
    $quserOutput = quser 2>&1
    if ($LASTEXITCODE -eq 0) {
        $quserOutput | ForEach-Object { Write-Host " $_" -ForegroundColor Cyan }
    } else {
        Write-Host " No active RDP/Console sessions found." -ForegroundColor DarkGray
    }

    Write-Host "`n---------------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host " [C] View Active Network Connections (Listening & Established)" -ForegroundColor White
    Write-Host " [D] View DNS Resolver Cache (Recent Network Lookups)" -ForegroundColor White
    Write-Host " [R] Return to Main Menu" -ForegroundColor White
    
    $sysChoice = Read-Host " [?] Select an option"
    if ($sysChoice -eq 'C') {
        Write-Host "`n=== ACTIVE NETWORK CONNECTIONS ===" -ForegroundColor Magenta
        Get-NetTCPConnection | Where-Object State -in @('Established', 'Listen') | 
            Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
            Format-Table -AutoSize | Out-String | Write-Host
        Pause
    } elseif ($sysChoice -eq 'D') {
        Write-Host "`n=== DNS RESOLVER CACHE ===" -ForegroundColor Magenta
        Get-DnsClientCache | Select-Object Entry, RecordName, RecordType, Status |
            Format-Table -AutoSize | Out-String | Write-Host
        Pause
    }
}

function Show-Menu {
    Show-Banner
    Write-Host "  THREAT HUNTING" -ForegroundColor Yellow
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [" -NoNewline -ForegroundColor White; Write-Host "1" -NoNewline -ForegroundColor Cyan; Write-Host "]  Hunt for Persistence" -ForegroundColor White
    Write-Host "       Registry Run Keys, Scheduled Tasks, Startup, Services" -ForegroundColor DarkGray
    Write-Host "  [" -NoNewline -ForegroundColor White; Write-Host "2" -NoNewline -ForegroundColor Cyan; Write-Host "]  Global Keyword Hunt" -ForegroundColor White
    Write-Host "       Registry, Tasks, Services, Processes, File System" -ForegroundColor DarkGray
    Write-Host "  [" -NoNewline -ForegroundColor White; Write-Host "3" -NoNewline -ForegroundColor Cyan; Write-Host "]  SentinelOne Threat Detail Hunt" -ForegroundColor White
    Write-Host "       Paste S1 alert details to hunt IOCs across the endpoint" -ForegroundColor DarkGray
    Write-Host "  [" -NoNewline -ForegroundColor White; Write-Host "4" -NoNewline -ForegroundColor Cyan; Write-Host "]  Stealth Persistence Hunt" -ForegroundColor White
    Write-Host "       WMI Subscriptions & BITS Jobs" -ForegroundColor DarkGray
    Write-Host "  [" -NoNewline -ForegroundColor White; Write-Host "5" -NoNewline -ForegroundColor Cyan; Write-Host "]  RMM Software Hunt" -ForegroundColor White
    Write-Host "       Detect AnyDesk, ScreenConnect, TeamViewer, and 20+ RMM tools" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  EXECUTION & PROCESS ANALYSIS" -ForegroundColor Yellow
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [" -NoNewline -ForegroundColor White; Write-Host "6" -NoNewline -ForegroundColor Cyan; Write-Host "]  PowerShell Execution History" -ForegroundColor White
    Write-Host "       Event Log (ID 4104) with timeframe filter" -ForegroundColor DarkGray
    Write-Host "  [" -NoNewline -ForegroundColor White; Write-Host "7" -NoNewline -ForegroundColor Cyan; Write-Host "]  Process Triage & Execution Hunt" -ForegroundColor White
    Write-Host "       Unsigned processes, suspicious paths & LOLBins" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  CLICKFIX / DRIVE-BY TRIAGE" -ForegroundColor Yellow
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [" -NoNewline -ForegroundColor White; Write-Host "8" -NoNewline -ForegroundColor Cyan; Write-Host "]  Recently Written Files Hunt" -ForegroundColor White
    Write-Host "       Detect files dropped during ClickFix or drive-by attacks" -ForegroundColor DarkGray
    Write-Host "  [" -NoNewline -ForegroundColor White; Write-Host "9" -NoNewline -ForegroundColor Cyan; Write-Host "]  RunMRU Execution Hunt" -ForegroundColor White
    Write-Host "       Run dialog history across all user profiles" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  FORENSICS" -ForegroundColor Yellow
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [" -NoNewline -ForegroundColor White; Write-Host "10" -NoNewline -ForegroundColor Cyan; Write-Host "]  DFIR System Info" -ForegroundColor White
    Write-Host "       OS baseline, network config, local admins, AV posture" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [Q]  Quit (returns to shell)" -ForegroundColor Red
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    
    $choice = Read-Host " [?] Select an option"
    
    if ($choice -eq '1') {
        $data = Get-Persistence
        if ($data) {
            Process-RemediationLoop -items $data -title "PERSISTENCE HUNT RESULTS"
        } else {
            Write-Host "[-] No obvious persistence mechanisms found." -ForegroundColor Green
            Pause
        }
    }
    elseif ($choice -eq '2') {
        Search-GlobalKeyword
    }
    elseif ($choice -eq '3') {
        Get-S1ThreatHunt
    }
    elseif ($choice -eq '4') {
        Get-StealthPersistence
    }
    elseif ($choice -eq '5') {
        Get-RMMHunt
    }
    elseif ($choice -eq '6') {
        Get-PSHistory
    }
    elseif ($choice -eq '7') {
        Get-ProcessTriage
    }
    elseif ($choice -eq '8') {
        Get-RecentlyWrittenFiles
    }
    elseif ($choice -eq '9') {
        Get-RunMRU
    }
    elseif ($choice -eq '10') {
        Get-SystemInfo
    }
    elseif ($choice -eq 'Q' -or $choice -eq 'q') {
        return $true
    }
    else {
        Write-Host "[-] Invalid selection." -ForegroundColor Red
        Start-Sleep -Seconds 1
    }
}

# Main Loop
while ($true) {
    $quit = Show-Menu
    if ($quit -eq $true) {
        Clear-Host
        Write-Host "[+] Riposte exited. Shell session preserved." -ForegroundColor Green
        break
    }
}