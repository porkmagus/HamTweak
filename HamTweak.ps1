#requires -RunAsAdministrator
<#
.SYNOPSIS
    HamTweak - Complete Windows 11/10 Customization & Optimization Suite
    
.DESCRIPTION
    All-in-one PowerShell script combining:
    - 150+ Windows tweaks across 8 categories
    - Interactive menu system with OS detection
    - Bloatware removal module
    - System restore point management
    
.VERSION
    1.0.0 (Consolidated Single-File Edition)
    
.REQUIREMENTS
    - PowerShell 5.0+
    - Administrator privileges
    - Windows 10 (Build 19041+) or Windows 11 (Build 22000+)
    
.USAGE
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    .\HamTweak.ps1
#>

param()

$ErrorActionPreference = "Continue"
$WarningPreference = "SilentlyContinue"

# Global state
$Global:OSVersion = ""
$Global:OSBuild = 0
$Global:IsWindows11 = $false
$Global:SelectedTweaks = @()
$Global:RestorePointName = ""
$Global:TweakLog = @()
$Global:TweakData = $null
$Global:LogFile = Join-Path $env:TEMP "HamTweak_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Mutually exclusive tweak groups - only one from each group can be selected at a time
$Global:MutualExclusionGroups = @(
    @{ Name = 'Power Plan'; IDs = @('pwr-high-perf', 'pwr-balanced', 'pwr-ultimate') },
    @{ Name = 'Theme Mode'; IDs = @('ui-dark-mode', 'ui-light-mode') },
    @{ Name = 'Taskbar Alignment'; IDs = @('ui-taskbar-left', 'ui-taskbar-center') },
    @{ Name = 'Search Box Display'; IDs = @('ui-search-hide', 'ui-search-icon') },
    @{ Name = 'Hibernation'; IDs = @('pwr-hibernation-on', 'pwr-hibernation-off') },
    @{ Name = 'Telemetry Level'; IDs = @('priv-telemetry-basic', 'priv-telemetry-off') },
    @{ Name = 'UAC Level'; IDs = @('priv-uac-low', 'priv-uac-normal') },
    @{ Name = 'Update Delivery'; IDs = @('upd-p2p-off', 'upd-p2p-local') },
    @{ Name = 'Update Policy'; IDs = @('upd-auto-normal', 'upd-notify-only', 'upd-disabled') },
    @{ Name = 'Transparency'; IDs = @('perf-transparency', 'ui-transparency-off') }
)

# ===========================================================================================
# SECTION 1: COLOR & FORMATTING
# ===========================================================================================

function Write-Color {
    param(
        [ValidateSet('Success', 'Error', 'Warning', 'Info', 'Header', 'HighRisk')]
        [string]$Type = 'Info',
        [string]$Message,
        [switch]$NoNewline
    )
    
    $colors = @{
        'Success'  = 'Green'
        'Error'    = 'Red'
        'Warning'  = 'Yellow'
        'Info'     = 'Cyan'
        'Header'   = 'Magenta'
        'HighRisk' = 'Red'
    }
    
    Write-Host $Message -ForegroundColor $colors[$Type] -NoNewline:$NoNewline
    
    # Log to file
    Add-Content -Path $Global:LogFile -Value "[$(Get-Date -Format 'HH:mm:ss')] [$Type] $Message" -ErrorAction SilentlyContinue
}

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Color 'Header' ("=" * 80)
    Write-Color 'Header' $Title
    Write-Color 'Header' ("=" * 80)
    Write-Host ""
}

function Write-Divider {
    Write-Color 'Info' ("-" * 80)
}

# ===========================================================================================
# SECTION 2: SYSTEM FUNCTIONS
# ===========================================================================================

function Invoke-MutualExclusion {
    param(
        [string]$SelectedTweakID,
        [switch]$Silent
    )
    
    # Find which group this tweak belongs to
    foreach ($group in $Global:MutualExclusionGroups) {
        if ($group.IDs -contains $SelectedTweakID) {
            # Remove all other tweaks in this group from selection
            $conflicting = @($group.IDs | Where-Object { $_ -ne $SelectedTweakID -and $Global:SelectedTweaks -contains $_ })
            if ($conflicting.Count -gt 0) {
                $Global:SelectedTweaks = @($Global:SelectedTweaks | Where-Object { $_ -notin $conflicting })
                if (-not $Silent) {
                    Write-Color 'Warning' "[$($group.Name)] Deselected conflicting: $($conflicting -join ', ')"
                }
                return $true
            }
            break
        }
    }
    return $false
}

function Get-OSInfo {
    try {
        # Use Get-CimInstance (faster than deprecated Get-WmiObject)
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $Global:OSVersion = $os.Caption
        $Global:OSBuild = [int]$os.BuildNumber
        
        if ($Global:OSBuild -ge 22000) {
            $Global:IsWindows11 = $true
            return "Windows 11"
        } else {
            $Global:IsWindows11 = $false
            return "Windows 10"
        }
    } catch {
        Write-Color 'Error' "Failed to detect OS: $_"
        exit 1
    }
}

function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-RestorePoint {
    param([string]$Description)
    
    try {
        Write-Color 'Info' "Creating restore point: $Description"
        # Enable System Protection if not already enabled
        $systemDrive = $env:SystemDrive
        Enable-ComputerRestore -Drive $systemDrive -ErrorAction SilentlyContinue
        # Create the restore point
        Checkpoint-Computer -Description $Description -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Color 'Success' "[OK] Restore point created"
        return $true
    } catch {
        Write-Color 'Warning' "[WARNING] Could not create restore point: $($_.Exception.Message)"
        Write-Color 'Warning' "Continuing anyway..."
        return $false
    }
}

# ===========================================================================================
# SECTION 3: TWEAK DATABASE (150+ Tweaks)
# ===========================================================================================

function Import-TweakData {
    $tweakData = @{
        # ===================================================================================
        # PRIVACY & SECURITY (40+ tweaks)
        # ===================================================================================
        'Privacy' = @(
            # --- Advertising & Tracking ---
            @{ID='priv-ads-master'; Name='Master Ads Control'; Desc='Disable all Microsoft ads and promotional content'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent';N='DisableWindowsConsumerFeatures';T='DWord';V=1})},
            @{ID='priv-personalized-ads'; Name='Disable Personalized Ads'; Desc='Turn off behavioral ad targeting'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo';N='Enabled';T='DWord';V=0})},
            @{ID='priv-advertising-id'; Name='Disable Advertising ID'; Desc='Reset and disable advertising identifier'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo';N='DisabledByGroupPolicy';T='DWord';V=1})},
            @{ID='priv-app-tracking'; Name='Disable App Launch Tracking'; Desc='Stop tracking which apps you launch'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';N='Start_TrackProgs';T='DWord';V=0})},
            @{ID='priv-content-delivery'; Name='Disable Content Delivery'; Desc='Stop dynamic content downloads'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='ContentDeliveryAllowed';T='DWord';V=0})},
            @{ID='priv-subscribed-content'; Name='Disable Subscribed Content'; Desc='Remove Microsoft suggestions'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='SubscribedContentEnabled';T='DWord';V=0})},
            @{ID='priv-suggestions'; Name='Disable App Suggestions'; Desc='Turn off suggested apps in Start'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='SystemPaneSuggestionsEnabled';T='DWord';V=0})},
            @{ID='priv-preinstalled-apps'; Name='Disable Pre-installed Apps'; Desc='Stop silent app installations'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='PreInstalledAppsEnabled';T='DWord';V=0})},
            @{ID='priv-oem-preinstalled'; Name='Disable OEM Pre-installed Apps'; Desc='Block OEM bloatware installation'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='OemPreInstalledAppsEnabled';T='DWord';V=0})},
            @{ID='priv-silent-install'; Name='Disable Silent App Install'; Desc='Prevent background app installs'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='SilentInstalledAppsEnabled';T='DWord';V=0})},
            @{ID='priv-feature-mgmt'; Name='Disable Feature Management'; Desc='Stop Microsoft feature experiments'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='FeatureManagementEnabled';T='DWord';V=0})},
            
            # --- Lock Screen Privacy ---
            @{ID='priv-spotlight'; Name='Disable Windows Spotlight'; Desc='Turn off rotating lock screen images'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='RotatingLockScreenEnabled';T='DWord';V=0},@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='RotatingLockScreenOverlayEnabled';T='DWord';V=0})},
            @{ID='priv-lockscreen-facts'; Name='Disable Lock Screen Fun Facts'; Desc='Remove tips from lock screen'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='SubscribedContent-338387Enabled';T='DWord';V=0})},
            @{ID='priv-lockscreen-notif'; Name='Disable Lock Screen Notifications'; Desc='Hide notifications on locked screen'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings';N='NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK';T='DWord';V=0})},
            
            # --- Speech & Voice ---
            @{ID='priv-speech-online'; Name='Disable Online Speech Recognition'; Desc='Keep speech processing local'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy';N='HasAccepted';T='DWord';V=0})},
            @{ID='priv-cortana'; Name='Disable Cortana'; Desc='Turn off Cortana assistant'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';N='AllowCortana';T='DWord';V=0})},
            @{ID='priv-cortana-voice'; Name='Disable Voice Activation'; Desc='Turn off Hey Cortana wake phrase'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Preferences';N='VoiceActivationEnableAboveLockscreen';T='DWord';V=0})},
            
            # --- Input & Typing ---
            @{ID='priv-inking'; Name='Disable Inking Personalization'; Desc='Stop learning from handwriting'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\InputPersonalization';N='RestrictImplicitInkCollection';T='DWord';V=1})},
            @{ID='priv-typing'; Name='Disable Typing Personalization'; Desc='Stop learning from typing patterns'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\InputPersonalization';N='RestrictImplicitTextCollection';T='DWord';V=1})},
            @{ID='priv-input-telemetry'; Name='Disable Input Telemetry'; Desc='Stop sending typing data to MS'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Input\TIPC';N='Enabled';T='DWord';V=0})},
            
            # --- Telemetry & Diagnostics ---
            @{ID='priv-telemetry-basic'; Name='Set Telemetry to Basic'; Desc='Minimize diagnostic data collection'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';N='AllowTelemetry';T='DWord';V=1})},
            @{ID='priv-telemetry-off'; Name='Disable Telemetry (RISK)'; Desc='Turn off all diagnostic data - may break features'; Risk=1; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';N='AllowTelemetry';T='DWord';V=0})},
            @{ID='priv-feedback'; Name='Disable Feedback Requests'; Desc='Stop Windows feedback prompts'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Siuf\Rules';N='NumberOfSIUFInPeriod';T='DWord';V=0})},
            @{ID='priv-tailored-exp'; Name='Disable Tailored Experiences'; Desc='Stop personalized tips based on data'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy';N='TailoredExperiencesWithDiagnosticDataEnabled';T='DWord';V=0})},
            @{ID='priv-error-reporting'; Name='Disable Error Reporting'; Desc='Dont send crash reports to Microsoft'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting';N='Disabled';T='DWord';V=1})},
            @{ID='priv-ceip'; Name='Disable CEIP'; Desc='Opt out of Customer Experience Program'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows';N='CEIPEnable';T='DWord';V=0})},
            
            # --- Location & Sensors ---
            @{ID='priv-location'; Name='Disable Location Services'; Desc='Turn off location tracking'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors';N='DisableLocation';T='DWord';V=1})},
            @{ID='priv-location-scripting'; Name='Disable Location Scripting'; Desc='Prevent apps from using location'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors';N='DisableLocationScripting';T='DWord';V=1})},
            
            # --- Camera & Microphone ---
            @{ID='priv-camera'; Name='Disable Camera Access'; Desc='Block apps from using camera'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy';N='LetAppsAccessCamera';T='DWord';V=2})},
            @{ID='priv-microphone'; Name='Disable Microphone Access'; Desc='Block apps from using microphone'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy';N='LetAppsAccessMicrophone';T='DWord';V=2})},
            
            # --- Account & Sync ---
            @{ID='priv-activity-history'; Name='Disable Activity History & Timeline'; Desc='Stop tracking activities and disable timeline'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';N='EnableActivityFeed';T='DWord';V=0},@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';N='PublishUserActivities';T='DWord';V=0})},
            @{ID='priv-settings-sync'; Name='Disable Settings Sync'; Desc='Dont sync settings across devices'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync';N='SyncPolicy';T='DWord';V=5})},
            @{ID='priv-clipboard-sync'; Name='Disable Clipboard Sync'; Desc='Dont sync clipboard across devices'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Clipboard';N='EnableClipboardHistory';T='DWord';V=0})},
            
            # --- Security Settings ---
            @{ID='priv-uac-low'; Name='Lower UAC (RISK)'; Desc='Reduce security prompts - less secure'; Risk=1; Reg=@(@{P='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';N='ConsentPromptBehaviorAdmin';T='DWord';V=0})},
            @{ID='priv-uac-normal'; Name='Normal UAC'; Desc='Standard User Account Control'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';N='ConsentPromptBehaviorAdmin';T='DWord';V=5})},
            @{ID='priv-remote-assist'; Name='Disable Remote Assistance'; Desc='Turn off remote help feature'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance';N='fAllowToGetHelp';T='DWord';V=0})},
            @{ID='priv-remote-desktop'; Name='Disable Remote Desktop'; Desc='Turn off remote desktop access'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server';N='fDenyTSConnections';T='DWord';V=1})}
        )

        # ===================================================================================
        # PERFORMANCE & GAMING (45+ tweaks)
        # ===================================================================================
        'Performance' = @(
            # --- Game Mode & Gaming ---
            @{ID='perf-gamemode'; Name='Enable Game Mode'; Desc='Optimize system for gaming'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\GameBar';N='AutoGameModeEnabled';T='DWord';V=1})},
            @{ID='perf-gamebar'; Name='Disable Game Bar'; Desc='Turn off Xbox game overlay'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR';N='AppCaptureEnabled';T='DWord';V=0},@{P='HKCU:\SOFTWARE\Microsoft\GameBar';N='UseNexusForGameBarEnabled';T='DWord';V=0})},
            @{ID='perf-gamedvr'; Name='Disable Game DVR'; Desc='Stop background game recording'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR';N='AllowGameDVR';T='DWord';V=0})},
            @{ID='perf-gamebar-tips'; Name='Disable Game Bar Tips'; Desc='Remove gaming overlay tips'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\GameBar';N='ShowStartupPanel';T='DWord';V=0})},
            @{ID='perf-fullscreen-opt'; Name='Disable Fullscreen Optimizations'; Desc='Legacy fullscreen for older games'; Risk=0; Reg=@(@{P='HKCU:\System\GameConfigStore';N='GameDVR_FSEBehaviorMode';T='DWord';V=2})},
            @{ID='perf-gpu-priority'; Name='GPU High Priority'; Desc='Prioritize graphics processing'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games';N='GPU Priority';T='DWord';V=8})},
            @{ID='perf-game-priority'; Name='Game Process Priority'; Desc='Higher CPU priority for games'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games';N='Priority';T='DWord';V=6})},
            @{ID='perf-game-scheduling'; Name='Game Scheduling Category'; Desc='Optimize thread scheduling for games'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games';N='Scheduling Category';T='String';V='High'})},
            
            # --- Graphics & Display ---
            @{ID='perf-hw-accel'; Name='Enable Hardware Acceleration'; Desc='Use GPU for rendering'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Avalon.Graphics';N='DisableHWAcceleration';T='DWord';V=0})},
            @{ID='perf-vrr'; Name='Enable Variable Refresh Rate'; Desc='G-Sync/FreeSync support'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\DirectX\UserGpuPreferences';N='VRROptimizeEnable';T='DWord';V=1})},
            @{ID='perf-hags'; Name='Enable HAGS'; Desc='Hardware Accelerated GPU Scheduling'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers';N='HwSchMode';T='DWord';V=2})},
            
            # --- Network Optimization ---
            @{ID='perf-nagle'; Name='Disable Nagle Algorithm'; Desc='Reduce network latency for gaming'; Risk=0; Cmd='Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object { $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($_.InterfaceGuid)"; if (Test-Path $path) { Set-ItemProperty -Path $path -Name TcpAckFrequency -Value 1 -Type DWord -Force; Set-ItemProperty -Path $path -Name TCPNoDelay -Value 1 -Type DWord -Force } }'},
            @{ID='perf-network-throttle'; Name='Disable Network Throttling'; Desc='Full bandwidth for applications'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile';N='NetworkThrottlingIndex';T='DWord';V=4294967295})},
            
            # --- CPU & Memory Optimization ---
            @{ID='perf-sys-responsiveness'; Name='System Responsiveness'; Desc='Prioritize foreground applications'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile';N='SystemResponsiveness';T='DWord';V=0})},
            @{ID='perf-foreground-boost'; Name='Foreground App Boost'; Desc='CPU priority for active window'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl';N='Win32PrioritySeparation';T='DWord';V=38})},
            @{ID='perf-large-cache'; Name='Large System Cache'; Desc='Optimize memory for applications'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management';N='LargeSystemCache';T='DWord';V=0})},
            @{ID='perf-disable-paging'; Name='Disable Paging Executive'; Desc='Keep drivers in RAM'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management';N='DisablePagingExecutive';T='DWord';V=1})},
            @{ID='perf-svchost-split'; Name='SvcHost Split Threshold'; Desc='Separate service processes'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Control';N='SvcHostSplitThresholdInKB';T='DWord';V=4194304})},
            
            # --- Storage & I/O ---
            @{ID='perf-ntfs-memory'; Name='NTFS Memory Usage'; Desc='Optimize NTFS for performance'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem';N='NtfsMemoryUsage';T='DWord';V=2})},
            @{ID='perf-ntfs-last-access'; Name='Disable Last Access Update'; Desc='Reduce disk writes'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem';N='NtfsDisableLastAccessUpdate';T='DWord';V=1})},
            @{ID='perf-8dot3-names'; Name='Disable 8.3 Filenames'; Desc='Improve NTFS performance'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem';N='NtfsDisable8dot3NameCreation';T='DWord';V=1})},
            @{ID='perf-prefetch'; Name='Optimize Prefetch'; Desc='Configure prefetch for SSD'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters';N='EnablePrefetcher';T='DWord';V=0})},
            @{ID='perf-superfetch'; Name='Optimize Superfetch'; Desc='Configure superfetch for SSD'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters';N='EnableSuperfetch';T='DWord';V=0})},
            
            # --- Visual Effects ---
            @{ID='perf-visual-fx'; Name='Best Performance Visual FX'; Desc='Disable animations for speed'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects';N='VisualFXSetting';T='DWord';V=2})},
            @{ID='perf-menu-delay'; Name='Reduce Menu Delay'; Desc='Faster menu appearance'; Risk=0; Reg=@(@{P='HKCU:\Control Panel\Desktop';N='MenuShowDelay';T='String';V='0'})},
            @{ID='perf-animations'; Name='Disable Window Animations'; Desc='Turn off minimize/maximize effects'; Risk=0; Reg=@(@{P='HKCU:\Control Panel\Desktop\WindowMetrics';N='MinAnimate';T='String';V='0'})},
            @{ID='perf-smooth-scroll'; Name='Disable Smooth Scrolling'; Desc='Instant scrolling response'; Risk=0; Reg=@(@{P='HKCU:\Control Panel\Desktop';N='SmoothScroll';T='DWord';V=0})},
            @{ID='perf-cursor-blink'; Name='Disable Cursor Blink'; Desc='Static cursor for less CPU'; Risk=0; Reg=@(@{P='HKCU:\Control Panel\Desktop';N='CursorBlinkRate';T='String';V='-1'})},
            @{ID='perf-transparency'; Name='Disable Transparency'; Desc='Solid colors for better performance'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize';N='EnableTransparency';T='DWord';V=0})},
            
            # --- Startup & Boot ---
            @{ID='perf-boot-timeout'; Name='Reduce Boot Timeout'; Desc='Faster OS selection timeout'; Risk=0; Cmd='bcdedit /timeout 3'},
            @{ID='perf-boot-log'; Name='Disable Boot Log'; Desc='Skip boot logging'; Risk=0; Cmd='bcdedit /set bootlog no'},
            @{ID='perf-startup-delay'; Name='Disable Startup Delay'; Desc='Launch apps immediately at login'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize';N='StartupDelayInMSec';T='DWord';V=0})},
            
            # --- Misc Performance ---
            @{ID='perf-search-indexing'; Name='Limit Search Indexing'; Desc='Reduce background indexing impact'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';N='PreventIndexingLowDiskSpaceMB';T='DWord';V=1})},
            @{ID='perf-maintenance'; Name='Disable Auto Maintenance'; Desc='Stop scheduled maintenance tasks'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance';N='MaintenanceDisabled';T='DWord';V=1})},
            @{ID='perf-cortana-search'; Name='Disable Cortana in Search'; Desc='Faster local search only'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';N='AllowCortana';T='DWord';V=0})},
            @{ID='perf-web-search'; Name='Disable Web Search Results'; Desc='Search local files only'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer';N='DisableSearchBoxSuggestions';T='DWord';V=1})}
        )

        # ===================================================================================
        # POWER MANAGEMENT (20+ tweaks)
        # ===================================================================================
        'Power' = @(
            # --- Fast Startup & Hibernation ---
            @{ID='pwr-fast-startup'; Name='Enable Fast Startup'; Desc='Hybrid boot for faster startup'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power';N='HiberbootEnabled';T='DWord';V=1})},
            @{ID='pwr-hibernation-on'; Name='Enable Hibernation'; Desc='Allow hibernation mode'; Risk=0; Cmd='powercfg /h on'},
            @{ID='pwr-hibernation-off'; Name='Disable Hibernation'; Desc='Disable to save disk space'; Risk=0; Cmd='powercfg /h off'},
            @{ID='pwr-hybrid-sleep'; Name='Enable Hybrid Sleep'; Desc='Combines sleep and hibernation'; Risk=0; Cmd='powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP 1; powercfg /setactive SCHEME_CURRENT'},
            
            # --- Power Plan ---
            @{ID='pwr-high-perf'; Name='High Performance Plan'; Desc='Maximum performance power plan'; Risk=0; Cmd='powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'},
            @{ID='pwr-balanced'; Name='Balanced Power Plan'; Desc='Balance performance and battery'; Risk=0; Cmd='powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e'},
            @{ID='pwr-ultimate'; Name='Ultimate Performance Plan'; Desc='Extreme performance power plan'; Risk=0; Cmd='$guid = (powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61) -replace ".*GUID: ([a-f0-9-]+).*","$1"; if ($guid) { powercfg /setactive $guid }'},
            
            # --- Display Power ---
            @{ID='pwr-display-off-never'; Name='Never Turn Off Display'; Desc='Keep monitor always on'; Risk=0; Cmd='powercfg /change monitor-timeout-ac 0'},
            @{ID='pwr-adaptive-brightness'; Name='Disable Adaptive Brightness'; Desc='Manual brightness control only'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SensorState\Sensors\{BF16F0E4-AF24-46BE-A26E-D76A1C0F0F1A}';N='Active';T='DWord';V=0})},
            
            # --- Sleep Settings ---
            @{ID='pwr-sleep-never-ac'; Name='Never Sleep (Plugged In)'; Desc='Disable sleep on AC power'; Risk=0; Cmd='powercfg /change standby-timeout-ac 0'},
            @{ID='pwr-sleep-never-dc'; Name='Never Sleep (Battery)'; Desc='Disable sleep on battery'; Risk=0; Cmd='powercfg /change standby-timeout-dc 0'},
            @{ID='pwr-wake-timers'; Name='Disable Wake Timers'; Desc='Prevent scheduled wake-ups'; Risk=0; Cmd='powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP RTCWAKE 0; powercfg /setactive SCHEME_CURRENT'},
            
            # --- USB Power ---
            @{ID='pwr-usb-suspend'; Name='Disable USB Selective Suspend'; Desc='Keep USB devices always powered'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Services\USB';N='DisableSelectiveSuspend';T='DWord';V=1})},
            @{ID='pwr-usb-hub-suspend'; Name='Disable USB Hub Power Saving'; Desc='USB hubs stay powered'; Risk=0; Cmd='powercfg /setacvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0; powercfg /setactive SCHEME_CURRENT'},
            
            # --- CPU Power States ---
            @{ID='pwr-cpu-max'; Name='Max CPU Performance'; Desc='CPU always at 100%'; Risk=0; Cmd='powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100; powercfg /setactive SCHEME_CURRENT'},
            @{ID='pwr-cpu-min'; Name='Set Min CPU to 5%'; Desc='Allow CPU to idle low'; Risk=0; Cmd='powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 5; powercfg /setactive SCHEME_CURRENT'},
            @{ID='pwr-cpu-boost'; Name='Enable CPU Turbo Boost'; Desc='Allow processor boost mode'; Risk=0; Reg=@(@{P='HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7';N='Attributes';T='DWord';V=2})},
            
            # --- Hard Disk ---
            @{ID='pwr-hdd-never-off'; Name='Never Turn Off Hard Disk'; Desc='Keep HDD spinning'; Risk=0; Cmd='powercfg /change disk-timeout-ac 0'},
            
            # --- Lid & Buttons ---
            @{ID='pwr-lid-nothing'; Name='Lid Close Does Nothing'; Desc='No action when closing laptop lid'; Risk=0; Cmd='powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0; powercfg /setactive SCHEME_CURRENT'},
            @{ID='pwr-power-button'; Name='Power Button Shuts Down'; Desc='Pressing power button shuts down'; Risk=0; Cmd='powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 3; powercfg /setactive SCHEME_CURRENT'}
        )

        # ===================================================================================
        # UI & APPEARANCE (30+ tweaks)
        # ===================================================================================
        'UI' = @(
            # --- Theme & Colors ---
            @{ID='ui-dark-mode'; Name='Enable Dark Mode'; Desc='System-wide dark theme'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize';N='AppsUseLightTheme';T='DWord';V=0},@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize';N='SystemUsesLightTheme';T='DWord';V=0})},
            @{ID='ui-light-mode'; Name='Enable Light Mode'; Desc='System-wide light theme'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize';N='AppsUseLightTheme';T='DWord';V=1},@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize';N='SystemUsesLightTheme';T='DWord';V=1})},
            @{ID='ui-transparency-off'; Name='Disable Transparency Effects'; Desc='Solid colors for better performance'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize';N='EnableTransparency';T='DWord';V=0})},
            @{ID='ui-accent-taskbar'; Name='Show Accent on Taskbar'; Desc='Colored taskbar and Start menu'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize';N='ColorPrevalence';T='DWord';V=1})},
            
            # --- Taskbar ---
            @{ID='ui-taskbar-left'; Name='Taskbar Left Alignment (W11)'; Desc='Move taskbar icons to left'; Risk=0; OS='W11'; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';N='TaskbarAl';T='DWord';V=0})},
            @{ID='ui-taskbar-center'; Name='Taskbar Center Alignment (W11)'; Desc='Center taskbar icons'; Risk=0; OS='W11'; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';N='TaskbarAl';T='DWord';V=1})},
            @{ID='ui-taskbar-small'; Name='Small Taskbar Icons (W10)'; Desc='Smaller taskbar buttons'; Risk=0; OS='W10'; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';N='TaskbarSmallIcons';T='DWord';V=1})},
            @{ID='ui-taskbar-labels'; Name='Show Taskbar Labels'; Desc='Display app names on taskbar'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';N='TaskbarGlomLevel';T='DWord';V=2})},
            @{ID='ui-widgets-off'; Name='Hide Widgets Button (W11)'; Desc='Remove widgets from taskbar'; Risk=0; OS='W11'; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';N='TaskbarDa';T='DWord';V=0})},
            @{ID='ui-chat-off'; Name='Hide Chat Button (W11)'; Desc='Remove Teams chat from taskbar'; Risk=0; OS='W11'; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';N='TaskbarMn';T='DWord';V=0})},
            @{ID='ui-taskview-off'; Name='Hide Task View Button'; Desc='Remove virtual desktops button'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';N='ShowTaskViewButton';T='DWord';V=0})},
            @{ID='ui-search-hide'; Name='Hide Search Box'; Desc='Remove search from taskbar'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search';N='SearchboxTaskbarMode';T='DWord';V=0})},
            @{ID='ui-search-icon'; Name='Search Icon Only'; Desc='Show search as icon'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search';N='SearchboxTaskbarMode';T='DWord';V=1})},
            @{ID='ui-news-off'; Name='Hide News and Interests (W10)'; Desc='Remove news feed from taskbar'; Risk=0; OS='W10'; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds';N='ShellFeedsTaskbarViewMode';T='DWord';V=2})},
            @{ID='ui-cortana-off'; Name='Hide Cortana Button'; Desc='Remove Cortana from taskbar'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';N='ShowCortanaButton';T='DWord';V=0})},
            @{ID='ui-end-task'; Name='Enable End Task (W11)'; Desc='Right-click to kill apps from taskbar'; Risk=0; OS='W11'; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings';N='TaskbarEndTask';T='DWord';V=1})},
            
            # --- Start Menu ---
            @{ID='ui-start-suggestions-off'; Name='Hide Start Menu Suggestions'; Desc='No app recommendations in Start'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='SystemPaneSuggestionsEnabled';T='DWord';V=0})},
            @{ID='ui-start-recent-off'; Name='Hide Recent Apps in Start'; Desc='Dont show recently added apps'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Start';N='ShowRecentList';T='DWord';V=0})},
            @{ID='ui-start-frequent-off'; Name='Hide Frequent Apps in Start'; Desc='Dont show most used apps'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Start';N='ShowFrequentList';T='DWord';V=0})},
            @{ID='ui-bing-search-off'; Name='Disable Bing in Start Search'; Desc='Local search results only'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer';N='DisableSearchBoxSuggestions';T='DWord';V=1})},
            
            # --- File Explorer ---
            @{ID='ui-file-extensions'; Name='Show File Extensions'; Desc='Display .exe, .txt, etc.'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';N='HideFileExt';T='DWord';V=0})},
            @{ID='ui-hidden-files'; Name='Show Hidden Files'; Desc='Display hidden files and folders'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';N='Hidden';T='DWord';V=1})},
            @{ID='ui-system-files'; Name='Show System Files'; Desc='Display protected system files'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';N='ShowSuperHidden';T='DWord';V=1})},
            @{ID='ui-checkboxes'; Name='Enable Item Checkboxes'; Desc='Checkboxes for file selection'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';N='AutoCheckSelect';T='DWord';V=1})},
            @{ID='ui-full-path'; Name='Show Full Path in Title'; Desc='Display full folder path'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CabinetState';N='FullPath';T='DWord';V=1})},
            @{ID='ui-classic-context'; Name='Classic Context Menu (W11)'; Desc='Old right-click menu style'; Risk=0; OS='W11'; Reg=@(@{P='HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32';N='';T='String';V=''})},
            @{ID='ui-explorer-thispc'; Name='Open Explorer to This PC'; Desc='Start in This PC not Quick Access'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';N='LaunchTo';T='DWord';V=1})},
            @{ID='ui-recent-quick'; Name='Hide Recent in Quick Access'; Desc='Dont show recent files'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer';N='ShowRecent';T='DWord';V=0})},
            @{ID='ui-frequent-quick'; Name='Hide Frequent in Quick Access'; Desc='Dont show frequent folders'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer';N='ShowFrequent';T='DWord';V=0})},
            
            # --- Notifications ---
            @{ID='ui-tips-off'; Name='Disable Tips and Suggestions'; Desc='No Windows tip notifications'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='SoftLandingEnabled';T='DWord';V=0})},
            @{ID='ui-welcome-off'; Name='Disable Welcome Experience'; Desc='Skip Windows welcome screens'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='SubscribedContent-310093Enabled';T='DWord';V=0})}
        )

        # ===================================================================================
        # SERVICES (25+ tweaks)
        # ===================================================================================
        'Services' = @(
            # --- Performance Services ---
            @{ID='svc-wsearch'; Name='Disable Windows Search'; Desc='Stop search indexing (RISK)'; Risk=1; Svc=@{N='WSearch';S='Disabled'}},
            @{ID='svc-sysmain'; Name='Disable SysMain/Superfetch'; Desc='Stop prefetching (RISK)'; Risk=1; Svc=@{N='SysMain';S='Disabled'}},
            @{ID='svc-bits'; Name='Disable BITS'; Desc='Background file transfers (RISK)'; Risk=1; Svc=@{N='BITS';S='Manual'}},
            
            # --- Telemetry Services ---
            @{ID='svc-diagtrack'; Name='Disable DiagTrack'; Desc='Stop telemetry collection (RISK)'; Risk=1; Svc=@{N='DiagTrack';S='Disabled'}},
            @{ID='svc-dmwappush'; Name='Disable WAP Push'; Desc='Stop dmwappushservice'; Risk=0; Svc=@{N='dmwappushservice';S='Disabled'}},
            @{ID='svc-diagsvc'; Name='Disable Diagnostic Service'; Desc='Diagnostic Policy Service'; Risk=0; Svc=@{N='DPS';S='Manual'}},
            
            # --- Remote Services ---
            @{ID='svc-remoteregistry'; Name='Disable Remote Registry'; Desc='Block remote registry access'; Risk=0; Svc=@{N='RemoteRegistry';S='Disabled'}},
            @{ID='svc-remoteaccess'; Name='Disable Remote Access'; Desc='Routing and Remote Access'; Risk=0; Svc=@{N='RemoteAccess';S='Disabled'}},
            @{ID='svc-termservice'; Name='Disable Remote Desktop'; Desc='Terminal Services'; Risk=0; Svc=@{N='TermService';S='Disabled'}},
            
            # --- Xbox Services ---
            @{ID='svc-xboxauth'; Name='Disable Xbox Auth'; Desc='Xbox Live Auth Manager'; Risk=0; Svc=@{N='XblAuthManager';S='Disabled'}},
            @{ID='svc-xboxsave'; Name='Disable Xbox Game Save'; Desc='Xbox Live Game Save'; Risk=0; Svc=@{N='XblGameSave';S='Disabled'}},
            @{ID='svc-xboxnet'; Name='Disable Xbox Networking'; Desc='Xbox Live Networking Service'; Risk=0; Svc=@{N='XboxNetApiSvc';S='Disabled'}},
            @{ID='svc-xboxgip'; Name='Disable Xbox Accessory'; Desc='Xbox Accessory Management'; Risk=0; Svc=@{N='XboxGipSvc';S='Disabled'}},
            
            # --- Print Services ---
            @{ID='svc-spooler'; Name='Disable Print Spooler'; Desc='No printing support (RISK)'; Risk=1; Svc=@{N='Spooler';S='Disabled'}},
            
            # --- Location Services ---
            @{ID='svc-geolocation'; Name='Disable Geolocation'; Desc='Location services'; Risk=0; Svc=@{N='lfsvc';S='Disabled'}},
            @{ID='svc-maps'; Name='Disable Map Downloads'; Desc='Offline maps service'; Risk=0; Svc=@{N='MapsBroker';S='Disabled'}},
            
            # --- Phone & Retail ---
            @{ID='svc-phone'; Name='Disable Phone Service'; Desc='Phone integration service'; Risk=0; Svc=@{N='PhoneSvc';S='Disabled'}},
            @{ID='svc-retaildemo'; Name='Disable Retail Demo'; Desc='Store demo mode service'; Risk=0; Svc=@{N='RetailDemo';S='Disabled'}},
            
            # --- Optional Services ---
            @{ID='svc-wallet'; Name='Disable Wallet Service'; Desc='Microsoft Wallet'; Risk=0; Svc=@{N='WalletService';S='Disabled'}},
            @{ID='svc-wmp-share'; Name='Disable Media Sharing'; Desc='Windows Media Player Network'; Risk=0; Svc=@{N='WMPNetworkSvc';S='Disabled'}},
            @{ID='svc-wisvc'; Name='Disable Insider Service'; Desc='Windows Insider Program'; Risk=0; Svc=@{N='wisvc';S='Disabled'}},
            @{ID='svc-wersvc'; Name='Disable Error Reporting'; Desc='Windows Error Reporting'; Risk=0; Svc=@{N='WerSvc';S='Disabled'}}
        )

        # ===================================================================================
        # WINDOWS UPDATES (10+ tweaks)
        # ===================================================================================
        'Updates' = @(
            # --- Update Policies ---
            @{ID='upd-auto-normal'; Name='Auto Updates Normal'; Desc='Standard Windows Update behavior'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU';N='NoAutoUpdate';T='DWord';V=0},@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU';N='AUOptions';T='DWord';V=3})},
            @{ID='upd-notify-only'; Name='Notify Before Download'; Desc='Ask before downloading updates'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU';N='NoAutoUpdate';T='DWord';V=0},@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU';N='AUOptions';T='DWord';V=2})},
            @{ID='upd-disabled'; Name='Disable Auto Updates (RISK)'; Desc='Stops all automatic updates'; Risk=1; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU';N='NoAutoUpdate';T='DWord';V=1})},
            
            # --- Update Delivery ---
            @{ID='upd-p2p-off'; Name='Disable P2P Delivery'; Desc='Download only from Microsoft'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization';N='DODownloadMode';T='DWord';V=0})},
            @{ID='upd-p2p-local'; Name='Local P2P Only'; Desc='Share updates on local network'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization';N='DODownloadMode';T='DWord';V=1})},
            @{ID='upd-metered'; Name='Metered Connection'; Desc='Treat as metered to limit updates'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost';N='Ethernet';T='DWord';V=2})},
            
            # --- Update Behavior ---
            @{ID='upd-no-restart'; Name='No Auto Restart'; Desc='Dont restart without permission'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU';N='NoAutoRebootWithLoggedOnUsers';T='DWord';V=1})},
            @{ID='upd-defer-feature'; Name='Defer Feature Updates'; Desc='Delay new features 365 days'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate';N='DeferFeatureUpdates';T='DWord';V=1},@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate';N='DeferFeatureUpdatesPeriodInDays';T='DWord';V=365})},
            @{ID='upd-defer-quality'; Name='Defer Quality Updates'; Desc='Delay patches 30 days'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate';N='DeferQualityUpdates';T='DWord';V=1},@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate';N='DeferQualityUpdatesPeriodInDays';T='DWord';V=30})},
            @{ID='upd-driver-off'; Name='Disable Driver Updates'; Desc='Dont auto-update drivers'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate';N='ExcludeWUDriversInQualityUpdate';T='DWord';V=1})}
        )

        # ===================================================================================
        # NOTIFICATIONS & SOUND (15+ tweaks)
        # ===================================================================================
        'Notifications' = @(
            # --- Notification Settings ---
            @{ID='notif-all-off'; Name='Disable All Notifications'; Desc='Turn off all system notifications'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications';N='ToastEnabled';T='DWord';V=0})},
            @{ID='notif-lock-off'; Name='Hide Lock Screen Notifications'; Desc='No notifications on lock screen'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings';N='NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK';T='DWord';V=0})},
            @{ID='notif-sound-off'; Name='Disable Notification Sounds'; Desc='Silent notifications'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings';N='NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND';T='DWord';V=0})},
            @{ID='notif-tips-off'; Name='Disable Tips Notifications'; Desc='No Windows tips'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='SoftLandingEnabled';T='DWord';V=0})},
            @{ID='notif-welcome-off'; Name='Disable Welcome Experience'; Desc='Skip Windows welcome dialogs'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='SubscribedContent-310093Enabled';T='DWord';V=0})},
            @{ID='notif-finish-off'; Name='Disable Finish Setup Reminders'; Desc='Stop setup completion nags'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement';N='ScoobeSystemSettingEnabled';T='DWord';V=0})},
            @{ID='notif-suggested-off'; Name='Disable Suggested Content'; Desc='No suggestions in Settings'; Risk=0; Reg=@(@{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';N='SubscribedContent-338393Enabled';T='DWord';V=0})},
            
            # --- Sound Settings ---
            @{ID='snd-startup-off'; Name='Disable Startup Sound'; Desc='No sound on Windows boot'; Risk=0; Reg=@(@{P='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation';N='DisableStartupSound';T='DWord';V=1})},
            @{ID='snd-navigation-off'; Name='Disable Navigation Sounds'; Desc='No Explorer click sounds'; Risk=0; Reg=@(@{P='HKCU:\AppEvents\Schemes\Apps\Explorer\Navigating\.Current';N='';T='String';V=''})},
            @{ID='snd-scheme-none'; Name='No Sound Scheme'; Desc='Disable all system sounds'; Risk=0; Reg=@(@{P='HKCU:\AppEvents\Schemes';N='';T='String';V='.None'})}
        )
    }
    
    return $tweakData
}

# ===========================================================================================
# SECTION 4: TWEAK APPLICATION
# ===========================================================================================

function Get-TweakStatus {
    param([hashtable]$Tweak)
    
    # Check registry-based tweaks (optimized)
    if ($Tweak.Reg) {
        foreach ($reg in $Tweak.Reg) {
            try {
                if (-not (Test-Path $reg.P)) { return $false }
                $props = Get-ItemProperty -Path $reg.P -ErrorAction Stop
                $currentValue = $props.($reg.N)
                if ($null -eq $currentValue -or $currentValue -ne $reg.V) {
                    return $false
                }
            } catch {
                return $false
            }
        }
        return $true
    }
    
    # Check service-based tweaks
    if ($Tweak.Svc) {
        try {
            $service = Get-Service -Name $Tweak.Svc.N -ErrorAction SilentlyContinue
            if ($null -eq $service) { return $false }
            # For "Disabled" startup type, check if it matches
            return ($service.StartType -eq $Tweak.Svc.S)
        } catch {
            return $false
        }
    }
    
    # Command-based tweaks - can't easily check, return null (unknown)
    if ($Tweak.Cmd) {
        return $null
    }
    
    return $null
}

function Set-RegistryTweak {
    param([hashtable]$RegItem)
    
    $path = $RegItem.P
    $name = $RegItem.N
    $value = $RegItem.V
    $type = $RegItem.T
    
    try {
        # Create path if it doesn't exist (optimized check)
        $pathExists = Test-Path $path
        if (-not $pathExists) {
            $null = New-Item -Path $path -Force -ErrorAction Stop
        }
        
        # Only set if value is different (avoid unnecessary writes)
        $currentValue = $null
        try {
            $currentValue = (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name
        } catch { }
        
        if ($currentValue -ne $value) {
            $null = New-ItemProperty -Path $path -Name $name -Value $value -PropertyType $type -Force -ErrorAction Stop
            $Global:TweakLog += "[OK] Registry: $path\$name = $value"
        } else {
            $Global:TweakLog += "[SKIP] Registry: $path\$name already set"
        }
        return $true
    } catch {
        $Global:TweakLog += "[ERROR] Registry: $path\$name - $($_.Exception.Message)"
        return $false
    }
}

function Set-ServiceTweak {
    param([hashtable]$ServiceItem)
    
    $serviceName = $ServiceItem.N
    $startupType = $ServiceItem.S
    
    try {
        # Check if service exists using faster CIM query
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            $Global:TweakLog += "[SKIP] Service: $serviceName not found"
            return $true
        }
        
        # Map startup type to CIM values
        $startModeMap = @{ 'Disabled'='Disabled'; 'Manual'='Manual'; 'Automatic'='Auto' }
        $targetMode = $startModeMap[$startupType]
        
        # Only modify if different
        if ($service.StartMode -ne $targetMode) {
            Set-Service -Name $serviceName -StartupType $startupType -ErrorAction Stop
        }
        
        # Stop if running and we're disabling
        if ($service.State -eq 'Running' -and $startupType -eq 'Disabled') {
            Stop-Service -Name $serviceName -Force -NoWait -ErrorAction SilentlyContinue
        }
        
        $Global:TweakLog += "[OK] Service: $serviceName -> $startupType"
        return $true
    } catch {
        $Global:TweakLog += "[ERROR] Service: $serviceName - $($_.Exception.Message)"
        return $false
    }
}

function Invoke-CommandTweak {
    param([string]$Command)
    
    try {
        Invoke-Expression $Command -ErrorAction Stop
        $Global:TweakLog += "[OK] Command: $Command"
        return $true
    } catch {
        $Global:TweakLog += "[ERROR] Command: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-AllTweaks {
    if ($Global:SelectedTweaks.Count -eq 0) {
        Write-Color 'Warning' "No tweaks selected"
        return $false
    }
    
    Write-Header "Applying Tweaks"
    
    $applied = 0
    $failed = 0
    
    foreach ($category in $Global:TweakData.Keys) {
        foreach ($tweak in $Global:TweakData[$category]) {
            if ($Global:SelectedTweaks -contains $tweak.ID) {
                Write-Color 'Info' "Applying: $($tweak.Name)"
                
                $success = $true
                
                if ($tweak.Reg) {
                    foreach ($reg in $tweak.Reg) {
                        if (-not (Set-RegistryTweak -RegItem $reg)) {
                            $success = $false
                        }
                    }
                }
                
                if ($tweak.Svc) {
                    if (-not (Set-ServiceTweak -ServiceItem $tweak.Svc)) {
                        $success = $false
                    }
                }
                
                if ($tweak.Cmd) {
                    if (-not (Invoke-CommandTweak -Command $tweak.Cmd)) {
                        $success = $false
                    }
                }
                
                if ($success) { $applied++ } else { $failed++ }
            }
        }
    }
    
    Write-Header "Application Summary"
    Write-Color 'Success' "Applied: $applied tweaks"
    if ($failed -gt 0) {
        Write-Color 'Warning' "Failed: $failed tweaks"
    }
    
    Write-Host ""
    $Global:TweakLog | ForEach-Object { Write-Host $_ }
    
    Write-Host ""
    Write-Color 'Info' "A restart may be required for all tweaks to take effect."
    Write-Color 'Info' "Log file saved to: $Global:LogFile"
    
    return $true
}

# ===========================================================================================
# SECTION 5: MENU FUNCTIONS
# ===========================================================================================

function Show-MainMenu {
    Clear-Host
    Write-Header "HamTweak - Main Menu"
    
    # Calculate total available tweaks
    $totalTweaks = ($Global:TweakData.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    
    Write-Color 'Info' "OS: $($Global:OSVersion) | Build: $($Global:OSBuild)"
    Write-Color 'Success' "Selected: $($Global:SelectedTweaks.Count) / $totalTweaks tweaks"
    Write-Host ""
    
    Write-Color 'Info' "1. Privacy & Security      ($($Global:TweakData.Privacy.Count) tweaks)"
    Write-Color 'Info' "2. Performance & Gaming    ($($Global:TweakData.Performance.Count) tweaks)"
    Write-Color 'Info' "3. Power Management        ($($Global:TweakData.Power.Count) tweaks)"
    Write-Color 'Info' "4. UI Customization        ($($Global:TweakData.UI.Count) tweaks)"
    Write-Color 'Info' "5. System Services         ($($Global:TweakData.Services.Count) tweaks)"
    Write-Color 'Info' "6. Windows Updates         ($($Global:TweakData.Updates.Count) tweaks)"
    Write-Color 'Info' "7. Notifications & Sound   ($($Global:TweakData.Notifications.Count) tweaks)"
    Write-Color 'Info' "8. Bloatware Removal"
    Write-Divider
    Write-Color 'Info' "9. Review Selected Tweaks"
    Write-Color 'Success' "A. Apply Tweaks & Create Script"
    Write-Color 'Warning' "C. Clear ALL Selections"
    Write-Color 'Info' "0. Exit"
    Write-Host ""
    
    return Read-Host "Select option"
}

function Show-CategoryMenu {
    param([string]$CategoryName, [array]$Tweaks)
    
    # Filter tweaks based on OS version (Issue 8: OS-specific filtering)
    $filteredTweaks = @()
    foreach ($tweak in $Tweaks) {
        if ($tweak.OS) {
            # Check if tweak matches current OS
            if (($tweak.OS -eq 'W11' -and $Global:IsWindows11) -or ($tweak.OS -eq 'W10' -and -not $Global:IsWindows11)) {
                $filteredTweaks += $tweak
            }
            # Skip tweaks that don't match current OS
        } else {
            # No OS restriction, include for all
            $filteredTweaks += $tweak
        }
    }
    $Tweaks = $filteredTweaks
    
    # Cache tweak statuses once per menu display (performance optimization)
    $statusCache = @{}
    
    while ($true) {
        Clear-Host
        Write-Header "$CategoryName Tweaks"
        
        # Show category selection counts
        $categoryIds = $Tweaks | ForEach-Object { $_.ID }
        $selectedInCategory = @($Global:SelectedTweaks | Where-Object { $_ -in $categoryIds }).Count
        Write-Color 'Info' "Selected in category: $selectedInCategory / $($Tweaks.Count)"
        Write-Host ""
        
        $index = 1
        $menu = @{}
        
        # Calculate column layout based on console width
        $consoleWidth = $Host.UI.RawUI.WindowSize.Width
        $columnWidth = 38  # Width for each column item
        $numColumns = [Math]::Max(1, [Math]::Floor($consoleWidth / $columnWidth))
        
        # Build tweak display data using ArrayList for performance
        $tweakItems = [System.Collections.ArrayList]::new()
        foreach ($tweak in $Tweaks) {
            $selected = if ($Global:SelectedTweaks -contains $tweak.ID) { "[X]" } else { "[ ]" }
            $riskMark = if ($tweak.Risk -eq 1) { "!" } else { "" }
            
            # Get current system status (use cache if available)
            if (-not $statusCache.ContainsKey($tweak.ID)) {
                $statusCache[$tweak.ID] = Get-TweakStatus -Tweak $tweak
            }
            $currentStatus = $statusCache[$tweak.ID]
            
            if ($currentStatus -eq $true) {
                $statusChar = "+"
                $statusColor = "Green"
            } elseif ($currentStatus -eq $false) {
                $statusChar = "-"
                $statusColor = "Yellow"
            } else {
                $statusChar = "?"
                $statusColor = "Gray"
            }
            
            $null = $tweakItems.Add(@{
                Index = $index
                Selected = $selected
                Name = $tweak.Name
                StatusChar = $statusChar
                StatusColor = $statusColor
                RiskMark = $riskMark
                Desc = $tweak.Desc
                ID = $tweak.ID
            })
            $menu[$index.ToString()] = $tweak.ID
            $index++
        }
        
        # Display in columns
        $totalItems = $tweakItems.Count
        $rows = [Math]::Ceiling($totalItems / $numColumns)
        
        for ($row = 0; $row -lt $rows; $row++) {
            for ($col = 0; $col -lt $numColumns; $col++) {
                $itemIndex = $row + ($col * $rows)
                if ($itemIndex -lt $totalItems) {
                    $item = $tweakItems[$itemIndex]
                    # Format: [X] 1. Name [+]!
                    $indexStr = $item.Index.ToString().PadLeft(2)
                    $nameDisplay = $item.Name
                    if ($nameDisplay.Length -gt 24) {
                        $nameDisplay = $nameDisplay.Substring(0, 21) + "..."
                    }
                    
                    Write-Host "$($item.Selected) $indexStr. " -NoNewline
                    Write-Host $nameDisplay.PadRight(24) -NoNewline
                    Write-Host "[$($item.StatusChar)]" -ForegroundColor $item.StatusColor -NoNewline
                    Write-Host "$($item.RiskMark)" -ForegroundColor Red -NoNewline
                    
                    # Add spacing between columns (but not after last column)
                    if ($col -lt $numColumns - 1) {
                        Write-Host " | " -NoNewline
                    }
                }
            }
            Write-Host ""  # New line after each row
        }
        
        Write-Host ""
        Write-Color 'Info' "Legend: [+]=Enabled [-]=Disabled [?]=Unknown | !=Risk"
        Write-Divider
        Write-Color 'Success' "[A] Select ALL  | [U] Deselect ALL | [C] Clear Category"
        Write-Color 'Info' "[B] Back        | [D#] Details     | [R] Refresh Status"
        Write-Host ""
        
        $choice = Read-Host "Enter numbers (comma-separated) or command"
        
        # Handle details view
        if ($choice -match '^[Dd](\d+)$') {
            $detailNum = $Matches[1]
            if ($menu.ContainsKey($detailNum)) {
                $detailTweak = $Tweaks | Where-Object { $_.ID -eq $menu[$detailNum] }
                if ($detailTweak) {
                    Write-Host ""
                    Write-Color 'Header' "--- $($detailTweak.Name) ---"
                    Write-Color 'Info' "Description: $($detailTweak.Desc)"
                    Write-Color 'Info' "Risk Level: $(if ($detailTweak.Risk -eq 1) { 'HIGH' } else { 'Normal' })"
                    Write-Color 'Info' "ID: $($detailTweak.ID)"
                    Write-Host ""
                    Read-Host "Press Enter to continue"
                }
            }
            continue
        }
        
        if ($choice -eq 'B' -or $choice -eq 'b') {
            return
        }
        
        # SELECT ALL in this category
        if ($choice -eq 'A' -or $choice -eq 'a') {
            $categoryIds = $Tweaks | ForEach-Object { $_.ID }
            foreach ($id in $categoryIds) {
                if ($Global:SelectedTweaks -notcontains $id) {
                    $Global:SelectedTweaks += $id
                    # Check for mutual exclusion conflicts (silent mode for bulk)
                    Invoke-MutualExclusion -SelectedTweakID $id -Silent
                }
            }
            Write-Color 'Success' "Selected all $($categoryIds.Count) tweaks in category"
            Write-Color 'Info' "Note: Conflicting options auto-resolved (last wins)"
            Start-Sleep -Milliseconds 800
            continue
        }
        
        # DESELECT ALL in this category
        if ($choice -eq 'U' -or $choice -eq 'u') {
            $categoryIds = $Tweaks | ForEach-Object { $_.ID }
            $Global:SelectedTweaks = @($Global:SelectedTweaks | Where-Object { $_ -notin $categoryIds })
            Write-Color 'Success' "Deselected all tweaks in category"
            Start-Sleep -Milliseconds 800
            continue
        }
        
        # Clear category (same as deselect all)
        if ($choice -eq 'C' -or $choice -eq 'c') {
            $categoryIds = $Tweaks | ForEach-Object { $_.ID }
            $Global:SelectedTweaks = @($Global:SelectedTweaks | Where-Object { $_ -notin $categoryIds })
            Write-Color 'Success' "Cleared category selections"
            Start-Sleep -Milliseconds 800
            continue
        }
        
        # Refresh status cache
        if ($choice -eq 'R' -or $choice -eq 'r') {
            $statusCache.Clear()
            Write-Color 'Info' "Refreshing status..."
            continue
        }
        
        # Handle numeric selections
        $choices = $choice -split ','
        $changed = 0
        foreach ($sel in $choices) {
            $sel = $sel.Trim()
            if ($menu.ContainsKey($sel)) {
                $tweakID = $menu[$sel]
                if ($Global:SelectedTweaks -contains $tweakID) {
                    $Global:SelectedTweaks = @($Global:SelectedTweaks | Where-Object { $_ -ne $tweakID })
                } else {
                    $Global:SelectedTweaks += $tweakID
                    # Check for mutual exclusion conflicts
                    Invoke-MutualExclusion -SelectedTweakID $tweakID
                }
                $changed++
            }
        }
        
        if ($changed -gt 0) {
            Write-Color 'Success' "Toggled $changed tweak(s)"
            Start-Sleep -Milliseconds 500
        }
    }
}

function Show-ReviewMenu {
    Clear-Host
    Write-Header "Review Selected Tweaks"
    
    if ($Global:SelectedTweaks.Count -eq 0) {
        Write-Color 'Warning' "No tweaks selected"
        Start-Sleep -Seconds 2
        return
    }
    
    Write-Color 'Info' "Selected $($Global:SelectedTweaks.Count) tweaks:"
    Write-Host ""
    
    foreach ($category in $Global:TweakData.Keys) {
        $categoryTweaks = $Global:TweakData[$category] | Where-Object { $Global:SelectedTweaks -contains $_.ID }
        if ($categoryTweaks) {
            Write-Color 'Header' "[$category]"
            $categoryTweaks | ForEach-Object {
                Write-Host "  - $($_.Name)"
            }
            Write-Host ""
        }
    }
    
    Write-Divider
    Read-Host "Press Enter to continue"
}

# ===========================================================================================
# SECTION 6: BLOATWARE REMOVAL
# ===========================================================================================

function Show-BloatwareMenu {
    Clear-Host
    Write-Header "Bloatware Removal Module"
    
    $Global:BloatwareApps = @(
        # Microsoft Apps
        @{Name='3D Builder'; Package='Microsoft.3DBuilder'; Type='AppxPackage'},
        @{Name='3D Viewer'; Package='Microsoft.Microsoft3DViewer'; Type='AppxPackage'},
        @{Name='Alarms & Clock'; Package='Microsoft.WindowsAlarms'; Type='AppxPackage'},
        @{Name='Bing News'; Package='Microsoft.BingNews'; Type='AppxPackage'},
        @{Name='Bing Weather'; Package='Microsoft.BingWeather'; Type='AppxPackage'},
        @{Name='Calculator'; Package='Microsoft.WindowsCalculator'; Type='AppxPackage'},
        @{Name='Calendar & Mail'; Package='microsoft.windowscommunicationsapps'; Type='AppxPackage'},
        @{Name='Camera'; Package='Microsoft.WindowsCamera'; Type='AppxPackage'},
        @{Name='Clipchamp'; Package='Clipchamp.Clipchamp'; Type='AppxPackage'},
        @{Name='Cortana'; Package='Microsoft.549981C3F5F10'; Type='AppxPackage'},
        @{Name='Family'; Package='MicrosoftCorporationII.MicrosoftFamily'; Type='AppxPackage'},
        @{Name='Feedback Hub'; Package='Microsoft.WindowsFeedbackHub'; Type='AppxPackage'},
        @{Name='Get Help'; Package='Microsoft.GetHelp'; Type='AppxPackage'},
        @{Name='Get Started / Tips'; Package='Microsoft.Getstarted'; Type='AppxPackage'},
        @{Name='Groove Music'; Package='Microsoft.ZuneMusic'; Type='AppxPackage'},
        @{Name='Maps'; Package='Microsoft.WindowsMaps'; Type='AppxPackage'},
        @{Name='Microsoft Edge'; Package='Microsoft.MicrosoftEdge'; Type='AppxPackage'},
        @{Name='Microsoft News'; Package='Microsoft.News'; Type='AppxPackage'},
        @{Name='Microsoft Pay'; Package='Microsoft.Wallet'; Type='AppxPackage'},
        @{Name='Microsoft Solitaire'; Package='Microsoft.MicrosoftSolitaireCollection'; Type='AppxPackage'},
        @{Name='Microsoft Teams'; Package='MicrosoftTeams'; Type='AppxPackage'},
        @{Name='Microsoft To Do'; Package='Microsoft.Todos'; Type='AppxPackage'},
        @{Name='Mixed Reality Portal'; Package='Microsoft.MixedReality.Portal'; Type='AppxPackage'},
        @{Name='Movies & TV'; Package='Microsoft.ZuneVideo'; Type='AppxPackage'},
        @{Name='Office Hub'; Package='Microsoft.MicrosoftOfficeHub'; Type='AppxPackage'},
        @{Name='OneDrive'; Package='Microsoft.OneDrive'; Type='AppxPackage'},
        @{Name='OneNote'; Package='Microsoft.Office.OneNote'; Type='AppxPackage'},
        @{Name='Outlook for Windows'; Package='Microsoft.OutlookForWindows'; Type='AppxPackage'},
        @{Name='Paint 3D'; Package='Microsoft.MSPaint'; Type='AppxPackage'},
        @{Name='People'; Package='Microsoft.People'; Type='AppxPackage'},
        @{Name='Phone Link'; Package='Microsoft.YourPhone'; Type='AppxPackage'},
        @{Name='Photos'; Package='Microsoft.Windows.Photos'; Type='AppxPackage'},
        @{Name='Power Automate'; Package='Microsoft.PowerAutomateDesktop'; Type='AppxPackage'},
        @{Name='Quick Assist'; Package='MicrosoftCorporationII.QuickAssist'; Type='AppxPackage'},
        @{Name='Skype'; Package='Microsoft.SkypeApp'; Type='AppxPackage'},
        @{Name='Snipping Tool'; Package='Microsoft.ScreenSketch'; Type='AppxPackage'},
        @{Name='Sticky Notes'; Package='Microsoft.MicrosoftStickyNotes'; Type='AppxPackage'},
        @{Name='Voice Recorder'; Package='Microsoft.WindowsSoundRecorder'; Type='AppxPackage'},
        @{Name='Whiteboard'; Package='Microsoft.Whiteboard'; Type='AppxPackage'},
        @{Name='Widgets'; Package='MicrosoftWindows.Client.WebExperience'; Type='AppxPackage'},
        @{Name='Xbox App'; Package='Microsoft.GamingApp'; Type='AppxPackage'},
        @{Name='Xbox Game Bar'; Package='Microsoft.XboxGamingOverlay'; Type='AppxPackage'},
        @{Name='Xbox Game Speech'; Package='Microsoft.XboxSpeechToTextOverlay'; Type='AppxPackage'},
        @{Name='Xbox Identity'; Package='Microsoft.XboxIdentityProvider'; Type='AppxPackage'},
        @{Name='Xbox TCUI'; Package='Microsoft.Xbox.TCUI'; Type='AppxPackage'}
    )
    
    $Global:OptionalFeatures = @(
        @{Name='Internet Explorer'; Feature='Internet-Explorer-Optional-amd64'; Type='WindowsFeature'},
        @{Name='Windows Media Player'; Feature='WindowsMediaPlayer'; Type='WindowsFeature'},
        @{Name='Work Folders Client'; Feature='WorkFolders-Client'; Type='WindowsFeature'},
        @{Name='Microsoft XPS Document Writer'; Feature='Printing-XPSServices-Features'; Type='WindowsFeature'},
        @{Name='Windows Fax and Scan'; Feature='FaxServicesClientPackage'; Type='WindowsFeature'},
        @{Name='Print to PDF'; Feature='Printing-PrintToPDFServices-Features'; Type='WindowsFeature'},
        @{Name='Remote Differential Compression'; Feature='MSRDC-Infrastructure'; Type='WindowsFeature'},
        @{Name='SMB 1.0/CIFS'; Feature='SMB1Protocol'; Type='WindowsFeature'},
        @{Name='SMB Direct'; Feature='SmbDirect'; Type='WindowsFeature'},
        @{Name='Telnet Client'; Feature='TelnetClient'; Type='WindowsFeature'},
        @{Name='TFTP Client'; Feature='TFTP'; Type='WindowsFeature'},
        @{Name='Windows PowerShell 2.0'; Feature='MicrosoftWindowsPowerShellV2Root'; Type='WindowsFeature'},
        @{Name='Windows Subsystem for Linux'; Feature='Microsoft-Windows-Subsystem-Linux'; Type='WindowsFeature'}
    )
    
    Write-Color 'Info' "1. Remove Windows Apps ($($Global:BloatwareApps.Count) items)"
    Write-Color 'Info' "2. Remove Optional Features ($($Global:OptionalFeatures.Count) items)"
    Write-Color 'Info' "0. Back"
    Write-Host ""
    
    $choice = Read-Host "Select option"
    
    if ($choice -eq '1') {
        Show-BloatwareSelection -Category "Windows Apps" -Items $Global:BloatwareApps
    } elseif ($choice -eq '2') {
        Show-FeatureSelection -Category "Optional Features" -Items $Global:OptionalFeatures
    }
    
    if ($choice -ne '0') {
        Show-BloatwareMenu
    }
}

function Show-BloatwareSelection {
    param([string]$Category, [array]$Items)
    
    Clear-Host
    Write-Header "Select Items to Remove - $Category"
    
    # Display in columns
    $colWidth = 35
    $consoleWidth = [Math]::Max(80, $Host.UI.RawUI.WindowSize.Width)
    $numCols = [Math]::Max(1, [Math]::Floor($consoleWidth / $colWidth))
    
    $index = 1
    $menu = @{}
    $row = @()
    
    foreach ($item in $Items) {
        $entry = "[$index] $($item.Name)"
        if ($entry.Length -gt ($colWidth - 2)) {
            $entry = $entry.Substring(0, $colWidth - 5) + "..."
        }
        $row += $entry.PadRight($colWidth)
        $menu[$index.ToString()] = $item
        $index++
        
        if ($row.Count -eq $numCols) {
            Write-Host ($row -join "")
            $row = @()
        }
    }
    if ($row.Count -gt 0) {
        Write-Host ($row -join "")
    }
    
    Write-Host ""
    Write-Color 'Info' "[A] Select All | [X] Execute Removal | [B] Back"
    Write-Host ""
    
    $choice = Read-Host "Select items (comma-separated numbers, or A for all)"
    
    if ($choice -eq 'B' -or $choice -eq 'b') { return }
    
    $selected = @()
    
    if ($choice -eq 'A' -or $choice -eq 'a') {
        $selected = $Items
    } else {
        $choices = $choice -split ','
        foreach ($sel in $choices) {
            $sel = $sel.Trim()
            if ($menu.ContainsKey($sel)) {
                $selected += $menu[$sel]
            }
        }
    }
    
    if ($selected.Count -gt 0) {
        Write-Host ""
        Write-Color 'Warning' "Selected $($selected.Count) app(s) for removal:"
        $selected | ForEach-Object { Write-Host "  - $($_.Name)" }
        Write-Host ""
        
        $confirm = Read-Host "Proceed with removal? (yes/no)"
        if ($confirm -eq 'yes') {
            foreach ($item in $selected) {
                try {
                    Write-Color 'Info' "Removing: $($item.Name)... " -NoNewline
                    Get-AppxPackage -Name "*$($item.Package)*" -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
                    Get-AppxPackage -Name "*$($item.Package)*" -AllUsers -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {$_.PackageName -like "*$($item.Package)*"} | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
                    Write-Color 'Success' "Done"
                } catch {
                    Write-Color 'Warning' "Failed"
                }
            }
            Write-Host ""
            Read-Host "Press Enter to continue"
        }
    }
}

function Show-FeatureSelection {
    param([string]$Category, [array]$Items)
    
    Clear-Host
    Write-Header "Select Items to Remove - $Category"
    
    $index = 1
    $menu = @{}
    
    foreach ($item in $Items) {
        # Check if feature is currently enabled
        $status = "?"
        try {
            $featureState = Get-WindowsOptionalFeature -Online -FeatureName $item.Feature -ErrorAction SilentlyContinue
            if ($featureState.State -eq 'Enabled') {
                $status = "Enabled"
                Write-Host "[$index] $($item.Name) " -NoNewline
                Write-Host "($status)" -ForegroundColor Green
            } else {
                $status = "Disabled"
                Write-Host "[$index] $($item.Name) " -NoNewline
                Write-Host "($status)" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "[$index] $($item.Name) (Unknown)"
        }
        $menu[$index.ToString()] = $item
        $index++
    }
    
    Write-Host ""
    Write-Color 'Info' "[A] Select All Enabled | [X] Execute Removal | [B] Back"
    Write-Host ""
    
    $choice = Read-Host "Select items (comma-separated numbers, or A for all enabled)"
    
    if ($choice -eq 'B' -or $choice -eq 'b') { return }
    
    $selected = @()
    
    if ($choice -eq 'A' -or $choice -eq 'a') {
        # Only select enabled features
        foreach ($item in $Items) {
            try {
                $featureState = Get-WindowsOptionalFeature -Online -FeatureName $item.Feature -ErrorAction SilentlyContinue
                if ($featureState.State -eq 'Enabled') {
                    $selected += $item
                }
            } catch {}
        }
    } else {
        $choices = $choice -split ','
        foreach ($sel in $choices) {
            $sel = $sel.Trim()
            if ($menu.ContainsKey($sel)) {
                $selected += $menu[$sel]
            }
        }
    }
    
    if ($selected.Count -gt 0) {
        Write-Host ""
        Write-Color 'Warning' "Selected $($selected.Count) feature(s) for removal:"
        $selected | ForEach-Object { Write-Host "  - $($_.Name)" }
        Write-Host ""
        Write-Color 'Warning' "NOTE: Some features may require a restart after removal."
        Write-Host ""
        
        $confirm = Read-Host "Proceed with removal? (yes/no)"
        if ($confirm -eq 'yes') {
            foreach ($item in $selected) {
                try {
                    Write-Color 'Info' "Disabling: $($item.Name)... " -NoNewline
                    Disable-WindowsOptionalFeature -Online -FeatureName $item.Feature -NoRestart -ErrorAction SilentlyContinue | Out-Null
                    Write-Color 'Success' "Done"
                } catch {
                    Write-Color 'Warning' "Failed"
                }
            }
            Write-Host ""
            Write-Color 'Info' "A restart may be required to complete feature removal."
            Read-Host "Press Enter to continue"
        }
    }
}

# ===========================================================================================
# SECTION 7: MAIN EXECUTION
# ===========================================================================================

function Main {
    # Validation
    if (-not (Test-AdminRights)) {
        Write-Color 'Error' "Administrator privileges required"
        exit 1
    }
    
    $osType = Get-OSInfo
    Write-Color 'Success' "[OK] Detected: $osType (Build $($Global:OSBuild))"
    
    # Load tweak data once into global scope
    $Global:TweakData = Import-TweakData
    Write-Color 'Success' "[OK] Loaded tweak database"
    Start-Sleep -Seconds 1
    
    # Main loop
    do {
        $choice = Show-MainMenu
        
        switch ($choice) {
            '1' { Show-CategoryMenu -CategoryName "Privacy & Security" -Tweaks $Global:TweakData.Privacy }
            '2' { Show-CategoryMenu -CategoryName "Performance & Gaming" -Tweaks $Global:TweakData.Performance }
            '3' { Show-CategoryMenu -CategoryName "Power Management" -Tweaks $Global:TweakData.Power }
            '4' { Show-CategoryMenu -CategoryName "UI Customization" -Tweaks $Global:TweakData.UI }
            '5' { Show-CategoryMenu -CategoryName "System Services" -Tweaks $Global:TweakData.Services }
            '6' { Show-CategoryMenu -CategoryName "Windows Updates" -Tweaks $Global:TweakData.Updates }
            '7' { Show-CategoryMenu -CategoryName "Notifications & Sound" -Tweaks $Global:TweakData.Notifications }
            '8' { Show-BloatwareMenu }
            '9' { Show-ReviewMenu }
            { $_ -eq 'A' -or $_ -eq 'a' } {
                if ($Global:SelectedTweaks.Count -eq 0) {
                    Write-Color 'Warning' "No tweaks selected"
                    Start-Sleep -Seconds 2
                } else {
                    Clear-Host
                    Write-Header "Confirm Application"
                    Write-Color 'Warning' "About to apply $($Global:SelectedTweaks.Count) tweaks"
                    Write-Color 'Info' "A restore point will be created first"
                    Write-Host ""
                    
                    $confirm = Read-Host "Type 'YES' to proceed"
                    if ($confirm -eq 'YES') {
                        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
                        New-RestorePoint -Description "HamTweak $timestamp ($($Global:SelectedTweaks.Count) tweaks)"
                        
                        Invoke-AllTweaks
                        
                        $restart = Read-Host "Restart now? (yes/no)"
                        if ($restart -eq 'yes' -or $restart -eq 'YES') {
                            Restart-Computer -Force
                        }
                        
                        exit 0
                    }
                }
            }
            { $_ -eq 'C' -or $_ -eq 'c' } {
                $Global:SelectedTweaks = @()
                Write-Color 'Success' "All selections cleared"
                Start-Sleep -Seconds 1
            }
            '0' {
                Write-Color 'Info' "Exiting without changes"
                exit 0
            }
        }
    } while ($true)
}

# Execute
Main
