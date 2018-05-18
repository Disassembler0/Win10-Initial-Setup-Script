#requires -RunAsAdministrator
[cmdletbinding(DefaultParametersetName="Preset")]
param(
[ValidateSet("Host","Log","Pipe")]$RedirectOutput = "Pipe",
[Parameter(ParameterSetName='Preset')]$PresetFile,
[Parameter(ParameterSetName='Input')][string[]]$Tweaks,
[switch]$WaitForKey,
[switch]$RestartComputer
)
<#
.SYNOPSIS
    .
.DESCRIPTION
    .
.PARAMETER PresetFile
    The file with tweaks to apply
	Create CSV file with Name of Function in first column and option(s) in 2nd column
.PARAMETER PresetFile
	array of tweaks parsed inline as parameter
.PARAMETER RedirectOutput
    Different output options:
		Host writes output (immediately) to host
		Log saves output to log file in temp folder
		Pipe returns all output at end of script to the pipeline
.EXAMPLE
    C:\PS>
    <Description of example>
.NOTES
    Author: Chris Kenis
    Date:   13 december 2017
#>
# Win10 / WinServer2016 Initial Setup Script
# Version: v3.0, 2017-12-13
# Source: https://github.com/ChrisKenis/POSH

process{
foreach ($Tweak in $Tweaks){
	if ($Functions -contains $Tweak){ Invoke-Expression $Tweak }
	else { Out-put "Failed to find $($Tweak) in script functions" }
	}
if ($WaitForKey) {
	Write-Host
	Write-Host "Press any key to continue..." -ForegroundColor Black -BackgroundColor White
	[Console]::ReadKey($true) | Out-Null
	}
if ($RestartComputer){ Restart-Computer }
}

begin{

# Default preset
$Functions = @(
"Set-Telemetry",
"Set-WiFiSense",
"Set-SmartScreen",
"Set-WebSearch",
"Set-AppSuggestions",
"Set-ActivityHistory",
"Set-StartSuggestions",
"Set-BackgroundApps",
"Set-LockScreenSpotlight",
"Set-LocationTracking",
"Set-MapUpdates",
"Set-Feedback",
"Set-TailoredExperiences",
"Set-AdvertisingID",
"Set-WebLangList",
"Set-Cortana",
"Set-ErrorReporting",
"Set-P2PUpdate",
"Set-AutoLogger",
"Set-DiagTrack",
"Set-WAPPush",
"Set-UAClevel",
"Set-SharingMappedDrives",
"Set-AdminShares",
"Set-SMBv1",
"Set-SMBServer",
"Set-LLMNR",
"Set-CurrentNetworkProfile",
"Set-UnknownNetworkProfile",
"Set-NetDevicesAutoInst",
"Set-FolderAccessControl",
"Set-Firewall",
"Set-WindowsDefender",
"Set-WindowsDefenderCloud",
"Set-F8BootMenu",
"Set-DEPOption",
"Set-CIMemoryIntegrity",
"Set-DotNetStrongCrypto",
"Set-ScriptHost",
"Set-MeltdownCompatFlag",
"Set-UpdateMSRT",
"Set-UpdateDrivers",
"Set-UpdateRestart",
"Set-HomeGroupServices",
"Set-SharedExperiences",
"Set-RemoteAssistance",
"Set-RemoteDesktop",
"Set-AutoPlay",
"Set-AutoRun",
"Set-StorageSense",
"Set-Defragmentation",
"Set-SuperFetch",
"Set-Indexing",
"Set-BIOSTimeZone",
"Set-Hibernation",
"Set-SleepButton",
"Set-SleepTimeout",
"Set-FastStartUp",
"Set-ActionCenter",
"Set-AccountProtectionWarning",
"Set-LockScreen",
"Set-LockScreenRS1",
"Set-LockScreenNetworkConnection",
"Set-LockScreenShutdownMenu",
"Set-StickyKeys",
"Set-TaskManagerDetails",
"Set-FileOperationsDetails",
"Set-FileDeleteConfirm",
"Set-TaskbarSearchOption",
"Set-TaskViewButton",
"Set-TaskbarIconSize",
"Set-TaskbarCombineTitles",
"Set-TaskbarPeopleIcon",
"Set-TrayIcons",
"Set-DisplayKnownExtensions",
"Set-ShowHiddenFiles",
"SelectCheckboxes",
"Set-ShowSyncNotifications",
"Set-ShowRecentShortcuts",
"Set-SetExplorerDefaultView",
"Set-ThisPCIconOnDesktop",
"Set-ShowUserFolderOnDesktop",
"Set-DesktopInThisPC",
"Set-DesktopIconInExplorer",
"Set-DocumentsIconInExplorer",
"Set-DocumentsIconInThisPC",
"Set-DownloadsIconInThisPC",
"Set-DownloadsIconInExplorer",
"Set-MusicIconInThisPC",
"Set-MusicIconInExplorer",
"Set-PicturesIconInThisPC",
"Set-PicturesIconInExplorer",
"Set-VideosIconInThisPC",
"Set-VideosIconInExplorer",
"Set-3DObjectsInThisPC",
"Set-3DObjectsInExplorer",
"Set-VisualFX",
"Set-ShowThumbnails",
"Set-LocalThumbnailsDB",
"Set-NetworkThumbnailsDB",
"Set-KeyboardLayout",
"Set-Numlock",
"Set-OneDriveStartUp",
"Set-OneDriveProvisioning",
"Set-ProvisionedPackages",
"Set-Provisioned3PartyPackages",
"Set-WindowsStoreProvisioning",
"Set-ConsumerApps",
"Set-XboxFeature",
"Set-AdobeFlash",
"Set-WindowsFeature",
"Set-MediaPlayerFeature",
"Set-PDFprinter",
"Set-Faxprinter",
"Set-XPSprinter",
"Set-InternetExplorerFeature",
"Set-WorkFoldersFeature",
"Set-LinuxSubsystemFeature",
"Set-HyperVFeature",
"Set-EdgeShortcutCreation",
"Set-PhotoViewerAssociation",
"Set-PhotoViewerOpenWith",
"Set-SearchAppInStore",
"Set-NewAppPrompt",
"Set-ControlPanelView",
"Set-DEP",
"Set-ServerManagerOnLogin",
"Set-ShutdownTracker",
"Set-PasswordPolicy",
"Set-CtrlAltDelLogin",
"Set-IEEnhancedSecurity",
"Set-Audio"
)

# Load function names from command line arguments or a preset file
switch ($PsCmdlet.ParameterSetName){
	"Preset" { $Tweaks = Get-Content $PresetFile }
	"Input" { continue }
	default { $Tweaks = Out-GridView $Functions -title "Select settings" -PassThru }
	}
#buffering array for output at end of script
$script:output = @()

#Script Functions
if ($RedirectOutput -eq "Log"){
	$script:LogFilePath = New-TemporaryFile
	Write-Output "results will be saved to $($script:LogFilePath)"
	#$stream = [System.IO.StreamWriter] $script:LogFilePath.FullName
	}

#output depending on global -RedirectOutput parameter
Function Out-put ( $InString ) {
Write-Verbose $InString
switch ($RedirectOutput){
	"Host" {Write-Host $InString}
	"Log" {Out-File $script:LogFilePath $InString -Append}
	"Pipe" {$script:Output += $InString}
	}
}

# Generic Set-Remove Single RegKey Function
Function Set-SingleRegKey {
param(
[Parameter(Mandatory = $true)]$Status,
[string]$Description = "Generic Single Regkey Function",
[Parameter(Mandatory = $true)]$RegPath,
[Parameter(Mandatory = $true)]$RegKey,
[Parameter(Mandatory = $true)]
[ValidateSet("DWord","String")]$RegType,
[Parameter(Mandatory = $false)]$RegVal = "",
[switch]$RemoveRegKey = $false
)
if ($RemoveRegKey){
	try{
		Remove-ItemProperty -Path $RegPath -Name $RegKey -EA SilentlyContinue
		Out-put "Removing $($Description) registry setting(s)"
		}
	catch { Out-put "Failed to remove setting(s) in $($RegPath) $($RegKey)"}
	}
else {
	try{
		Out-put "setting $($Description) to $($Status)"
		If (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
		Set-ItemProperty -Path $RegPath -Name $RegKey -Type $RegType -Value $RegVal
		Out-put "set value in $($RegPath) $($RegKey) to $($RegVal)"
		}
	catch { Out-put "could not set value of $($RegVal) in $($RegPath) $($RegKey)"}
	}
}#Set-SingleRegKey

#Tweak Functions

Function Set-Telemetry {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Telemetry"
$RegPaths = @(
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
)
$RegKey = @("AllowTelemetry")
Out-put "setting $($Description) to $($Status)"
switch ($Status){
	"Enabled"{$RegVal = 3}
	"Disabled" {$RegVal = 0}
	}
foreach ($RegPath in $RegPaths){
	try {
		If (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
		Set-ItemProperty -Path $RegPath -Name $RegKey[0] -Type DWord -Value $RegVal
		}
	catch { Out-put "could not set $($Description) to $($Status)" }
	}
}#Set-Telemetry

Function Set-WiFiSense {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "WiFi Auto Sense"
$RegPaths = @(
"HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting",
"HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
)
$RegKeys = @("AllowTelemetry")
switch ($Status){
	"Enabled"{$RegVal = 1}
	"Disabled" {$RegVal = 0}
	}
Out-put "setting $($Description) to $($Status)"
foreach ($RegPath in $RegPaths){
	try {
		If (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
		Set-ItemProperty -Path $RegPath -Name $RegKeys[0] -Type DWord -Value $RegVal
		}
	catch { Out-put "could not set $($Description) to $($Status)" }
	}
}#Set-WiFiSense

Function Set-SmartScreen {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Edge SmartScreen and Phishing filter"
$edge = (Get-AppxPackage -AllUsers "Microsoft.MicrosoftEdge").PackageFamilyName
$RegPaths = @(
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost",
"HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter"
)
$RegKey = @(
"SmartScreenEnabled",
"EnableWebContentEvaluation",
"EnabledV9",
"PreventOverride"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKey[0] -Type String -Value "RequireAdmin"
			Remove-ItemProperty -Path $RegPaths[1] -Name $RegKey[1] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[2] -Name $RegKey[2] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[2] -Name $RegKey[3] -ErrorAction SilentlyContinue
			}
		"Disabled" {
			$RegVal = 0
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKey[0] -Type String -Value "Off"
			Set-ItemProperty -Path $RegPaths[1] -Name $RegKey[1] -Type DWord -Value $RegVal
			If (!(Test-Path -Path $RegPaths[2] )) { New-Item -Path $RegPaths[2] -Force | Out-Null }
			Set-ItemProperty -Path $RegPaths[2] -Name $RegKey[2] -Type DWord -Value $RegVal
			Set-ItemProperty -Path $RegPaths[2] -Name $RegKey[3] -Type DWord -Value $RegVal
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)" }
}#Set-SmartScreen

Function Set-WebSearch {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Bing Search in Start Menu"
$RegPaths = @(
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
)
$RegKey = @(
"BingSearchEnabled",
"DisableWebSearch"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKey[0] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[1] -Name $RegKey[1] -ErrorAction SilentlyContinue
			}
		"Disabled" {
			$RegVal = 0
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKey[0] -Type Dword -Value $RegVal
			If (!(Test-Path -Path $RegPaths[1] )) { New-Item -Path $RegPaths[1] -Force | Out-Null }
			Set-ItemProperty -Path $RegPaths[1] -Name $RegKey[1] -Type DWord -Value $RegVal
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)" }
}#Set-WebSearch

Function Set-AppSuggestions {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Application Suggestions and Automatic Installation"
$RegPaths = @(
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
)
$RegKeys = @(
"ContentDeliveryAllowed",
"OemPreInstalledAppsEnabled",
"PreInstalledAppsEnabled",
"PreInstalledAppsEverEnabled",
"SilentInstalledAppsEnabled",
"SubscribedContent-338389Enabled",
"SystemPaneSuggestionsEnabled",
"SubscribedContent-338388Enabled",
"DisableWindowsConsumerFeatures"
)
Out-put "setting $($Description) to $($Status)"
try{
	switch ($Status){
		"Disabled" {
			$RegVal = 0 
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[7] -Type DWord -Value $RegVal
			If (!(Test-Path $RegPaths[1])) { New-Item -Path $RegPaths[1] -Force | Out-Null }
			Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[8] -Type DWord -Value $RegVals[1]
			}
		"Enabled"{
			$RegVal = 1
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[7] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[1] -Name $RegKeys[8] -ErrorAction SilentlyContinue
			}
		}
	foreach ($RegKey in $RegKeys[0..6]){ Set-ItemProperty -Path $RegPaths[0] -Name $RegKey -Type DWord -Value $RegVal }
	}
catch { Out-put "could not set $($Description) to $($Status)" }
}#Set-AppSuggestions

Function Set-ActivityHistory {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Activity History"
$RegPaths = @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")
$RegKeys = @(
"EnableActivityFeed",
"PublishUserActivities",
"UploadUserActivities"
)
Out-put "setting $($Description) to $($Status)"
try{
	switch ($Status){
		"Disabled" {
			$RegVal = 0 
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -Type DWord -Value $RegVal
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[2] -Type DWord -Value $RegVal
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[3] -Type DWord -Value $RegVal
			}
		"Enabled"{
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[2] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[3] -ErrorAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)" }
}

Function Set-StartSuggestions {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Start Menu Suggestions"
$RegPaths = @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")
$RegKeys = @(
"SystemPaneSuggestionsEnabled",
"SilentInstalledAppsEnabled"
)
Out-put "setting $($Description) to $($Status)"
switch ($Status){
	"Enabled"{$RegVal = 1}
	"Disabled" {$RegVal = 0}
	}
try {
	If (!(Test-Path $RegPaths[0])) { New-Item -Path $RegPaths[0] -Force | Out-Null }
	foreach ($RegKey in $RegKeys){ Set-ItemProperty -Path $RegPaths[0] -Name $RegKey -Type DWord -Value $RegVal	}
	}
catch { Out-put "could not set $($RegPaths[0]) to $($Status)" }
}#Set-StartSuggestions

# Disable Background application access - ie. if apps can download or update even when they aren't used
Function Set-BackgroundApps {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Background application access policy"
$RegPaths = @(Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")
$RegKeys = @(
"Disabled",
"DisabledByUser"
)
Out-put "setting $($Description) to $($Status)"
try{
	switch ($Status){
		"Enabled"{
			foreach ($RegPath in $RegPaths){
				foreach ($RegKey in $RegKeys){ 
					Remove-ItemProperty -Path $RegPath -Name $RegKey -ErrorAction SilentlyContinue 
					}
				}
			}
		"Disabled" {
			$RegVal = 1
			foreach ($RegPath in $RegPaths){
				foreach ($RegKey in $RegKeys){ 
					Set-ItemProperty -Path $RegPath -Name $RegKey -Type DWord -Value $RegVal
					}
				}
			}
		}
	}
catch { Out-put "could not set $($RegPaths[0]) to $($Status)" }
}#Set-BackgroundApps

# Set LockScreen Advertising
Function Set-LockScreenSpotlight {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Background application access policy"
$RegPaths = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")
$RegKeys = @(
"RotatingLockScreenEnabled",
"RotatingLockScreenOverlayEnabled",
"SubscribedContent-338387Enabled"
)
Out-put "setting $($Description) to $($Status)"
try{
	switch ($Status){
		"Enabled"{
			$RegVal = 1
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value $RegVal
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -Type DWord -Value $RegVal
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[2] -ErrorAction SilentlyContinue
			}
		"Disabled" {
			$RegVal = 0		
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value $RegVal
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -Type DWord -Value $RegVal
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[2] -Type DWord -Value $RegVal
			}
		}
	}
catch { Out-put "could not set $($RegPaths[0]) to $($Status)" }
}#Set-LockScreenSpotlight

Function Set-LocationTracking {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Location Tracking"
$RegPaths = @(
"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}",
"HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
)
$RegKeys = @(
"SensorPermissionState",
"Status"
)
switch ($Status){
	"Enabled"{$RegVal = 1}
	"Disabled" {$RegVal = 0}
	}
Out-put "setting $($Description) to $($Status)"
foreach ($RegPath in $RegPaths){
	foreach ($RegKey in $RegKeys){
		try { Set-ItemProperty -Path $RegPath -Name $RegKey -Type DWord -Value $RegVal }
		catch { Out-put "could not set $($RegPath) $($RegKey) to $($Status)"}
		}
	}
}#Set-LocationTracking

Function Set-MapUpdates {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $True }
	"Disabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Automatic Map Updates"
RegPath = "HKLM:\SYSTEM\Maps"
RegKey = "AutoUpdateEnabled"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-MapUpdates

Function Set-Feedback {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $True }
	"Disabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Feedback"
RegPath = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"
RegKey = "NumberOfSIUFInPeriod"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-Feedback

Function Set-TailoredExperiences {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $True }
	"Disabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Tailored Experiences"
RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
RegKey = "DisableTailoredExperiencesWithDiagnosticData"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}

Function Set-AdvertisingID {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $True }
	"Disabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Advertising ID"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
RegKey = "Enabled"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-AdvertisingID

#Let websites provide locally relevant content by accessing my language list
Function Set-WebLangList {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $True }
	"Disabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Advertising ID"
RegPath = "HKCU:\Control Panel\International\User Profile"
RegKey = "HttpAcceptLanguageOptOut"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}

Function Set-Cortana {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Cortana preferences"
$RegPaths = @(
"HKCU:\SOFTWARE\Microsoft\Personalization\Settings",
"HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore",
"HKCU:\SOFTWARE\Microsoft\InputPersonalization",
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
)
$RegKey = @(
"AcceptedPrivacyPolicy",
"RestrictImplicitTextCollection",
"RestrictImplicitInkCollection",
"HarvestContacts",
"AllowCortana",
"EnableWebContentEvaluation"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKey[0] -ErrorAction SilentlyContinue
			If (!(Test-Path -Path $RegPaths[2] )) { New-Item -Path $RegPaths[2] -Force | Out-Null }
			Set-ItemProperty -Path $RegPaths[2] -Name $RegKey[1] -Type DWord -Value 0
			Set-ItemProperty -Path $RegPaths[2] -Name $RegKey[2] -Type DWord -Value 0
			Remove-ItemProperty -Path $RegPaths[1] -Name $RegKey[3] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[3] -Name $RegKey[5] -ErrorAction SilentlyContinue
			}
		"Disabled" {
			foreach ($RegPath in $RegPaths){ If (!(Test-Path -Path $RegPath )) { New-Item -Path $RegPath -Force | Out-Null } }
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKey[0] -Type Dword -Value 0
			Set-ItemProperty -Path $RegPaths[1] -Name $RegKey[3] -Type DWord -Value 0
			Set-ItemProperty -Path $RegPaths[2] -Name $RegKey[1] -Type DWord -Value 1
			Set-ItemProperty -Path $RegPaths[2] -Name $RegKey[2] -Type DWord -Value 1
			Set-ItemProperty -Path $RegPaths[3] -Name $RegKey[4] -Type DWord -Value 0
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-Cortana

Function Set-ErrorReporting {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $True }
	"Disabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Error Reporting"
RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"
RegKey = "Disabled"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-ErrorReporting

Function Set-P2PUpdate {
param(
[ValidateSet("Local","Internet")]$Status
)
$Description = "P2P Updating Policy"
$RegPaths = @(
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config",
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization"
)
$RegKeys = @(
"DODownloadMode",
"SystemSettingsDownloadMode"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Local"{
			foreach ($RegPath in $RegPaths){ If (!(Test-Path -Path $RegPath )) { New-Item -Path $RegPath -Force | Out-Null } }
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 1
			Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[1] -Type DWord -Value 3
			}
		"Internet" {
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[1] -Name $RegKeys[1] -ErrorAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-P2PUpdate

Function Set-AutoLogger {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "AutoLogger log folder and file"
$LogPaths = @("$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger")
$LogFiles = @("AutoLogger-Diagtrack-Listener.etl")
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{
			icacls $LogPaths[0] /grant:r SYSTEM:`(OI`)`(CI`)F | Out-Null
			}
		"Disabled" {
			Remove-Item -Path $LogPaths[0] -Filter $LogFiles[0] -Force
			icacls $LogPaths[0] /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-AutoLogger

Function Set-DiagTrack {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Diagnostic Tracking Service"
$Services = @("DiagTrack")
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{
			Set-Service $Services[0] -StartupType Automatic
			Start-Service $Services[0] -WarningAction SilentlyContinue
			}
		"Disabled" {
			Stop-Service $Services[0] -WarningAction SilentlyContinue
			Set-Service $Services[0] -StartupType Disabled
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-DiagTrack

Function Set-WAPPush {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "WAP Push Service"
$Services = @("dmwappushservice")
$RegPaths = @("HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice")
$RegKeys = @("DelayedAutoStart")
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{
			Set-Service $Services[0] -StartupType Automatic
			Start-Service $Services[0] -WarningAction SilentlyContinue
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 1
			}
		"Disabled" {
			Stop-Service $Services[0] -WarningAction SilentlyContinue
			Set-Service $Services[0] -StartupType Disabled
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-WAPPush

########### Service Tweaks ##########

# Lower UAC level (disabling it completely would break apps)
Function Set-UAClevel {
param(
[ValidateSet("Low","High")]$Status
)
$Description = "UAC level"
$RegPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
$RegKeys = @(
"ConsentPromptBehaviorAdmin",
"PromptOnSecureDesktop"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Low"{
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 0
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -Type DWord -Value 0
			}
		"High" {
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 5
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -Type DWord -Value 1
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-UAClevel

# Allow sharing mapped drives between users
Function Set-SharingMappedDrives {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RemoveRegKey = $True }
	"Enabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Sharing Mapped Drives"
RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
RegKey = "EnableLinkedConnections"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-SharingMappedDrives

# Create Adminstrative shares on startup
Function Set-AdminShares {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $True }
	"Disabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Admin Shares"
RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
RegKey = "AutoShareWks"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-AdminShares

# Disable obsolete SMB 1.0 protocol
Function Set-SMBv1 {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "SMB v1"
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{ Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force }
		"Disabled" { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force }
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-SMBv1

Function Set-SMBServer {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "SMB Server"
try {
	switch ($Status){
		"Enabled"{ Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force }
		"Disabled" { 
			Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
			Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}

Function Set-LLMNR {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $True }
	"Disabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Link-Local Multicast Name Resolution (LLMNR) protocol"
RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
RegKey = "EnableMulticast"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}

Function Set-CurrentNetworkProfile {
param(
[ValidateSet("Private","Public")]$Status
)
$Description = "Current Network profile"
Out-put "setting $($Description) to $($Status)"
try { Set-NetConnectionProfile -NetworkCategory $Status }
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-CurrentNetworkProfile

Function Set-UnknownNetworkProfile {
param(
[ValidateSet("Private","Public")]$Status
)
switch ($Status){
	"Public"{ $RemoveRegKey = $True }
	"Private" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Unknown Network profile"
RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24"
RegKey = "Category"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-UnknownNetworkProfile

Function Set-NetDevicesAutoInst {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $True }
	"Disabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Automatic installation of network devices"
RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private"
RegKey = "AutoSetup"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}

# Controlled Folder Access (Defender Exploit Guard feature) - Not applicable to Server
Function Set-FolderAccessControl {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Controlled Folder Access"
Out-put "setting $($Description) to $($Status)"
try { Set-MpPreference -EnableControlledFolderAccess $Status }
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-FolderAccessControl

Function Set-Firewall {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $True }
	"Disabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Windows Firewall"
RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
RegKey = "EnableFirewall"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-Firewall

Function Set-WindowsDefender {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Windows Defender"
$RegPaths = @(
"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)
$RegKeys = @(
"DisableAntiSpyware",
"SecurityHealth",
"WindowsDefender"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{
			If (!(Test-Path -Path $RegPaths[0] )) { New-Item -Path $RegPaths[0] -Force | Out-Null }
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 1
			If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
				Remove-ItemProperty -Path $RegPaths[1] -Name $RegKeys[2] -ErrorAction SilentlyContinue
				}
			ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
				Remove-ItemProperty -Path $RegPaths[1] -Name $RegKeys[1] -ErrorAction SilentlyContinue
				}
			}
		"Enabled" {
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue
			If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
				Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[2] -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
				}
			ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
				Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[1] -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
				}
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-WindowsDefender

Function Set-WindowsDefenderCloud {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Windows Defender Cloud"
$RegPaths = @( "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" )
$RegKeys = @(
"SpynetReporting",
"SubmitSamplesConsent"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{
			If (!(Test-Path -Path $RegPaths[0] )) { New-Item -Path $RegPaths[0] -Force | Out-Null }
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 0
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -Type DWord -Value 2
			}
		"Enabled" {
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -ErrorAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-WindowsDefenderCloud

Function Set-F8BootMenu {
param(
[ValidateSet("Legacy","Standard")]$Status
)
$Description = "F8 boot menu options"
Out-put "setting $($Description) to $($Status)"
try { bcdedit /set `{current`} bootmenupolicy $Status | Out-Null }
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-F8BootMenu

# Set Data Execution Prevention (DEP) policy to OptOut
Function Set-DEPOption {
param(
[ValidateSet("OpIn","OptOut")]$Status
)
$Description = "Data Execution Prevention"
bcdedit /set `{current`} nx $Status | Out-Null
Out-put "setting $($Description) to $($Status)"
}

Function Set-CIMemoryIntegrity {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RemoveRegKey = $True }
	"Enabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Core Isolation Memory Integrity"
RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
RegKey = "Enabled"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
#supported on Win10 v1803 or greater
if ([System.Environment]::OSVersion.Version.Build -lt 17134) {
	Out-Put "$($SingleRegKeyProps["Description"]) not supported on current OS version"
	}
else { Set-SingleRegKey @SingleRegKeyProps }
}

# Enable strong cryptography for .NET Framework (version 4 and above)
# https://stackoverflow.com/questions/36265534/invoke-webrequest-ssl-fails
Function Set-DotNetStrongCrypto {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = ".NET strong cryptography"
$RegPaths = @("HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319","HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319")
$RegKeys = @( "SchUseStrongCrypto" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 1
			Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[0] -Type DWord -Value 1
			}
		"Disabled" {
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[1] -Name $RegKeys[0] -ErrorAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-DotNetStrongCrypto

Function Set-ScriptHost {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $True }
	"Disabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Windows Script Host"
RegPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
RegKey = "Enabled"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}

# Enable Meltdown (CVE-2017-5754) compatibility flag - Required for January 2018 and all subsequent Windows updates
# This flag is normally automatically enabled by compatible antivirus software (such as Windows Defender).
# Use the tweak only if you have confirmed that your AV is compatible but unable to set the flag automatically or if you don't use any AV at all.
# See https://support.microsoft.com/en-us/help/4072699/january-3-2018-windows-security-updates-and-antivirus-software for details.
Function Set-MeltdownCompatFlag {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RemoveRegKey = $True }
	"Enabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Meltdown (CVE-2017-5754) compatibility flag"
RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat"
RegKey = "cadca5fe-87d3-4b96-b7fb-a231484277cc"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}

Function Set-UpdateMSRT {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $True }
	"Disabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Malicious Software Removal Tool Update"
RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\MRT"
RegKey = "DontOfferThroughWUAU"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-UpdateMSRT

# Disable offering of drivers through Windows Update
Function Set-UpdateDrivers {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Windows Update Drivers"
$RegPaths = @(
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching",
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"
)
$RegKeys = @(
"ExcludeWUDriversInQualityUpdate",
"PreventDeviceMetadataFromNetwork",
"DontPromptForWindowsUpdate",
"DontSearchWindowsUpdate",
"DriverUpdateWizardWuSearchEnabled"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{
			If (!(Test-Path -Path $RegPaths[0] )) { New-Item -Path $RegPaths[0] -Force | Out-Null }
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[2] -Type DWord -Value 1
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[3] -Type DWord -Value 1
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[4] -Type DWord -Value 0
			If (!(Test-Path -Path $RegPaths[1] )) { New-Item -Path $RegPaths[1] -Force | Out-Null }
			Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[0] -Type DWord -Value 1
			If (!(Test-Path -Path $RegPaths[2] )) { New-Item -Path $RegPaths[2] -Force | Out-Null }
			Set-ItemProperty -Path $RegPaths[2] -Name $RegKeys[1] -Type DWord -Value 1
			}
		"Enabled" {
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[2] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[3] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[4] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[1] -Name $RegKeys[0] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[2] -Name $RegKeys[1] -ErrorAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-UpdateDrivers

Function Set-UpdateRestart {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Windows Update Restart"
$RegPaths = @( "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" )
$RegKeys = @(
"NoAutoRebootWithLoggedOnUsers",
"AUPowerManagement"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{
			If (!(Test-Path -Path $RegPaths[0] )) { New-Item -Path $RegPaths[0] -Force | Out-Null }
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 1
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -Type DWord -Value 0
			}
		"Enabled" {
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -ErrorAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-UpdateRestart

# Stop and disable Home Groups services - Not applicable to Server
Function Set-HomeGroupServices {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Home Group Services"
$Services = @(
"HomeGroupListener",
"HomeGroupProvider"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{
			foreach ($Service in $Services){ Set-Service $Service -StartupType Manual }
			Start-Service $Services[1] -WarningAction SilentlyContinue
			}
		"Disabled" {
			foreach ($Service in $Services){
				Stop-Service $Service -WarningAction SilentlyContinue
				Set-Service $Service -StartupType Disabled
				}
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-HomeGroupServices

Function Set-SharedExperiences {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Shared Experiences"
$RegPaths = @( "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" )
$RegKeys = @(
"EnableCdp",
"EnableMmx"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 0
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -Type DWord -Value 0
			}
		"Enabled" {
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -ErrorAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-SharedExperiences

Function Set-RemoteAssistance {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RegVal = 1 }
	"Disabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Remote Assistance"
RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
RegKey = "fAllowToGetHelp"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-RemoteAssistance

Function Set-RemoteDesktop {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Authenticated Remote Desktop"
$RegPaths = @(
"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server",
"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
)
$RegKeys = @(
"fDenyTSConnections",
"UserAuthentication"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{ $RegVal = 0 }
		"Enabled" { $RegVal = 1 }
		}
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value $RegVal
	Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[1] -Type DWord -Value $RegVal
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-RemoteDesktop

Function Set-AutoPlay {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RegVal = 0 }
	"Disabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "AutoPlay"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
RegKey = "DisableAutoplay"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-AutoPlay

Function Set-AutoRun {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $true }
	"Disabled" { $RegVal = 255 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "AutoRun on All Drives"
RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
RegKey = "NoDriveTypeAutoRun"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-AutoRun

Function Set-StorageSense {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Automatic Disk Cleanup"
$RegPaths = @( "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" )
$RegKeys = @(
"01",
"04"
"08"
"32"
"StoragePoliciesNotified"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 1
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -Type DWord -Value 1
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[2] -Type DWord -Value 1
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[3] -Type DWord -Value 0
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[4] -Type DWord -Value 1
			}
		"Disabled" {
			Remove-Item -Path $RegPaths[0] -Recurse -ErrorAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-StorageSense

Function Set-Defragmentation {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Scheduled Disk Defragmentation Task"
$TaskNames = @( "\Microsoft\Windows\Defrag\ScheduledDefrag" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{ Disable-ScheduledTask -TaskName $TaskNames[0] | Out-Null }
		"Enabled" {	Enable-ScheduledTask -TaskName $TaskNames[0] | Out-Null }
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-Defragmentation

# Set Superfetch service - Not applicable to Server
Function Set-SuperFetch {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "SuperFetching"
$Services = @( "SysMain" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{
			Set-Service $Services[0] -StartupType Automatic
			Start-Service $Services[0] -WarningAction SilentlyContinue
			}
		"Disabled" {
			Stop-Service $Services[0] -WarningAction SilentlyContinue
			Set-Service $Services[0] -StartupType Disabled
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-SuperFetch

Function Set-Indexing {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Search Indexing Service"
$Services = @("WSearch")
$RegPaths = @("HKLM:\SYSTEM\CurrentControlSet\Services\WSearch")
$RegKeys = @("DelayedAutoStart")
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{
			Set-Service $Services[0] -StartupType Automatic
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 1
			Start-Service $Services[0] -WarningAction SilentlyContinue
			}
		"Disabled" {
			Stop-Service $Services[0] -WarningAction SilentlyContinue
			Set-Service $Services[0] -StartupType Disabled
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-Indexing

Function Set-BIOSTimeZone {
param(
[ValidateSet("UTC","Local")]$Status
)
switch ($Status){
	"UTC"{ $RegVal = 1 }
	"Local" { $RemoveRegKey = $true }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "BIOS Time Zone"
RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
RegKey = "RealTimeIsUniversal"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-BIOSTimeZone

# Enable Hibernation
# Do not use on Server if Hyper-V service set to Automatic
# it may lead to BSODs (Win10 with Hyper-V is fine)
Function Set-Hibernation {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Hibernation"
$RegPaths = @(
"HKLM:\System\CurrentControlSet\Control\Session Manager\Power",
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"
)
$RegKeys = @(
"HibernteEnabled",
"ShowHibernateOption"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{ $RegVal = 0 }
		"Enabled" { $RegVal = 1 }
		}
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value $RegVal
	If (!(Test-Path -Path $RegPaths[1] )) { New-Item -Path $RegPaths[1] -Force | Out-Null }
	Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[1] -Type DWord -Value $RegVal
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-Hibernation

# Disable Sleep start menu and keyboard button
Function Set-SleepButton {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Sleep button action"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" )
$RegKeys = @( "ShowSleepOption" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{ $RegVal = 0	}
		"Enabled" { $RegVal = 1 }
		}
	If (!(Test-Path -Path $RegPaths[0] )) { New-Item -Path $RegPaths[0] -Force | Out-Null }
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value $RegVal
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION $RegVal
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION $RegVal
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}

# Disable display and sleep mode timeouts
Function Set-SleepTimeout {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Sleep Time Out"
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{
				powercfg /X monitor-timeout-ac 0
				powercfg /X monitor-timeout-dc 0
				powercfg /X standby-timeout-ac 0
				powercfg /X standby-timeout-dc 0			
			}
		"Enabled" {
				powercfg /X monitor-timeout-ac 10
				powercfg /X monitor-timeout-dc 5
				powercfg /X standby-timeout-ac 30
				powercfg /X standby-timeout-dc 15
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}

Function Set-FastStartUp {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RegVal = 0 }
	"Enabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Fast Startup"
RegPath = "HKLM:\System\CurrentControlSet\Control\Session Manager\Power"
RegKey = "HiberbootEnabled"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-FastStartUp

########### UI Tweaks ##########

Function Set-ActionCenter {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "ActionCenter"
$RegPaths = @(
"HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications"
)
$RegKeys = @(
"DisableNotificationCenter",
"ToastEnabled"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{
			If (!(Test-Path -Path $RegPaths[0] )) { New-Item -Path $RegPaths[0] -Force | Out-Null }
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 1
			Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[1] -Type DWord -Value 0
			}
		"Enabled" {
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[1] -Name $RegKeys[1] -ErrorAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-ActionCenter

# Hide Account Protection warning in Defender about not using a Microsoft account
Function Set-AccountProtectionWarning {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RegVal = 1 }
	"Enabled" { $RemoveRegKey = $true }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Microsoft Account Protection warning"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows Security Health\State"
RegKey = "AccountProtection_MicrosoftAccount_Disconnected"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}

Function Set-LockScreen {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RegVal = 1 }
	"Enabled" { $RemoveRegKey = $true }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "LockScreen"
RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
RegKey = "NoLockScreen"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-LockScreen

# Lock screen - Applicable to RS1 (1607) or newer
Function Set-LockScreenRS1 {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "LockScreen RS1"
$TaskNames = @("LockScreen Status")
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{
			$service = New-Object -com Schedule.Service
			$service.Connect()
			$task = $service.NewTask(0)
			$task.Settings.DisallowStartIfOnBatteries = $false
			$trigger = $task.Triggers.Create(9)
			$trigger = $task.Triggers.Create(11)
			$trigger.StateChange = 8
			$action = $task.Actions.Create(0)
			$action.Path = "reg.exe"
			$action.Arguments = "add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f"
			$service.GetFolder("\").RegisterTaskDefinition($TaskNames[0], $task, 6, "NT AUTHORITY\SYSTEM", $null, 4) | Out-Null
			}
		"Enabled" {
			Unregister-ScheduledTask -TaskName $TaskNames[0] -Confirm:$false -ErrorAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-LockScreenRS1

Function Set-LockScreenNetworkConnection {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RegVal = 1 }
	"Enabled" { $RemoveRegKey = $true }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Network connection on LockScreen"
RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
RegKey = "DontDisplayNetworkSelectionUI"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-LockScreenNetworkConnection

Function Set-LockScreenShutdownMenu {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RegVal = 0 }
	"Enabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Shutdown Menu on LockScreen"
RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
RegKey = "ShutdownWithoutLogon"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-LockScreenShutdownMenu

Function Set-StickyKeys {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RegVal = "506" }
	"Enabled" { $RegVal = "510" }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Stickey Keys prompt"
RegPath = "HKCU:\Control Panel\Accessibility\StickyKeys"
RegKey = "Flags"
RegType = "String"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-StickyKeys

Function Set-TaskManagerDetails {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Detail view in TaskManager"
$RegPaths = @( "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" )
$RegKeys = @( "Preferences" )
$preferences = New-Object PSObject
Out-put "setting $($Description) to $($Status)"
try {
	If (!(Test-Path -Path $RegPaths[0] )) { New-Item -Path $RegPaths[0] -Force | Out-Null }
	$preferences = Get-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue
	switch ($Status){
		"Enabled"{
			If (!($preferences.Preferences)) {
				$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
				While (!($preferences)) {
					Start-Sleep -m 250
					$preferences = Get-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue
					}
				Stop-Process $taskmgr
				}
			$preferences.Preferences[28] = 0
			}
		"Disabled" {
			If ($preferences.Preferences) { $preferences.Preferences[28] = 1 }
			}
		}
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type Binary -Value $Preferences.Preferences
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-TaskManagerDetails

# Show file operations details
Function Set-FileOperationsDetails {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RemoveRegKey = $true }
	"Enabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Details for File Operations"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"
RegKey = "EnthusiastMode"
RegType = "DWord"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-FileOperationsDetails

Function Set-FileDeleteConfirm {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RemoveRegKey = $true }
	"Enabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Ask Confirmation for File Deletion"
RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
RegKey = "ConfirmFileDelete"
RegType = "DWord"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-FileDeleteConfirm

Function Set-TaskbarSearchOption {
param(
[ValidateSet("Box","Icon","Hidden")]$Status
)
switch ($Status){
	"Box"{ $RegVal = 2 }
	"Icon" { $RegVal = 1 }
	"Hidden" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Searchbox on Taskbar"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
RegKey = "SearchboxTaskbarMode"
RegType = "DWord"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-TaskbarSearchOption

Function Set-TaskViewButton {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $true }
	"Disabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Taskview Button on Taskbar"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
RegKey = "ShowTaskViewButton"
RegType = "DWord"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-TaskViewButton

Function Set-TaskbarIconSize {
param(
[ValidateSet("Small","Large")]$Status
)
switch ($Status){
	"Large"{ $RemoveRegKey = $true }
	"Small" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Small Icons on Taskbar"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
RegKey = "TaskbarSmallIcons"
RegType = "DWord"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-TaskbarIconSize

Function Set-TaskbarCombineTitles {
param(
[ValidateSet("WhenFull","Never","Always")]$Status
)
$Description = "Show Taskbar Titles"
$RegPaths = @( "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" )
$RegKeys = @(
"TaskbarGlomLevel",
"MMTaskbarGlomLevel"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Never"{
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 2
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -Type DWord -Value 2
			}
		"WhenFull"{
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 1
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -Type DWord -Value 1
			}
		"Always" {
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -ErrorAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-TaskbarCombineTitles

Function Set-TaskbarPeopleIcon {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $true }
	"Disabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "People icon on Taskbar"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
RegKey = "PeopleBand"
RegType = "DWord"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-TaskbarPeopleIcon

Function Set-TrayIcons {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RemoveRegKey = $true }
	"Enabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Tray icons on Taskbar"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
RegKey = "EnableAutoTray"
RegType = "DWord"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-TrayIcons

Function Set-DisplayKnownExtensions {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RegVal = 1 }
	"Enabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Display of known extensions"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
RegKey = "HideFileExt"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-DisplayKnownExtensions

Function Set-ShowHiddenFiles {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RegVal = 2 }
	"Enabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Display of hidden files"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
RegKey = "Hidden"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-ShowHiddenFiles

# Hide item selection checkboxes
Function Set-SelectCheckboxes {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RegVal = 2 }
	"Enabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Display of hidden files"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
RegKey = "AutoCheckSelect"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}

Function Set-ShowSyncNotifications {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled"{ $RegVal = 0 }
	"Enabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Synchronization Notifications"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
RegKey = "ShowSyncProviderNotifications"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-ShowSyncNotifications

Function Set-ShowRecentShortcuts {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Shortcuts of Recent files in Computer folder"
$RegPaths = @( "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" )
$RegKeys = @( "ShowRecent","ShowFrequent" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 0
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -Type DWord -Value 0
			}
		"Enabled" {
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -ErrorAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-ShowRecentShortcuts

Function Set-SetExplorerDefaultView {
param(
[ValidateSet("ThisPC","QuickAccess")]$Status
)
switch ($Status){
	"QuickAccess"{ $RemoveRegKey = $true }
	"ThisPC" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Default Explorer view"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
RegKey = "LaunchTo"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-SetExplorerDefaultView

Function Set-ThisPCIconOnDesktop {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "ThisPC Icon On Desktop"
$RegPaths = @(
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu",
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
)
$RegKeys = @( "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{
			foreach ($RegPath in $RegPaths){
				If (!(Test-Path -Path $RegPath )) { New-Item -Path $RegPath -Force | Out-Null }
				Set-ItemProperty -Path $RegPath -Name $RegKeys[0] -Type DWord -Value 0
				}
			}
		"Disabled" {
			foreach ($RegPath in $RegPaths){
				Remove-ItemProperty -Path $RegPath -Name $RegKeys[0] -ErrorAction SilentlyContinue
				}
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-ThisPCIconOnDesktop

Function Set-ShowUserFolderOnDesktop {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "User folder Icon On Desktop"
$RegPaths = @(
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu",
"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
)
$RegKeys = @( "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{
			foreach ($RegPath in $RegPaths){
				If (!(Test-Path -Path $RegPath )) { New-Item -Path $RegPath -Force | Out-Null }
				Set-ItemProperty -Path $RegPath -Name $RegKeys[0] -Type DWord -Value 0
				}
			}
		"Disabled" {
			foreach ($RegPath in $RegPaths){
				Remove-ItemProperty -Path $RegPath -Name $RegKeys[0] -ErrorAction SilentlyContinue
				}
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-ShowUserFolderOnDesktop

Function Set-DesktopInThisPC {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Desktop icon in ThisPC"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{ If (!(Test-Path $RegPaths[0] )) { New-Item -Path $RegPaths[0] | Out-Null } }
		"Disabled" { Remove-Item -Path $RegPaths[0] -Recurse -ErrorAction SilentlyContinue } }
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-DesktopInThisPC

Function Set-DesktopIconInExplorer {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Desktop icon in Explorer Namespace"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag"
)
$RegKeys = @("ThisPCPolicy")

Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled" { $RegVal = "Show" }
		"Disabled" { $RegVal = "Hide" }
		}
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Value "Hide"
	Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[0] -Value "Hide"
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}

Function Set-DocumentsIconInExplorer {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Documents icon in Explorer Namespace"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag"
)
$RegKeys = @("ThisPCPolicy")

Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled" { $RegVal = "Show" }
		"Disabled" { $RegVal = "Hide" }
		}
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Value $RegVal
	Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[0] -Value $RegVal
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-DocumentsIconInExplorer

Function Set-DocumentsIconInThisPC {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Documents Icon in ThisPC"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}",
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{ 
			foreach ($RegPath in $RegPaths){ 
				If (!(Test-Path $RegPath )) { New-Item -Path $RegPath | Out-Null } 
				}
			}
		"Disabled" { 
			foreach ($RegPath in $RegPaths){ 
				Remove-Item -Path $RegPath -Recurse -ErrorAction SilentlyContinue 
				} 
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-DocumentsIconInThisPC

Function Set-DownloadsIconInThisPC {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Downloads Icon in ThisPC"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{ 
			If (!(Test-Path $RegPaths[0] )) { New-Item -Path $RegPaths[0] | Out-Null }
			If (!(Test-Path $RegPaths[1] )) { New-Item -Path $RegPaths[0] | Out-Null }
			}
		"Disabled" {
			Remove-Item -Path $RegPaths[0] -Recurse -ErrorAction SilentlyContinue 
			Remove-Item -Path $RegPaths[1] -Recurse -ErrorAction SilentlyContinue 
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-DownloadsIconInThisPC

Function Set-DownloadsIconInExplorer {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Downloads Icon in Explorer"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" )
$RegKeys = @( "ThisPCPolicy" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled" { $RegVal = "Show" }
		"Disabled" { $RegVal = "Hide" }
		}
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Value $RegVal
	Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[0] -Value $RegVal
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-DownloadsIconInExplorer

Function Set-MusicIconInThisPC {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Music Icon in ThisPC"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{ If (!(Test-Path $RegPaths[0] )) { New-Item -Path $RegPaths[0] | Out-Null } }
		"Disabled" { Remove-Item -Path $RegPaths[0] -Recurse -ErrorAction SilentlyContinue } }
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-MusicIconInThisPC

Function Set-MusicIconInExplorer {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Documents icon in Explorer Namespace"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag"
)
$RegKeys = @("ThisPCPolicy")

Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled" { $RegVal = "Show" }
		"Disabled" { $RegVal = "Hide" }
		}
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Value $RegVal
	Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[0] -Value $RegVal
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-MusicIconInExplorer

# Hide Pictures icon from This PC
Function Set-PicturesIconInThisPC {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Pictures Icon in ThisPC"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"; "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{ 
			If (!(Test-Path $RegPaths[0] )) { New-Item -Path $RegPaths[0] | Out-Null } 
			If (!(Test-Path $RegPaths[1] )) { New-Item -Path $RegPaths[1] | Out-Null } 
			}
		"Disabled" { 
			Remove-Item -Path $RegPaths[0] -Recurse -ErrorAction SilentlyContinue
			Remove-Item -Path $RegPaths[1] -Recurse -ErrorAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-PicturesIconInThisPC

Function Set-PicturesIconInExplorer {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Downloads Icon in Explorer"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" )
$RegKeys = @( "ThisPCPolicy" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled" { $RegVal = "Show" }
		"Disabled" { $RegVal = "Hide" }
		}
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Value $RegVal
	Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[0] -Value $RegVal
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-PicturesIconInExplorer

Function Set-VideosIconInThisPC {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Videos icon in ThisPC"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{ If (!(Test-Path $RegPaths[0] )) { New-Item -Path $RegPaths[0] | Out-Null } }
		"Disabled" { Remove-Item -Path $RegPaths[0] -Recurse -ErrorAction SilentlyContinue } }
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-VideosIconInThisPC

Function Set-VideosIconInExplorer {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Downloads Icon in Explorer"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" )
$RegKeys = @( "ThisPCPolicy" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled" { $RegVal = "Show" }
		"Disabled" { $RegVal = "Hide" }
		}
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Value $RegVal
	Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[0] -Value $RegVal
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-VideosIconInExplorer

Function Set-3DObjectsInThisPC {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "3D icon in ThisPC"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{ If (!(Test-Path $RegPaths[0] )) { New-Item -Path $RegPaths[0] | Out-Null } }
		"Disabled" { Remove-Item -Path $RegPaths[0] -Recurse -ErrorAction SilentlyContinue } }
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-3DObjectsInThisPC

Function Set-3DObjectsInExplorer {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Downloads Icon in Explorer"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" )
$RegKeys = @( "ThisPCPolicy" )
$RegVal = "Hide"
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled" {
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0]
			Remove-ItemProperty -Path $RegPaths[1] -Name $RegKeys[0]
			}
		"Disabled" {
			If (!(Test-Path $RegPaths[0] )) { New-Item -Path $RegPaths[0] }
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Value $RegVal
			If (!(Test-Path $RegPaths[1] )) { New-Item -Path $RegPaths[1] }
			Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[0] -Value $RegVal
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-3DObjectsInExplorer

#-PerFormace disables animations, transparency etc. but leaves font smoothing and miniatures enabled
Function Set-VisualFX {
param(
[ValidateSet("Performance","Quality")]$Status
)
$Description = "Visual FX rendering"
$RegPaths = @(
"HKCU:\Control Panel\Desktop",
"HKCU:\Control Panel\Desktop\WindowMetrics",
"HKCU:\Control Panel\Keyboard",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects",
"HKCU:\Software\Microsoft\Windows\DWM"
)
$RegKeys = @(
"DragFullWindows",
"MenuShowDelay",
"UserPreferencesMask",
"MinAnimate",
"KeyboardDelay",
"ListviewAlphaSelect",
"ListviewShadow",
"TaskbarAnimations",
"VisualFXSetting",
"EnableAeroPeek"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Performance"{ $RegVals = @(0,0,[byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00),3) }
		"Quality" {	$RegVals = @(1,400,[byte[]](0x9E,0x1E,0x07,0x80,0x12,0x00,0x00,0x00),3)	}
		}
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type String -Value $RegVals[0]
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -Type String -Value $RegVals[1]
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[2] -Type Binary -Value $RegVals[2]
	Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[3] -Type String -Value $RegVals[0]
	Set-ItemProperty -Path $RegPaths[2] -Name $RegKeys[4] -Type DWord -Value $RegVals[0]
	Set-ItemProperty -Path $RegPaths[3] -Name $RegKeys[5] -Type DWord -Value $RegVals[0]
	Set-ItemProperty -Path $RegPaths[3] -Name $RegKeys[6] -Type DWord -Value $RegVals[0]
	Set-ItemProperty -Path $RegPaths[3] -Name $RegKeys[7] -Type DWord -Value $RegVals[0]
	Set-ItemProperty -Path $RegPaths[4] -Name $RegKeys[8] -Type DWord -Value $RegVals[3]
	Set-ItemProperty -Path $RegPaths[5] -Name $RegKeys[9] -Type DWord -Value $RegVals[0]
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-VisualFX

Function Set-ShowThumbnails {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RegVal = 0 }
	"Disabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Show Thumbnails as icon"
RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
RegKey = "IconsOnly"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-ShowThumbnails

Function Set-LocalThumbnailsDB {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Save ThumbnailsDB on local system"
$RegPaths = @( "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" )
$RegKeys = @( "DisableThumbnailCache" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{ Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 1 }
		"Enabled" { Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue }
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-LocalThumbnailsDB

Function Set-NetworkThumbnailsDB {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Save ThumbnailsDB in networkfolder(s)"
$RegPaths = @( "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" )
$RegKeys = @( "DisableThumbsDBOnNetworkFolders" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{ Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 1 }
		"Enabled" { Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue }
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-NetworkThumbnailsDB

Function Set-KeyboardLayout {
param(
[ValidateSet("Add","Remove")]$Status,
[string[]]$KeyboardLayout = "en-US"
)
$Description = "Keyboard layout(s)"
try {
	$langs = Get-WinUserLanguageList
	switch ($Status){
		"Add"{
			foreach ($Keyboard in $KeyboardLayout){
				$langs.Add($Keyboard)
				Set-WinUserLanguageList $langs -Force
				}
			}
		"Remove"{
			foreach ($Keyboard in $KeyboardLayout){
				Set-WinUserLanguageList ($langs | Where-Object {$_.LanguageTag -ne $Keyboard}) -Force
				}
			}
		}
	$langs = (Get-WinUserLanguageList).LocalizedName -join ", "
	Out-put "current $($Description) set to $($langs)"
	}
catch { Out-put "could not $($Status) $($Description)"}
}#Set-KeyboardLayout

Function Set-Numlock {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "default Numlock state at startup"
$RegPaths = @( "HKU:\.DEFAULT\Control Panel\Keyboard" )
$RegKeys = @( "InitialKeyboardIndicators" )
Out-put "setting $($Description) to $($Status)"
try {
	If (!(Test-Path "HKU:")) { New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null }
	switch ($Status){
		"Disabled"{ $RegVal = 2147483648 ; $NumLock = $True }
		"Enabled" { $RegVal = 2147483650 ; $NumLock = $False }
		}
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value $RegVal
	Add-Type -AssemblyName System.Windows.Forms
	If (([System.Windows.Forms.Control]::IsKeyLocked('NumLock')) -eq $Numlock) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-Numlock

Function Set-OneDriveStartUp {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $true }
	"Disabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Set OneDrive startup"
RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
RegKey = "DisableFileSyncNGSC"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-OneDriveStartUp

Function Set-OneDriveProvisioning {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Provisioning of OneDrive"
Out-put "setting $($Description) to $($Status)"
$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
If (!(Test-Path $onedrive)) { $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe" }
$RegPaths = @(
"HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
"HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
)
$Items = @(
"$env:USERPROFILE\OneDrive",
"$env:LOCALAPPDATA\Microsoft\OneDrive",
"$env:PROGRAMDATA\Microsoft OneDrive",
"$env:SYSTEMDRIVE\OneDriveTemp"
)
try {
	switch ($Status){
		"Disabled"{
			Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
			Start-Sleep -s 3
			Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
			Start-Sleep -s 3
			Stop-Process -Name explorer -ErrorAction SilentlyContinue
			Start-Sleep -s 3
			foreach ($Item in $Items){ Remove-Item $Item -Force -Recurse -ErrorAction SilentlyContinue }
			If (!(Test-Path "HKCR:")) { New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null }
			foreach ($RegPath in $RegPaths){ Remove-Item -Path $RegPath -Recurse -ErrorAction SilentlyContinue }
			}
		"Enabled" {
			Start-Process $onedrive -NoNewWindow
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-OneDriveProvisioning

# (Un)Install Windows Store Apps
Function Set-ProvisionedPackages {
param(
[ValidateSet("Enabled","Disabled")]$Status,
$Description = "Microsoft AppxPackages",
[string[]]$AppxPackages = @(
	"Microsoft.3DBuilder",
	"Microsoft.AppConnector",
	"Microsoft.BingFinance",
	"Microsoft.BingNews",
	"Microsoft.BingSports",
	"Microsoft.BingWeather",
	"Microsoft.BingTranslator",
	"Microsoft.GetHelp",
	"Microsoft.Getstarted",
	"Microsoft.Messaging",
	"Microsoft.Microsoft3DViewer",
	"Microsoft.MicrosoftOfficeHub",
	"Microsoft.Office.OneNote",
	"Microsoft.Office.Sway",
	"Microsoft.MicrosoftPowerBIForWindows",
	"Microsoft.MicrosoftSolitaireCollection",
	"Microsoft.MicrosoftStickyNotes",
	"Microsoft.People",
	"Microsoft.SkypeApp",
	"Microsoft.Windows.Photos",
	"Microsoft.WindowsAlarms",
	"Microsoft.WindowsCamera",
	"Microsoft.windowscommunicationsapps",
	"Microsoft.Wallet",
	"Microsoft.WindowsMaps",
	"Microsoft.WindowsPhone",
	"Microsoft.WindowsSoundRecorder",
	"Microsoft.ZuneMusic",
	"Microsoft.ZuneVideo",
	"Microsoft.AppConnector",
	"Microsoft.ConnectivityStore",
	"Microsoft.Messaging",
	"Microsoft.CommsPhone",
	"Microsoft.MicrosoftStickyNotes",
	"Microsoft.OneConnect",
	"Microsoft.WindowsFeedbackHub",
	"Microsoft.MinecraftUWP",
	"Microsoft.MicrosoftPowerBIForWindows",
	"Microsoft.NetworkSpeedTest",
	"Microsoft.MSPaint",
	"Microsoft.Microsoft3DViewer",
	"Microsoft.RemoteDesktop",
	"Microsoft.Print3D"
	)
)
Out-put "Provisioning of $($Description) is $($Status)"
switch ($Status){
	"Disabled"{
		foreach ($AppxPackage in $AppxPackages){
			Remove-AppxPackage $AppxPackage
			Out-put "Uninstalling Package $($AppxPackage)"
			}#foreach AppxPackage
		}
	"Enabled" {
		foreach ($AppxPackage in $AppxPackages){
			try {
				Get-AppxPackage -AllUsers $AppxPackage | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
				Out-put "Installing Package $($AppxPackage)"
				}
			catch { Out-put "could not set $($Description) to $($Status)"}
			}#foreach AppxPackage
		}
	}#switch
}#Set-ProvisionedPackages

# In case you have removed them for good, you can try to restore the files using installation medium as follows
# New-Item C:\Mnt -Type Directory | Out-Null
# dism /Mount-Image /ImageFile:D:\sources\install.wim /index:1 /ReadOnly /MountDir:C:\Mnt
# robocopy /S /SEC /R:0 "C:\Mnt\Program Files\WindowsApps" "C:\Program Files\WindowsApps"
# dism /Unmount-Image /Discard /MountDir:C:\Mnt
# Remove-Item -Path C:\Mnt -Recurse

# (Un)Install third party applications
Function Set-Provisioned3PartyPackages {
param(
[ValidateSet("Enabled","Disabled")]$Status,
[string[]]$AppXPackages = @(
	"9E2F88E3.Twitter",
	"king.com.CandyCrushSodaSaga",
	"41038Axilesoft.ACGMediaPlayer",
	"2414FC7A.Viber",
	"46928bounde.EclipseManager",
	"64885BlueEdge.OneCalendar",
	"7EE7776C.LinkedInforWindows",
	"828B5831.HiddenCityMysteryofShadows",
	"A278AB0D.DisneyMagicKingdoms",
	"DB6EA5DB.CyberLinkMediaSuiteEssentials",
	"DolbyLaboratories.DolbyAccess",
	"E046963F.LenovoCompanion",
	"LenovoCorporation.LenovoID",
	"LenovoCorporation.LenovoSettings",
	"SpotifyAB.SpotifyMusic",
	"WinZipComputing.WinZipUniversal",
	"XINGAG.XING",
	"PandoraMediaInc.29680B314EFC2",
	"4DF9E0F8.Netflix",
	"Drawboard.DrawboardPDF",
	"D52A8D61.FarmVille2CountryEscape",
	"GAMELOFTSA.Asphalt8Airborne",
	"flaregamesGmbH.RoyalRevolt2",
	"AdobeSystemsIncorporated.AdobePhotoshopExpress",
	"ActiproSoftwareLLC.562882FEEB491",
	"D5EA27B7.Duolingo-LearnLanguagesforFree",
	"Facebook.Facebook",
	"46928bounde.EclipseManager",
	"A278AB0D.MarchofEmpires",
	"KeeperSecurityInc.Keeper",
	"king.com.BubbleWitch3Saga",
	"89006A2E.AutodeskSketchBook",
	"CAF9E577.Plex"
	)
)
switch ($Status){
	"Enabled" { 
		ForEach ($AppXPackage in $AppxPackages){
			Get-AppxPackage -AllUsers $AppxPackage | ForEach { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
			}
		}
	"Disabled" {
		ForEach ($AppxPackage in $AppxPackages){
			Get-AppxPackage $AppxPackages | Remove-AppxPackage
			}
		}
	}
}#Set-Provisioned3PartyPackages

Function Set-WindowsStoreProvisioning {
param(
[ValidateSet("Enabled","Disabled")]$Status,
[string[]]$AppXPackages = @( "Microsoft.DesktopAppInstaller","Microsoft.WindowsStore" )
)
switch ($Status){
	"Enabled" { 
		ForEach ($AppXPackage in $AppxPackages){
			Get-AppxPackage -AllUsers $AppxPackage | ForEach { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
			}
		}
	"Disabled" {
		ForEach ($AppxPackage in $AppxPackages){
			Get-AppxPackage $AppxPackages | Remove-AppxPackage
			}
		}
	}
}#Set-WindowsStoreProvisioning

Function Set-ConsumerApps {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $true }
	"Disabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Consumer Experience"
RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
RegKey = "DisableWindowsConsumerFeatures"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-ConsumerApps

Function Set-XboxFeature {
param(
[ValidateSet("Enabled","Disabled")]$Status,
[string[]]$AppXPackages = @(
	"Microsoft.XboxApp",
	"Microsoft.XboxIdentityProvider",
	"Microsoft.XboxSpeechToTextOverlay",
	"Microsoft.XboxGameOverlay",
	"Microsoft.Xbox.TCUI"
	)
)
$Description = "Xbox Feature"
Set-ProvisionedPackages -Status $Status -AppxPackages $AppxPackages -Description $Description
$RegPaths = @(
"HKCU:\System\GameConfigStore",
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
)
$RegKeys = @( "GameDVR_Enabled", "AllowGameDVR" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 0
			If (!(Test-Path -Path $RegPaths[1] )) { New-Item -Path $RegPaths[1] -Force | Out-Null }
			Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[1] -Type Dword -Value 0
			}
		"Enabled" {
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 1
			Remove-ItemProperty -Path $RegPaths[1] -Name $RegKeys[1] -ErrorAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-XboxFeature

# Disable built-in Adobe Flash in IE and Edge
Function Set-AdobeFlash {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Adobe Flash plugin (builtin for Edge and IE)"
$edge = (Get-AppxPackage -AllUsers "Microsoft.MicrosoftEdge").PackageFamilyName
$RegPaths = @(
"HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\Addons",
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings\{D27CDB6E-AE6D-11CF-96B8-444553540000}"
)
$RegKeys = @(
"FlashPlayerEnabled",
"Flags"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Enabled"{
			Remove-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $RegPaths[1] -Name $RegKeys[1] -ErrorAction SilentlyContinue
			}
		"Disabled" {
			If (!(Test-Path $RegPaths[0])) { New-Item -Path $RegPaths[0] -Force | Out-Null }
			Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value 0
			If (!(Test-Path $RegPaths[1])) { New-Item -Path $RegPaths[1] -Force | Out-Null }
			Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[1] -Type DWord -Value 1			
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-AdobeFlash

# Generic Windows Feature Function
Function Set-WindowsFeature {
param(
[ValidateSet("Enabled","Disabled")]$Status,
[string[]]$WindowsFeatures
)
$Description = "Windows feature"
switch ($Status){
	"Disabled"{
		try {
			foreach ($WindowsFeature in $WindowsFeatures){
				Disable-WindowsOptionalFeature -Online -FeatureName $WindowsFeature -NoRestart -WarningAction SilentlyContinue | Out-Null
				Out-put "setting $($Description) $($WindowsFeature) to $($Status)"
				}
			}
		catch { Out-put "could not set $($Description) to $($Status)"}
		}
	"Enabled" {
		try {
			foreach ($WindowsFeature in $WindowsFeatures){
				Enable-WindowsOptionalFeature -Online -FeatureName $WindowsFeature -NoRestart -WarningAction SilentlyContinue | Out-Null
				Out-put "setting $($Description) $($WindowsFeature) to $($Status)"
				}
			}
		catch { Out-put "could not set $($Description) to $($Status)"}
		}
	}
}#Set-WindowsFeature

Function Set-MediaPlayerFeature {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
Set-WindowsFeature -Status $Status -WindowsFeatures "WindowsMediaPlayer"
}#Set-MediaPlayerFeature

Function Set-PDFprinter {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
Set-WindowsFeature -Status $Status -WindowsFeatures "Printing-PrintToPDFServices-Features"
}#Set-PDFprinter

Function Set-Faxprinter {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
Set-WindowsFeature -Status $Status -WindowsFeatures "Microsoft Shared Fax Driver"
}#Set-Faxprinter

Function Set-XPSprinter {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
Set-WindowsFeature -Status $Status -WindowsFeatures "Printing-XPSServices-Features"
}#Set-XPSprinter

Function Set-InternetExplorerFeature {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
Set-WindowsFeature -Status $Status -WindowsFeatures "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE"
}#Set-InternetExplorerFeature

Function Set-WorkFoldersFeature {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
Set-WindowsFeature -Status $Status -WindowsFeatures "WorkFolders-Client"
}#Set-WorkFoldersFeature

Function Set-LinuxSubsystemFeature {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Linux SubSystem"
$RegPaths = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" )
$RegKeys = @(
"AllowDevelopmentWithoutDevLicense",
"AllowAllTrustedApps"
)
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{ $RegVal = 0 }
		"Enabled" { $RegVal = 1 }
		}
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value $RegVal
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[1] -Type DWord -Value $RegVal
	Set-WindowsFeature -Status $Status -WindowsFeatures "Microsoft-Windows-Subsystem-Linux"
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-LinuxSubsystemFeature

Function Set-HyperVFeature {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Windows HyperV feature"
Out-put "setting $($Description) to $($Status)"
switch ($Status){
	"Disabled"{
		try {
			if ((Get-WMIObject -class Win32_Computersystem).DomainRole -gt 1 ){
				Uninstall-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
				}
			else {
				Set-WindowsFeature -Status $Status -WindowsFeatures "Microsoft-Hyper-V-All"
				}
			}
		catch { Out-put "could not set $($Description) to $($Status)"}
		}
	"Enabled" {
		try {
			if ((Get-WMIObject -class Win32_Computersystem).DomainRole -gt 1 ){
				Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
				}
			else {
				Set-WindowsFeature -Status $Status -WindowsFeatures "Microsoft-Hyper-V-All"
				}
			}
		catch { Out-put "could not set $($Description) to $($Status)"}
		}
	}
}#Set-HyperVFeature

Function Set-EdgeShortcutCreation {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Edge Shortcuts creation"
Out-put "setting $($Description) to $($Status)"
$RegPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer")
$RegKeys = @("DisableEdgeDesktopShortcutCreation")
$RegVal = 1
switch ($Status){
	"Disabled" { Set-ItemProperty $RegPaths[0] -Name $RegKeys[0] -Type Dword -Value $RegVal }
	"Enabled" { Remove-ItemProperty $RegPaths[0] -Name $RegKeys[0] -ErrorAction SilentlyContinue }
	}
}

Function Set-PhotoViewerAssociation {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$FileTypes = @("Paint.Picture", "giffile", "jpegfile", "pngfile")
$Description = "Photo Viewer Associations for $($FileTypes -join ',')"
Out-put "setting $($Description) to $($Status)"
If (!(Test-Path "HKCR:")) { New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null }
try {
	switch ($Status){
		"Disabled"{
			Remove-Item -Path "HKCR:\Paint.Picture\shell\open" -Recurse -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "MuiVerb" -ErrorAction SilentlyContinue
			Set-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "CommandId" -Type String -Value "IE.File"
			Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "(Default)" -Type String -Value "`"$env:SystemDrive\Program Files\Internet Explorer\iexplore.exe`" %1"
			Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "DelegateExecute" -Type String -Value "{17FE9752-0B5A-4665-84CD-569794602F5C}"
			Remove-Item -Path "HKCR:\jpegfile\shell\open" -Recurse -ErrorAction SilentlyContinue
			Remove-Item -Path "HKCR:\pngfile\shell\open" -Recurse -ErrorAction SilentlyContinue
			}
		"Enabled" {
			ForEach ($FileType in $FileTypes) {
				New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
				New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
				Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
				Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
				}
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-PhotoViewerAssociation

Function Set-PhotoViewerOpenWith {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Photo Viewer as Open With... option for pictures"
$RegPaths = @(
"HKCR:\Applications\photoviewer.dll\shell\open",
"HKCR:\Applications\photoviewer.dll\shell\open\command",
"HKCR:\Applications\photoviewer.dll\shell\open\DropTarget"
)
Out-put "setting $($Description) to $($Status)"
If (!(Test-Path "HKCR:")) { New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null }
try {
	switch ($Status){
		"Disabled"{
			Remove-Item -Path $RegPaths[0] -Recurse -ErrorAction SilentlyContinue
			}
		"Enabled" {
			foreach ($RegPath in $RegPaths){ If (!(Test-Path -Path $RegPath )) { New-Item -Path $RegPath -Force | Out-Null } }
			Set-ItemProperty -Path $RegPaths[0] -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
			Set-ItemProperty -Path $RegPaths[1] -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
			Set-ItemProperty -Path $RegPaths[2] -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-PhotoViewerOpenWith

Function Set-SearchAppInStore {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $true }
	"Disabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Open With... in AppStore for unknown extension"
RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
RegKey = "NoUseStoreOpenWith"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-SearchAppInStore

Function Set-NewAppPrompt {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $true }
	"Disabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Open With... prompt for unknown extension"
RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
RegKey = "NoNewAppAlert"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-NewAppPrompt

Function Set-ControlPanelView {
param(
[ValidateSet("Category","Large","Small")]$Status
)
$Description = "Control Panel view"
$RegPath = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")
$RegKey = @("StartupPage","AllItemsIconView")
Out-put "Setting $($Description)  to $($Status)"
switch ($Status){
	"Category"{ 
		Remove-ItemProperty -Path $RegPath[0] -Name $RegKey[0] -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path $RegPath[0] -Name $RegKey[1] -ErrorAction SilentlyContinue }
	"Large" { 
		If (!(Test-Path $RegPath[0])) { New-Item -Path $RegPath[0] | Out-Null }
		Set-ItemProperty -Path $RegPath[0] -Name $RegKey[0] -Type DWord -Value 1
		Set-ItemProperty -Path $RegPath[0] -Name $RegKey[1] -Type DWord -Value 0 
		}
	"Small" { 
		If (!(Test-Path $RegPath[0])) { New-Item -Path $RegPath[0] | Out-Null }
		Set-ItemProperty -Path $RegPath[0] -Name $RegKey[0] -Type DWord -Value 1
		Set-ItemProperty -Path $RegPath[0] -Name $RegKey[1] -Type DWord -Value 1 
		}
	}
}

# Set Data Execution Prevention (DEP) policy to OptOut
Function Set-DEP {
param(
[ValidateSet("OptOut","OptIn")]$Status
)
$Description = "DEP policy"
Out-put "setting $($Description) to $($Status)"
try { bcdedit /set `{current`} nx $($Status) | Out-Null }
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-DEP

########### Server specific Tweaks ###########

Function Set-ServerManagerOnLogin {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $true }
	"Disabled" { $RegVal = 1 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Server Manager startup on login"
RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager"
RegKey = "DoNotOpenAtLogon"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-ServerManagerOnLogin

Function Set-ShutdownTracker {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Enabled"{ $RemoveRegKey = $true }
	"Disabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Shutdown Event Tracker"
RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability"
RegKey = "ShutdownReasonOn"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-ShutdownTracker

Function Set-PasswordPolicy {
param(
[ValidateRange(0,90)][int]$PasswordAge,
[ValidateRange(0,24)]$History,
[switch]$Complexity
)
$Description = "Password complexity, history and age"
Out-put "setting $($Description) to $($Status)"
try {
	$tmpfile = New-TemporaryFile
	secedit /export /cfg $tmpfile /quiet
	$pwdpolicy = (Get-Content $tmpfile)
	$pwdpolicy.Replace("PasswordComplexity = 1", "PasswordComplexity = $([int][bool]$Complexity)")
	$pwdpolicy.Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = $($PasswordAge)")
	$pwdpolicy.Replace("PasswordHistorySize = 0", "PasswordHistorySize = $($History)")
	$pwdpolicy | out-file $tmpfile
	secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
	Remove-Item -Path $tmpfile
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-PasswordPolicy

Function Set-CtrlAltDelLogin {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
switch ($Status){
	"Disabled" { $RegVal = 1 }
	"Enabled" { $RegVal = 0 }
	}
$SingleRegKeyProps =@{
Status = $Status
Description = "Login with CtrlAltDelete"
RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
RegKey = "DisableCAD"
RegType = "Dword"
RegVal = $RegVal
RemoveRegKey = $RemoveRegKey
}
Set-SingleRegKey @SingleRegKeyProps
}#Set-CtrlAltDelLogin

Function Set-IEEnhancedSecurity {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Internet Explorer Enhanced Security Config"
$RegPaths = @(
"HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}",
"HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
)
$RegKeys = @( "IsInstalled" )
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{ $RegVal = 1	}
		"Enabled" { $RegVal = 0	}
		}
	Set-ItemProperty -Path $RegPaths[0] -Name $RegKeys[0] -Type DWord -Value $RegVal
	Set-ItemProperty -Path $RegPaths[1] -Name $RegKeys[0] -Type DWord -Value $RegVal
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}#Set-IEEnhancedSecurity

Function Set-Audio {
param(
[ValidateSet("Enabled","Disabled")]$Status
)
$Description = "Audio device"
Out-put "setting $($Description) to $($Status)"
try {
	switch ($Status){
		"Disabled"{
			Stop-Service "Audiosrv" -WarningAction SilentlyContinue
			Set-Service "Audiosrv" -StartupType Manual	
			}
		"Enabled" {
			Set-Service "Audiosrv" -StartupType Automatic
			Start-Service "Audiosrv" -WarningAction SilentlyContinue
			}
		}
	}
catch { Out-put "could not set $($Description) to $($Status)"}
}



}#begin

end{
switch ($Output){
	"Host" { Write-Host "W10 setup script has finished"}
	"Log" { Out-File $script:LogFilePath "End of script execution at $(Get-Date)" -Append -NoClobber }
	"Pipe" { $script:output}
	}
}
