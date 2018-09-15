##########
# Win10 / WinServer2016 Initial Setup Script - Main execution loop
# Author: Disassembler <disassembler@dasm.cz>
# Version: v3.0, 2018-09-15
# Source: https://github.com/Disassembler0/Win10-Initial-Setup-Script
##########

# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -Verb RunAs
		Exit
	}
}

$tweaks = @()
$PSCommandArgs = @()

# Parse and resolve paths in passed arguments
$i = 0
While ($i -lt $args.Length) {
	If ($args[$i].ToLower() -eq "-include") {
		# Resolve full path to the included file
		$include = Resolve-Path $args[++$i]
		$PSCommandArgs += "-include `"$include`""
		# Import the included file as a module
		Import-Module -Name $include
	} ElseIf ($args[$i].ToLower() -eq "-preset") {
		# Resolve full path to the preset file
		$preset = Resolve-Path $args[++$i]
		$PSCommandArgs += "-preset `"$preset`""
		# Load tweak names from the preset file
		$tweaks += Get-Content $preset -ErrorAction Stop | ForEach { $_.Split("#")[0].Trim() } | Where { $_ -ne "" }
	} Else {
		$PSCommandArgs += $args[$i]
		# Load tweak names from command line
		$tweaks += $args[$i]
	}
	$i++
}

# Call the desired tweak functions
$tweaks | ForEach { Invoke-Expression $_ }
