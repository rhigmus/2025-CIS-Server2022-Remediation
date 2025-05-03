<#
.SYNOPSIS
    Executes one or more CIS benchmark control modules by invoking their corresponding functions.

.DESCRIPTION
    This script dynamically imports all CIS control modules from a specified directory and invokes the corresponding 
    functions based on the provided parameters. It supports running all controls or a specific subset, with optional 
    application of remediations via the -ApplyAll flag.

.PARAMETER ApplyAll
    If specified, the script automatically applies the remediations for each control without prompting for confirmation.

.PARAMETER ControlIds
    A list of specific Control IDs to execute. If omitted, all available modules will be executed.

.PARAMETER ModulesPath
    Optional. The path to the directory containing control module (.psm1) files. Defaults to a '1431_ntt_mgmt__MODULES' 
    subfolder in the script's directory.

.EXAMPLE
    .\Invoke-Controls.ps1 -ApplyAll

    Executes all controls and applies their remediations without user confirmation.

.EXAMPLE
    .\Invoke-Controls.ps1 -ControlIds 13344,10377 -ApplyAll

    Executes only the specified controls with automatic remediation.

.NOTES
    Author: Rob Stark
    Date: 2025-05-01
    Script Version: 1.0
    Project: CIS Compliance Automation for Windows Systems
#>

param (
    [switch]$ApplyAll = $false,
    [int[]]$ControlIds,
    [string]$ModulesPath = "$PSScriptRoot\CIS-MODULES"
)

# Import logger module
$loggerPath = Join-Path $PSScriptRoot "Logger.psm1"
Import-Module $loggerPath -Force

Write-Host "Logging to: $(Get-LogPath)"

# Discover and import all module files
$moduleFiles = Get-ChildItem -Path $ModulesPath -Filter "Invoke-Control*.psm1"

foreach ($mod in $moduleFiles) {
    Import-Module $mod.FullName -Force
}

# Get all available Invoke-Control functions
$invokeFunctions = Get-Command -Module (Get-Module) | Where-Object { $_.Name -like 'Invoke-Control*' }

# Filter if specific control IDs were passed
if ($ControlIds) {
    $invokeFunctions = $invokeFunctions | Where-Object {
        $id = ($_ -split 'Invoke-Control')[1]
        $ControlIds -contains [int]$id
    }
}

# Execute the functions
foreach ($func in $invokeFunctions) {
    Write-Host "`n--- Executing $($func.Name) ---"
    & $func.Name -Apply:$ApplyAll
}
