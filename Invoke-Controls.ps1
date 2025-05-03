param (
    [switch]$ApplyAll = $false,
    [int[]]$ControlIds,
    [string]$ModulesPath = "$PSScriptRoot\CIS-MODULES"
)

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
