New-ModuleManifest -Path Logger.psd1 `
    -RootModule Logger.psm1 `
    -FunctionsToExport @('Write-Log', 'Get-LogPath', 'Set-LogPath') `
    -ModuleVersion '1.0' `
    -Author 'RS' `
    -Description 'Logging module for CIS remediation framework'
