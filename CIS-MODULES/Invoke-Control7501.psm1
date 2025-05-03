function Invoke-Control7501 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 7501: Status of the Registry policy processing option: Process even if the Group Policy objects have not changed setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 7501"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 7501: Status of the Registry policy processing option: Process even if the Group Policy objects have not changed setting"
        try {
            # Enable "Process even if the Group Policy objects have not changed"
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableRsop" -PropertyType DWord -Value 0 -Force | Out-Null
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ProcessEvenIfGPOUnchanged" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set ProcessEvenIfGPOUnchanged to 1 and DisableRsop to 0 under HKLM:\Software\Policies\Microsoft\Windows\System"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 7501: $_"
}
