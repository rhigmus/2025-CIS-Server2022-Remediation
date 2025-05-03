function Invoke-Control27617 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 27617: Status of the Configure security policy processing: Process even if the Group Policy objects have not changed setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 27617"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 27617: Status of the Configure security policy processing: Process even if the Group Policy objects have not changed setting"
        try {
            # Ensure security policies are processed even if GPOs haven't changed
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ProcessEvenIfGPOUnchanged" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set ProcessEvenIfGPOUnchanged to 1 under HKLM:\Software\Policies\Microsoft\Windows\System"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 27617: $_"
}
