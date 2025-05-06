function Invoke-Control9388 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9388: Status of the Turn off picture password sign-in setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9388"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9388: Status of the Turn off picture password sign-in setting"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "BlockPicturePassword" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Disabled picture password sign-in (BlockPicturePassword set to 1)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9388: $_"
}
}
