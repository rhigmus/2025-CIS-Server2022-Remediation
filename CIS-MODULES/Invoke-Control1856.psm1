function Invoke-Control1856 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.5.6: Status of the MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from the WINS servers setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.5.6"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.5.6: Status of the MSS: (NoNameReleaseOnDemand)..."
        try {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters" -Name "NoNameReleaseOnDemand" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set NoNameReleaseOnDemand to 1 (ignores NetBIOS name release requests unless from WINS)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.5.6: $_"
}
}
