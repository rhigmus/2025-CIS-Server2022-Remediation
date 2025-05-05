# CIS Level 1 Remediation for Windows Server 2022

## Overview

This repository provides an automated solution to **harden Windows Server 2022** according to the **Center for Internet Security (CIS) Level 1** benchmark recommendations. It includes a PowerShell script, **`Invoke-Controls.ps1`**, which applies a series of security configuration controls (Level 1 baseline) to a target Windows Server 2022 system. Each CIS control is implemented as an individual PowerShell module in the `CIS-MODULES` directory, and the main script orchestrates their execution.

**Key Features:**

- **Complete CIS Level 1 Baseline** – Deploy all CIS Level 1 recommended settings for Windows Server 2022 in one run.
- **Granular Control** – Optionally apply individual controls by ID, or a comma-separated list of IDs.
- **Interactive or Unattended Execution** – Supports confirmation prompts or full auto-deployment.
- **Logging and Audit Trail** – All changes are logged for later review.
- **Pure PowerShell Implementation** – No external tools or dependencies required.

## Technologies Used

- **PowerShell** – Implemented using native PowerShell (compatible with Windows PowerShell 5.1 and PowerShell 7.x).
- **Windows Server 2022 Security Settings** – Applies settings through registry, services, and policy edits.

## Prerequisites and Requirements

- **OS**: Windows Server 2022
- **Run as Administrator**: Required for applying system-level changes.
- **Execution Policy**:
  ```powershell
  Set-ExecutionPolicy RemoteSigned -Scope Process
  Unblock-File -Path .\Invoke-Controls.ps1 -Confirm:$false
  Unblock-File -Path .\CIS-MODULES\* -Confirm:$false
