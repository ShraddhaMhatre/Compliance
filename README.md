# Compliance Script for Basic device posture check

## Purpose
This Python script performs basic workstation compliance checks on Windows systems.
It is designed to provide a quick security posture snapshot, for example, before allowing access to sensitive networks or systems.

The script automatically gathers:
System information (OS, version, hostname)
Security controls status (encryption, EDR, firewall)

and outputs a JSON-formatted compliance report.


## What It Checks

| Check               | Description                                                                                     | Implementation                                                                                                                                  |
| ------------------- | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| **Disk Encryption** | Verifies if **BitLocker full-disk encryption** is enabled on the system drive (`C:`).           | Uses `manage-bde -status` and parses output for encryption %, conversion status, and protection state.                                          |
| **EDR Agent**       | Confirms whether an **EDR/AV agent** (e.g., CrowdStrike Falcon, Microsoft Defender) is running. | Uses `psutil` to detect known process names (`CSFalconService.exe`, `MsMpEng.exe`, etc.) and falls back to `sc.exe query` for Windows services. |
| **Firewall**        | Checks whether the **Windows Defender Firewall** is enabled for any profile.                    | Runs `netsh advfirewall show allprofiles` and parses ON/OFF state.                                                                              |


## Requirements

- **Python 3.7+**
- **psutil** library  
  Install with:
  ```bash
  pip install psutil

# Usage

## Run directly from terminal:
python compliance_script.py

## Example output
{
  "system_info": {
    "os": "Windows",
    "os_version": "10.0.xxxx",
    "hostname": "<samplehostname>"
  },
  "checks": {
    "disk_encryption": {
      "status": "enabled",
      "details": "C:: 100.0% encrypted; Used Space Only Encrypted; Protection On; Method XTS-AES 128"
    },
    "edr_agent": {
      "status": "running",
      "service_name": "CSFalconService.exe"
    },
    "firewall": {
      "status": "enabled",
      "details": "Profiles: ON, ON, ON"
    }
  }
}

## Notes
## On Windows, ensure you run the terminal as Administrator for full accuracy.
