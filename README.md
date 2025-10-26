# Compliance Script for Basic device posture check

## Purpose
This Python script performs **basic security posture checks** on a workstation (macOS or Windows).  
It is designed to simulate a lightweight endpoint compliance or "health check" mechanism before granting access to sensitive systems.

---

## What It Checks

| Check | Description | Implementation |
|-------|--------------|----------------|
| **Disk Encryption** | Verifies if full-disk encryption is enabled. | Uses `manage-bde -status` (Windows) or `fdesetup status` (macOS). |
| **EDR Agent Running** | Ensures a security agent (mocked process) is active. | Looks for a process name like `defender` using `psutil`. |
| **Firewall Enabled** | Confirms the OS-native firewall is active. | Uses `netsh advfirewall show allprofiles` (Windows) or `defaults read /Library/Preferences/com.apple.alf globalstate` (macOS). |

---

## Requirements

- **Python 3.7+**
- **psutil** library  
  Install with:
  ```bash
  pip install psutil

## Usage

# Run directly from terminal:
python3 device_posture_check.py

# Customizing EDR Agent Check (By default, it looks for a process named defender)
python3 device_posture_check.py --edr process_name="crowdstrike"

## Notes
# The EDR agent check is mocked — it only confirms a process is running.
# The script requires local admin privileges on macOS to read FileVault and firewall settings.
# On Windows, ensure you run the terminal as Administrator for full accuracy.
