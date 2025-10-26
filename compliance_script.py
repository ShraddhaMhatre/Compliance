#!/usr/bin/env python3
"""
Device Posture Check Script
Author: Shraddha Mhatre
Purpose: Perform basic compliance checks on a local workstation
Target OS: Windows and macOS
Output: JSON-formatted compliance report

Checks performed:
1. Disk Encryption (BitLocker / FileVault)
2. EDR Agent process check (mocked via configurable process name)
3. Firewall status
"""

import json
import platform
import subprocess
import psutil
import shutil

def check_disk_encryption():
    """Check if full-disk encryption is enabled."""
    system = platform.system()
    result = {"status": "unknown", "details": ""}

    try:
        if system == "Windows":
            # Run 'manage-bde -status' to check BitLocker
            if shutil.which("manage-bde"):
                output = subprocess.check_output(
                    ["manage-bde", "-status"], text=True, stderr=subprocess.DEVNULL
                )
                if "Percentage Encrypted: 100%" in output:
                    result["status"] = "enabled"
                elif "Percentage Encrypted" in output:
                    result["status"] = "partial"
                else:
                    result["status"] = "disabled"
            else:
                result["details"] = "BitLocker command not found."

        elif system == "Darwin":
            # Check FileVault status
            output = subprocess.check_output(
                ["fdesetup", "status"], text=True, stderr=subprocess.DEVNULL
            )
            if "FileVault is On" in output:
                result["status"] = "enabled"
            elif "FileVault is Off" in output:
                result["status"] = "disabled"
            else:
                result["status"] = "unknown"
            result["details"] = output.strip()

        else:
            result["details"] = "Unsupported OS for disk encryption check."

    except subprocess.CalledProcessError as e:
        result["details"] = f"Error checking encryption: {e}"

    return result


def check_edr_agent(process_name="defender"):
    """
    Check if an EDR (Endpoint Detection & Response) agent process is running.
    Mocked by checking for a specific process name.
    Default process: 'defender' (Microsoft Defender)
    """
    result = {"status": "not running", "details": ""}
    found = False

    for proc in psutil.process_iter(attrs=['name']):
        try:
            if process_name.lower() in proc.info['name'].lower():
                found = True
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if found:
        result["status"] = "running"
    else:
        result["details"] = f"No process matching '{process_name}' found."

    return result


def check_firewall_status():
    """Check if OS firewall is enabled."""
    system = platform.system()
    result = {"status": "unknown", "details": ""}

    try:
        if system == "Windows":
            output = subprocess.check_output(
                ["netsh", "advfirewall", "show", "allprofiles"], text=True
            )
            if "State ON" in output:
                result["status"] = "enabled"
            elif "State OFF" in output:
                result["status"] = "disabled"
            result["details"] = output.strip().splitlines()[0]

        elif system == "Darwin":
            output = subprocess.check_output(
                ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            # macOS Firewall states: 0=Off, 1=On for specific apps, 2=On for essential services
            result["status"] = "enabled" if output in ["1", "2"] else "disabled"
            result["details"] = f"macOS firewall globalstate={output}"

        else:
            result["details"] = "Unsupported OS for firewall check."

    except subprocess.CalledProcessError as e:
        result["details"] = f"Error checking firewall: {e}"

    return result


def main():
    system_info = {
        "os": platform.system(),
        "os_version": platform.version(),
        "hostname": platform.node(),
    }

    report = {
        "system_info": system_info,
        "checks": {
            "disk_encryption": check_disk_encryption(),
            "edr_agent": check_edr_agent(process_name="defender"),  # configurable
            "firewall": check_firewall_status(),
        },
    }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
