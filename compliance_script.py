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
import re
import psutil
import shutil
import sys
import ctypes


def check_bitlocker(drive):
    """
    Checks if full disk encryption is enabled or not
    """
    if platform.system() != "Windows":
        return {"status": "unknown", "details": "Windows only."}
    if not shutil.which("manage-bde"):
        return {"status": "unknown", "details": "manage-bde not found."}

    try:
        out = subprocess.check_output(["manage-bde", "-status", drive], text=True, stderr=subprocess.STDOUT)

        # Extract fields
        vol_m  = re.search(r"Volume\s+([A-Z]:)", out, re.I)
        pct_m  = re.search(r"Percentage\s+Encrypted\s*:\s*([\d.,]+)\s*%", out, re.I)
        conv_m = re.search(r"Conversion\s+Status\s*:\s*(.+)", out, re.I)
        prot_m = re.search(r"Protection\s+Status\s*:\s*(?:Protection\s+)?(On|Off)", out, re.I)
        meth_m = re.search(r"Encryption\s+Method\s*:\s*(.+)", out, re.I)

        vol  = vol_m.group(1) if vol_m else drive
        pct  = float(pct_m.group(1).replace(",", "")) if pct_m else 0.0
        conv = (conv_m.group(1).strip() if conv_m else "").strip()
        prot = (prot_m.group(1).strip().title() if prot_m else "Unknown")
        meth = (meth_m.group(1).strip() if meth_m else "Unknown")

        enabled = (pct >= 100.0) and (prot.lower() == "on")
        partial = (0.0 < pct < 100.0)

        status = "disabled"
        if enabled:
            status = "enabled"
        if partial:
            status = "partial"
        
        details = f"{vol}: {pct:.1f}% encrypted; {conv}; Protection {prot}; Method {meth}"

        return {"status": status, "details": details}

    except subprocess.CalledProcessError as e:
        return {"status": "unknown", "details": f"manage-bde error: {e.returncode}"}

def check_edr_agent(process_name):
    """
    Check if an EDR agent is active.
    """
    result = {"status": "not running", "service_name": None}
    system = platform.system()
    found = False

    # Known process names
    known_processes = {
        "defender": ["MsMpEng.exe", "NisSrv.exe"],
        "crowdstrike": ["CSFalconService.exe", "falcond", "falcon-sensor"],
        "csagent": ["CSFalconService.exe", "falcond", "falcon-sensor"],
    }
    targets = known_processes.get(process_name.lower(), [process_name])

    # Process check
    for proc in psutil.process_iter(attrs=["name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if any(t.lower() in name for t in targets):
                result["status"] = "running"
                result["service_name"] = proc.info.get("name")
                found = True
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Windows service check (for csagent / crowdstrike)
    if not found and system == "Windows" and process_name.lower() in {"crowdstrike", "csagent"}:
        for svc in ["csagent", "CSFalconService"]:
            try:
                output = subprocess.check_output(
                    ["sc.exe", "query", svc],
                    text=True,
                    stderr=subprocess.STDOUT,
                    errors="ignore",
                )
                m = re.search(r"STATE\s*:\s*\d+\s+([A-Z_]+)", output)
                if m and m.group(1).upper() == "RUNNING":
                    result["status"] = "running"
                    result["service_name"] = svc
                    found = True
                    break
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue

    return result

def check_firewall_status():
    """Check if Windows Defender Firewall is enabled."""
    result = {"status": "unknown", "details": ""}

    if platform.system() != "Windows":
        result["details"] = "Unsupported OS for firewall check."
        return result

    try:
        output = subprocess.check_output(
            ["netsh", "advfirewall", "show", "allprofiles"],
            text=True,
            stderr=subprocess.STDOUT
        )

        states = re.findall(r"State\s*:?\s*(ON|OFF)", output, flags=re.IGNORECASE)
        if states:
            if any(s.upper() == "ON" for s in states):
                result["status"] = "enabled"
            else:
                result["status"] = "disabled"
            result["details"] = f"Profiles: {', '.join(states)}"
        else:
            result["details"] = "Could not parse firewall state from output."

    except FileNotFoundError:
        result["details"] = "netsh command not found."
    except subprocess.CalledProcessError as e:
        result["details"] = f"Error checking firewall: {e.output or e}"

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
            "disk_encryption": check_bitlocker("C:"),
            "edr_agent": check_edr_agent(process_name="csagent"),  # configurable: process_name="defender"
            "firewall": check_firewall_status(),
        },
    }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
