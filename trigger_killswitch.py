#!/usr/bin/env python3
"""
KillSwitch Python Trigger Script
=================================
Uses 100% Python standard library (no 'pip install' needed).
Works directly against the local KillSwitch API (auto-detects port 3031 / 3030).
"""

import sys
import json
import urllib.request
import urllib.error

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def detect_killswitch_url():
    """Detects which port KillSwitch is currently listening on."""
    ports = [3031, 3030, 4040]
    
    # Check if active_port.txt exists
    try:
        with open("active_port.txt", "r") as f:
            p = int(f.read().strip())
            if p not in ports:
                ports.insert(0, p)
    except Exception:
        pass

    for port in ports:
        url = f"http://127.0.0.1:{port}"
        try:
            req = urllib.request.Request(f"{url}/status", headers={"User-Agent": "KillSwitch-Python"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    return url
        except Exception:
            continue
            
    return "http://127.0.0.1:3031"


def trigger_killswitch(base_url, reason="Triggered by Python emergency script"):
    """Sends the emergency containment command to activate KillSwitch."""
    url = f"{base_url}/engage"
    payload = {
        "operator": "python_automation",
        "reason": reason,
        "level": "hermetic_isolation",  # "hermetic_isolation", "network_quarantine", or "process_freeze"
        "token": "CONFIRM ISOLATE"
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "KillSwitch-Python"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode("utf-8"))
    except Exception as e:
        return {"success": False, "error": str(e)}


def restore_internet(base_url):
    """Restores full internet access by disarming the KillSwitch."""
    url = f"{base_url}/disarm"
    payload = {
        "operator": "python_automation",
        "reason": "Restored via Python script",
        "token": "CONFIRM RESTORE"
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "KillSwitch-Python"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode("utf-8"))
    except Exception as e:
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    base_url = detect_killswitch_url()
    print(f"[*] Connected to KillSwitch at: {base_url}")

    # Check command-line arguments
    if len(sys.argv) > 1 and sys.argv[1].lower() in ["--restore", "--disarm", "restore", "disarm"]:
        print("[*] Sending Disarm / Restore command...")
        res = restore_internet(base_url)
        if res.get("success"):
            print("[+] INTERNET RESTORED!")
            print(f"    Message: {res.get('message')}")
        else:
            print(f"[-] Failed to restore: {res}")
    else:
        reason = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "Rogue AI breakout / Data exfiltration detected"
        print(f"[*] Activating KillSwitch with reason: '{reason}'...")
        res = trigger_killswitch(base_url, reason=reason)
        
        if res.get("success"):
            status = res.get("status", {})
            print("\n[!] KILLSWITCH TRIGGERED SUCCESSFULLY!")
            print(f"    Status Message  : {res.get('message')}")
            print(f"    Network Blocked : {status.get('network_isolated')}")
            print(f"    Level           : {status.get('containment_level')}")
            print(f"    Dashboard Port  : {base_url} (Still Accessible)")
            print("\nTo restore internet later, run:")
            print("    python trigger_killswitch.py --restore")
        else:
            print(f"\n[-] Trigger Failed: {res.get('error') or res.get('message')}")
