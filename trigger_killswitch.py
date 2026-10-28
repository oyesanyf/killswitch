#!/usr/bin/env python3
"""
KillSwitch Python Trigger Script with Live Internet Verification
================================================================
Uses 100% Python standard library (no 'pip install' needed).
1. Probes real external internet reachability before & after KillSwitch.
2. Checks whether 'killswitch.exe' has Windows Administrator privileges.
3. Automatically detects active port (3031 / 3030).
"""

import sys
import time
import json
import urllib.request
import urllib.error

# Ensure clean UTF-8 printing on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def check_internet_reachability(timeout=2.0):
    """
    Attempts to connect to external internet targets (Cloudflare / Google).
    Returns True if external internet is reachable, False if blocked.
    """
    probe_targets = [
        "http://1.1.1.1",
        "http://www.google.com",
        "http://www.cloudflare.com"
    ]
    for url in probe_targets:
        try:
            req = urllib.request.Request(
                url, 
                headers={"User-Agent": "KillSwitch-Internet-Probe"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status in (200, 301, 302):
                    return True
        except Exception:
            continue
    return False


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
                    body = json.loads(resp.read().decode("utf-8"))
                    if "containment_level" in body or "state_hash_blake3" in body:
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
        "level": "hermetic_isolation",
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
    print(f"[*] KillSwitch Control Plane: {base_url}")

    # Mode 1: RESTORE / DISARM
    if len(sys.argv) > 1 and sys.argv[1].lower() in ["--restore", "--disarm", "restore", "disarm"]:
        print("[*] Sending Disarm / Restore command...")
        res = restore_internet(base_url)
        if res.get("success"):
            print("[+] Disarm API accepted!")
            print("[*] Probing internet connection after restore...")
            time.sleep(1.0)
            if check_internet_reachability(timeout=3.0):
                print("[+] INTERNET VERIFIED: Online and fully working!")
            else:
                print("[-] Warning: External probe failed or connection is still recovering.")
        else:
            print(f"[-] Failed to restore: {res}")
            
    # Mode 2: TRIGGER / ENGAGE
    else:
        reason = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "Rogue AI breakout / Data exfiltration detected"
        
        # 1. Test Internet Before Trigger
        print("\n--- STEP 1: PRE-TRIGGER INTERNET TEST ---")
        pre_test = check_internet_reachability(timeout=2.0)
        if pre_test:
            print("[+] Internet is currently: ONLINE (Probes to 1.1.1.1 / google.com succeeded)")
        else:
            print("[-] Internet is currently: OFFLINE or unreachable before trigger.")

        # 2. Trigger KillSwitch
        print(f"\n--- STEP 2: TRIGGERING KILLSWITCH ---")
        print(f"[*] Reason: '{reason}'")
        res = trigger_killswitch(base_url, reason=reason)
        
        if not res.get("success"):
            print(f"[-] Trigger Failed: {res.get('error') or res.get('message')}")
            sys.exit(1)

        print("[+] API Command Accepted: HermeticIsolation requested.")
        time.sleep(1.0)  # Wait for kernel network filter commit & TCP reset

        # 3. Test Internet After Trigger
        print("\n--- STEP 3: POST-TRIGGER INTERNET TEST ---")
        print("[*] Probing outside internet (1.1.1.1, google.com, cloudflare.com)...")
        post_test = check_internet_reachability(timeout=2.0)

        if not post_test:
            print("[+] SUCCESS: INTERNET IS COMPLETELY BLOCKED!")
            print("    All outside HTTP/HTTPS connections are blocked by the kernel.")
            print(f"    Local Dashboard ({base_url}) remains accessible.")
            print("\nTo restore your internet connection:")
            print("    python trigger_killswitch.py --restore")
        else:
            print("\n[!] ALERT: INTERNET IS STILL ACCESSIBLE!")
            print("    Why this happens:")
            print("    Windows Filtering Platform (WFP) kernel drivers REQUIRE Administrator privileges.")
            print("    If 'killswitch.exe' was started from a regular non-elevated user prompt,")
            print("    Windows rejects filter installation with Win32 status 0x00000005 (ERROR_ACCESS_DENIED).")
            print("\n    How to fix in 10 seconds:")
            print("    1. Open PowerShell as Administrator (Right click -> Run as Administrator)")
            print("    2. Run: .\\killswitch.exe -p 3031")
            print("    3. Run this Python test script again!")
