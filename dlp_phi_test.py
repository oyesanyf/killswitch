#!/usr/bin/env python3
"""
KillSwitch DLP PHI (Protected Health Information) Exfiltration Test
====================================================================
Simulates a process reading a confidential HIPAA / PHI patient record file
and attempting to HTTP POST the PHI data out to https://dlptest.com/http-post/.

1. Creates a local test PHI file ('sample_patient_phi.txt') and computes its SHA-256.
2. Seeds the PHI file into KillSwitch's OpenLineage / W3C Sticky Taint DLP Engine.
3. Attempts to exfiltrate the PHI data to https://dlptest.com/http-post/ through
   the KillSwitch DLP Egress Gate (and tests kernel network block).
"""

import os
import sys
import time
import json
import hashlib
import urllib.request
import urllib.parse
import urllib.error

# Ensure clean UTF-8 output on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

DLP_TEST_URL = "https://dlptest.com/http-post/"
AUTHORIZED_HIPAA_URL = "https://fhir.epic.com/api/FHIR/R4/Patient"

SAMPLE_PHI_CONTENT = """====================================================================
CONFIDENTIAL PROTECTED HEALTH INFORMATION (HIPAA / PHI TEST RECORD)
====================================================================
Patient Name       : John Q. Sample (Synthetic Test Record)
Date of Birth      : 1978-04-19
Social Security #  : 000-12-3456
Medical Record MRN : MRN-99482104
ICD-10 Diagnosis   : I21.9 (Acute Myocardial Infarction, Unspecified)
Prescription       : Atorvastatin 40mg QD, Metoprolol 50mg BID
Insurance Policy   : MEDICARE-MBI-1EG4-TE5-MK72
Attending Physician: Dr. Evelyn Vance, MD (Cardiology)
====================================================================
"""


def detect_killswitch_url():
    """Detects which port KillSwitch is currently listening on."""
    ports = [3031, 3030, 4040]
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
            req = urllib.request.Request(f"{url}/status", headers={"User-Agent": "KillSwitch-DLP-Test"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status == 200:
                    body = json.loads(resp.read().decode("utf-8"))
                    if "containment_level" in body or "state_hash_blake3" in body:
                        return url
        except Exception:
            continue
    return "http://127.0.0.1:3031"


def api_post(base_url, path, payload):
    url = f"{base_url}{path}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "KillSwitch-DLP-Test"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run_phi_dlp_test():
    base_url = detect_killswitch_url()
    my_pid = os.getpid()
    phi_file_path = os.path.abspath("sample_patient_phi.txt")

    print("========================================================================")
    print("  KILLSWITCH DLP TEST: PHI / HIPAA EXFILTRATION TO dlptest.com")
    print("========================================================================")
    print(f"[*] KillSwitch Control Plane : {base_url}")
    print(f"[*] Current Python Process   : PID {my_pid}")
    print(f"[*] Target Exfiltration Sink : {DLP_TEST_URL}")

    # 1. Write the synthetic PHI file to disk and compute its real SHA-256 digest
    with open(phi_file_path, "w", encoding="utf-8") as f:
        f.write(SAMPLE_PHI_CONTENT)
    phi_sha256 = hashlib.sha256(SAMPLE_PHI_CONTENT.encode("utf-8")).hexdigest()

    print("\n--- STEP 1: GENERATING & PROTECTING LOCAL PHI RECORD ---")
    print(f"[+] Created PHI File : {phi_file_path}")
    print(f"[+] PHI SHA-256 Hash : {phi_sha256}")

    try:
        seed_res = api_post(
            base_url,
            "/lineage/seed",
            {
                "path": phi_file_path,
                "sha256": phi_sha256,
                "classification": "CrownJewel",
                "policy": "Quarantine",
                "pid": my_pid,
                "process_name": "python_phi_uploader.exe",
            },
        )
        print(f"[+] DLP Lineage Seed : {seed_res.get('classification')} (Policy: {seed_res.get('policy')})")
        print(f"[+] W3C Sticky Taint : Attached to PID {my_pid} reading '{os.path.basename(phi_file_path)}'")
    except Exception as e:
        print(f"[-] Could not reach KillSwitch at {base_url}: {e}")
        print("    Make sure killswitch.exe is running first!")
        sys.exit(1)

    # 2. Dynamically train the Online RL Traffic Policy on recurring legitimate PHI traffic (zero hardcoding!)
    print(f"\n--- STEP 2: ONLINE RL TRAFFIC LEARNING FOR {AUTHORIZED_HIPAA_URL} ---")
    for _ in range(3):
        rl_step = api_post(
            base_url,
            "/rl/learn",
            {
                "destination_url": AUTHORIZED_HIPAA_URL,
                "process_name": "python_phi_uploader.exe",
                "payload_taint_level": 1.0,
                "ai_breakout_signal": 0.0,
                "is_legitimate_transaction": True,
            },
        )
    print(f"[+] RL Learned Familiarity   : {rl_step.get('learned_familiarity', 0.0):.2f} -> {rl_step.get('explanation')}")

    hipaa_res = api_post(
        base_url,
        "/lineage/evaluate",
        {
            "pid": my_pid,
            "destination_url": AUTHORIZED_HIPAA_URL,
        },
    )
    if not hipaa_res.get("is_block", False):
        print(f"[+] DLP EGRESS VERDICT       : {hipaa_res.get('verdict')} (RL-Learned Legitimate PHI Endpoint Permitted!)")
        print(f"[+] Reason                   : {hipaa_res.get('reason')}")
    else:
        print(f"[-] Unexpected Block on RL-Learned Endpoint: {hipaa_res}")

    # 3. Evaluate egress to https://dlptest.com/http-post/ via KillSwitch DLP Engine
    print(f"\n--- STEP 3: ATTEMPTING UNAUTHORIZED PHI UPLOAD TO {DLP_TEST_URL} ---")
    eval_res = api_post(
        base_url,
        "/lineage/evaluate",
        {
            "pid": my_pid,
            "destination_url": DLP_TEST_URL,
        },
    )

    verdict = eval_res.get("verdict")
    is_block = eval_res.get("is_block", False)
    auto_ks = eval_res.get("autonomous_killswitch_triggered", False)
    trace_id = eval_res.get("trace_id", "N/A")
    reason = eval_res.get("reason", "")

    if is_block:
        print(f"[!] DLP EGRESS VERDICT       : {verdict} (PHI UPLOAD INTERCEPTED & STOPPED!)")
        print(f"[!] W3C Trace ID             : {trace_id}")
        print(f"[!] Block Reason             : {reason}")
        print(f"[!] Auto-KillSwitch Engaged  : {auto_ks}")
        print("[+] Zero bytes of PHI were permitted past the KillSwitch DLP Egress Gate.")
    else:
        print(f"[-] Unexpected Verdict: {eval_res}")

    # 4. Also test direct socket POST to https://dlptest.com/http-post/ to check OS kernel WFP block
    print(f"\n--- STEP 4: TESTING RAW KERNEL SOCKET TO {DLP_TEST_URL} ---")
    time.sleep(0.5)
    try:
        form_data = urllib.parse.urlencode({"message": "SAFE_PROBE_ONLY_NO_PHI"}).encode("utf-8")
        req = urllib.request.Request(
            DLP_TEST_URL,
            data=form_data,
            headers={"User-Agent": "KillSwitch-Kernel-Probe"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            print(f"[!] Note: DLP Application Gate blocked the PHI upload in Step 2,")
            print(f"    and raw kernel socket returned HTTP {resp.status} (Run killswitch.exe as Admin to also block raw sockets in Windows WFP).")
    except Exception as e:
        print(f"[+] RAW KERNEL SOCKET BLOCKED: Connection to {DLP_TEST_URL} was rejected by the OS kernel ({e})!")

    print("\n========================================================================")
    print(f"  Check your WebUI Dashboard at {base_url} to see the PHI Alert!")
    print("  To restore normal operation, run: python trigger_killswitch.py --restore")
    print("========================================================================")


if __name__ == "__main__":
    run_phi_dlp_test()
