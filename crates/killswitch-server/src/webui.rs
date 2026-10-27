//! # Embedded Interactive WebUI Dashboard (`GET /` and `GET /ui`)
//!
//! Serves a self-contained, zero-external-dependency HTML5/CSS/JS Dashboard
//! designed for both everyday users (plain-English status, 1-click Internet KillSwitch & Restore,
//! clear "Why Did the KillSwitch Turn On?" root-cause explanation) and security engineers.

use axum::response::Html;

pub async fn get_webui_dashboard() -> Html<&'static str> {
    Html(WEBUI_HTML)
}

pub const WEBUI_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>KillSwitch — Emergency Internet &amp; Data Protection</title>
  <style>
    :root {
      --bg-light: #f1f5f9;
      --bg-dark: #0b0f19;
      --surface-light: #ffffff;
      --surface-dark: #131c31;
      --surface-alt-light: #f8fafc;
      --surface-alt-dark: #1b2742;
      --text-light: #0f172a;
      --text-dark: #f1f5f9;
      --muted-light: #475569;
      --muted-dark: #94a3b8;
      --border-light: #cbd5e1;
      --border-dark: #2a3a5c;
      --brand-light: #0284c7;
      --brand-dark: #38bdf8;
      --danger-light: #dc2626;
      --danger-dark: #ef4444;
      --ok-light: #16a34a;
      --ok-dark: #22c55e;
      --warn-light: #d97706;
      --warn-dark: #f59e0b;

      --bg: var(--bg-light);
      --surface: var(--surface-light);
      --surface-alt: var(--surface-alt-light);
      --text: var(--text-light);
      --muted: var(--muted-light);
      --border: var(--border-light);
      --brand: var(--brand-light);
      --danger: var(--danger-light);
      --ok: var(--ok-light);
      --warn: var(--warn-light);

      color-scheme: light dark;
      accent-color: var(--brand);
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --bg: var(--bg-dark);
        --surface: var(--surface-dark);
        --surface-alt: var(--surface-alt-dark);
        --text: var(--text-dark);
        --muted: var(--muted-dark);
        --border: var(--border-dark);
        --brand: var(--brand-dark);
        --danger: var(--danger-dark);
        --ok: var(--ok-dark);
        --warn: var(--warn-dark);
      }
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.55;
    }

    :where(a:any-link, button, input, select, summary):focus-visible {
      outline: 3px solid var(--brand);
      outline-offset: 3px;
    }

    button, input, select {
      font: inherit;
      min-block-size: 28px;
      min-inline-size: 28px;
      border-radius: 0.55rem;
      border: 1px solid var(--border);
      background: var(--surface-alt);
      color: var(--text);
      padding: 0.6rem 1rem;
    }

    button {
      cursor: pointer;
      font-weight: 700;
      transition: transform 0.08s ease, opacity 0.15s ease;
    }

    button:hover:not(:disabled) {
      opacity: 0.92;
    }

    button:active:not(:disabled) {
      transform: scale(0.99);
    }

    button:disabled {
      opacity: 0.6;
      cursor: wait;
    }

    button[aria-pressed="true"] {
      background: var(--brand);
      color: #0b0f19;
      border-color: var(--brand);
    }

    header {
      background: var(--surface);
      border-block-end: 1px solid var(--border);
      padding: 1rem 1.5rem;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      position: sticky;
      inset-block-start: 0;
      z-index: 20;
    }

    .brand-title {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.75rem;
    }

    .brand-title h1 {
      font-size: 1.3rem;
      margin: 0;
      font-weight: 800;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.3rem 0.8rem;
      border-radius: 999px;
      font-size: 0.82rem;
      font-weight: 700;
      border: 1px solid var(--border);
      background: var(--surface-alt);
    }

    .badge.ok {
      color: var(--ok);
      border-color: var(--ok);
    }

    .badge.danger {
      color: #ffffff;
      background: var(--danger);
      border-color: var(--danger);
    }

    .badge.warn {
      color: var(--warn);
      border-color: var(--warn);
    }

    main {
      max-inline-size: 1180px;
      margin: 0 auto;
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1.35rem;
    }

    /* Big Plain-English Hero Card */
    .hero-card {
      background: var(--surface);
      border: 3px solid var(--ok);
      border-radius: 1rem;
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
    }

    .hero-card.isolated {
      border-color: var(--danger);
      background: color-mix(in srgb, var(--danger) 8%, var(--surface));
    }

    .hero-top {
      display: flex;
      flex-wrap: wrap;
      align-items: flex-start;
      justify-content: space-between;
      gap: 1rem;
    }

    .hero-headline {
      font-size: 1.65rem;
      font-weight: 800;
      margin: 0;
    }

    .hero-sub {
      font-size: 1.05rem;
      color: var(--muted);
      margin: 0.35rem 0 0 0;
    }

    /* Root Cause / "Why did the KillSwitch turn on?" Box */
    .cause-box {
      background: var(--surface-alt);
      border: 2px solid var(--border);
      border-radius: 0.8rem;
      padding: 1.1rem 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.45rem;
    }

    .cause-box.isolated {
      border-color: var(--danger);
    }

    .cause-title {
      font-size: 0.85rem;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
    }

    .cause-main {
      font-size: 1.15rem;
      font-weight: 800;
    }

    .cause-details {
      font-size: 0.96rem;
      color: var(--muted);
    }

    /* Big 1-Click Action Buttons */
    .big-actions {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1rem;
    }

    .big-btn {
      padding: 1.1rem 1.25rem;
      font-size: 1.08rem;
      border-radius: 0.8rem;
      display: flex;
      flex-direction: column;
      align-items: flex-start;
      gap: 0.3rem;
      text-align: start;
    }

    .big-btn span.btn-sub {
      font-size: 0.84rem;
      font-weight: 500;
      opacity: 0.9;
    }

    .big-btn.danger {
      background: var(--danger);
      color: #ffffff;
      border-color: var(--danger);
    }

    .big-btn.ok {
      background: var(--ok);
      color: #052e16;
      border-color: var(--ok);
    }

    .big-btn.primary {
      background: var(--brand);
      color: #0b0f19;
      border-color: var(--brand);
    }

    button.primary {
      background: var(--brand);
      color: #0b0f19;
      border-color: var(--brand);
    }

    button.danger {
      background: var(--danger);
      color: #ffffff;
      border-color: var(--danger);
    }

    button.ok {
      background: var(--ok);
      color: #052e16;
      border-color: var(--ok);
    }

    .grid-2 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(420px, 1fr));
      gap: 1.25rem;
    }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 0.9rem;
      padding: 1.35rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    .card h2 {
      margin: 0;
      font-size: 1.18rem;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem;
    }

    .card-desc {
      margin: -0.4rem 0 0 0;
      font-size: 0.94rem;
      color: var(--muted);
    }

    .kv-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
      gap: 0.75rem;
    }

    .kv-box {
      background: var(--surface-alt);
      border: 1px solid var(--border);
      border-radius: 0.6rem;
      padding: 0.7rem 0.9rem;
    }

    .kv-label {
      font-size: 0.78rem;
      color: var(--muted);
      font-weight: 700;
    }

    .kv-val {
      font-size: 0.98rem;
      font-weight: 700;
      margin-block-start: 0.2rem;
      word-break: break-word;
    }

    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 0.8rem;
    }

    label {
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
      font-size: 0.86rem;
      color: var(--muted);
      font-weight: 700;
    }

    .btn-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.65rem;
      align-items: center;
    }

    .toast {
      padding: 0.85rem 1rem;
      border-radius: 0.6rem;
      border: 2px solid var(--border);
      background: var(--surface-alt);
      font-size: 0.94rem;
      font-weight: 600;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .toast.ok {
      border-color: var(--ok);
    }

    .toast.danger {
      border-color: var(--danger);
      background: color-mix(in srgb, var(--danger) 12%, var(--surface));
    }

    .toast.warn {
      border-color: var(--warn);
    }

    .table-wrapper {
      overflow: auto;
      max-inline-size: 100%;
      max-block-size: 280px;
      border: 1px solid var(--border);
      border-radius: 0.6rem;
    }

    table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      font-size: 0.88rem;
    }

    caption {
      text-align: start;
      padding: 0.55rem 0.85rem;
      font-weight: 700;
      color: var(--muted);
      background: var(--surface-alt);
      border-block-end: 1px solid var(--border);
    }

    th, td {
      padding: 0.6rem 0.85rem;
      text-align: start;
      border-block-end: 1px solid var(--border);
    }

    thead {
      position: sticky;
      inset-block-start: 0;
      background: var(--surface-alt);
    }

    details.advanced-panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 0.9rem;
      padding: 1rem 1.35rem;
    }

    details.advanced-panel > summary {
      cursor: pointer;
      font-weight: 800;
      font-size: 1.05rem;
      padding: 0.25rem 0;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand-title">
      <h1 id="dashboard-heading" tabindex="-1">🛡️ KillSwitch — Personal &amp; Endpoint Protection</h1>
      <span id="isolation-badge" class="badge ok">🟢 INTERNET CONNECTED</span>
      <span id="peers-badge" class="badge ok">🌐 Connected Peers: 0</span>
      <span id="os-badge" class="badge">OS: Detecting...</span>
      <span id="mode-badge" class="badge">Auto-Protection: ON</span>
    </div>
    <div class="btn-row">
      <button type="button" class="primary" onclick="refreshAll(true, this)">🔄 Refresh Status</button>
      <button id="btn-header-peers" type="button" class="danger" onclick="togglePeers(null, this)">🔌 Disable Peers</button>
      <button id="btn-mode-auto" type="button" aria-pressed="true" onclick="toggleMode('autonomous', this)">🤖 Automatic Protection ON</button>
      <button id="btn-mode-manual" type="button" aria-pressed="false" onclick="toggleMode('manual', this)">👤 Ask Me First (Manual)</button>
    </div>
  </header>

  <main>
    <!-- HERO SECTION: Plain-English Status, Root Cause ("What Caused the KillSwitch"), & Giant 1-Click Buttons -->
    <section id="hero-section" class="hero-card" role="region" aria-label="Emergency KillSwitch Control">
      <div class="hero-top">
        <div>
          <h2 id="hero-headline" class="hero-headline">🟢 Your Computer is Safe &amp; Connected to the Internet</h2>
          <p id="hero-subtitle" class="hero-sub">
            KillSwitch is running on its own in the background (no extra antivirus or EDR needed). Your internet works normally.
          </p>
        </div>
        <span id="uptime-pill" class="badge">Running: 0s</span>
      </div>

      <!-- WHAT CAUSED THE KILLSWITCH BOX -->
      <div id="cause-box" class="cause-box" role="status" aria-live="polite" aria-atomic="true">
        <div class="cause-title">🔍 What Caused the KillSwitch? (Current Trigger &amp; Reason)</div>
        <div id="cause-headline" class="cause-main">No Emergency Active — Normal Computer &amp; Internet Operation</div>
        <div id="cause-details" class="cause-details">
          If you click "Disconnect Internet Now" or if an app tries to leak a protected private file, this box will immediately tell you what triggered the KillSwitch and why.
        </div>
      </div>
      <div id="global-alert-bar" role="alert" aria-live="assertive" style="display:none;" class="toast danger"></div>

      <!-- 3 GIANT ONE-CLICK BUTTONS FOR EVERYDAY USERS -->
      <div class="big-actions">
        <button id="btn-engage" type="button" class="big-btn danger" onclick="engageKillSwitch(this)">
          <span>🚨 Disconnect Internet Now (Turn On KillSwitch)</span>
          <span class="btn-sub">Instantly blocks all outside internet access to stop hackers or data leaks. This control page stays open.</span>
        </button>

        <button id="btn-disarm" type="button" class="big-btn ok" onclick="disarmKillSwitch(this)">
          <span>🟢 Reconnect Internet &amp; Restore Normal Use</span>
          <span class="btn-sub">Turns off the KillSwitch, removes all firewall blocks, and brings your internet back immediately.</span>
        </button>

        <button id="btn-probe" type="button" class="big-btn primary" onclick="runHealthProbe(false, this)">
          <span>🩺 Check Computer &amp; App Health</span>
          <span class="btn-sub">Scans running programs on your computer to verify system apps are safe and healthy.</span>
        </button>

        <button id="btn-hero-peers" type="button" class="big-btn danger" onclick="togglePeers(null, this)">
          <span id="btn-hero-peers-title">🔌 Disable Connected Peers (0 Active)</span>
          <span id="btn-hero-peers-sub" class="btn-sub">Instantly disconnects all external peer connections while keeping your local control dashboard open.</span>
        </button>
      </div>

      <div id="card1-status" class="toast">Ready. Click any button above to control your internet protection.</div>

      <!-- Simple 5-box Summary -->
      <div class="kv-grid">
        <div class="kv-box">
          <div class="kv-label">Internet Status</div>
          <div id="st-net" class="kv-val">Connected (Normal)</div>
        </div>
        <div class="kv-box">
          <div class="kv-label">Connected Peers</div>
          <div id="st-peers" class="kv-val">0 Peers (Enabled)</div>
        </div>
        <div class="kv-box">
          <div class="kv-label">Protection Level</div>
          <div id="st-level" class="kv-val">Disarmed (Monitoring)</div>
        </div>
        <div class="kv-box">
          <div class="kv-label">Paused Suspicious Apps</div>
          <div id="st-pids" class="kv-val">0 apps paused</div>
        </div>
        <div class="kv-box">
          <div class="kv-label">Dashboard Port (Always Open)</div>
          <div id="st-ports" class="kv-val">4040</div>
        </div>
      </div>
    </section>

    <div class="grid-2">
      <!-- SIMPLE CARD 1: Private File Leak Protection -->
      <section class="card">
        <h2>
          <span>📁 Private File Leak Protection</span>
          <span id="dlp-counts-badge" class="badge">0 Protected Files</span>
        </h2>
        <p class="card-desc">
          Protect important files (like passwords, tax returns, or company roadmaps). If any app tries to upload a protected file to the internet, KillSwitch automatically blocks it and turns on the KillSwitch.
        </p>

        <div class="btn-row">
          <button type="button" class="primary" onclick="runOneClickLeakDemo(this)">⚡ 1-Click Test: Simulate File Leak &amp; Auto-KillSwitch</button>
          <button type="button" onclick="seedSensitiveFile(this)">➕ Protect File Below</button>
          <button type="button" class="danger" onclick="evaluateLineageEgress(this)">🛡️ Test Upload Check</button>
        </div>

        <div id="card3-status" class="toast">Click "⚡ 1-Click Test: Simulate File Leak &amp; Auto-KillSwitch" to see how KillSwitch catches a file leak and explains what caused it!</div>

        <div class="form-grid">
          <label for="dlp-path">File to Protect
            <input id="dlp-path" type="text" value="C:\Users\Alice\Documents\secret_roadmap.docx">
          </label>
          <label for="dlp-class">Importance Level
            <select id="dlp-class">
              <option value="CrownJewel">Top Secret / Crown Jewel (Auto-Disconnect Internet on Leak)</option>
              <option value="Confidential">Confidential (Block Upload)</option>
              <option value="Internal">Internal (Log Warning)</option>
              <option value="Public">Public (Allow)</option>
            </select>
          </label>
          <label for="dlp-url">Website Attempting Upload
            <input id="dlp-url" type="text" value="https://external-drop.example.com/upload">
          </label>
        </div>

        <!-- Hidden technical fields with defaults kept for full API compatibility -->
        <input id="dlp-sha" type="hidden" value="8f3a9b1c4d2e7a908f3a9b1c4d2e7a908f3a9b1c4d2e7a908f3a9b1c4d2e7a90">
        <input id="dlp-policy" type="hidden" value="Quarantine">
        <input id="dlp-pid" type="hidden" value="5001">

        <div tabindex="0" role="region" aria-labelledby="dlp-files-caption" class="table-wrapper">
          <table>
            <caption id="dlp-files-caption">Currently Protected Private Files</caption>
            <thead>
              <tr>
                <th scope="col">File Path</th>
                <th scope="col">Fingerprint</th>
                <th scope="col">Importance</th>
                <th scope="col">Action on Leak</th>
              </tr>
            </thead>
            <tbody id="dlp-files-tbody">
              <tr><th scope="row" colspan="4">No private files added yet. Click "1-Click Test" or "Protect File Below".</th></tr>
            </tbody>
          </table>
        </div>
      </section>

      <!-- SIMPLE CARD 2: Live App Scanner & Activity Timeline -->
      <section class="card">
        <h2>
          <span>🔍 Standalone App Scanner &amp; Activity History</span>
          <span id="svc-state-badge" class="badge ok">Standalone Active</span>
        </h2>
        <p class="card-desc">
          KillSwitch works 100% independently on Windows, macOS, and Linux without needing any external antivirus or EDR software.
        </p>

        <div class="btn-row">
          <button type="button" class="ok" onclick="scanLiveHostSensor(this)">🔍 Scan Running Apps Now</button>
          <button type="button" class="primary" onclick="ingestEdrEvent(this)">🧪 Test Suspicious App Alert</button>
          <button type="button" onclick="refreshServiceAndHistory(true, this)">🔄 Refresh History</button>
        </div>

        <div id="card4-status" class="toast">Click "🔍 Scan Running Apps Now" to check all running programs on your computer.</div>

        <div tabindex="0" role="region" aria-labelledby="history-caption" class="table-wrapper">
          <table>
            <caption id="history-caption">Recent KillSwitch Events (What Happened &amp; Why)</caption>
            <thead>
              <tr>
                <th scope="col">Action</th>
                <th scope="col">Time</th>
                <th scope="col">Triggered By</th>
                <th scope="col">Why It Happened (Reason)</th>
                <th scope="col">Receipt</th>
              </tr>
            </thead>
            <tbody id="history-tbody">
              <tr><th scope="row" colspan="5">Loading recent activity...</th></tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <!-- SWE-BENCH TWO-GATE (FAIL_TO_PASS + PASS_TO_PASS) ANTI-BLIND-KILLSWITCH CARD -->
    <section class="card" role="region" aria-label="SWE-Bench Two-Gate Anti-Blind-KillSwitch Verification">
      <h2>
        <span>🛡️ Anti-Blind-KillSwitch Guard (SWE-Bench 2-Gate Verification: FAIL_TO_PASS &amp; PASS_TO_PASS)</span>
        <span id="bench-gate-badge" class="badge ok">2-Gate Guard Active (0 FP Required)</span>
      </h2>
      <p class="card-desc">
        Why doesn't KillSwitch blindly disconnect your internet on a false alarm? Before any autonomous rule is allowed to trigger the KillSwitch, it must pass <strong>two SWE-bench gates</strong>:
        <strong>Gate 1 (<code>FAIL_TO_PASS</code>)</strong> proves it catches the real threat, and <strong>Gate 2 (<code>PASS_TO_PASS</code>)</strong> proves it causes <strong>0 false positives</strong> on normal signed system programs (<code>ls_benign.elf</code>, <code>ssh_benign.elf</code>).
      </p>

      <div class="btn-row">
        <button type="button" class="danger" onclick="runSweBenchGate('overbroad_blind', false, this)">🛑 1. Test Bad/Broad Rule (See PASS_TO_PASS Block Blind KillSwitch)</button>
        <button type="button" class="ok" onclick="runSweBenchGate('overbroad_blind', true, this)">✨ 2. Auto-Refine Rule (Compiler Loop Fixes Rule to 0 False Positives)</button>
        <button type="button" class="primary" onclick="runSweBenchGate('surgical_verified', false, this)">✅ 3. Test Verified Multi-Token Rule (Passes Both Gates)</button>
        <button type="button" onclick="refreshEdrBenchTasks(true, this)">📋 Load Tasks (/api/edr-bench/tasks)</button>
      </div>

      <div class="kv-grid">
        <div class="kv-box">
          <div class="kv-label">Gate 1: FAIL_TO_PASS (Catches Threat)</div>
          <div id="bench-f2p" class="kv-val">Ready to Test</div>
        </div>
        <div class="kv-box">
          <div class="kv-label">Gate 2: PASS_TO_PASS (0 False Positives)</div>
          <div id="bench-p2p" class="kv-val">Ready to Test (0 FP Max)</div>
        </div>
        <div class="kv-box">
          <div class="kv-label">KillSwitch Allowed?</div>
          <div id="bench-allowed" class="kv-val">Protected by 2-Gate Guard</div>
        </div>
        <div class="kv-box">
          <div class="kv-label">SWE-Bench Tasks Loaded</div>
          <div id="bench-task-count" class="kv-val">2 Tasks Active</div>
        </div>
      </div>

      <div id="bench-status" class="toast">Click "🛑 1. Test Bad/Broad Rule" above to see how Gate 2 (PASS_TO_PASS) stops a bad rule from blindly triggering the KillSwitch!</div>
    </section>

    <!-- COLLAPSIBLE ADVANCED TECHNICAL SECTION FOR ENGINEERS -->
    <details class="advanced-panel">
      <summary>🔧 Show Advanced Technical Controls (LangGraph Orchestrator, 18-Arm Mesh, Custom Isolation Options &amp; Cryptographic Hashes)</summary>
      <div class="grid-2" style="margin-top: 1.25rem;">
        <section class="card">
          <h2>
            <span>Advanced Containment &amp; OS Service Options</span>
            <span id="octopus-count-badge" class="badge ok">18 Arms Active</span>
          </h2>
          <div class="form-grid">
            <label for="ctl-operator">Operator Name
              <input id="ctl-operator" type="text" value="secops_admin" autocomplete="username">
            </label>
            <label for="ctl-level">Isolation Method
              <select id="ctl-level">
                <option value="hermetic_isolation">Full Isolation (Block Internet + Pause Untrusted Apps)</option>
                <option value="network_quarantine">Block Internet Only</option>
                <option value="process_freeze">Pause Untrusted Apps Only</option>
              </select>
            </label>
            <label for="ctl-reason">Custom Reason Note
              <input id="ctl-reason" type="text" value="Manual emergency disconnect">
            </label>
            <label for="ctl-token">Confirmation Phrase
              <input id="ctl-token" type="text" value="CONFIRM RESTORE">
            </label>
          </div>
          <div class="kv-grid">
            <div class="kv-box">
              <div class="kv-label">BLAKE3 Ledger Hash</div>
              <div id="st-hash" class="kv-val">-</div>
            </div>
            <div class="kv-box">
              <div class="kv-label">Last Operator / Reason</div>
              <div id="st-reason" class="kv-val">-</div>
            </div>
            <div class="kv-box">
              <div class="kv-label">Service / Agent Name</div>
              <div id="svc-name" class="kv-val">killswitch</div>
            </div>
            <div class="kv-box">
              <div class="kv-label">OS Engine &amp; State</div>
              <div id="svc-installed" class="kv-val">-</div>
            </div>
          </div>
          <div class="btn-row">
            <button type="button" onclick="runHealthProbe(true, this)">♻️ Force Early Rollback Probe</button>
            <button type="button" onclick="controlService('status', this)">🔍 Check OS Service</button>
            <button type="button" onclick="controlService('stop', this)">🛑 Disarm &amp; Stop Service</button>
          </div>
          <div id="card5-status" class="toast">Advanced service and cryptographic ledger controls ready.</div>
        </section>

        <section class="card">
          <h2>
            <span>10-Node LangGraph Orchestrator &amp; 18-Arm Mesh</span>
            <span id="graph-valid-badge" class="badge ok">Trace Chain Valid</span>
          </h2>
          <div class="kv-grid">
            <div class="kv-box">
              <div class="kv-label">Current Graph Stage</div>
              <div id="gr-node" class="kv-val">Monitoring</div>
            </div>
            <div class="kv-box">
              <div class="kv-label">Threat Score</div>
              <div id="gr-score" class="kv-val">0.00</div>
            </div>
            <div class="kv-box">
              <div class="kv-label">Threats / Hops</div>
              <div id="gr-threats" class="kv-val">0 / 0</div>
            </div>
            <div class="kv-box">
              <div class="kv-label">Vetoed False Positives</div>
              <div id="gr-fraud" class="kv-val">0</div>
            </div>
          </div>
          <div class="form-grid">
            <label for="gr-force-node">Target Stage
              <select id="gr-force-node">
                <option value="">Auto Next Stage</option>
                <option value="Monitoring">Monitoring</option>
                <option value="IngestingSignals">IngestingSignals</option>
                <option value="CorrelatingEdrAndOctopus">CorrelatingEdrAndOctopus</option>
                <option value="AdjudicatingZeroFalsePositive">AdjudicatingZeroFalsePositive</option>
                <option value="OptionalOllamaReasoning">OptionalOllamaReasoning</option>
                <option value="EngagingContainment">EngagingContainment</option>
                <option value="IsolatedHealthProbing">IsolatedHealthProbing</option>
                <option value="DisarmingAndRestoring">DisarmingAndRestoring</option>
              </select>
            </label>
            <label for="edr-pid">Test App PID
              <input id="edr-pid" type="number" value="8842">
            </label>
            <label for="edr-name">Test App Name
              <input id="edr-name" type="text" value="suspicious_agent.exe">
            </label>
            <label for="edr-cmd">Test Command
              <input id="edr-cmd" type="text" value="suspicious_agent.exe --exfil">
            </label>
          </div>
          <div class="btn-row">
            <button type="button" class="primary" onclick="stepLangGraph(this)">⚡ Step LangGraph Cycle</button>
            <button type="button" onclick="refreshGraph(true, this)">🔄 Refresh Graph</button>
            <button type="button" onclick="resetLangGraph(this)">🔁 Reset Graph</button>
            <button type="button" onclick="refreshOctopus(true, this)">🔄 Refresh 18-Arm Mesh</button>
          </div>
          <div id="action-toast" class="toast">LangGraph state machine ready.</div>
          <div tabindex="0" role="region" aria-labelledby="octopus-caption" class="table-wrapper">
            <table>
              <caption id="octopus-caption">Octopus 18-Arm Containment Mesh</caption>
              <thead>
                <tr>
                  <th scope="col">Arm</th>
                  <th scope="col">Name</th>
                  <th scope="col">Role</th>
                  <th scope="col">Epoch</th>
                </tr>
              </thead>
              <tbody id="octopus-tbody">
                <tr><th scope="row" colspan="4">Loading arms...</th></tr>
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </details>
  </main>

  <script>
    function nowStamp() {
      return new Date().toLocaleTimeString();
    }

    function setCardStatus(cardId, msg, tone) {
      const text = '[' + nowStamp() + '] ' + (typeof msg === 'string' ? msg : JSON.stringify(msg, null, 2));
      if (cardId) {
        const cardEl = document.getElementById(cardId);
        if (cardEl) {
          cardEl.textContent = text;
          cardEl.className = 'toast' + (tone ? ' ' + tone : '');
        }
      }
      const card1 = document.getElementById('card1-status');
      if (card1 && cardId !== 'card1-status') {
        card1.textContent = text;
        card1.className = 'toast' + (tone ? ' ' + tone : '');
      }
      const alertBar = document.getElementById('global-alert-bar');
      if (alertBar) {
        if (tone === 'danger') {
          alertBar.style.display = 'block';
          alertBar.textContent = text;
        } else if (tone === 'ok') {
          alertBar.style.display = 'none';
        }
      }
    }

    async function withButtonFeedback(btn, busyLabel, fn) {
      const origHtml = btn ? btn.innerHTML : '';
      if (btn) {
        btn.disabled = true;
        btn.textContent = busyLabel || '⏳ Working...';
      }
      try {
        return await fn();
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = origHtml;
        }
      }
    }

    async function api(path, opts) {
      const res = await fetch(path, Object.assign({
        headers: { 'Content-Type': 'application/json' }
      }, opts || {}));
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.message || data.error || ('HTTP ' + res.status));
      }
      return data;
    }

    async function refreshStatus() {
      const s = await api('/status');
      const hero = document.getElementById('hero-section');
      const heroHead = document.getElementById('hero-headline');
      const heroSub = document.getElementById('hero-subtitle');
      const causeBox = document.getElementById('cause-box');
      const causeHead = document.getElementById('cause-headline');
      const causeDetails = document.getElementById('cause-details');
      const badge = document.getElementById('isolation-badge');

      const osName = (s.platform_os || 'windows').toUpperCase();
      document.getElementById('os-badge').textContent = 'OS: ' + osName;

      if (s.isolated) {
        hero.className = 'hero-card isolated';
        heroHead.textContent = '🚨 Emergency KillSwitch is ON — Outside Internet is Blocked';
        heroSub.textContent = 'All outside internet traffic is blocked to protect this computer. This dashboard page stays open so you can click "Reconnect Internet" whenever you are ready.';
        badge.textContent = '🚨 INTERNET BLOCKED (KILLSWITCH ON)';
        badge.className = 'badge danger';

        causeBox.className = 'cause-box isolated';
        causeHead.textContent = '🚨 What Triggered the KillSwitch: ' + (s.trigger_cause || 'Emergency Host Isolation');
        causeDetails.textContent =
          (s.trigger_details || ('Reason: ' + (s.reason || 'Manual disconnect'))) +
          (s.isolated_at ? ' | Time: ' + new Date(s.isolated_at).toLocaleTimeString() : '');
      } else {
        hero.className = 'hero-card';
        heroHead.textContent = '🟢 Your Computer is Safe & Connected to the Internet';
        heroSub.textContent = 'KillSwitch is actively protecting your computer on ' + osName + ' (no external antivirus/EDR needed). Your internet is working normally.';
        badge.textContent = '🟢 INTERNET CONNECTED';
        badge.className = 'badge ok';

        causeBox.className = 'cause-box';
        causeHead.textContent = '🟢 No Emergency Active — Normal Internet Operation';
        causeDetails.textContent = s.trigger_details || 'Your internet connection is open and working normally.';
      }

      const activeMode = (s.active_mode || 'autonomous').toLowerCase();
      document.getElementById('mode-badge').textContent =
        activeMode === 'autonomous' ? 'Auto-Protection: ON' : 'Mode: Manual (Ask First)';
      const btnAuto = document.getElementById('btn-mode-auto');
      const btnManual = document.getElementById('btn-mode-manual');
      if (btnAuto && btnManual) {
        btnAuto.setAttribute('aria-pressed', activeMode === 'autonomous' ? 'true' : 'false');
        btnManual.setAttribute('aria-pressed', activeMode === 'manual' ? 'true' : 'false');
      }

      document.getElementById('uptime-pill').textContent = 'Running: ' + s.uptime_secs + 's';
      document.getElementById('st-net').textContent = s.network_isolated
        ? 'Blocked (Protected)'
        : 'Connected (Normal)';
      document.getElementById('st-level').textContent = s.isolated
        ? 'KillSwitch ON (' + s.containment_level + ')'
        : 'Normal Monitoring';
      document.getElementById('st-pids').textContent = s.processes_frozen_count + ' apps paused';
      document.getElementById('st-ports').textContent = (s.allowlisted_ports || []).join(', ');
      document.getElementById('st-hash').textContent = (s.state_hash_blake3 || '').slice(0, 24) + '…';
      document.getElementById('st-reason').textContent = (s.reason || 'Normal') + (s.isolated_by ? ' (' + s.isolated_by + ')' : '');

      updatePeersUi(s.peers_enabled !== false, Number(s.connected_peers_count || 0), s.connected_peer_endpoints || []);
      return s;
    }

    function updatePeersUi(peersEnabled, peersCount, endpoints) {
      window.__peersEnabled = peersEnabled;
      const peersBadge = document.getElementById('peers-badge');
      const stPeers = document.getElementById('st-peers');
      const hdrBtn = document.getElementById('btn-header-peers');
      const heroBtn = document.getElementById('btn-hero-peers');
      const heroTitle = document.getElementById('btn-hero-peers-title');
      const heroSub = document.getElementById('btn-hero-peers-sub');

      if (peersEnabled) {
        if (peersBadge) {
          peersBadge.textContent = '🌐 Connected Peers: ' + peersCount;
          peersBadge.className = 'badge ok';
        }
        if (stPeers) {
          stPeers.textContent = peersCount + ' Connected (Enabled)';
          stPeers.title = (endpoints || []).join(', ');
        }
        if (hdrBtn) {
          hdrBtn.textContent = '🔌 Disable Peers (' + peersCount + ')';
          hdrBtn.className = 'danger';
        }
        if (heroBtn) {
          heroBtn.className = 'big-btn danger';
        }
        if (heroTitle) {
          heroTitle.textContent = '🔌 Disable Connected Peers (' + peersCount + ' Active)';
        }
        if (heroSub) {
          heroSub.textContent = 'Click to immediately disconnect all ' + peersCount + ' external peer connection(s) while keeping this dashboard open.';
        }
      } else {
        if (peersBadge) {
          peersBadge.textContent = '🔌 Peers Disabled (0 Connected)';
          peersBadge.className = 'badge danger';
        }
        if (stPeers) {
          stPeers.textContent = '0 Connected (Disabled)';
          stPeers.title = 'External peer connections are disabled';
        }
        if (hdrBtn) {
          hdrBtn.textContent = '🟢 Enable Peers';
          hdrBtn.className = 'ok';
        }
        if (heroBtn) {
          heroBtn.className = 'big-btn ok';
        }
        if (heroTitle) {
          heroTitle.textContent = '🟢 Enable Connected Peers (Currently Disabled)';
        }
        if (heroSub) {
          heroSub.textContent = 'External peer connections are currently disabled (0 connected). Click to allow peer connections again.';
        }
      }
    }

    async function togglePeers(forceEnabled, btn) {
      const targetEnabled = typeof forceEnabled === 'boolean' ? forceEnabled : !(window.__peersEnabled !== false);
      const busyMsg = targetEnabled ? '🟢 Enabling Peers...' : '🔌 Disconnecting Peers...';
      return withButtonFeedback(btn, busyMsg, async () => {
        try {
          const res = await api('/peers/control', {
            method: 'POST',
            body: JSON.stringify({ enabled: targetEnabled })
          });
          updatePeersUi(res.peers_enabled, Number(res.connected_peers_count || 0), res.connected_peer_endpoints || []);
          await refreshStatus();
          setCardStatus('card1-status', res.message, res.peers_enabled ? 'ok' : 'danger');
        } catch (e) {
          setCardStatus('card1-status', '❌ Could not update peer connections: ' + e.message, 'danger');
        }
      });
    }

    async function refreshGraph(showFeedback, btn) {
      return withButtonFeedback(btn, '⏳ Refreshing...', async () => {
        const g = await api('/graph/state');
        document.getElementById('gr-node').textContent = g.current_node;
        document.getElementById('gr-score').textContent = Number(g.aggregate_threat_score || 0).toFixed(2);
        document.getElementById('gr-threats').textContent = g.active_threats_count + ' threats / ' + g.execution_trace_len + ' steps';
        document.getElementById('gr-fraud').textContent = String(g.vetoed_fraud_proofs_count);
        const vb = document.getElementById('graph-valid-badge');
        vb.textContent = g.trace_chain_valid ? 'Trace Chain Valid' : 'Trace Chain Tampered';
        vb.className = 'badge ' + (g.trace_chain_valid ? 'ok' : 'danger');
        if (showFeedback) {
          setCardStatus('action-toast', '✅ Advanced Graph Refreshed — Current Stage: ' + g.current_node, 'ok');
        }
        return g;
      });
    }

    async function refreshLineage(showFeedback, btn) {
      return withButtonFeedback(btn, '⏳ Refreshing...', async () => {
        const l = await api('/lineage/status');
        document.getElementById('dlp-counts-badge').textContent =
          l.tainted_files_count + ' Protected Files';
        const tbody = document.getElementById('dlp-files-tbody');
        tbody.replaceChildren();
        const files = l.tainted_files || [];
        if (files.length === 0) {
          const tr = document.createElement('tr');
          const th = document.createElement('th');
          th.colSpan = 4;
          th.scope = 'row';
          th.textContent = 'No private files added yet. Click "1-Click Test" or "Protect File Below".';
          tr.appendChild(th);
          tbody.appendChild(tr);
        } else {
          for (const f of files) {
            const tr = document.createElement('tr');
            const th = document.createElement('th');
            th.scope = 'row';
            th.textContent = f.path;
            const tdSha = document.createElement('td');
            tdSha.textContent = (f.sha256 || '').slice(0, 14) + '…';
            const tdClass = document.createElement('td');
            tdClass.textContent = f.classification;
            const tdPol = document.createElement('td');
            tdPol.textContent = f.policy === 'QUARANTINE' ? 'Block & Turn On KillSwitch' : f.policy;
            tr.append(th, tdSha, tdClass, tdPol);
            tbody.appendChild(tr);
          }
        }
        if (showFeedback) {
          setCardStatus('card3-status', '✅ Protected Files List Updated (' + l.tainted_files_count + ' files protected).', 'ok');
        }
        return l;
      });
    }

    async function refreshOctopus(showFeedback, btn) {
      return withButtonFeedback(btn, '⏳ Refreshing...', async () => {
        const o = await api('/octopus/arms');
        document.getElementById('octopus-count-badge').textContent = o.total_arms + ' Arms Active';
        const tbody = document.getElementById('octopus-tbody');
        tbody.replaceChildren();
        for (const arm of (o.arms || [])) {
          const tr = document.createElement('tr');
          const th = document.createElement('th');
          th.scope = 'row';
          th.textContent = 'Arm #' + arm.arm_id;
          const tdName = document.createElement('td');
          tdName.textContent = arm.agent_name;
          const tdRole = document.createElement('td');
          tdRole.textContent = arm.role;
          const tdGen = document.createElement('td');
          tdGen.textContent = 'Gen ' + arm.generation;
          tr.append(th, tdName, tdRole, tdGen);
          tbody.appendChild(tr);
        }
        if (showFeedback) {
          setCardStatus('action-toast', '✅ 18-Arm Containment Mesh Refreshed.', 'ok');
        }
        return o;
      });
    }

    async function refreshServiceAndHistory(showFeedback, btn) {
      return withButtonFeedback(btn, '⏳ Refreshing...', async () => {
        try {
          const sv = await api('/service/status');
          document.getElementById('svc-name').textContent = sv.name + ' (' + sv.display_name + ')';
          document.getElementById('svc-installed').textContent =
            (sv.is_installed ? 'Installed Service' : 'Standalone Mode') + ' / ' + sv.state;
          document.getElementById('svc-state-badge').textContent = 'Standalone Active';
        } catch (_) {}

        const h = await api('/history?limit=15');
        const tbody = document.getElementById('history-tbody');
        tbody.replaceChildren();
        const entries = h.entries || [];
        if (entries.length === 0) {
          const tr = document.createElement('tr');
          const th = document.createElement('th');
          th.colSpan = 5;
          th.scope = 'row';
          th.textContent = 'No events yet.';
          tr.appendChild(th);
          tbody.appendChild(tr);
        } else {
          for (const e of entries) {
            const tr = document.createElement('tr');
            const th = document.createElement('th');
            th.scope = 'row';
            th.textContent = e.action === 'ENGAGE' ? '🚨 KillSwitch Turned ON' : (e.action === 'DISARM' ? '🟢 Internet Restored' : e.action);
            const tdTs = document.createElement('td');
            tdTs.textContent = new Date(e.timestamp).toLocaleTimeString() || e.timestamp;
            const tdOp = document.createElement('td');
            tdOp.textContent = e.operator;
            const tdRe = document.createElement('td');
            tdRe.textContent = e.reason;
            const tdHa = document.createElement('td');
            tdHa.textContent = (e.entry_hash || '').slice(0, 12) + '…';
            tr.append(th, tdTs, tdOp, tdRe, tdHa);
            tbody.appendChild(tr);
          }
        }
        if (showFeedback) {
          setCardStatus('card4-status', '✅ Activity History Updated (' + h.total_entries + ' events recorded).', 'ok');
        }
        return h;
      });
    }

    async function refreshAll(showFeedback, btn) {
      return withButtonFeedback(btn, '⏳ Refreshing...', async () => {
        try {
          const [s] = await Promise.all([
            refreshStatus(),
            refreshGraph(false),
            refreshLineage(false),
            refreshOctopus(false),
            refreshServiceAndHistory(false),
            refreshEdrBenchTasks(false)
          ]);
          if (showFeedback) {
            setCardStatus(
              'card1-status',
              '✅ Status Refreshed — ' + (s.isolated ? '🚨 KillSwitch is ON (Cause: ' + s.trigger_cause + ')' : '🟢 Internet is Connected and Safe.'),
              s.isolated ? 'danger' : 'ok'
            );
          }
        } catch (e) {
          setCardStatus('card1-status', '⚠️ Refresh warning: ' + e.message, 'warn');
        }
      });
    }

    async function toggleMode(mode, btn) {
      return withButtonFeedback(btn, '⏳ Switching...', async () => {
        try {
          await api('/mode', {
            method: 'POST',
            body: JSON.stringify({ mode })
          });
          await refreshAll(false);
          setCardStatus(
            'card1-status',
            mode === 'autonomous'
              ? '🤖 Automatic Protection is ON: KillSwitch will automatically disconnect the internet if a private file leak is detected.'
              : '👤 Manual Mode is ON: KillSwitch will alert you and wait for your click before disconnecting the internet.',
            'ok'
          );
        } catch (e) {
          setCardStatus('card1-status', '❌ Could not change mode: ' + e.message, 'danger');
        }
      });
    }

    async function engageKillSwitch(btn) {
      return withButtonFeedback(btn, '🚨 Disconnecting Internet...', async () => {
        try {
          const res = await api('/engage', {
            method: 'POST',
            body: JSON.stringify({
              operator: document.getElementById('ctl-operator').value || 'user_console',
              reason: document.getElementById('ctl-reason').value || 'Manual emergency disconnect from WebUI',
              level: document.getElementById('ctl-level').value || 'hermetic_isolation',
              token: document.getElementById('ctl-token').value || 'CONFIRM ISOLATE'
            })
          });
          await refreshAll(false);
          setCardStatus(
            'card1-status',
            '🚨 KILLSWITCH TURNED ON: Outside internet is now blocked to protect your computer. Click "🟢 Reconnect Internet" whenever you want to restore normal internet.',
            'danger'
          );
        } catch (e) {
          setCardStatus('card1-status', '❌ Could not turn on KillSwitch: ' + e.message, 'danger');
        }
      });
    }

    async function disarmKillSwitch(btn) {
      return withButtonFeedback(btn, '🟢 Reconnecting Internet...', async () => {
        try {
          await api('/disarm', {
            method: 'POST',
            body: JSON.stringify({
              operator: document.getElementById('ctl-operator').value || 'user_console',
              reason: 'User clicked Reconnect Internet in WebUI',
              token: document.getElementById('ctl-token').value || 'CONFIRM RESTORE'
            })
          });
          await refreshAll(false);
          setCardStatus(
            'card1-status',
            '🟢 INTERNET RECONNECTED: All firewall blocks have been removed and your internet connection is back to normal.',
            'ok'
          );
        } catch (e) {
          setCardStatus('card1-status', '❌ Could not reconnect internet: ' + e.message, 'danger');
        }
      });
    }

    async function runHealthProbe(forceRollback, btn) {
      return withButtonFeedback(btn, '🩺 Checking Computer...', async () => {
        try {
          const res = await api('/health-probe', {
            method: 'POST',
            body: JSON.stringify({ force_rollback: forceRollback })
          });
          await refreshAll(false);
          const r = res.probe_report || {};
          setCardStatus(
            'card1-status',
            '🩺 Computer Health Check Complete: Checked ' + (r.total_processes_scanned || 0) + ' running apps. All ' + (r.critical_os_anchors_verified || 0) + ' core operating system apps are safe and healthy (' + ((r.anomalies || []).length) + ' issues found).',
            'ok'
          );
        } catch (e) {
          setCardStatus('card1-status', '❌ Health check error: ' + e.message, 'danger');
        }
      });
    }

    async function runOneClickLeakDemo(btn) {
      return withButtonFeedback(btn, '⚡ Testing Leak Protection...', async () => {
        try {
          const filePath = document.getElementById('dlp-path').value || 'C:\\Users\\Alice\\Documents\\secret_roadmap.docx';
          const url = document.getElementById('dlp-url').value || 'https://external-drop.example.com/upload';
          const targetPid = 5001;

          await api('/lineage/seed', {
            method: 'POST',
            body: JSON.stringify({
              path: filePath,
              sha256: '8f3a9b1c4d2e7a908f3a9b1c4d2e7a908f3a9b1c4d2e7a908f3a9b1c4d2e7a90',
              classification: 'CrownJewel',
              policy: 'Quarantine',
              pid: targetPid
            })
          });

          const res = await api('/lineage/evaluate', {
            method: 'POST',
            body: JSON.stringify({
              pid: targetPid,
              destination_url: url
            })
          });

          await refreshAll(false);
          setCardStatus(
            'card3-status',
            '🛑 LEAK BLOCKED & KILLSWITCH TRIGGERED!\nWhat Happened: App (PID ' + targetPid + ') tried to upload your protected file "' + filePath + '" to "' + url + '".\nAction Taken: KillSwitch blocked the upload and automatically disconnected the internet! Check the top box to see the full cause, then click "🟢 Reconnect Internet" to restore.',
            'danger'
          );
        } catch (e) {
          setCardStatus('card3-status', '❌ Test error: ' + e.message, 'danger');
        }
      });
    }

    async function seedSensitiveFile(btn) {
      return withButtonFeedback(btn, '➕ Protecting File...', async () => {
        try {
          const targetPid = Number(document.getElementById('dlp-pid').value || 5001);
          const fileClass = document.getElementById('dlp-class').value;
          const policy = (fileClass === 'CrownJewel' || fileClass === 'Confidential') ? 'Quarantine' : 'Audit';
          const res = await api('/lineage/seed', {
            method: 'POST',
            body: JSON.stringify({
              path: document.getElementById('dlp-path').value,
              sha256: document.getElementById('dlp-sha').value,
              classification: fileClass,
              policy: policy,
              pid: targetPid
            })
          });
          await refreshLineage(false);
          setCardStatus(
            'card3-status',
            '✅ File Protected: "' + res.path + '" is now watched by KillSwitch. If any app tries to upload it, it will be blocked.',
            'ok'
          );
        } catch (e) {
          setCardStatus('card3-status', '❌ Could not protect file: ' + e.message, 'danger');
        }
      });
    }

    async function evaluateLineageEgress(btn) {
      return withButtonFeedback(btn, '🛡️ Checking Upload...', async () => {
        try {
          const pid = Number(document.getElementById('dlp-pid').value || 5001);
          const url = document.getElementById('dlp-url').value;
          const res = await api('/lineage/evaluate', {
            method: 'POST',
            body: JSON.stringify({
              pid: pid,
              destination_url: url
            })
          });
          await refreshAll(false);
          if (res.is_block) {
            setCardStatus(
              'card3-status',
              '🛑 UPLOAD BLOCKED! App (PID ' + pid + ') was stopped from sending a protected ' + res.classification + ' file to "' + url + '"' +
              (res.autonomous_killswitch_triggered ? ' — Automatic KillSwitch Turned ON!' : '.'),
              'danger'
            );
          } else {
            setCardStatus(
              'card3-status',
              '🟢 UPLOAD ALLOWED: No protected private files were touched by PID ' + pid + '.',
              'ok'
            );
          }
        } catch (e) {
          setCardStatus('card3-status', '❌ Upload check error: ' + e.message, 'danger');
        }
      });
    }

    async function scanLiveHostSensor(btn) {
      return withButtonFeedback(btn, '🔍 Scanning Apps...', async () => {
        try {
          const res = await api('/edr/ingest', {
            method: 'POST',
            body: JSON.stringify({
              event_id: 'scan-' + Date.now(),
              event_kind: 'ProcessCreate',
              pid: Number(document.getElementById('edr-pid').value || 8842),
              process_name: 'standalone_os_sensor',
              scan_live_host: true
            })
          });
          await refreshAll(false);
          setCardStatus(
            'card4-status',
            '✅ Scan Complete: Checked ' + res.live_processes_scanned + ' running programs on your computer (' + res.critical_anchors_verified + ' core system apps verified safe). Works 100% independently.',
            'ok'
          );
        } catch (e) {
          setCardStatus('card4-status', '❌ Scan error: ' + e.message, 'danger');
        }
      });
    }

    async function ingestEdrEvent(btn) {
      return withButtonFeedback(btn, '🧪 Testing Alert...', async () => {
        try {
          const pid = Number(document.getElementById('edr-pid').value || 8842);
          const name = document.getElementById('edr-name').value || 'suspicious_agent.exe';
          const cmd = document.getElementById('edr-cmd').value || name;
          const res = await api('/edr/ingest', {
            method: 'POST',
            body: JSON.stringify({
              event_id: 'evt-' + Date.now(),
              event_kind: 'ProcessCreate',
              pid: pid,
              process_name: name,
              image_path: 'C:\\Temp\\' + name,
              command_line: cmd,
              scan_live_host: false
            })
          });
          await refreshAll(false);
          setCardStatus(
            'card4-status',
            '🧪 Simulated Suspicious App Checked: "' + name + '" (PID ' + pid + ') — Risk Score: ' + Number(res.correlator_score || 0).toFixed(2) + ' (Scanned ' + res.live_processes_scanned + ' total running programs).',
            'warn'
          );
        } catch (e) {
          setCardStatus('card4-status', '❌ Test alert error: ' + e.message, 'danger');
        }
      });
    }

    async function stepLangGraph(btn) {
      return withButtonFeedback(btn, '⚡ Stepping...', async () => {
        try {
          const forceNode = document.getElementById('gr-force-node').value || null;
          const res = await api('/graph/step', {
            method: 'POST',
            body: JSON.stringify({ force_node: forceNode })
          });
          await refreshAll(false);
          setCardStatus('action-toast', '⚡ Advanced Graph Step: ' + res.summary, 'ok');
        } catch (e) {
          setCardStatus('action-toast', '❌ Graph step error: ' + e.message, 'danger');
        }
      });
    }

    async function resetLangGraph(btn) {
      return withButtonFeedback(btn, '🔁 Resetting...', async () => {
        try {
          const res = await api('/graph/step', {
            method: 'POST',
            body: JSON.stringify({ force_node: 'Monitoring' })
          });
          document.getElementById('gr-force-node').value = '';
          await refreshAll(false);
          setCardStatus('action-toast', '🔁 Graph Reset to Monitoring.', 'ok');
        } catch (e) {
          setCardStatus('action-toast', '❌ Graph reset error: ' + e.message, 'danger');
        }
      });
    }

    async function controlService(action, btn) {
      return withButtonFeedback(btn, '⏳ Working...', async () => {
        try {
          if (action === 'status') {
            const sv = await api('/service/status');
            await refreshServiceAndHistory(false);
            setCardStatus('card5-status', '🔍 Service Status: ' + sv.state + ' (' + (sv.is_installed ? 'Installed OS Service' : 'Running Standalone') + ')', 'ok');
            return;
          }
          const res = await api('/service/control', {
            method: 'POST',
            body: JSON.stringify({ action: action, service_name: 'killswitch' })
          });
          await refreshAll(false);
          setCardStatus('card5-status', '✅ Service action "' + action + '" finished (' + res.resulting_status.state + ').', 'ok');
        } catch (e) {
          setCardStatus('card5-status', '❌ Service error: ' + e.message, 'danger');
        }
      });
    }

    async function refreshEdrBenchTasks(showFeedback, btn) {
      return withButtonFeedback(btn, '📋 Loading Tasks...', async () => {
        try {
          const data = await api('/api/edr-bench/tasks');
          const tasks = data.tasks || [];
          const ids = tasks.map(t => t.instance_id).join(', ');
          const el = document.getElementById('bench-task-count');
          if (el) {
            el.textContent = tasks.length + ' Tasks (' + ids + ')';
          }
          if (showFeedback) {
            setCardStatus(
              'bench-status',
              '📋 Loaded ' + tasks.length + ' SWE-Bench Tasks from /api/edr-bench/tasks: ' + ids + ' — Paradigm: ' + data.paradigm,
              'ok'
            );
          }
          return data;
        } catch (e) {
          if (showFeedback) {
            setCardStatus('bench-status', '❌ Failed to load tasks: ' + e.message, 'danger');
          }
        }
      });
    }

    async function runSweBenchGate(preset, autoRefine, btn) {
      return withButtonFeedback(btn, '🛡️ Running 2-Gate Check...', async () => {
        try {
          const res = await api('/api/edr-bench/evaluate', {
            method: 'POST',
            body: JSON.stringify({
              preset: preset,
              auto_refine: autoRefine,
              max_iterations: 3,
              engage_if_promoted: false
            })
          });

          const f2pEl = document.getElementById('bench-f2p');
          const p2pEl = document.getElementById('bench-p2p');
          const allowEl = document.getElementById('bench-allowed');
          const badgeEl = document.getElementById('bench-gate-badge');

          f2pEl.textContent = res.fail_to_pass_succeeded ? '✅ PASS (Caught Threat)' : '❌ FAIL (Missed Threat)';
          p2pEl.textContent = res.pass_to_pass_succeeded
            ? '✅ PASS (0 False Positives)'
            : '🛑 FAIL (' + res.false_positive_count + ' False Positives: ' + (res.false_positive_files || []).join(', ') + ')';

          if (res.promoted_to_production) {
            allowEl.textContent = '✅ YES (Verified Safe — ' + res.iterations_used + ' iter)';
            badgeEl.textContent = '✅ Both Gates Passed (0 FP)';
            badgeEl.className = 'badge ok';
            setCardStatus(
              'bench-status',
              res.gate_verdict_summary + '\nCryptographic Receipt: ' + (res.bft_promotion_receipt || '').slice(0, 64) + '…',
              'ok'
            );
          } else {
            allowEl.textContent = '🛑 VETOED (Blind KillSwitch Prevented!)';
            badgeEl.textContent = '🛑 Blind KillSwitch Blocked by PASS_TO_PASS';
            badgeEl.className = 'badge danger';
            setCardStatus('bench-status', res.gate_verdict_summary, 'danger');
          }
        } catch (e) {
          setCardStatus('bench-status', '❌ SWE-Bench evaluation error: ' + e.message, 'danger');
        }
      });
    }

    refreshAll(false);
    setInterval(() => refreshAll(false), 5000);
  </script>
</body>
</html>
"#;
