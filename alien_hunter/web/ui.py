"""
Embedded Single-Page UI for Alien Hunter Web Interface.
Zero-dependency, client-side rendered HTML5/CSS/JavaScript dashboard.
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Alien Hunter // Sentinel Dashboard</title>
<style>
:root {
  --bg-primary: #0a0d14;
  --bg-card: #121824;
  --bg-elevated: #1a2234;
  --border: #232e42;
  --text-main: #e2e8f0;
  --text-dim: #94a3b8;
  --accent-green: #10b981;
  --accent-cyan: #06b6d4;
  --accent-red: #ef4444;
  --accent-amber: #f59e0b;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background-color: var(--bg-primary);
  color: var(--text-main);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", monospace, sans-serif;
  line-height: 1.5;
  padding: 16px;
}
.container { max-width: 1200px; margin: 0 auto; }
header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 20px;
  gap: 12px;
}
.brand { display: flex; align-items: center; gap: 10px; }
.brand h1 { font-size: 1.4rem; font-weight: 700; letter-spacing: 1px; color: var(--text-main); }
.brand span { color: var(--accent-cyan); }
.status-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 9999px;
  font-size: 0.8rem;
  font-weight: 600;
  background: rgba(16, 185, 129, 0.15);
  color: var(--accent-green);
  border: 1px solid rgba(16, 185, 129, 0.3);
}
.status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent-green); box-shadow: 0 0 8px var(--accent-green); }
.controls { display: flex; align-items: center; gap: 10px; }
button, select, input {
  background: var(--bg-card);
  color: var(--text-main);
  border: 1px solid var(--border);
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 0.85rem;
  cursor: pointer;
  outline: none;
}
button:hover { background: var(--bg-elevated); border-color: var(--accent-cyan); }
.btn-primary {
  background: rgba(6, 182, 212, 0.15);
  color: var(--accent-cyan);
  border-color: rgba(6, 182, 212, 0.4);
  font-weight: 600;
}
.btn-primary:hover { background: rgba(6, 182, 212, 0.3); }
.btn-success {
  background: rgba(16, 185, 129, 0.15);
  color: var(--accent-green);
  border-color: rgba(16, 185, 129, 0.4);
  font-weight: 600;
}
.btn-success:hover { background: rgba(16, 185, 129, 0.3); }
.grid-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 14px;
  margin-bottom: 24px;
}
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
}
.card-title { font-size: 0.75rem; text-transform: uppercase; color: var(--text-dim); letter-spacing: 0.5px; margin-bottom: 6px; }
.card-val { font-size: 1.5rem; font-weight: 700; color: var(--text-main); }
.card-sub { font-size: 0.78rem; color: var(--text-dim); margin-top: 4px; }
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  margin: 2px 4px 2px 0;
}
.badge-active { background: rgba(16, 185, 129, 0.15); color: var(--accent-green); border: 1px solid rgba(16, 185, 129, 0.3); }
.badge-inactive { background: rgba(148, 163, 184, 0.1); color: var(--text-dim); border: 1px solid var(--border); }
.badge-red { background: rgba(239, 68, 68, 0.15); color: var(--accent-red); border: 1px solid rgba(239, 68, 68, 0.3); }
.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin: 24px 0 12px 0;
  gap: 10px;
}
.section-title { font-size: 1.1rem; font-weight: 600; display: flex; align-items: center; gap: 8px; }
.alien-panel {
  border-color: rgba(239, 68, 68, 0.4);
  background: rgba(239, 68, 68, 0.03);
  margin-bottom: 24px;
}
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
th { color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; background: var(--bg-card); }
tr:hover { background: rgba(255, 255, 255, 0.02); }
.mono { font-family: monospace; }
.ports-list { font-size: 0.78rem; color: var(--accent-cyan); font-family: monospace; }
.empty-msg { padding: 24px; text-align: center; color: var(--text-dim); font-size: 0.9rem; }
.modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.7);
  backdrop-filter: blur(2px);
  align-items: center;
  justify-content: center;
  z-index: 50;
  padding: 16px;
}
.modal {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  max-width: 480px;
  width: 100%;
  padding: 20px;
  box-shadow: 0 10px 25px rgba(0,0,0,0.5);
}
.modal h3 { margin-bottom: 14px; font-size: 1.1rem; }
.form-group { margin-bottom: 12px; }
.form-group label { display: block; font-size: 0.8rem; color: var(--text-dim); margin-bottom: 4px; }
.form-group input, .form-group select { width: 100%; padding: 8px 10px; font-size: 0.9rem; }
.modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 18px; }
.toast {
  position: fixed;
  bottom: 20px;
  right: 20px;
  padding: 12px 18px;
  border-radius: 6px;
  font-size: 0.85rem;
  font-weight: 600;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  box-shadow: 0 4px 12px rgba(0,0,0,0.4);
  transform: translateY(100px);
  opacity: 0;
  transition: all 0.25s ease;
  z-index: 100;
}
.toast.show { transform: translateY(0); opacity: 1; }
.threat-box {
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: 6px;
  padding: 12px;
  margin-bottom: 16px;
  color: #fca5a5;
  font-size: 0.85rem;
}
.threat-box ul { margin-left: 20px; margin-top: 6px; }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">
      <h1>ALIEN<span>HUNTER</span></h1>
      <div id="statusPill" class="status-pill">
        <span class="status-dot"></span>
        <span id="daemonStatusText">ONLINE</span>
      </div>
    </div>
    <div class="controls">
      <select id="pollIntervalSelect" onchange="updatePolling()">
        <option value="15">Auto-refresh (15s)</option>
        <option value="30" selected>Auto-refresh (30s)</option>
        <option value="60">Auto-refresh (60s)</option>
        <option value="0">Manual only</option>
      </select>
      <button class="btn-primary" onclick="fetchData()">🔄 Refresh</button>
    </div>
  </header>

  <div id="threatSection" style="display: none;" class="threat-box">
    <strong>⚠️ Active Threats Detected:</strong>
    <ul id="threatList"></ul>
  </div>

  <div class="grid-stats">
    <div class="card">
      <div class="card-title">Daemon Uptime</div>
      <div class="card-val" id="valUptime">--</div>
      <div class="card-sub" id="valLastScan">Last scan: --</div>
    </div>
    <div class="card">
      <div class="card-title">Network Interface</div>
      <div class="card-val mono" id="valIface" style="font-size: 1.2rem;">--</div>
      <div class="card-sub" id="valGateway">Gateway: --</div>
    </div>
    <div class="card">
      <div class="card-title">Trusted Devices</div>
      <div class="card-val" style="color: var(--accent-green);" id="valTrustedCount">0</div>
      <div class="card-sub">In known_devices.json</div>
    </div>
    <div class="card">
      <div class="card-title">Unrecognized / Alien</div>
      <div class="card-val" style="color: var(--accent-red);" id="valAlienCount">0</div>
      <div class="card-sub">Untrusted devices on LAN</div>
    </div>
  </div>

  <div class="card" style="margin-bottom: 24px;">
    <div class="card-title" style="margin-bottom: 8px;">Active Intrusion Guards</div>
    <div id="defensesBadges">Loading defensive posture...</div>
  </div>

  <div class="card alien-panel" id="alienPanel" style="display: none;">
    <div class="section-header" style="margin: 0 0 12px 0;">
      <div class="section-title" style="color: var(--accent-red);">
        <span>👽 Unrecognized Devices Outside Whitelist</span>
        <span class="badge badge-red" id="alienBadgeCount">0</span>
      </div>
    </div>
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th>IP Address</th>
            <th>MAC Address</th>
            <th>Vendor</th>
            <th>Hostname / Discovery</th>
            <th>Open Ports</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="alienTableBody"></tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <div class="section-header" style="margin: 0 0 12px 0;">
      <div class="section-title">
        <span>🛡️ Trusted Device Whitelist</span>
        <span class="badge badge-active" id="trustedBadgeCount">0</span>
      </div>
      <div>
        <input type="text" id="whitelistSearch" placeholder="Search devices..." oninput="renderTrustedTable()">
      </div>
    </div>
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th>Name / Owner</th>
            <th>Primary IP</th>
            <th>MAC Address</th>
            <th>Vendor</th>
            <th>Ports & Services</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody id="trustedTableBody"></tbody>
      </table>
    </div>
  </div>
</div>

<div class="modal-overlay" id="whitelistModal">
  <div class="modal">
    <h3>Trust / Whitelist Device</h3>
    <form id="whitelistForm" onsubmit="submitWhitelist(event)">
      <div class="form-group">
        <label>MAC Address</label>
        <input type="text" id="formMac" readonly class="mono" style="opacity: 0.7;">
      </div>
      <div class="form-group">
        <label>Primary IP</label>
        <input type="text" id="formIp" readonly class="mono" style="opacity: 0.7;">
      </div>
      <div class="form-group">
        <label>Friendly Device Name</label>
        <input type="text" id="formName" required placeholder="e.g. My Phone, Office Printer">
      </div>
      <div class="form-group">
        <label>Owner / Department</label>
        <input type="text" id="formOwner" value="User" placeholder="e.g. Alice, Network Admin">
      </div>
      <div class="form-group">
        <label>Device Type</label>
        <select id="formType">
          <option value="Phone / Mobile">Phone / Mobile</option>
          <option value="Workstation / Laptop">Workstation / Laptop</option>
          <option value="Server / NAS">Server / NAS</option>
          <option value="IoT / Smart Device">IoT / Smart Device</option>
          <option value="Gateway / Switch">Gateway / Switch</option>
          <option value="Printer">Printer</option>
          <option value="Generic" selected>Generic Host</option>
        </select>
      </div>
      <div class="modal-actions">
        <button type="button" onclick="closeModal()">Cancel</button>
        <button type="submit" class="btn-success">✔ Add to Whitelist</button>
      </div>
    </form>
  </div>
</div>

<div class="toast" id="toastMsg"></div>

<script>
let pollTimer = null;
let cachedTrusted = [];
let cachedAlien = [];

async function fetchData() {
  try {
    const [resStatus, resDevices] = await Promise.all([
      fetch('/api/status').then(r => r.json()),
      fetch('/api/devices').then(r => r.json())
    ]);

    // Status updates
    document.getElementById('valUptime').textContent = resStatus.uptime_human || '--';
    if (resStatus.seconds_since_last_scan !== null && resStatus.seconds_since_last_scan !== undefined) {
      document.getElementById('valLastScan').textContent = `Last scan: ${resStatus.seconds_since_last_scan}s ago`;
    } else {
      document.getElementById('valLastScan').textContent = 'Last scan: In progress...';
    }

    const net = resStatus.network || {};
    document.getElementById('valIface').textContent = net.interface || 'auto';
    document.getElementById('valGateway').textContent = `Gateway: ${net.gateway_ip || 'N/A'}`;
    document.getElementById('valTrustedCount').textContent = resStatus.counts.trusted_devices;
    document.getElementById('valAlienCount').textContent = resStatus.counts.alien_devices;

    // Defense badges
    const defs = resStatus.active_defenses || {};
    const badgeMap = [
      { key: 'honey_ports', label: 'Honey-Ports', detail: defs.honey_ports ? defs.honey_ports.join(',') : '' },
      { key: 'syn_scan', label: 'Stealth SYN Scan' },
      { key: 'dns_tunneling', label: 'DNS Tunneling' },
      { key: 'dhcp_starvation', label: 'DHCP Starvation' },
      { key: 'arp_poison', label: 'ARP Poison Guard' }
    ];
    let badgesHtml = '';
    badgeMap.forEach(b => {
      const active = Boolean(defs[b.key]);
      const cls = active ? 'badge-active' : 'badge-inactive';
      const mark = active ? '● ' : '○ ';
      const extra = b.detail ? ` (${b.detail})` : '';
      badgesHtml += `<span class="badge ${cls}">${mark}${b.label}${extra}</span>`;
    });
    document.getElementById('defensesBadges').innerHTML = badgesHtml;

    // Threats
    const threats = resStatus.recent_threats || [];
    const threatBox = document.getElementById('threatSection');
    const threatList = document.getElementById('threatList');
    if (threats.length > 0) {
      threatBox.style.display = 'block';
      threatList.innerHTML = threats.map(t => `<li>${escapeHtml(t)}</li>`).join('');
    } else {
      threatBox.style.display = 'none';
      threatList.innerHTML = '';
    }

    // Devices
    cachedTrusted = resDevices.trusted || [];
    cachedAlien = resDevices.alien || [];

    renderAlienTable();
    renderTrustedTable();
  } catch (err) {
    document.getElementById('daemonStatusText').textContent = 'CONNECTING...';
    document.getElementById('statusPill').style.borderColor = 'rgba(245, 158, 11, 0.4)';
  }
}

function renderAlienTable() {
  const panel = document.getElementById('alienPanel');
  const tbody = document.getElementById('alienTableBody');
  document.getElementById('alienBadgeCount').textContent = cachedAlien.length;

  if (cachedAlien.length === 0) {
    panel.style.display = 'none';
    tbody.innerHTML = '';
    return;
  }

  panel.style.display = 'block';
  tbody.innerHTML = cachedAlien.map(dev => {
    const ports = (dev.open_ports || []).join(', ') || 'None open';
    return `
      <tr>
        <td class="mono" style="font-weight: 600;">${dev.ip}</td>
        <td class="mono">${dev.mac}</td>
        <td>${escapeHtml(dev.vendor || 'Unknown')}</td>
        <td>${escapeHtml(dev.hostname || dev.discovery_method || 'Unknown')}</td>
        <td class="ports-list">${escapeHtml(ports)}</td>
        <td>
          <button class="btn-success" onclick="openWhitelistModal('${dev.mac}', '${dev.ip}', '${escapeHtml(dev.hostname || dev.vendor || '')}')">
            ➕ Whitelist
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function renderTrustedTable() {
  const tbody = document.getElementById('trustedTableBody');
  const query = (document.getElementById('whitelistSearch').value || '').toLowerCase().trim();
  document.getElementById('trustedBadgeCount').textContent = cachedTrusted.length;

  const filtered = cachedTrusted.filter(dev => {
    if (!query) return true;
    const name = (dev.name || dev.hostname || '').toLowerCase();
    const owner = (dev.owner || '').toLowerCase();
    const ip = (dev.ip || dev.primary_ip || '').toLowerCase();
    const mac = (dev.mac || '').toLowerCase();
    const vendor = (dev.vendor || '').toLowerCase();
    return name.includes(query) || owner.includes(query) || ip.includes(query) || mac.includes(query) || vendor.includes(query);
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-msg">${cachedTrusted.length === 0 ? 'No trusted devices recorded yet.' : 'No devices match your search query.'}</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(dev => {
    const name = dev.name || dev.hostname || 'Device';
    const owner = dev.owner ? ` <span style="color: var(--text-dim); font-size: 0.75rem;">(${dev.owner})</span>` : '';
    const ip = dev.ip || dev.primary_ip || '--';
    const aliases = (dev.aliases && dev.aliases.length > 0) ? `<div style="font-size: 0.7rem; color: var(--text-dim);">${dev.aliases.join(', ')}</div>` : '';
    const ports = (dev.ports || dev.open_ports || []).join(', ') || '--';
    const lastSeen = dev.last_seen ? dev.last_seen.replace('T', ' ').replace('Z', '') : '--';

    return `
      <tr>
        <td><strong>${escapeHtml(name)}</strong>${owner}</td>
        <td class="mono">${escapeHtml(ip)}${aliases}</td>
        <td class="mono">${escapeHtml(dev.mac)}</td>
        <td>${escapeHtml(dev.vendor || 'N/A')}</td>
        <td class="ports-list">${escapeHtml(ports)}</td>
        <td style="font-size: 0.75rem; color: var(--text-dim);">${escapeHtml(lastSeen)}</td>
      </tr>
    `;
  }).join('');
}

function openWhitelistModal(mac, ip, suggestion) {
  document.getElementById('formMac').value = mac;
  document.getElementById('formIp').value = ip;
  document.getElementById('formName').value = suggestion || 'My Device';
  document.getElementById('whitelistModal').style.display = 'flex';
}

function closeModal() {
  document.getElementById('whitelistModal').style.display = 'none';
}

async function submitWhitelist(e) {
  e.preventDefault();
  const mac = document.getElementById('formMac').value;
  const ip = document.getElementById('formIp').value;
  const name = document.getElementById('formName').value;
  const owner = document.getElementById('formOwner').value;
  const device_type = document.getElementById('formType').value;

  try {
    const res = await fetch('/api/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac, primary_ip: ip, name, owner, device_type })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`✔ Device ${mac} whitelisted successfully`);
      closeModal();
      fetchData();
    } else {
      showToast(`✘ Failed: ${data.message || 'Error'}`);
    }
  } catch (err) {
    showToast(`✘ Whitelisting failed: ${err.message}`);
  }
}

function showToast(msg) {
  const toast = document.getElementById('toastMsg');
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 3500);
}

function updatePolling() {
  const sec = parseInt(document.getElementById('pollIntervalSelect').value, 10);
  if (pollTimer) clearInterval(pollTimer);
  if (sec > 0) {
    pollTimer = setInterval(fetchData, sec * 1000);
  }
}

function escapeHtml(str) {
  return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Initial fetch & start timer
fetchData();
updatePolling();
</script>
</body>
</html>
"""
