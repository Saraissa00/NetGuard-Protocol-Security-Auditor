#!/usr/bin/env python3
from flask import Flask, jsonify
import socket, struct, subprocess, sys
from datetime import datetime

app = Flask(__name__)

# ── DNS Logic ────────────────────────────────────────────────────────────────
def same_subnet(ip1, ip2):
    return ip1.rsplit(".", 1)[0] == ip2.rsplit(".", 1)[0]

def build_query(domain):
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b"".join(struct.pack("B", len(l)) + l.encode() for l in domain.split("."))
    return header + q + b"\x00" + struct.pack(">HH", 1, 1)

def parse_response(data):
    if len(data) < 12 or struct.unpack(">H", data[6:8])[0] == 0:
        return None
    off = 12
    while off < len(data) and data[off] != 0:
        off += data[off] + 1
    off += 5
    for _ in range(10):
        if off + 10 > len(data):
            break
        off += 2
        rtype = struct.unpack(">H", data[off:off+2])[0]
        off += 8
        rdlen = struct.unpack(">H", data[off:off+2])[0]
        off += 2
        if rtype == 1 and rdlen == 4:
            return ".".join(str(b) for b in data[off:off+4])
        off += rdlen
    return None

def resolve_trusted(domain):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(build_query(domain), ("8.8.8.8", 53))
        data, _ = s.recvfrom(512)
        s.close()
        return parse_response(data)
    except Exception:
        return None

def resolve_local(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def get_gateway():
    try:
        if sys.platform == "win32":
            out = subprocess.run(["route","print","0.0.0.0"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                p = line.split()
                if len(p) >= 3 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0":
                    return p[2]
        else:
            out = subprocess.run(["ip","route"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                if line.startswith("default"):
                    return line.split()[2]
    except Exception:
        pass
    return None

def get_my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetGuard - Security Auditor</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0d1117;
    color: #c9d1d9;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 40px 20px;
  }
  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 14px;
    padding: 36px;
    width: 100%;
    max-width: 560px;
    text-align: center;
  }
  .shield { font-size: 3.5rem; }
  h1 { color: #58a6ff; font-size: 1.9rem; margin: 10px 0 4px; }
  .sub { color: #8b949e; font-size: 0.9rem; margin-bottom: 6px; }
  .badges { margin: 12px 0 28px; display: flex; flex-wrap: wrap; justify-content: center; gap: 8px; }
  .badge {
    background: #21262d; border: 1px solid #30363d;
    border-radius: 20px; padding: 4px 14px;
    font-size: 0.8rem; color: #58a6ff;
  }
  button {
    background: linear-gradient(135deg, #1f6feb, #388bfd);
    color: #fff; border: none; border-radius: 10px;
    font-size: 1.15rem; font-weight: 700; letter-spacing: 2px;
    padding: 16px 0; width: 100%; cursor: pointer;
    transition: opacity .2s;
  }
  button:hover { opacity: .85; }
  button:disabled { opacity: .5; cursor: not-allowed; }

  #spinner { display: none; margin: 28px 0 0; font-size: 1rem; color: #8b949e; }
  .dot { animation: blink 1.2s infinite; }
  .dot:nth-child(2) { animation-delay: .2s; }
  .dot:nth-child(3) { animation-delay: .4s; }
  @keyframes blink { 0%,80%,100%{opacity:0} 40%{opacity:1} }

  #result { display: none; margin-top: 28px; border-radius: 12px; padding: 28px 20px; }
  #result.safe   { background: #0d2818; border: 2px solid #2ea043; }
  #result.danger { background: #2d0f0f; border: 2px solid #da3633; }
  #result h2 { font-size: 1.8rem; margin-bottom: 6px; }
  #result.safe   h2 { color: #3fb950; }
  #result.danger h2 { color: #f85149; }
  #result p { font-size: 0.9rem; color: #c9d1d9; margin: 4px 0; }

  .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 18px 0; text-align: left; }
  .info-box { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 12px 14px; }
  .info-box .lbl { font-size: 0.72rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }
  .info-box .val { font-size: 0.95rem; color: #e6edf3; font-family: monospace; margin-top: 3px; }

  .warn-list { list-style: none; text-align: left; margin-top: 16px; }
  .warn-list li {
    background: #1a0a0a; border-left: 4px solid #f85149;
    padding: 9px 14px; margin: 6px 0;
    border-radius: 0 6px 6px 0;
    color: #ffa198; font-size: 0.88rem;
  }
  .footer { margin-top: 28px; font-size: 0.75rem; color: #484f58; text-align: center; }
</style>
</head>
<body>
<div class="card">
  <div class="shield">&#128737;&#65039;</div>
  <h1>NetGuard</h1>
  <p class="sub">Protocol Security Auditor</p>
  <div class="badges">
    <span class="badge">&#128105;&#8205;&#128187; Sara Alissa</span>
    <span class="badge">&#127891; BAU Computer Engineering</span>
  </div>
  <button id="scanBtn" onclick="scan()">&#128269;&nbsp; SCAN NETWORK</button>
  <div id="spinner">Scanning<span class="dot">.</span><span class="dot">.</span><span class="dot">.</span></div>
  <div id="result"></div>
</div>
<div class="footer">NetGuard v2.0 &nbsp;|&nbsp; Layer 3 / Layer 7 DNS Verification &nbsp;|&nbsp; No external dependencies</div>

<script>
async function scan() {
  const btn = document.getElementById('scanBtn');
  const spinner = document.getElementById('spinner');
  const result = document.getElementById('result');

  btn.disabled = true;
  spinner.style.display = 'block';
  result.style.display = 'none';

  try {
    const res = await fetch('/scan');
    const d = await res.json();

    spinner.style.display = 'none';
    btn.disabled = false;
    result.style.display = 'block';

    const infoGrid = `
      <div class="info-grid">
        <div class="info-box"><div class="lbl">Your IP</div><div class="val">${d.my_ip || '—'}</div></div>
        <div class="info-box"><div class="lbl">Gateway</div><div class="val">${d.gateway || '—'}</div></div>
        <div class="info-box"><div class="lbl">Local DNS</div><div class="val">${d.local_ip || 'Failed'}</div></div>
        <div class="info-box"><div class="lbl">Trusted DNS (8.8.8.8)</div><div class="val">${d.trusted_ip || 'Failed'}</div></div>
      </div>`;

    if (d.status === 'safe') {
      result.className = 'safe';
      result.innerHTML = `<h2>&#9989; SECURE</h2><p>DNS Verified &mdash; No hijacking detected.</p><p>Both resolvers agree — no hijacking detected.</p>${infoGrid}<p style="font-size:.78rem;color:#8b949e;margin-top:8px">${d.timestamp}</p>`;
    } else if (d.status === 'danger') {
      result.className = 'danger';
      result.innerHTML = `<h2>&#128680; DANGER</h2><p><strong>DNS HIJACKING DETECTED</strong></p><p>Your local DNS returned a suspicious IP address.</p>${infoGrid}
        <ul class="warn-list">
          <li>&#9888;&#65039; Disconnect from this network immediately.</li>
          <li>&#9888;&#65039; Do NOT log in to any accounts or enter passwords.</li>
          <li>&#9888;&#65039; Enable a VPN with DNS-leak protection.</li>
          <li>&#9888;&#65039; Set your DNS manually to 1.1.1.1 or 8.8.8.8.</li>
        </ul>`;
    } else {
      result.className = 'danger';
      result.innerHTML = `<h2>&#9888;&#65039; ERROR</h2><p>Could not complete the scan.</p><p>Check your internet connection and try again.</p>`;
    }
  } catch(e) {
    spinner.style.display = 'none';
    btn.disabled = false;
    result.style.display = 'block';
    result.className = 'danger';
    result.innerHTML = '<h2>&#9888;&#65039; ERROR</h2><p>Could not connect to the scan server.</p>';
  }
}
</script>
</body>
</html>"""

TEST_DOMAINS = ["iana.org", "internic.net", "ietf.org", "ripe.net"]

@app.route("/scan")
def scan():
    gateway = get_gateway()
    my_ip   = get_my_ip()

    matches = 0
    last_local, last_trusted = None, None
    for domain in TEST_DOMAINS:
        l = resolve_local(domain)
        t = resolve_trusted(domain)
        if l and t:
            last_local, last_trusted = l, t
            if same_subnet(l, t):
                matches += 1

    if last_local is None or last_trusted is None:
        status = "error"
    elif matches >= 3:
        status = "safe"
    else:
        status = "danger"

    return jsonify({
        "status":     status,
        "local_ip":   last_local,
        "trusted_ip": last_trusted,
        "gateway":    gateway,
        "my_ip":      my_ip,
        "timestamp":  datetime.now().strftime("%Y-%m-%d  %H:%M:%S"),
    })

if __name__ == "__main__":
    print("\n  NetGuard is running!")
    print("  Open this in your browser --> http://localhost:5000\n")
    app.run(debug=False, port=5000)
