"""Client Portal frontend (Flask) — port 8081.

PURE FRONTEND. Under the architecture rule "only the Server may touch the
database", this process does NOT import Database, does NOT open vpn.db and does
NOT use VPN_DB. It serves the portal HTML/JS and forwards every /api/* request
to the VPN Server's HTTP API (the sole DB owner), configured via VPN_API_URL.

Register / login / status / quota are all validated and served by the Server
through control-protocol-equivalent methods (portal_authenticate,
portal_status, portal_request_quota). The browser shows Server responses only.

Run the Server API first, then:

    cd Server
    set VPN_API_URL=http://127.0.0.1:8090
    python client_portal.py                 # http://127.0.0.1:8081
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, render_template_string

# proxy.py lives next to the Server code; make it importable when this file is
# run from the Client/ tree as well as the Server/ tree.
_SERVER_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Server"))
if os.path.isdir(_SERVER_DIR):
    sys.path.insert(0, _SERVER_DIR)

from proxy import proxy_request  # noqa: E402

API_URL = os.environ.get("VPN_API_URL", "http://10.165.145.221:9001")

app = Flask(__name__)


@app.route("/api/<path:subpath>",
           methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def api_proxy(subpath):
    """Forward all API calls to the Server (the only DB owner)."""
    return proxy_request(API_URL, "/api/" + subpath)


@app.get("/")
def index():
    return render_template_string(PAGE)


PAGE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPN Client Portal</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<nav class="navbar navbar-dark bg-primary px-3">
  <span class="navbar-brand mb-0 h1">🔐 VPN Client Portal</span>
  <button id="logoutBtn" class="btn btn-outline-light btn-sm d-none">Logout</button>
</nav>

<div class="container my-4">
  <!-- Auth -->
  <div id="authCard" class="row justify-content-center">
    <div class="col-md-5">
      <div class="card shadow-sm">
        <div class="card-body">
          <ul class="nav nav-pills mb-3">
            <li class="nav-item"><a class="nav-link active" id="tabLogin" href="#">Login</a></li>
            <li class="nav-item"><a class="nav-link" id="tabReg" href="#">Register</a></li>
          </ul>
          <div id="authErr" class="alert alert-danger d-none"></div>
          <div id="authOk" class="alert alert-success d-none"></div>

          <div id="loginForm">
            <div class="mb-3"><label class="form-label">Username</label>
              <input id="lu" class="form-control"></div>
            <div class="mb-3"><label class="form-label">Password</label>
              <input id="lp" type="password" class="form-control"></div>
            <div class="form-check mb-3">
              <input id="rem" class="form-check-input" type="checkbox">
              <label class="form-check-label" for="rem">Remember me (30 days)</label>
            </div>
            <button id="loginBtn" class="btn btn-primary w-100">Login</button>
          </div>

          <div id="regForm" class="d-none">
            <div class="mb-3"><label class="form-label">Username</label>
              <input id="ru" class="form-control"></div>
            <div class="mb-3"><label class="form-label">Password</label>
              <input id="rp" type="password" class="form-control"></div>
            <button id="regBtn" class="btn btn-success w-100">Create Account</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Dashboard -->
  <div id="dash" class="d-none">
    <div id="dashAlert" class="alert d-none"></div>
    <div class="row g-3">
      <div class="col-md-4">
        <div class="card h-100 shadow-sm"><div class="card-body">
          <h6 class="text-muted">Account Status</h6>
          <div id="acctStatus" class="fs-4">—</div>
        </div></div>
      </div>
      <div class="col-md-4">
        <div class="card h-100 shadow-sm"><div class="card-body">
          <h6 class="text-muted">Remaining Quota</h6>
          <div id="quota" class="fs-4">—</div>
        </div></div>
      </div>
      <div class="col-md-4">
        <div class="card h-100 shadow-sm"><div class="card-body">
          <h6 class="text-muted">Connection</h6>
          <div id="connStatus" class="fs-4">—</div>
          <small id="assignedIp" class="text-muted"></small>
        </div></div>
      </div>
    </div>

    <div class="my-3">
      <button id="refreshBtn" class="btn btn-outline-primary">🔄 Refresh Status</button>
    </div>

    <div class="card shadow-sm">
      <div class="card-body">
        <h5 class="card-title">Request Quota Increase</h5>
        <p class="text-muted mb-2">Enter an amount in bytes (max 4,294,967,295 per request).</p>
        <div class="input-group" style="max-width:480px;">
          <input id="qAmount" type="number" min="1" max="4294967295" class="form-control" placeholder="e.g. 1073741824">
          <button id="qBtn" class="btn btn-success">Request Increase</button>
        </div>
        <div class="form-text">1 GB = 1073741824 bytes.</div>
      </div>
    </div>
  </div>
</div>

<script>
const $ = (id) => document.getElementById(id);

async function api(path, opts={}) {
  opts.headers = Object.assign({'Content-Type':'application/json'}, opts.headers||{});
  const r = await fetch(path, opts);
  if (r.status === 401) { showAuth(); }
  return r;
}
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

function showAuth(){ $('dash').classList.add('d-none'); $('authCard').classList.remove('d-none'); $('logoutBtn').classList.add('d-none'); }
function showDash(){ $('authCard').classList.add('d-none'); $('dash').classList.remove('d-none'); $('logoutBtn').classList.remove('d-none'); refresh(); }

$('tabLogin').onclick=(e)=>{e.preventDefault();$('tabLogin').classList.add('active');$('tabReg').classList.remove('active');
  $('loginForm').classList.remove('d-none');$('regForm').classList.add('d-none');clearMsg();};
$('tabReg').onclick=(e)=>{e.preventDefault();$('tabReg').classList.add('active');$('tabLogin').classList.remove('active');
  $('regForm').classList.remove('d-none');$('loginForm').classList.add('d-none');clearMsg();};
function clearMsg(){ $('authErr').classList.add('d-none'); $('authOk').classList.add('d-none'); }
function authErr(m){ $('authErr').textContent=m; $('authErr').classList.remove('d-none'); $('authOk').classList.add('d-none'); }
function authOk(m){ $('authOk').textContent=m; $('authOk').classList.remove('d-none'); $('authErr').classList.add('d-none'); }

$('loginBtn').onclick = async () => {
  clearMsg();
  const r = await fetch('/api/portal/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body: JSON.stringify({username:$('lu').value, password:$('lp').value, remember:$('rem').checked})});
  const j = await r.json();
  if (!r.ok) return authErr(j.error||'Login failed');
  showDash();
};
$('regBtn').onclick = async () => {
  clearMsg();
  const r = await fetch('/api/portal/register',{method:'POST',headers:{'Content-Type':'application/json'},
    body: JSON.stringify({username:$('ru').value, password:$('rp').value})});
  const j = await r.json();
  if (!r.ok) return authErr(j.error||'Registration failed');
  authOk('Account created — you can now log in.');
  $('tabLogin').click(); $('lu').value=$('ru').value;
};
$('logoutBtn').onclick = async () => { await fetch('/api/logout',{method:'POST'}); showAuth(); };

function statusBadge(s){
  const map = {active:'success', banned:'danger', quota_exhausted:'warning'};
  return `<span class="badge bg-${map[s]||'secondary'}">${esc(s)}</span>`;
}

async function refresh(){
  const r = await api('/api/portal/status');
  if (!r.ok) return;
  const j = await r.json();
  $('acctStatus').innerHTML = statusBadge(j.account_status);
  $('quota').textContent = j.remaining_quota_h;
  $('connStatus').innerHTML = j.connection_status==='connect'
      ? '<span class="badge bg-info">connected</span>' : '<span class="badge bg-secondary">disconnected</span>';
  $('assignedIp').textContent = j.assigned_ip ? ('IP: '+j.assigned_ip) : '';

  const a = $('dashAlert');
  a.classList.add('d-none'); a.classList.remove('alert-danger','alert-warning');
  if (j.account_status==='banned'){ a.textContent='Your account is banned. Contact the administrator.'; a.classList.add('alert-danger'); a.classList.remove('d-none'); }
  else if (j.account_status==='quota_exhausted'){ a.textContent='Your quota is exhausted. Request an increase below to reconnect.'; a.classList.add('alert-warning'); a.classList.remove('d-none'); }
}
$('refreshBtn').onclick = refresh;

$('qBtn').onclick = async () => {
  const amount = parseInt($('qAmount').value, 10);
  const a = $('dashAlert');
  a.classList.remove('d-none','alert-danger','alert-success','alert-warning');
  const r = await api('/api/portal/quota',{method:'POST', body: JSON.stringify({amount})});
  const j = await r.json();
  if (!r.ok){ a.textContent = j.error || 'Request failed'; a.classList.add('alert-danger'); return; }
  a.textContent = `Success — added ${j.added} bytes. New quota: ${j.remaining_quota_h}.`;
  a.classList.add('alert-success');
  $('qAmount').value = '';
  refresh();
};

(async ()=>{ try { const r = await fetch('/api/portal/status'); if (r.ok) showDash(); else showAuth(); } catch(e){ showAuth(); } })();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=False)
