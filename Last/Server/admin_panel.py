"""Admin Panel frontend (Flask) — port 8080.

PURE FRONTEND. This process does NOT own or import the database. It serves the
admin HTML/JS and transparently proxies every /api/* request to the VPN Server's
HTTP API (the only DB owner), configured via VPN_API_URL.

Run the Server API first (it is started by the VPN Server process, see
run_server.py), then:

    cd Server
    set VPN_API_URL=http://127.0.0.1:9000      # where the Server API listens
    python admin_panel.py                        # http://127.0.0.1:8080

Login: admin / admin  (validated by the Server, not here).
"""

import os

from flask import Flask, request, render_template_string, Response

from proxy import proxy_request

API_URL = os.environ.get("VPN_API_URL", "http://127.0.0.1:9001")

app = Flask(__name__)


@app.route("/api/<path:subpath>",
           methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def api_proxy(subpath):
    """Forward all API calls to the Server (which owns the DB)."""
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
<title>VPN Admin Panel</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<nav class="navbar navbar-dark bg-dark px-3">
  <span class="navbar-brand mb-0 h1">🛡️ VPN Admin Panel</span>
  <button id="logoutBtn" class="btn btn-outline-light btn-sm d-none">Logout</button>
</nav>

<div class="container my-4">
  <!-- Login -->
  <div id="loginCard" class="row justify-content-center">
    <div class="col-md-5">
      <div class="card shadow-sm">
        <div class="card-body">
          <h5 class="card-title mb-3">Admin Login</h5>
          <div id="loginErr" class="alert alert-danger d-none"></div>
          <div class="mb-3">
            <label class="form-label">Username</label>
            <input id="u" class="form-control" value="admin">
          </div>
          <div class="mb-3">
            <label class="form-label">Password</label>
            <input id="p" type="password" class="form-control" value="">
          </div>
          <div class="form-check mb-3">
            <input id="rem" class="form-check-input" type="checkbox">
            <label class="form-check-label" for="rem">Remember me (30 days)</label>
          </div>
          <button id="loginBtn" class="btn btn-primary w-100">Login</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Main -->
  <div id="main" class="d-none">
    <ul class="nav nav-tabs mb-3">
      <li class="nav-item"><a class="nav-link active" data-tab="users" href="#">Users</a></li>
      <li class="nav-item"><a class="nav-link" data-tab="fw" href="#">Firewall</a></li>
      <li class="nav-item"><a class="nav-link" data-tab="logs" href="#">Traffic Logs</a></li>
    </ul>

    <!-- Users -->
    <div data-panel="users">
      <div class="d-flex justify-content-between align-items-center mb-2">
        <h5>Users Management</h5>
        <small class="text-muted">Auto-refresh every 30s</small>
      </div>
      <div class="table-responsive">
        <table class="table table-striped table-hover bg-white">
          <thead><tr>
            <th>Username</th><th>Remaining Quota</th><th>Account</th>
            <th>Connection</th><th>Assigned IP</th><th>Actions</th>
          </tr></thead>
          <tbody id="usersBody"></tbody>
        </table>
      </div>
    </div>

    <!-- Firewall -->
    <div data-panel="fw" class="d-none">
      <h5>Firewall Management</h5>
      <div class="row">
        <div class="col-md-6">
          <div class="card mb-3"><div class="card-body">
            <h6>Domain Rules</h6>
            <div class="input-group mb-2">
              <input id="fdUser" class="form-control" placeholder="username or 'all'" value="all">
              <input id="fdDomain" class="form-control" placeholder="example.com">
              <button id="fdAdd" class="btn btn-outline-primary">Add</button>
            </div>
            <table class="table table-sm">
              <thead><tr><th>ID</th><th>User</th><th>Domain</th><th></th></tr></thead>
              <tbody id="fdBody"></tbody>
            </table>
          </div></div>
        </div>
        <div class="col-md-6">
          <div class="card mb-3"><div class="card-body">
            <h6>IP Rules</h6>
            <div class="input-group mb-2">
              <input id="fiUser" class="form-control" placeholder="username or 'all'" value="all">
              <input id="fiIp" class="form-control" placeholder="1.2.3.4">
              <button id="fiAdd" class="btn btn-outline-primary">Add</button>
            </div>
            <table class="table table-sm">
              <thead><tr><th>ID</th><th>User</th><th>IP</th><th></th></tr></thead>
              <tbody id="fiBody"></tbody>
            </table>
          </div></div>
        </div>
      </div>
    </div>

    <!-- Logs -->
    <div data-panel="logs" class="d-none">
      <div class="d-flex justify-content-between align-items-center mb-2">
        <h5>Traffic Logs</h5>
        <div class="d-flex gap-2">
          <input id="logFilter" class="form-control form-control-sm" placeholder="filter by username">
          <button id="logRefresh" class="btn btn-sm btn-outline-secondary">Refresh</button>
          <button id="logClear" class="btn btn-sm btn-outline-danger">Clear All Logs</button>
        </div>
      </div>
      <div class="table-responsive" style="max-height:65vh; overflow:auto;">
        <table class="table table-sm table-striped bg-white">
          <thead class="sticky-top bg-white"><tr>
            <th>Time</th><th>User</th><th>Dest IP</th><th>Port</th><th>Domain</th><th>Action</th>
          </tr></thead>
          <tbody id="logsBody"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<script>
const $ = (id) => document.getElementById(id);
let refreshTimer = null;

async function api(path, opts={}) {
  opts.headers = Object.assign({'Content-Type':'application/json'}, opts.headers||{});
  const r = await fetch(path, opts);
  if (r.status === 401 || r.status === 403) { showLogin(); throw new Error('auth'); }
  return r;
}
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

function showLogin(){ $('main').classList.add('d-none'); $('loginCard').classList.remove('d-none');
  $('logoutBtn').classList.add('d-none'); if(refreshTimer) clearInterval(refreshTimer); }
function showMain(){ $('loginCard').classList.add('d-none'); $('main').classList.remove('d-none');
  $('logoutBtn').classList.remove('d-none'); loadUsers();
  refreshTimer = setInterval(()=>{ if(!$('[data-panel=users]').classList.contains('d-none')) loadUsers(); }, 30000); }

$('loginBtn').onclick = async () => {
  $('loginErr').classList.add('d-none');
  const r = await fetch('/api/admin/login', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({username:$('u').value, password:$('p').value, remember:$('rem').checked})});
  const j = await r.json();
  if (!r.ok) { $('loginErr').textContent = j.error || 'Login failed'; $('loginErr').classList.remove('d-none'); return; }
  showMain();
};
$('logoutBtn').onclick = async () => { await fetch('/api/logout',{method:'POST'}); showLogin(); };

// tabs
document.querySelectorAll('[data-tab]').forEach(a => a.onclick = (e) => {
  e.preventDefault();
  document.querySelectorAll('[data-tab]').forEach(x=>x.classList.remove('active'));
  a.classList.add('active');
  const t = a.dataset.tab;
  document.querySelectorAll('[data-panel]').forEach(p=>p.classList.toggle('d-none', p.dataset.panel!==t));
  if (t==='users') loadUsers(); if (t==='fw') loadFirewall(); if (t==='logs') loadLogs();
});

async function loadUsers(){
  const j = await (await api('/api/admin/users')).json();
  $('usersBody').innerHTML = j.users.map(u => {
    const badge = u.account_status==='active' ? 'success' : (u.account_status==='banned' ? 'danger' : 'warning');
    const conn = u.connection_status==='connect' ? '<span class="badge bg-info">connect</span>' : '<span class="badge bg-secondary">disconnect</span>';
    const banBtn = u.account_status==='banned'
      ? `<button class="btn btn-sm btn-success" onclick="unban('${esc(u.username)}')">Unban</button>`
      : `<button class="btn btn-sm btn-danger" onclick="ban('${esc(u.username)}')">Ban</button>`;
    return `<tr>
      <td>${esc(u.username)}</td>
      <td>${esc(u.remaining_quota_h)}</td>
      <td><span class="badge bg-${badge}">${esc(u.account_status)}</span></td>
      <td>${conn}</td>
      <td>${esc(u.assigned_ip)||'-'}</td>
      <td class="d-flex gap-1">${banBtn}
        <button class="btn btn-sm btn-outline-primary" onclick="addQuota('${esc(u.username)}')">+Quota</button>
      </td></tr>`;
  }).join('');
}
async function ban(u){ await api(`/api/admin/users/${encodeURIComponent(u)}/ban`,{method:'POST'}); loadUsers(); }
async function unban(u){ await api(`/api/admin/users/${encodeURIComponent(u)}/unban`,{method:'POST'}); loadUsers(); }
async function addQuota(u){
  const v = prompt('Add how many bytes to '+u+'?','1073741824');
  if (v===null) return;
  const r = await api(`/api/admin/users/${encodeURIComponent(u)}/quota`,{method:'POST', body: JSON.stringify({amount: parseInt(v,10)})});
  const j = await r.json();
  if(!r.ok){ alert(j.error||'failed'); return; }
  loadUsers();
}

async function loadFirewall(){
  const j = await (await api('/api/admin/firewall')).json();
  $('fdBody').innerHTML = (j.domains||[]).map(r=>`<tr><td>${r.id}</td><td>${esc(r.username)}</td><td>${esc(r.domain)}</td>
    <td><button class="btn btn-sm btn-outline-danger" onclick="delRule('domain',${r.id})">✕</button></td></tr>`).join('');
  $('fiBody').innerHTML = (j.ips||[]).map(r=>`<tr><td>${r.id}</td><td>${esc(r.username)}</td><td>${esc(r.ip)}</td>
    <td><button class="btn btn-sm btn-outline-danger" onclick="delRule('ip',${r.id})">✕</button></td></tr>`).join('');
}
$('fdAdd').onclick = async () => {
  const r = await api('/api/admin/firewall/domain',{method:'POST', body: JSON.stringify({username:$('fdUser').value, domain:$('fdDomain').value})});
  if(r.ok){ $('fdDomain').value=''; loadFirewall(); } else { alert((await r.json()).error||'failed'); }
};
$('fiAdd').onclick = async () => {
  const r = await api('/api/admin/firewall/ip',{method:'POST', body: JSON.stringify({username:$('fiUser').value, ip:$('fiIp').value})});
  if(r.ok){ $('fiIp').value=''; loadFirewall(); } else { alert((await r.json()).error||'failed'); }
};
async function delRule(type,id){ await api(`/api/admin/firewall/${type}/${id}`,{method:'DELETE'}); loadFirewall(); }

async function loadLogs(){
  const f = $('logFilter').value.trim();
  const j = await (await api('/api/admin/logs'+(f?('?username='+encodeURIComponent(f)):''))).json();
  $('logsBody').innerHTML = (j.logs||[]).map(l=>{
    const cls = l.action==='blocked' ? 'text-danger fw-bold' : 'text-success';
    return `<tr><td>${esc(l.timestamp)}</td><td>${esc(l.username)}</td><td>${esc(l.dest_ip)}</td>
      <td>${l.dest_port==null?'-':l.dest_port}</td><td>${esc(l.domain)||'-'}</td>
      <td class="${cls}">${esc(l.action)}</td></tr>`;
  }).join('');
}
$('logRefresh').onclick = loadLogs;
$('logFilter').addEventListener('keyup', e=>{ if(e.key==='Enter') loadLogs(); });
$('logClear').onclick = async () => { if(confirm('Delete ALL traffic logs?')){ await api('/api/admin/logs/clear',{method:'POST'}); loadLogs(); } };

// Enter main if a valid cookie token already exists.
(async ()=>{ try { const r = await fetch('/api/admin/users'); if (r.ok) showMain(); else showLogin(); } catch(e){ showLogin(); } })();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
