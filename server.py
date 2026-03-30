from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional
import tempfile, os, base64, io, threading
from pathlib import Path
from datetime import datetime
from cryptography.fernet import InvalidToken

from qrypto import (
    scan_qr, encrypt, decrypt, make_qr,
    load_store, save_store, detect_qr_meta, detect_auth,
    key_from_password, key_from_keychain, key_from_file,
    get_paths,
)
import qrcode as _qrcode

app = FastAPI(title="Qrypto")
_lock = threading.Lock()


def _resolve_key(password: Optional[str], use_keyfile: bool) -> bytes:
    """Auth-aware key resolver that's safe to call from a web handler."""
    if use_keyfile:
        _, key_file, _, _ = get_paths()
        if not key_file.exists():
            raise ValueError(f"Key file not found: {key_file}")
        return key_from_file(str(key_file))
    if password:
        return key_from_password(password)
    try:
        return key_from_keychain()
    except SystemExit:
        raise ValueError("Keychain unavailable in this environment")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index():
    return HTML


@app.get("/entries")
def list_entries():
    store = load_store()
    return [
        {
            "name": k,
            "added": v["added"],
            "auth": v.get("auth", "keychain"),
            "qr_type": v.get("qr_type", "Generic"),
            "otp_type": v.get("otp_type", "—"),
            "issuer": v.get("issuer", "—"),
            "account": v.get("account", "—"),
        }
        for k, v in store.items()
    ]


@app.post("/scan")
async def scan_entry(
    image: UploadFile = File(...),
    name: str = Form(...),
    password: Optional[str] = Form(None),
    keyfile: Optional[str] = Form(None),
):
    use_keyfile = keyfile == "true"

    with _lock:
        if name in load_store():
            raise HTTPException(400, f"Name '{name}' already exists")

    suffix = Path(image.filename).suffix or ".png"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(await image.read())
        tmp_path = tmp.name

    try:
        data = scan_qr(tmp_path)
    except ValueError as e:
        raise HTTPException(400, str(e))
    finally:
        os.unlink(tmp_path)

    try:
        key = _resolve_key(password or None, use_keyfile)
    except ValueError as e:
        raise HTTPException(400, str(e))

    meta = detect_qr_meta(data)
    token = encrypt(data, key)

    with _lock:
        store = load_store()
        if name in store:
            raise HTTPException(400, f"Name '{name}' already exists")
        store[name] = {
            "token": token,
            "added": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "auth": detect_auth(password or None, use_keyfile),
            **meta,
        }
        save_store(store)

    return {"ok": True, "name": name, **meta}


class AuthBody(BaseModel):
    password: Optional[str] = None
    keyfile: bool = False


@app.post("/show/{name}")
def show_entry(name: str, body: AuthBody):
    store = load_store()
    if name not in store:
        raise HTTPException(404, f"No entry '{name}'")

    try:
        key = _resolve_key(body.password, body.keyfile)
        data = decrypt(store[name]["token"], key)
    except InvalidToken:
        raise HTTPException(400, "Decryption failed — wrong password or key")
    except ValueError as e:
        raise HTTPException(400, str(e))

    qr = _qrcode.make(data)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return {"image": f"data:image/png;base64,{b64}"}


@app.post("/regen/{name}")
def regen_entry(name: str, body: AuthBody):
    store = load_store()
    if name not in store:
        raise HTTPException(404, f"No entry '{name}'")

    try:
        key = _resolve_key(body.password, body.keyfile)
        data = decrypt(store[name]["token"], key)
    except InvalidToken:
        raise HTTPException(400, "Decryption failed — wrong password or key")
    except ValueError as e:
        raise HTTPException(400, str(e))

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        make_qr(data, tmp_path)
        with open(tmp_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
    finally:
        os.unlink(tmp_path)

    output = f"{name}_qr.png"
    return {"ok": True, "file": output, "image": f"data:image/png;base64,{b64}"}


@app.delete("/entries/{name}")
def delete_entry(name: str):
    with _lock:
        store = load_store()
        if name not in store:
            raise HTTPException(404, f"No entry '{name}'")
        del store[name]
        save_store(store)
    return {"ok": True}


# ---------------------------------------------------------------------------
# UI — GitHub-dark single-page app
# ---------------------------------------------------------------------------

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Qrypto</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--bg-s:#161b22;--bg-o:#1c2128;
  --bd:#30363d;--bd-m:#21262d;
  --fg:#e6edf3;--fg-m:#7d8590;
  --acc:#58a6ff;
  --green:#3fb950;--green-btn:#238636;--green-btn-h:#2ea043;
  --red:#f85149;--yellow:#d29922;
  --r:6px;
  --font:-apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans",Helvetica,Arial,sans-serif;
  --mono:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;
}
body{background:var(--bg);color:var(--fg);font-family:var(--font);font-size:14px;line-height:1.5;min-height:100vh}

/* Header */
.hdr{background:var(--bg-s);border-bottom:1px solid var(--bd);padding:0 24px;height:56px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}
.brand{display:flex;align-items:center;gap:10px}
.brand h1{font-size:16px;font-weight:600;letter-spacing:-.3px}
.brand .sub{color:var(--fg-m);font-size:12px}

/* Main */
.main{max-width:1100px;margin:0 auto;padding:28px 24px}
.sec-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.sec-t{font-size:15px;font-weight:600;display:flex;align-items:center;gap:8px}
.cnt{background:var(--bd);color:var(--fg-m);font-size:11px;padding:1px 8px;border-radius:20px;font-weight:500}

/* Buttons */
.btn{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:var(--r);font-size:13px;font-weight:500;font-family:var(--font);cursor:pointer;border:1px solid var(--bd);background:var(--bg-o);color:var(--fg);transition:background .1s,border-color .1s;white-space:nowrap;line-height:1.5;text-decoration:none}
.btn:hover{background:var(--bd)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn-primary{background:var(--green-btn);border-color:var(--green-btn);color:#fff}
.btn-primary:hover{background:var(--green-btn-h);border-color:var(--green-btn-h)}
.btn-sm{padding:3px 9px;font-size:12px}
.btn-ghost{color:var(--fg-m);border-color:transparent;background:transparent}
.btn-ghost:hover{background:var(--bg-s);color:var(--fg);border-color:var(--bd)}
.btn-danger{color:var(--red)}
.btn-danger:hover{background:rgba(248,81,73,.1);border-color:var(--red)}

/* Table */
.tbl-box{border:1px solid var(--bd);border-radius:var(--r);overflow:hidden}
table{width:100%;border-collapse:collapse}
thead{background:var(--bg-s)}
th{padding:10px 16px;text-align:left;font-size:11px;font-weight:600;color:var(--fg-m);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--bd)}
td{padding:11px 16px;border-bottom:1px solid var(--bd-m);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(177,186,196,.04)}
.c-name{font-family:var(--mono);font-size:13px;font-weight:600;color:var(--acc)}
.c-dim{color:var(--fg-m);font-size:13px}
.c-mono{font-family:var(--mono);font-size:12px;color:var(--fg-m)}
.acts{display:flex;gap:6px;justify-content:flex-end}

/* Pills */
.pill{display:inline-flex;align-items:center;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:500;border:1px solid transparent;white-space:nowrap}
.p2fa{background:rgba(63,185,80,.15);color:var(--green);border-color:rgba(63,185,80,.3)}
.purl{background:rgba(88,166,255,.15);color:var(--acc);border-color:rgba(88,166,255,.3)}
.pwifi{background:rgba(210,153,34,.15);color:var(--yellow);border-color:rgba(210,153,34,.3)}
.pgen{background:var(--bd-m);color:var(--fg-m)}
.pkc{background:rgba(88,166,255,.1);color:var(--acc);border-color:rgba(88,166,255,.25)}
.ppw{background:rgba(210,153,34,.1);color:var(--yellow);border-color:rgba(210,153,34,.25)}
.pkf{background:rgba(63,185,80,.1);color:var(--green);border-color:rgba(63,185,80,.25)}

/* Empty */
.empty{text-align:center;padding:72px 24px;border:1px solid var(--bd);border-radius:var(--r)}
.ei{font-size:40px;margin-bottom:16px;opacity:.4}
.et{font-size:18px;font-weight:600;margin-bottom:8px}
.es{color:var(--fg-m);margin-bottom:24px}

/* Modal */
.backdrop{display:none;position:fixed;inset:0;background:rgba(1,4,9,.85);z-index:50;align-items:center;justify-content:center;backdrop-filter:blur(4px)}
.backdrop.open{display:flex}
.modal{background:var(--bg-s);border:1px solid var(--bd);border-radius:12px;width:100%;max-height:92vh;overflow-y:auto;margin:16px;animation:pop .15s ease}
@keyframes pop{from{transform:scale(.96);opacity:0}to{transform:scale(1);opacity:1}}
.modal-md{max-width:500px}
.modal-sm{max-width:400px}
.modal-qr{max-width:320px}
.m-hd{display:flex;align-items:center;justify-content:space-between;padding:18px 20px 14px;border-bottom:1px solid var(--bd)}
.m-t{font-size:15px;font-weight:600}
.m-x{background:none;border:none;color:var(--fg-m);cursor:pointer;font-size:18px;width:28px;height:28px;display:flex;align-items:center;justify-content:center;border-radius:var(--r);transition:background .1s}
.m-x:hover{background:var(--bd);color:var(--fg)}
.m-body{padding:18px 20px}
.m-foot{padding:14px 20px 18px;display:flex;justify-content:flex-end;gap:8px;border-top:1px solid var(--bd)}

/* Form */
.field{margin-bottom:14px}
.field:last-child{margin-bottom:0}
label{display:block;font-size:13px;font-weight:600;margin-bottom:5px}
.note{font-weight:400;color:var(--fg-m);font-size:12px;margin-left:4px}
input[type=text],input[type=password],select{width:100%;background:var(--bg);border:1px solid var(--bd);border-radius:var(--r);color:var(--fg);font-family:var(--font);font-size:14px;padding:6px 10px;outline:none;transition:border-color .1s,box-shadow .1s}
input:focus,select:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(88,166,255,.15)}
select option{background:var(--bg-s)}

/* File drop */
.fdrop{border:2px dashed var(--bd);border-radius:var(--r);padding:28px 16px;text-align:center;cursor:pointer;transition:border-color .15s,background .15s;position:relative}
.fdrop:hover,.fdrop.drag{border-color:var(--acc);background:rgba(88,166,255,.05)}
.fdrop input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.fdrop .dico{font-size:28px;margin-bottom:6px}
.fdrop .dtxt{color:var(--fg-m);font-size:13px}
.fdrop .dtxt b{color:var(--acc);font-weight:500}
.fname{margin-top:6px;font-size:12px;color:var(--green);font-weight:500}

/* QR display */
.qr-area{text-align:center;padding:4px 0}
.qr-area img{max-width:200px;width:100%;border-radius:var(--r);border:1px solid var(--bd);background:#fff;padding:8px}
.qr-lbl{font-family:var(--mono);font-size:13px;font-weight:600;color:var(--acc);margin-bottom:14px}

/* Toasts */
.toasts{position:fixed;top:16px;right:16px;z-index:200;display:flex;flex-direction:column;gap:8px;pointer-events:none}
.toast{display:flex;align-items:center;gap:8px;padding:10px 14px;border-radius:var(--r);border:1px solid;font-size:13px;max-width:320px;animation:tin .2s ease;background:var(--bg-s);pointer-events:auto}
@keyframes tin{from{transform:translateX(110%);opacity:0}to{transform:translateX(0);opacity:1}}
.tok{border-color:rgba(63,185,80,.5);color:var(--green)}
.terr{border-color:rgba(248,81,73,.5);color:var(--red)}

/* Spinner */
.spin{display:inline-block;width:12px;height:12px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:rot .6s linear infinite;vertical-align:middle;margin-right:2px}
@keyframes rot{to{transform:rotate(360deg)}}

.hidden{display:none!important}
</style>
</head>
<body>

<header class="hdr">
  <div class="brand">
    <span style="font-size:22px">🔐</span>
    <h1>Qrypto</h1>
    <span class="sub">QR Code Manager</span>
  </div>
  <button class="btn btn-primary" onclick="openAdd()">+ Add QR Code</button>
</header>

<main class="main">
  <div class="sec-hd">
    <div class="sec-t">Entries <span class="cnt" id="cnt">0</span></div>
  </div>

  <div id="empty" class="empty hidden">
    <div class="ei">🔲</div>
    <div class="et">No entries yet</div>
    <div class="es">Scan a QR code image to encrypt and store it securely.</div>
    <button class="btn btn-primary" onclick="openAdd()">+ Add QR Code</button>
  </div>

  <div id="tbl" class="tbl-box hidden">
    <table>
      <thead>
        <tr>
          <th>Name</th><th>Type</th><th>Issuer</th>
          <th>Account</th><th>Added</th><th>Auth</th>
          <th style="text-align:right">Actions</th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>
</main>

<!-- Add QR Code Modal -->
<div class="backdrop" id="add-modal">
  <div class="modal modal-md">
    <div class="m-hd">
      <div class="m-t">Add QR Code</div>
      <button class="m-x" onclick="closeModal('add-modal')">✕</button>
    </div>
    <div class="m-body">
      <div class="field">
        <label>QR Code Image</label>
        <div class="fdrop" id="fa" ondragover="onDragOver(event)" ondragleave="onDragLeave(event)" ondrop="onDrop(event)">
          <input type="file" accept="image/*" id="fi" onchange="filePicked(this)">
          <div class="dico">📷</div>
          <div class="dtxt">Drop image here or <b>browse</b></div>
          <div class="fname hidden" id="fn"></div>
        </div>
      </div>
      <div class="field">
        <label>Name <span class="note">used to retrieve it later</span></label>
        <input type="text" id="sname" placeholder="e.g. aws-prod, github-2fa">
      </div>
      <div class="field">
        <label>Auth Mode</label>
        <select id="sauth" onchange="onAuthChange()">
          <option value="keychain">Keychain — macOS (default)</option>
          <option value="password">Password</option>
          <option value="keyfile">Key File (.qrypto/qr.key)</option>
        </select>
      </div>
      <div class="field hidden" id="spwf">
        <label>Password</label>
        <input type="password" id="spw" placeholder="Enter passphrase">
      </div>
    </div>
    <div class="m-foot">
      <button class="btn" onclick="closeModal('add-modal')">Cancel</button>
      <button class="btn btn-primary" id="sbtn" onclick="doScan()">Scan & Encrypt</button>
    </div>
  </div>
</div>

<!-- QR Display Modal -->
<div class="backdrop" id="qr-modal">
  <div class="modal modal-qr">
    <div class="m-hd">
      <div class="m-t" id="qr-title">QR Code</div>
      <button class="m-x" onclick="closeModal('qr-modal')">✕</button>
    </div>
    <div class="m-body">
      <div class="qr-area">
        <div class="qr-lbl" id="qr-lbl"></div>
        <img id="qr-img" src="" alt="QR Code">
      </div>
    </div>
    <div class="m-foot">
      <button class="btn" onclick="closeModal('qr-modal')">Close</button>
      <a class="btn btn-primary" id="qr-dl" download>↓ Download</a>
    </div>
  </div>
</div>

<!-- Auth Prompt Modal -->
<div class="backdrop" id="pw-modal">
  <div class="modal modal-sm">
    <div class="m-hd">
      <div class="m-t">Authentication</div>
      <button class="m-x" onclick="closeModal('pw-modal')">✕</button>
    </div>
    <div class="m-body">
      <div class="field">
        <label id="pw-lbl">Password</label>
        <input type="password" id="pw-inp" placeholder="Enter passphrase"
               onkeydown="if(event.key==='Enter')doAuth()">
      </div>
    </div>
    <div class="m-foot">
      <button class="btn" onclick="closeModal('pw-modal')">Cancel</button>
      <button class="btn btn-primary" onclick="doAuth()">Continue</button>
    </div>
  </div>
</div>

<!-- Delete Confirm Modal -->
<div class="backdrop" id="del-modal">
  <div class="modal modal-sm">
    <div class="m-hd">
      <div class="m-t">Delete entry</div>
      <button class="m-x" onclick="closeModal('del-modal')">✕</button>
    </div>
    <div class="m-body">
      <p style="color:var(--fg-m);font-size:13px;line-height:1.6">
        Are you sure you want to delete <strong id="del-name" style="color:var(--fg);font-family:var(--mono)"></strong>?<br>
        <span style="color:var(--red)">This cannot be undone.</span>
      </p>
    </div>
    <div class="m-foot">
      <button class="btn" onclick="closeModal('del-modal')">Cancel</button>
      <button class="btn btn-danger" id="del-confirm-btn" style="border-color:var(--red);background:rgba(248,81,73,.1)" onclick="doDelConfirmed()">Delete</button>
    </div>
  </div>
</div>

<div class="toasts" id="toasts"></div>

<script>
'use strict';
let entries = [];
let _authCb = null;

// ── Data ───────────────────────────────────────────────────────
async function loadEntries() {
  try {
    const r = await fetch('/entries');
    entries = await r.json();
    renderEntries();
  } catch(e) { toast('Could not load entries', true); }
}

function renderEntries() {
  const cnt   = document.getElementById('cnt');
  const empty = document.getElementById('empty');
  const tbl   = document.getElementById('tbl');
  const tbody = document.getElementById('tbody');

  cnt.textContent = entries.length;
  if (!entries.length) {
    empty.classList.remove('hidden');
    tbl.classList.add('hidden');
    return;
  }
  empty.classList.add('hidden');
  tbl.classList.remove('hidden');

  tbody.innerHTML = entries.map(e => `
    <tr>
      <td><span class="c-name">${esc(e.name)}</span></td>
      <td>${typePill(e.qr_type)}</td>
      <td class="c-dim">${esc(e.issuer)}</td>
      <td class="c-mono">${esc(e.account)}</td>
      <td class="c-dim">${esc(e.added)}</td>
      <td>${authPill(e.auth)}</td>
      <td><div class="acts">
        <button class="btn btn-sm btn-ghost" onclick="doShow(${q(e.name)},${q(e.auth)})">👁 Show</button>
        <button class="btn btn-sm btn-danger" onclick="doDel(${q(e.name)})">Delete</button>
      </div></td>
    </tr>
  `).join('');
}

function typePill(t) {
  const m = {'2FA':'p2fa','URL':'purl','WiFi':'pwifi','Generic':'pgen'};
  return `<span class="pill ${m[t]||'pgen'}">${esc(t)}</span>`;
}
function authPill(a) {
  const m = {'keychain':'pkc','password':'ppw','key-file':'pkf'};
  return `<span class="pill ${m[a]||'pgen'}">${esc(a)}</span>`;
}

// ── Add entry ──────────────────────────────────────────────────
function openAdd() {
  document.getElementById('fi').value = '';
  document.getElementById('fn').textContent = '';
  document.getElementById('fn').classList.add('hidden');
  document.getElementById('sname').value = '';
  document.getElementById('sauth').value = 'keychain';
  document.getElementById('spw').value = '';
  document.getElementById('spwf').classList.add('hidden');
  openModal('add-modal');
}

function onAuthChange() {
  document.getElementById('spwf').classList.toggle(
    'hidden', document.getElementById('sauth').value !== 'password'
  );
}

function filePicked(inp) {
  const f = inp.files[0];
  const el = document.getElementById('fn');
  if (f) { el.textContent = '✓ ' + f.name; el.classList.remove('hidden'); }
}

function onDragOver(e) { e.preventDefault(); document.getElementById('fa').classList.add('drag'); }
function onDragLeave(e) { document.getElementById('fa').classList.remove('drag'); }
function onDrop(e) {
  e.preventDefault();
  document.getElementById('fa').classList.remove('drag');
  const f = e.dataTransfer.files[0];
  if (f) {
    const dt = new DataTransfer();
    dt.items.add(f);
    const inp = document.getElementById('fi');
    inp.files = dt.files;
    filePicked(inp);
  }
}

async function doScan() {
  const file = document.getElementById('fi').files[0];
  const name = document.getElementById('sname').value.trim();
  const auth = document.getElementById('sauth').value;
  const pw   = document.getElementById('spw').value;

  if (!file) return toast('Select a QR image', true);
  if (!name) return toast('Enter a name', true);
  if (auth === 'password' && !pw) return toast('Enter a password', true);

  const btn = document.getElementById('sbtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span>Processing…';

  const fd = new FormData();
  fd.append('image', file);
  fd.append('name', name);
  if (auth === 'password') fd.append('password', pw);
  if (auth === 'keyfile')  fd.append('keyfile', 'true');

  try {
    const r = await fetch('/scan', { method: 'POST', body: fd });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Scan failed');
    closeModal('add-modal');
    toast(`"${name}" encrypted and saved`);
    loadEntries();
  } catch(e) { toast(e.message, true); }
  finally {
    btn.disabled = false;
    btn.innerHTML = 'Scan & Encrypt';
  }
}

// ── Show ───────────────────────────────────────────────────────
function doShow(name, auth) {
  if (auth === 'password') {
    askPw(`Password for "${name}"`, pw => _fetchShow(name, { password: pw }));
  } else {
    _fetchShow(name, { keyfile: auth === 'key-file' });
  }
}

async function _fetchShow(name, body) {
  try {
    const r = await fetch(`/show/${encodeURIComponent(name)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Failed');
    showQRModal(name, d.image);
  } catch(e) { toast(e.message, true); }
}

// ── Regen ──────────────────────────────────────────────────────
function doRegen(name, auth) {
  if (auth === 'password') {
    askPw(`Password for "${name}"`, pw => _fetchRegen(name, { password: pw }));
  } else {
    _fetchRegen(name, { keyfile: auth === 'key-file' });
  }
}

async function _fetchRegen(name, body) {
  try {
    const r = await fetch(`/regen/${encodeURIComponent(name)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Failed');
    toast(`Saved as ${d.file}`);
    showQRModal(name, d.image);
  } catch(e) { toast(e.message, true); }
}

function showQRModal(name, img) {
  document.getElementById('qr-title').textContent = name;
  document.getElementById('qr-lbl').textContent   = name;
  document.getElementById('qr-img').src           = img;
  document.getElementById('qr-dl').href           = img;
  document.getElementById('qr-dl').download       = `${name}_qr.png`;
  openModal('qr-modal');
}

// ── Delete ─────────────────────────────────────────────────────
let _delName = null;

function doDel(name) {
  _delName = name;
  document.getElementById('del-name').textContent = name;
  openModal('del-modal');
}

async function doDelConfirmed() {
  const name = _delName;
  closeModal('del-modal');
  try {
    const r = await fetch(`/entries/${encodeURIComponent(name)}`, { method: 'DELETE' });
    if (!r.ok) throw new Error('Delete failed');
    toast(`"${name}" deleted`);
    loadEntries();
  } catch(e) { toast(e.message, true); }
}

// ── Auth prompt ────────────────────────────────────────────────
function askPw(label, cb) {
  document.getElementById('pw-lbl').textContent = label;
  document.getElementById('pw-inp').value = '';
  _authCb = cb;
  openModal('pw-modal');
  setTimeout(() => document.getElementById('pw-inp').focus(), 120);
}

function doAuth() {
  const pw = document.getElementById('pw-inp').value;
  closeModal('pw-modal');
  if (_authCb) { _authCb(pw); _authCb = null; }
}

// ── Modal helpers ──────────────────────────────────────────────
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

document.querySelectorAll('.backdrop').forEach(b =>
  b.addEventListener('click', e => { if (e.target === b) b.classList.remove('open'); })
);

// ── Toasts ─────────────────────────────────────────────────────
function toast(msg, err = false) {
  const el = document.createElement('div');
  el.className = `toast ${err ? 'terr' : 'tok'}`;
  el.innerHTML = `<span>${err ? '✕' : '✓'}</span>${esc(msg)}`;
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// ── Helpers ────────────────────────────────────────────────────
function esc(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c]
  );
}
function q(s) { return JSON.stringify(String(s)).replace(/"/g, '&quot;'); }

// ── Init ───────────────────────────────────────────────────────
loadEntries();
</script>
</body>
</html>"""
