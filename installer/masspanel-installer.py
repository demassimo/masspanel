#!/usr/bin/env python3
"""Single-use MassPanel first-boot web installer (standard library only)."""
import html, json, os, re, secrets, socket, subprocess, threading, time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

TOKEN = os.environ.get("MASSPANEL_INSTALL_TOKEN", "")
STAGE = Path(os.environ.get("MASSPANEL_INSTALL_STAGE", "/opt/masspanel-installer/stage"))
RUNNER = STAGE / "installer" / "run-install.sh"
LOCK = Path("/run/masspanel-installer.lock")
MARKER = Path("/etc/masspanel/installation-complete.json")
state = {"phase":"ready", "progress":0, "message":"Ready to configure this server.", "log":[], "panel_url":""}
guard = threading.Lock()
HOST = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
USER = re.compile(r"^[a-z][a-z0-9_-]{2,31}$")
EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

PAGE = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Install MassPanel</title><style>
*{box-sizing:border-box}body{margin:0;font:14px Inter,system-ui,sans-serif;color:#17243a;background:#f3f6fa}.shell{max-width:1080px;margin:45px auto;padding:0 20px}.brand{display:flex;align-items:center;gap:12px;margin-bottom:26px}.logo{display:grid;place-items:center;width:42px;height:42px;border-radius:10px;background:#1677ff;color:#fff;font-size:22px;font-weight:800}.brand h1{margin:0;font-size:22px}.brand p{margin:3px 0;color:#6c788a}.card{background:#fff;border:1px solid #d9e1eb;border-radius:12px;box-shadow:0 18px 50px #1028460b;overflow:hidden}.steps{display:grid;grid-template-columns:repeat(4,1fr);border-bottom:1px solid #e1e6ed}.steps span{padding:17px;text-align:center;color:#748095;font-size:12px}.steps span:first-child{color:#1677ff;font-weight:750;border-bottom:2px solid #1677ff}.content{padding:30px}.intro{display:flex;justify-content:space-between;gap:25px;margin-bottom:25px}.intro h2{font-size:26px;margin:0 0 7px}.intro p{color:#667386;margin:0;line-height:1.55}.badge{align-self:start;background:#eaf4ff;color:#1267d6;padding:8px 11px;border-radius:7px;font-weight:700;font-size:11px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}label{display:grid;gap:7px;font-size:11px;font-weight:750;color:#40506a}input{height:44px;border:1px solid #cbd5e2;border-radius:7px;padding:0 12px;font:14px system-ui;outline:none}input:focus{border-color:#1677ff;box-shadow:0 0 0 3px #1677ff17}.wide{grid-column:1/-1}.check{display:flex;gap:10px;align-items:flex-start;padding:13px;border:1px solid #dce4ee;border-radius:7px}.check input{height:auto;margin-top:2px}.check span{font-size:12px;font-weight:600}.check small{display:block;color:#748095;font-weight:400;margin-top:3px}.actions{display:flex;justify-content:flex-end;border-top:1px solid #e2e7ed;margin:26px -30px -30px;padding:20px 30px}.primary{height:44px;border:0;border-radius:7px;background:#1677ff;color:white;padding:0 22px;font-weight:750;cursor:pointer}.primary:disabled{opacity:.5}.status{display:none}.status.show{display:block}.form.hide{display:none}.bar{height:9px;background:#e7edf5;border-radius:6px;overflow:hidden;margin:25px 0}.bar i{display:block;height:100%;width:0;background:#1677ff;transition:.4s}.log{height:300px;overflow:auto;background:#0c1828;color:#b9c8da;border-radius:8px;padding:15px;font:12px/1.6 ui-monospace,Consolas,monospace;white-space:pre-wrap}.finish{display:none;padding:18px;background:#eaf9f0;color:#177344;border-radius:8px;margin-top:18px}.error{display:none;padding:12px;background:#fff0f0;color:#a52222;border-radius:7px;margin-top:14px}@media(max-width:700px){.grid,.steps{grid-template-columns:1fr}.steps span:not(:first-child){display:none}.intro{display:grid}}
</style></head><body><main class="shell"><div class="brand"><div class="logo">M</div><div><h1>MassPanel</h1><p>Secure first-time server configuration</p></div></div><section class="card"><div class="steps"><span>1. Server details</span><span>2. Install services</span><span>3. Issue certificates</span><span>4. Open panel</span></div><div class="content"><div class="form" id="form"><div class="intro"><div><h2>Set up your hosting server</h2><p>This installs the panel, website stack, DNS, Grommunio groupware, mail security, firewall and management tools.</p></div><div class="badge">Ubuntu 24.04 LTS</div></div><form id="setup"><div class="grid"><label>Panel hostname<input name="panel_host" placeholder="panel.example.com" required></label><label>Mail hostname<input name="mail_host" placeholder="mail.example.com" required></label><label>Administrator username<input name="admin_user" value="admin" required></label><label>Administrator password<input name="admin_password" type="password" minlength="14" required autocomplete="new-password"></label><label>Confirm password<input name="confirm_password" type="password" minlength="14" required></label><label>Let's Encrypt email<input name="cert_email" type="email" placeholder="owner@example.com" required></label><label class="wide">Company / panel name<input name="panel_name" value="MassPanel" maxlength="80" required></label><label class="check wide"><input name="confirm_dns" type="checkbox" required><span>I have pointed both hostnames to this server's public IP.<small>The installer tests DNS before requesting certificates. Your mail hostname should also have a matching PTR record.</small></span></label></div><div class="error" id="error"></div><div class="actions"><button class="primary">Install everything</button></div></form></div><div class="status" id="status"><div class="intro"><div><h2 id="title">Installing MassPanel</h2><p id="message">Preparing the server…</p></div><div class="badge" id="percent">0%</div></div><div class="bar"><i id="bar"></i></div><div class="log" id="log"></div><div class="finish" id="finish">Installation complete. <a id="open" href="#">Open MassPanel</a></div><div class="error" id="failed"></div></div></div></section></main><script>
const token=new URLSearchParams(location.search).get('token')||'';const form=document.querySelector('#setup'),err=document.querySelector('#error');
form.onsubmit=async e=>{e.preventDefault();err.style.display='none';const data=Object.fromEntries(new FormData(form));if(data.admin_password!==data.confirm_password){err.textContent='Passwords do not match.';err.style.display='block';return}data.token=token;try{const r=await fetch('/api/start',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(data)}),j=await r.json();if(!r.ok)throw Error(j.error);document.querySelector('#form').classList.add('hide');document.querySelector('#status').classList.add('show');poll()}catch(x){err.textContent=x.message;err.style.display='block'}};
async function poll(){try{const r=await fetch('/api/status?token='+encodeURIComponent(token),{cache:'no-store'}),s=await r.json();document.querySelector('#message').textContent=s.message;document.querySelector('#percent').textContent=s.progress+'%';document.querySelector('#bar').style.width=s.progress+'%';document.querySelector('#log').textContent=(s.log||[]).join('\n');document.querySelector('#log').scrollTop=999999;if(s.phase==='complete'){document.querySelector('#finish').style.display='block';document.querySelector('#open').href=s.panel_url;return}if(s.phase==='failed'){const f=document.querySelector('#failed');f.textContent=s.message;f.style.display='block';return}}catch(e){}setTimeout(poll,1500)}
if(!token){err.textContent='Open the one-time setup URL printed by the server.';err.style.display='block';form.querySelector('button').disabled=true}
</script></body></html>'''

def public_ip():
    try:
        with socket.socket() as s: s.connect(("1.1.1.1",53)); return s.getsockname()[0]
    except OSError: return "server-ip"

def run_install(data):
    env = os.environ.copy()
    for key in ("panel_host","mail_host","admin_user","admin_password","cert_email","panel_name"):
        env["MASSPANEL_" + key.upper()] = data[key]
    env["MASSPANEL_INSTALL_STAGE"] = str(STAGE)
    with guard: state.update(phase="running", progress=3, message="Starting installation…")
    try:
        proc = subprocess.Popen([str(RUNNER)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
        for line in proc.stdout:
            clean=line.rstrip()[-500:]
            match=re.match(r"^PROGRESS:(\d+):(.*)$", clean)
            with guard:
                if match: state.update(progress=min(99,int(match.group(1))),message=match.group(2).strip())
                elif clean: state["log"]=(state["log"]+[clean])[-250:]
        code=proc.wait()
        if code: raise RuntimeError(f"Installer stopped with exit code {code}. Review the log above.")
        panel_url="https://"+data["panel_host"]
        with guard: state.update(phase="complete",progress=100,message="MassPanel is ready.",panel_url=panel_url)
    except Exception as exc:
        with guard: state.update(phase="failed",message=str(exc))
    finally: LOCK.unlink(missing_ok=True)

class Handler(BaseHTTPRequestHandler):
    def send(self, code, body, content_type="application/json"):
        raw=body.encode(); self.send_response(code); self.send_header("Content-Type",content_type); self.send_header("Content-Length",str(len(raw))); self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff"); self.end_headers(); self.wfile.write(raw)
    def authorized(self, supplied): return bool(TOKEN and secrets.compare_digest(supplied,TOKEN))
    def do_GET(self):
        parsed=urlparse(self.path); query=parse_qs(parsed.query)
        if parsed.path=="/": return self.send(200,PAGE,"text/html; charset=utf-8")
        if parsed.path=="/api/status" and self.authorized(query.get("token",[""])[0]):
            with guard: payload=json.dumps(state)
            return self.send(200,payload)
        self.send(404,json.dumps({"error":"Not found"}))
    def do_POST(self):
        if self.path!="/api/start": return self.send(404,json.dumps({"error":"Not found"}))
        try: data=json.loads(self.rfile.read(min(int(self.headers.get("Content-Length","0")),8192)))
        except Exception: return self.send(400,json.dumps({"error":"Invalid request."}))
        if not self.authorized(str(data.get("token",""))): return self.send(403,json.dumps({"error":"Invalid setup token."}))
        if str(data.get("confirm_dns","")).lower() not in {"on","true","1"}: return self.send(400,json.dumps({"error":"Confirm that both DNS records are ready."}))
        if MARKER.exists(): return self.send(409,json.dumps({"error":"This server is already installed."}))
        if LOCK.exists() or state["phase"]=="running": return self.send(409,json.dumps({"error":"Installation is already running."}))
        for key in ("panel_host","mail_host"): data[key]=str(data.get(key,"")).lower().strip().rstrip(".")
        if not HOST.fullmatch(data["panel_host"]) or not HOST.fullmatch(data["mail_host"]) or data["panel_host"]==data["mail_host"]: return self.send(400,json.dumps({"error":"Enter two different valid hostnames."}))
        data["admin_user"]=str(data.get("admin_user","")).lower().strip(); data["admin_password"]=str(data.get("admin_password","")); data["cert_email"]=str(data.get("cert_email","")).strip(); data["panel_name"]=str(data.get("panel_name","")).strip()
        if not USER.fullmatch(data["admin_user"]): return self.send(400,json.dumps({"error":"Invalid administrator username."}))
        if len(data["admin_password"])<14 or len(data["admin_password"])>256: return self.send(400,json.dumps({"error":"Use an administrator password of at least 14 characters."}))
        if not EMAIL.fullmatch(data["cert_email"]) or not data["panel_name"]: return self.send(400,json.dumps({"error":"Enter a valid certificate email and panel name."}))
        LOCK.touch(mode=0o600,exist_ok=False); threading.Thread(target=run_install,args=(data,),daemon=True).start(); return self.send(202,json.dumps({"ok":True}))
    def log_message(self, *_): pass

if __name__=="__main__": ThreadingHTTPServer(("0.0.0.0",8080),Handler).serve_forever()
