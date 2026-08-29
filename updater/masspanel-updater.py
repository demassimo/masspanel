#!/usr/bin/env python3
"""Root-only, application-independent MassPanel release updater."""
import argparse, base64, datetime as dt, fcntl, hashlib, json, os, re, shutil, ssl, subprocess, sys, tarfile, tempfile, time, urllib.request
from pathlib import Path, PurePosixPath

UPDATER_VERSION = "1.0.0"
ROOT = Path("/var/lib/masspanel-updater")
CONFIG = Path("/etc/masspanel-updater/config.json")
PUBLIC_KEY = Path("/etc/masspanel-updater/update-signing-public.pem")
STATUS = ROOT / "status.json"
LOCK = ROOT / "update.lock"
CURRENT = Path("/opt/masspanel/VERSION")
MAX_ARTIFACT = 1024 * 1024 * 1024
VERSION = re.compile(r"^[0-9]{4}\.[0-9]{2}\.[0-9]{2}(?:\.[0-9]+)?(?:-[a-z0-9.-]+)?$")

def stamp(): return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
def write_status(**values):
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    data={"state":"idle","updated_at":stamp(),"current_version":current_version()}
    if STATUS.exists():
        try: data.update(json.loads(STATUS.read_text()))
        except Exception: pass
    data.update(values,updated_at=stamp(),current_version=current_version())
    temp=STATUS.with_suffix(".tmp"); temp.write_text(json.dumps(data,indent=2)+"\n"); os.chmod(temp,0o600); os.replace(temp,STATUS)
def current_version(): return CURRENT.read_text().strip() if CURRENT.is_file() else "unknown"
def version_key(value):
    match=re.match(r"^(\d{4})\.(\d{2})\.(\d{2})(?:\.(\d+))?",value)
    return tuple(map(int,match.groups(default="0"))) if match else (0,0,0,0)
def semver_key(value):
    parts=str(value).split(".")
    return tuple(int(part) if part.isdigit() else 0 for part in (parts+["0","0","0"])[:3])
def load_config():
    try: cfg=json.loads(CONFIG.read_text())
    except Exception as exc: raise RuntimeError(f"Cannot read updater configuration: {exc}")
    url=str(cfg.get("manifest_url", "")); channel=str(cfg.get("channel","beta"))
    if not url.startswith("https://"): raise RuntimeError("The update manifest URL must use HTTPS.")
    return cfg,url,channel
def canonical(manifest):
    body={k:v for k,v in manifest.items() if k!="signature"}
    return json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def run(command, *, input_data=None, timeout=600, check=True, env=None):
    result=subprocess.run(command,input=input_data,capture_output=True,text=isinstance(input_data,str) or input_data is None,timeout=timeout,env=env)
    if check and result.returncode: raise RuntimeError((result.stderr or result.stdout or "Command failed").strip()[-2000:])
    return result
def verify_manifest(manifest):
    if manifest.get("schema") != 1 or manifest.get("channel") not in {"beta","stable"}: raise RuntimeError("Unsupported update manifest.")
    version=str(manifest.get("version","")); artifact=manifest.get("artifact",{}); signature=manifest.get("signature",{})
    if not VERSION.fullmatch(version): raise RuntimeError("Invalid release version.")
    if semver_key(manifest.get("minimum_updater_version","1.0.0")) > semver_key(UPDATER_VERSION): raise RuntimeError("This release requires a newer updater bootstrap.")
    if signature.get("algorithm")!="ed25519": raise RuntimeError("Unsupported release signature.")
    url=str(artifact.get("url","")); digest=str(artifact.get("sha256","")).lower(); size=artifact.get("size")
    if not url.startswith("https://") or not re.fullmatch(r"[0-9a-f]{64}",digest) or not isinstance(size,int) or not 0<size<=MAX_ARTIFACT: raise RuntimeError("Invalid release artifact details.")
    try: sig=base64.b64decode(signature["value"],validate=True)
    except Exception: raise RuntimeError("Invalid release signature encoding.")
    with tempfile.TemporaryDirectory(prefix="masspanel-signature-") as folder:
        body=Path(folder)/"manifest.json"; sigfile=Path(folder)/"manifest.sig"
        body.write_bytes(canonical(manifest)); sigfile.write_bytes(sig)
        checked=run(["/usr/bin/openssl","pkeyutl","-verify","-pubin","-inkey",str(PUBLIC_KEY),"-rawin","-in",str(body),"-sigfile",str(sigfile)],check=False)
        if checked.returncode: raise RuntimeError("Release signature verification failed.")
    return version,artifact
def fetch_json(url):
    separator="&" if "?" in url else "?"
    request=urllib.request.Request(url+separator+"_masspanel_check="+str(int(time.time())),headers={"User-Agent":f"MassPanel-Updater/{UPDATER_VERSION}","Accept":"application/json","Cache-Control":"no-cache"})
    with urllib.request.urlopen(request,timeout=30,context=ssl.create_default_context()) as response:
        if int(response.headers.get("Content-Length","0") or 0)>1024*1024: raise RuntimeError("Manifest is too large.")
        return json.loads(response.read(1024*1024+1))
def download(artifact,target):
    request=urllib.request.Request(artifact["url"],headers={"User-Agent":f"MassPanel-Updater/{UPDATER_VERSION}"})
    digest=hashlib.sha256(); total=0
    with urllib.request.urlopen(request,timeout=60,context=ssl.create_default_context()) as response, target.open("wb") as stream:
        while chunk:=response.read(1024*1024):
            total+=len(chunk)
            if total>MAX_ARTIFACT or total>artifact["size"]: raise RuntimeError("Release artifact exceeds its signed size.")
            digest.update(chunk); stream.write(chunk)
    if total!=artifact["size"] or digest.hexdigest()!=artifact["sha256"]: raise RuntimeError("Release artifact checksum or size does not match its signed manifest.")
def safe_extract(archive,destination):
    with tarfile.open(archive,"r:gz") as tar:
        members=tar.getmembers()
        if len(members)>100000: raise RuntimeError("Release contains too many files.")
        for member in members:
            path=PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or member.isdev() or member.issym() or member.islnk(): raise RuntimeError(f"Unsafe release path: {member.name}")
        tar.extractall(destination,filter="data")
def backup(version):
    backups=ROOT/"backups"; backups.mkdir(mode=0o700,parents=True,exist_ok=True)
    path=backups/f"{version}-{dt.datetime.now().strftime('%Y%m%d%H%M%S')}.tar.gz"
    candidates=["/opt/masspanel","/etc/masspanel","/var/lib/masspanel/masspanel.db","/opt/masspanel-updater/current","/etc/masspanel-updater","/usr/local/sbin/masspanel-update","/usr/local/libexec/masspanel-helper","/usr/local/libexec/masspanel-system-mail-sorter","/etc/systemd/system/masspanel.service","/etc/systemd/system/masspanel-updater.service","/etc/systemd/system/masspanel-updater.timer","/etc/nginx/sites-available/masspanel","/etc/nginx/sites-available/masspanel-panel-host","/etc/nginx/sites-enabled/masspanel","/etc/nginx/sites-enabled/masspanel-panel-host","/etc/nginx/snippets/masspanel-tools.conf"]
    existing=[item.lstrip("/") for item in candidates if Path(item).exists() or Path(item).is_symlink()]
    run(["/usr/bin/tar","--acls","--xattrs","--numeric-owner","-czf",str(path),"-C","/",*existing],timeout=1800)
    return path
def restore(snapshot):
    run(["/usr/bin/systemctl","stop","masspanel"],check=False)
    # These two release-owned trees are replaced wholesale so files introduced
    # by a failed release cannot survive the rollback.
    for owned in (Path("/opt/masspanel"),Path("/opt/masspanel-updater/current")):
        if owned.is_dir() and not owned.is_symlink(): shutil.rmtree(owned)
    run(["/usr/bin/tar","--acls","--xattrs","--numeric-owner","-xzf",str(snapshot),"-C","/"],timeout=1800)
    run(["/usr/bin/systemctl","daemon-reload"]); run(["/usr/sbin/nginx","-t"]); run(["/usr/bin/systemctl","restart","masspanel","nginx"])
def healthcheck():
    run(["/opt/masspanel/venv/bin/python","-m","py_compile","/opt/masspanel/backend/app.py","/usr/local/libexec/masspanel-helper","/opt/masspanel/backend/scheduled_backup.py"])
    run(["/usr/sbin/nginx","-t"]); run(["/usr/bin/systemctl","is-active","--quiet","masspanel","nginx"])
    run(["/usr/bin/curl","--fail","--silent","--show-error","--max-time","15","http://127.0.0.1:8100/api/live"])
    if not Path("/opt/masspanel/frontend/index.html").is_file(): raise RuntimeError("Frontend entrypoint is missing.")
def check():
    cfg,url,channel=load_config(); manifest=fetch_json(url); version,artifact=verify_manifest(manifest)
    if manifest["channel"]!=channel: raise RuntimeError("Release channel does not match this server configuration.")
    available=version_key(version)>version_key(current_version())
    write_status(state="available" if available else "current",available_version=version,manifest_url=url,message="Update available." if available else "Already current.")
    return manifest,available
def apply(manifest=None):
    if os.geteuid()!=0: raise RuntimeError("Updates must run as root.")
    manifest,available=(check() if manifest is None else (manifest,True)); version,artifact=verify_manifest(manifest)
    if not available: return
    work=Path(tempfile.mkdtemp(prefix="masspanel-update-",dir=str(ROOT))); snapshot=None
    try:
        write_status(state="downloading",available_version=version,message="Downloading signed release.")
        archive=work/"release.tar.gz"; download(artifact,archive)
        release=work/"release"; release.mkdir(); safe_extract(archive,release)
        if (release/"VERSION").read_text().strip()!=version or not (release/"deploy/update.sh").is_file(): raise RuntimeError("Release contents do not match the signed version.")
        write_status(state="backing_up",message="Creating rollback snapshot."); snapshot=backup(current_version())
        write_status(state="installing",message="Applying release while the panel is stopped.",snapshot=str(snapshot))
        run(["/usr/bin/systemctl","stop","masspanel"])
        env=os.environ.copy(); env["MASSPANEL_UPDATE_STAGE"]=str(release)
        run(["/usr/bin/bash",str(release/"deploy/update.sh")],timeout=3600,env=env)
        CURRENT.write_text(version+"\n"); os.chmod(CURRENT,0o644)
        write_status(state="verifying",message="Running independent health checks."); healthcheck()
        write_status(state="complete",installed_version=version,message="Update installed successfully.",snapshot=str(snapshot))
        try:
            retain=max(1,min(int(load_config()[0].get("retain_backups",3)),10))
            for old in sorted((ROOT/"backups").glob("*.tar.gz"),key=lambda p:p.stat().st_mtime,reverse=True)[retain:]: old.unlink()
        except Exception: pass
    except Exception as exc:
        write_status(state="rolling_back",message=f"Update failed; restoring the previous release: {exc}",snapshot=str(snapshot or ""))
        if snapshot:
            try: restore(snapshot); write_status(state="rolled_back",message=f"Update failed and was rolled back: {exc}",snapshot=str(snapshot))
            except Exception as rollback_exc: write_status(state="rollback_failed",message=f"Update failed: {exc}; rollback also failed: {rollback_exc}",snapshot=str(snapshot)); raise
        raise
    finally: shutil.rmtree(work,ignore_errors=True)
def rollback(snapshot_name=""):
    backups=ROOT/"backups"; candidates=sorted(backups.glob("*.tar.gz"),key=lambda p:p.stat().st_mtime,reverse=True)
    snapshot=(backups/snapshot_name) if snapshot_name else (candidates[0] if candidates else None)
    if not snapshot or snapshot.parent!=backups or not snapshot.is_file(): raise RuntimeError("Rollback snapshot not found.")
    write_status(state="rolling_back",message="Manual rollback in progress.",snapshot=str(snapshot)); restore(snapshot); write_status(state="rolled_back",message="Manual rollback completed.",snapshot=str(snapshot))
def main():
    parser=argparse.ArgumentParser(prog="masspanel-update"); parser.add_argument("command",choices=("check","apply","auto","status","rollback")); parser.add_argument("snapshot",nargs="?"); args=parser.parse_args()
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    if args.command=="status": print(STATUS.read_text() if STATUS.exists() else json.dumps({"state":"never_checked","current_version":current_version()},indent=2)); return
    with LOCK.open("w") as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError("Another update operation is running.")
        if args.command=="check": print(json.dumps(check()[0],indent=2))
        elif args.command=="apply": apply()
        elif args.command=="rollback": rollback(args.snapshot or "")
        else:
            cfg,_,_=load_config(); manifest,available=check()
            if available and bool(cfg.get("automatic_updates",False)): apply(manifest)
if __name__=="__main__":
    try: main()
    except Exception as exc: write_status(state="failed",message=str(exc)); print(f"masspanel-update: {exc}",file=sys.stderr); raise SystemExit(1)
