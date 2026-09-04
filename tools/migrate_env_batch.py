#!/usr/bin/env python3
"""One-shot: migrate resy/browser-use/SUDO/DASHBOARD secrets to vault with hash verify."""
import base64, hashlib, json, os, shutil, subprocess, sys
from pathlib import Path

BW = os.path.expanduser("~/.local/bin/bw")
CA = os.path.expanduser("~/vw-certs/ca.crt")
FOLDER = "hermes"
BACKUP_DIR = Path(os.path.expanduser("~/vw-backups"))
MARKER = "# vault-managed 2026-09-04"

def h(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()[:12]

session = ""
for line in Path(os.path.expanduser("~/.hermes/.env")).read_text().splitlines():
    if line.startswith("BW_SESSION="):
        session = line.partition("=")[2]
        break
if not session:
    sys.exit("no BW_SESSION")

def bw_env():
    e = dict(os.environ); e["BW_SESSION"] = session; e["BW_NOINTERACTION"] = "true"
    if os.path.exists(CA): e["NODE_EXTRA_CA_CERTS"] = CA
    return e

def bw_json(argv):
    r = subprocess.run([BW]+argv, env=bw_env(), capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"bw {argv[:3]} rc={r.returncode}: {r.stderr[:200]}")
    return json.loads(r.stdout)

def dec(s):
    try: return base64.b64decode(s).decode()
    except Exception: return s

def parse_env(p: Path):
    out = {}
    for line in p.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s: continue
        k, _, v = s.partition("=")
        out[k.strip()] = v.strip()
    return out

def encode_new(name, value, folder_id):
    data = {"type":1,"name":base64.b64encode(name.encode()).decode(),"notes":None,
            "login":{"username":None,"password":base64.b64encode(value.encode()).decode(),"totp":None},
            "folderId":folder_id}
    return base64.b64encode(json.dumps(data).encode()).decode()

# backups
BACKUP_DIR.mkdir(mode=0o700, exist_ok=True)
targets = {
    Path(os.path.expanduser("~/.hermes/resy.env")): ["RESY_EMAIL","RESY_PASSWORD"],
    Path(os.path.expanduser("~/.hermes/browser-use.env")): ["BROWSER_USE_API_KEY"],
    Path(os.path.expanduser("~/.hermes/.env")): ["SUDO_PASSWORD","DASHBOARD_BASIC_AUTH"],
}
for p in targets:
    dst = BACKUP_DIR / (p.name.replace(".env","") + "-pre-vault-20260904.bak")
    shutil.copy2(p, dst); os.chmod(dst, 0o600)
    print(f"backup: {dst}")

folders = bw_json(["list","folders"])
fid = next((f["id"] for f in folders if dec(f["name"])==FOLDER or f["name"]==FOLDER), None)
if not fid: sys.exit("folder hermes not found")
items = bw_json(["list","items","--folderid",fid])
existing = {}
for i in items:
    n = dec(i["name"]) if isinstance(i.get("name"),str) else i["name"]
    existing[n] = i["id"]

migrated, failed = [], []
for path, keys in targets.items():
    env = parse_env(path)
    for name in keys:
        value = env.get(name,"")
        if not value:
            print(f"SKIP {name}: empty/missing in {path.name}"); continue
        src_hash = h(value)
        try:
            if name in existing:
                item = bw_json(["get","item",existing[name]])
                item["login"]["password"] = base64.b64encode(value.encode()).decode()
                enc = base64.b64encode(json.dumps(item).encode()).decode()
                r = subprocess.run([BW,"edit","item",existing[name],enc],env=bw_env(),
                                   capture_output=True,text=True,timeout=90)
                if r.returncode!=0: raise RuntimeError(r.stderr[:200])
                op="updated"
            else:
                enc = encode_new(name, value, fid)
                r = subprocess.run([BW,"create","item",enc],env=bw_env(),
                                   capture_output=True,text=True,timeout=90)
                if r.returncode!=0: raise RuntimeError(r.stderr[:200])
                op="created"
            # hash-verify: re-fetch and compare
            chk = bw_json(["get","item",existing.get(name) or json.loads(r.stdout)["id"]])
            vault_val = dec(chk["login"]["password"])
            if h(vault_val)==src_hash:
                print(f"{op}: {name} src_hash={src_hash} vault_hash={h(vault_val)} MATCH")
                if name not in existing:
                    existing[name]=chk["id"]
                migrated.append(name)
            else:
                print(f"FAILED {name}: hash mismatch src={src_hash} vault={h(vault_val)}")
                failed.append(name)
        except Exception as e:
            print(f"FAILED {name}: {str(e)[:150]}"); failed.append(name)

if failed:
    print(f"FAILURES present {failed} — source files NOT rewritten"); sys.exit(1)

# rewrite sources: replace migrated lines with marker
modified = []
for path, keys in targets.items():
    lines = path.read_text().splitlines()
    keep, removed = [], []
    for line in lines:
        k = line.partition("=")[0].strip()
        if k in migrated and not line.strip().startswith("#"):
            removed.append(k); continue
        keep.append(line)
    if removed:
        for k in removed:
            keep.append(f"{MARKER}: {k} moved to vault folder 'hermes'")
        path.write_text("\n".join(keep)+"\n"); os.chmod(path,0o600)
        modified.append(str(path)); print(f"rewrote {path}: removed {removed}")
print(f"MIGRATED={','.join(sorted(migrated))}")
print(f"MODIFIED={','.join(modified)}")
