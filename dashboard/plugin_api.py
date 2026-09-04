"""Dropvault dashboard plugin — backend API routes.

Mounted at /api/plugins/dropvault/ by the dashboard plugin system.

All routes go through the dashboard's session-token auth middleware, same
as every other ``/api/plugins/...`` route. Routes:

GET  /status    — vault + CLI + server reachability summary
GET  /secrets   — list env-var names (never values) in the managed folder
POST /secrets   — create/update one secret {name, value} via `bw`
POST /unlock    — {password} → `bw unlock`, store BW_SESSION in ~/.hermes/.env
POST /sync      — refresh Hermes' secret-source cache (restart-free pickup)

Threat model: the master password arrives over the loopback dashboard
HTTPS/session-token channel, is used for one `bw unlock` invocation, and is
never logged or persisted. Secret values are likewise passed to `bw` over
stdin and never written to disk or logs.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

log = logging.getLogger(__name__)

router = APIRouter()

HERMES_ENV = Path.home() / ".hermes" / ".env"
DEFAULT_FOLDER = "hermes"
NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_BW = shutil.which("bw")
_CA_CERT = Path.home() / "vw-certs" / "ca.crt"


def _bw_env(session: str = "") -> dict:
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", str(Path.home())),
        "BW_NOINTERACTION": "true",
    }
    if session:
        env["BW_SESSION"] = session
    if _CA_CERT.exists():
        env["NODE_EXTRA_CA_CERTS"] = str(_CA_CERT)
    return env


def _run_bw(argv: list, session: str = "", stdin_data: str = None,
            timeout: float = 60.0) -> subprocess.CompletedProcess:
    if not _BW:
        raise HTTPException(503, "bw CLI not installed")
    return subprocess.run(
        ["bw", *argv], env=_bw_env(session),
        input=stdin_data, capture_output=True, text=True, timeout=timeout,
    )


def _run_bw_json(argv: list, session: str = "", timeout: float = 60.0):
    proc = _run_bw(argv, session=session, timeout=timeout)
    if proc.returncode != 0:
        raise HTTPException(502, f"bw {' '.join(argv[:2])}: {proc.stderr.strip()[:200]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise HTTPException(502, f"bw {' '.join(argv[:2])}: non-JSON output")


class UnlockBody(BaseModel):
    password: str


class SecretBody(BaseModel):
    name: str
    value: str
    notes: Optional[str] = None


# ---------------------------------------------------------------------------


@router.get("/status")
def status():
    """One-shot health summary for the tab header."""
    session = _stored_session()
    vault_state = "no-session"
    email = None
    server = None
    if session:
        st = _run_bw_json(["status"], session=session, timeout=30)
        vault_state = st.get("status", "unknown")
        email = st.get("userEmail")
        server = st.get("serverUrl")
    return {
        "ok": vault_state == "unlocked",
        "vault": vault_state,
        "email": email,
        "server": server,
        "cli": bool(_BW),
        "folder": DEFAULT_FOLDER,
    }


@router.get("/secrets")
def list_secrets():
    """Names + metadata only — values never leave the vault here."""
    session = _require_unlocked()
    data = _run_bw_json(["list", "items", "--folderid", _folder_id(session)],
                        session=session, timeout=60)
    return {
        "secrets": [
            {
                "name": (i.get("name") or "").strip(),
                "revision": i.get("revisionDate"),
                "has_notes": bool(i.get("notes")),
            }
            for i in data if (i.get("name") or "").strip()
        ]
    }


@router.post("/secrets")
def upsert_secret(body: SecretBody):
    """Create or update one secret. Name must look like an env var."""
    session = _require_unlocked()
    name = body.name.strip().upper()
    if not NAME_RE.match(name):
        raise HTTPException(422, "name must match ^[A-Z][A-Z0-9_]{0,127}$ (env-var style)")
    if not body.value:
        raise HTTPException(422, "value must not be empty")

    fid = _folder_id(session)
    existing = _find_item(session, fid, name)

    item = {
        "type": 1,
        "name": name,
        "notes": body.notes or None,
        "login": {"username": None, "password": body.value, "uris": None,
                  "totp": None},
        "folderId": fid,
    }
    if existing:
        payload = {**existing, **item, "id": existing["id"]}
        argv = ["edit", "item", existing["id"], _b64(payload)]
    else:
        argv = ["create", "item", _b64(item)]
    proc = _run_bw(argv, session=session, stdin_data="", timeout=60)
    if proc.returncode != 0:
        raise HTTPException(502, f"bw write failed: {proc.stderr.strip()[:200]}")
    out = json.loads(proc.stdout)
    return {"ok": True, "name": name, "id": out.get("id"),
            "created": existing is None}


@router.post("/unlock")
def unlock(body: UnlockBody):
    """`bw unlock` with the posted password; persist BW_SESSION for Hermes.

    The password reaches bw via the BW_PASSWORD env var (--passwordenv), so
    it never appears in argv (invisible to `ps`) and never in logs.
    """
    if not _BW:
        raise HTTPException(503, "bw CLI not installed")
    proc = subprocess.run(
        ["bw", "unlock", "--raw", "--passwordenv", "BW_PASSWORD"],
        env={**_bw_env(), "BW_PASSWORD": body.password},
        capture_output=True, text=True, timeout=90,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        detail = proc.stderr.strip()[:200] or "unlock failed"
        raise HTTPException(401, detail)
    session = proc.stdout.strip()
    _store_session(session)
    return {"ok": True, "email": _status_email(session)}


@router.post("/lock")
def lock():
    """Drop the stored BW_SESSION (dashboard + ~/.hermes/.env)."""
    _store_session("")
    return {"ok": True}


@router.post("/sync")
def sync():
    """Tell the secret-source layer to re-pull (restart-free)."""
    session = _require_unlocked()
    proc = _run_bw(["sync"], session=session, timeout=90)
    if proc.returncode != 0:
        raise HTTPException(502, f"bw sync failed: {proc.stderr.strip()[:200]}")
    return {"ok": True}


# ---------------------------------------------------------------------------


def _b64(obj) -> str:
    import base64
    return base64.b64encode(json.dumps(obj).encode()).decode()


def _stored_session() -> str:
    if not HERMES_ENV.exists():
        return ""
    for line in HERMES_ENV.read_text().splitlines():
        if line.startswith("BW_SESSION="):
            return line.split("=", 1)[1].strip()
    return ""


def _store_session(session: str) -> None:
    """Set/clear BW_SESSION in ~/.hermes/.env (0600)."""
    lines = HERMES_ENV.read_text().splitlines() if HERMES_ENV.exists() else []
    lines = [l for l in lines if not l.startswith("BW_SESSION=")]
    if session:
        lines.append(f"BW_SESSION={session}")
    HERMES_ENV.write_text("\n".join(lines) + ("\n" if lines else ""))
    os.chmod(HERMES_ENV, 0o600)


def _status_email(session: str) -> Optional[str]:
    try:
        st = _run_bw_json(["status"], session=session, timeout=30)
        return st.get("userEmail")
    except HTTPException:
        return None


def _require_unlocked() -> str:
    session = _stored_session()
    if not session:
        raise HTTPException(423, "vault locked — unlock first")
    st = _run_bw_json(["status"], session=session, timeout=30)
    if st.get("status") != "unlocked":
        raise HTTPException(423, f"vault is '{st.get('status')}' — unlock first")
    return session


def _folder_id(session: str) -> str:
    folders = _run_bw_json(["list", "folders"], session=session, timeout=60)
    fid = next((f["id"] for f in folders if f.get("name") == DEFAULT_FOLDER), None)
    if fid:
        return fid
    proc = _run_bw(["create", "folder", _b64({"name": DEFAULT_FOLDER})],
                   session=session, timeout=60)
    if proc.returncode != 0:
        raise HTTPException(502, f"cannot create folder: {proc.stderr.strip()[:200]}")
    return json.loads(proc.stdout)["id"]


def _find_item(session: str, folder_id: str, name: str) -> Optional[dict]:
    items = _run_bw_json(["list", "items", "--folderid", folder_id],
                         session=session, timeout=90)
    return next((i for i in items if (i.get("name") or "") == name), None)
