"""Dropvault dashboard plugin — backend API routes.

Mounted at /api/plugins/dropvault/ by the dashboard plugin system.

All routes go through the dashboard's session-token auth middleware, same
as every other ``/api/plugins/...`` route. Routes (``{vid}`` = vault id;
unsuffixed routes alias the ``default`` vault for back-compat):

GET  /vaults               — [{id, label, ok, vault, email, server, folder}]
GET  /status?vid= | GET  /status/{vid}
GET  /secrets?vid= | GET /secrets/{vid}  — names + metadata, never values
POST /secrets   body += {vault?: id} — create/update one secret
POST /unlock    body += {vault?: id} — {password} → store session in .env
POST /lock      body += {vault?: id} — drop the stored session
POST /sync      body += {vault?: id} — `bw sync` for one vault
POST /sync-env  (unchanged — gateway-wide re-apply via trigger file)

Sessions are stored per vault in ~/.hermes/.env: ``BW_SESSION`` for the
``default`` vault (legacy), ``BW_SESSION_<ID>`` otherwise. Each vault
gets its own CLI state dir (BITWARDENCLI_APPDATA_DIR isolation).

Threat model: the master password arrives over the loopback dashboard
HTTPS/session-token channel, is used for one `bw unlock` invocation, and is
never logged or persisted. Secret values are likewise passed to `bw` over
stdin and never written to disk or logs.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

try:
    from vault_handle import (
        TWO_FACTOR_METHODS,
        _find_usable_node,
        is_two_factor_challenge,
        login_argv,
    )
except ImportError:
    # The dashboard loads this file standalone (module
    # hermes_dashboard_plugin_dropvault) with the plugin root NOT on
    # sys.path — add it so the helpers stay single-sourced.
    import sys as _sys

    _ROOT = Path(__file__).resolve().parent.parent
    if str(_ROOT) not in _sys.path:
        _sys.path.insert(0, str(_ROOT))
    from vault_handle import (  # noqa: E402
        TWO_FACTOR_METHODS,
        _find_usable_node,
        is_two_factor_challenge,
        login_argv,
    )

log = logging.getLogger(__name__)

# What "CLI lost its auth token" looks like (matched case-insensitively
# against bw's stderr+stdout). The login branch must ONLY fire on these —
# never on a bad master password, where `bw unlock` fails with a
# decryption error and retrying `bw login` would CLOBBER the working
# state dir's auth token with a failed-login attempt.
_NOT_LOGGED_IN_MARKERS = (
    "not logged in",
    "no active account",
    "not authenticated",
)

router = APIRouter()

HERMES_ENV = Path.home() / ".hermes" / ".env"
CONFIG_PATH = Path.home() / ".hermes" / "config.yaml"
DEFAULT_FOLDER = "hermes"
LEGACY_SESSION_ENV = "BW_SESSION"
NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_")

# Process-wide lock for config.yaml read-modify-write cycles (the dashboard
# is threaded; two concurrent vault edits must not interleave). The gateway
# only READS config, so this just serializes dashboard writers.
import threading as _threading

_CONFIG_LOCK = _threading.RLock()


def _valid_vault_id(vid) -> bool:
    return isinstance(vid, str) and bool(vid) and all(c in _ID_CHARS for c in vid)


def _session_env_for(vid: str) -> str:
    if vid == "default":
        return LEGACY_SESSION_ENV
    return "BW_SESSION_" + vid.upper()


def _state_dir(vid: str, cli_data_dir: str = "") -> Path:
    if cli_data_dir:
        return Path(os.path.expanduser(str(cli_data_dir)))
    base = Path.home() / ".config" / "Bitwarden CLI"
    if vid == "default":
        return base
    return Path(str(base) + "-" + vid)


def _dropvault_cfg() -> dict:
    import yaml
    try:
        data = yaml.safe_load(CONFIG_PATH.read_text()) or {}
        dv = (data.get("secrets") or {}).get("dropvault") or {}
        return dv if isinstance(dv, dict) else {}
    except Exception:
        return {}


def _load_vaults(*, include_disabled: bool = False) -> list:
    """Configured vaults with legacy flat config migrated to id=default.

    Disabled vaults are SKIPPED by default (they're invisible to the
    gateway); pass include_disabled=True for the dashboard roster, which
    must show them greyed-out with an enable toggle.

    Scope (collection/folder) is per entry, no defaults applied — absent
    scope = whole vault. Legacy flat `folder:` migrates as-is.
    """
    dv = _dropvault_cfg()
    raw = dv.get("vaults")
    if isinstance(raw, list) and raw:
        out, seen = [], set()
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            vid = entry.get("id")
            if not _valid_vault_id(vid) or vid in seen:
                continue
            seen.add(vid)
            if not include_disabled and not entry.get("enabled", True):
                continue
            merged = dict(entry)
            merged.setdefault("session_env", _session_env_for(vid))
            out.append(merged)
        return out
    legacy_keys = ("folder", "collection", "email", "server_url", "ca_cert",
                   "cli_path", "cli_data_dir", "cli_timeout_seconds")
    if any(k in dv for k in legacy_keys):
        entry = {"id": "default"}
        for k in legacy_keys:
            if k in dv and dv[k] is not None:
                entry[k] = dv[k]
        entry.setdefault("session_env", LEGACY_SESSION_ENV)
        return [entry]
    # No vault keys at all: single default vault, no scope = whole vault.
    return [{"id": "default",
             "session_env": LEGACY_SESSION_ENV}]


# ---------------------------------------------------------------------------
# per-vault bw plumbing
# ---------------------------------------------------------------------------

def _ensure_bw_server(cfg: dict, env: dict) -> None:
    """Point this vault's CLI state at cfg server_url (best-effort).

    No-op when server_url is empty ("don't touch CLI server config").
    Never raises; real errors surface from bw.
    """
    url = (str((cfg or {}).get("server_url") or "").strip())
    if not url:
        return
    try:
        cli = str((cfg or {}).get("cli_path") or "") or "bw"
        if cli == "bw" and not shutil.which("bw"):
            return
        st = subprocess.run([cli, "status"], env=env,
                            capture_output=True, text=True, timeout=30)
        cur = ""
        try:
            cur = json.loads(st.stdout).get("serverUrl") or ""
        except Exception:
            pass
        if cur.rstrip("/") == url.rstrip("/"):
            return
        subprocess.run([cli, "config", "server", url], env=env,
                       capture_output=True, text=True, timeout=30)
    except Exception:
        pass


def _resolve_cli(cfg: dict) -> Optional[str]:
    cand = (cfg or {}).get("cli_path")
    if cand and os.path.isfile(str(cand)):
        return str(cand)
    w = shutil.which("bw")
    if w:
        return w
    for c in (os.path.expanduser("~/.local/bin/bw"),
              "/usr/local/bin/bw", "/usr/bin/bw"):
        if os.path.isfile(c):
            return c
    return None


def _bw_env(cfg: dict, session: str = "") -> dict:
    vid = str((cfg or {}).get("id") or "default")
    session_env = str((cfg or {}).get("session_env")
                      or _session_env_for(vid))
    node = _find_usable_node()
    node_dir = os.path.dirname(node) if node else None
    # Dashboard/systemd PATH lacks ~/.local/bin AND contains a DANGLING
    # /usr/local/bin/node (-> /root/.hermes, Permission denied): bw's
    # #!/usr/bin/env node resolves to the broken one -> 'Permission denied'.
    # Prepend our node dir, strip /usr/local/bin.
    parts = [p for p in os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin").split(":")
             if p and p != "/usr/local/bin"]
    env = {
        "PATH": (node_dir + ":" + ":".join(parts)) if node_dir else ":".join(parts),
        "HOME": os.environ.get("HOME", str(Path.home())),
        "BW_NOINTERACTION": "true",
        "BITWARDENCLI_APPDATA_DIR": str(_state_dir(
            vid, str((cfg or {}).get("cli_data_dir") or ""))),
    }
    if session:
        env[session_env] = session
        env["BW_SESSION"] = session  # bw only reads BW_SESSION
    ca = (cfg or {}).get("ca_cert")
    if ca and os.path.isfile(os.path.expanduser(str(ca))):
        env["NODE_EXTRA_CA_CERTS"] = str(ca)
    return env


def _run_bw(cfg: dict, argv: list, session: str = "",
            stdin_data: str = None,
            timeout: float = 60.0) -> subprocess.CompletedProcess:
    cli = _resolve_cli(cfg)
    if cli is None:
        raise HTTPException(503, "bw CLI not installed")
    return subprocess.run(
        [cli, *argv], env=_bw_env(cfg, session),
        input=stdin_data, capture_output=True, text=True, timeout=timeout,
    )


def _run_bw_json(cfg: dict, argv: list, session: str = "",
                 timeout: float = 60.0):
    proc = _run_bw(cfg, argv, session=session, timeout=timeout)
    if proc.returncode != 0:
        raise HTTPException(502, f"bw {' '.join(argv[:2])}: {proc.stderr.strip()[:200]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise HTTPException(502, f"bw {' '.join(argv[:2])}: non-JSON output")


# ---------------------------------------------------------------------------
# vault resolution + sessions
# ---------------------------------------------------------------------------

def _vault_cfg(vid: Optional[str]) -> dict:
    """Resolve id → vault cfg dict. 404 unknown; 400 when several vaults
    exist and none was named (require explicit); default when omitted."""
    vaults = _load_vaults()
    by_id = {v["id"]: v for v in vaults}
    if vid is None or vid == "":
        if len(by_id) == 1:
            return next(iter(by_id.values()))
        raise HTTPException(
            400, "several vaults configured — pass ?vid=<id> or {vault: id}")
    if vid not in by_id:
        raise HTTPException(404, f"unknown vault '{vid}'")
    return by_id[vid]


def _stored_session(cfg: dict) -> str:
    session_env = str(cfg.get("session_env")
                      or _session_env_for(str(cfg.get("id") or "default")))
    if not HERMES_ENV.exists():
        return ""
    prefix = session_env + "="
    for line in HERMES_ENV.read_text().splitlines():
        if line.startswith(prefix):
            return line.split("=", 1)[1].strip()
    return ""


def _store_session(cfg: dict, session: str) -> None:
    """Set/clear this vault's session var in ~/.hermes/.env (0600)."""
    session_env = str(cfg.get("session_env")
                      or _session_env_for(str(cfg.get("id") or "default")))
    lines = HERMES_ENV.read_text().splitlines() if HERMES_ENV.exists() else []
    prefix = session_env + "="
    lines = [line for line in lines if not line.startswith(prefix)]
    if session:
        lines.append(f"{session_env}={session}")
    HERMES_ENV.write_text("\n".join(lines) + ("\n" if lines else ""))
    os.chmod(HERMES_ENV, 0o600)


def _status_email(cfg: dict, session: str) -> Optional[str]:
    try:
        st = _run_bw_json(cfg, ["status"], session=session, timeout=30)
        return st.get("userEmail")
    except HTTPException:
        return None


def _require_unlocked(cfg: dict) -> str:
    session = _stored_session(cfg)
    if not session:
        raise HTTPException(423, "vault locked — unlock first")
    st = _run_bw_json(cfg, ["status"], session=session, timeout=30)
    if st.get("status") != "unlocked":
        raise HTTPException(423, f"vault is '{st.get('status')}' — unlock first")
    return session


def _scope_items_argv(cfg: dict, session: str) -> tuple:
    """Resolve a vault's scope to a `bw list items` argv + short desc.

    Scope: `collection:` wins, else `folder:`, else whole vault.
    Returns (argv, desc); missing named scope → (None, desc) so callers
    report a clean error instead of dumping everything.
    """
    collection = str(cfg.get("collection") or "").strip()
    folder_name = str(cfg.get("folder") or "").strip()
    if collection:
        collections = _run_bw_json(cfg, ["list", "collections"],
                                   session=session, timeout=60)
        coll = next((c for c in collections if c.get("name") == collection),
                    None)
        if coll is None:
            return None, f"collection '{collection}'"
        return (["list", "items", "--collectionid", coll.get("id")],
                f"collection '{collection}'")
    if folder_name:
        folders = _run_bw_json(cfg, ["list", "folders"], session=session,
                               timeout=60)
        folder = next((f for f in folders if f.get("name") == folder_name),
                      None)
        if folder is None:
            return None, f"folder '{folder_name}'"
        return (["list", "items", "--folderid", folder.get("id")],
                f"folder '{folder_name}'")
    return ["list", "items"], "whole vault"


def _create_target(cfg: dict, session: str) -> dict:
    """Where a new secret goes: collection (org item) XOR folder XOR none.

    Returns the item-framework dict ({"collectionIds": [...]} /
    {"folderId": ...} / {}). Creates a missing FOLDER on demand (personal
    vault mechanic); a missing COLLECTION is a 422 — collections live
    under orgs and the dashboard must not mint org structure silently.
    """
    collection = str(cfg.get("collection") or "").strip()
    folder_name = str(cfg.get("folder") or "").strip()
    if collection:
        collections = _run_bw_json(cfg, ["list", "collections"],
                                   session=session, timeout=60)
        coll = next((c for c in collections if c.get("name") == collection),
                    None)
        if coll is None:
            raise HTTPException(
                422, f"collection '{collection}' not found — create it in "
                "the org first (collections need an organization)")
        return {"collectionIds": [coll.get("id")]}
    if folder_name:
        return {"folderId": _folder_id(cfg, session)}
    return {}


def _folder_id(cfg: dict, session: str) -> str:
    folder_name = str(cfg.get("folder") or "").strip()
    if not folder_name:
        raise HTTPException(500, "no folder scope configured")
    folders = _run_bw_json(cfg, ["list", "folders"], session=session,
                           timeout=60)
    fid = next((f["id"] for f in folders if f.get("name") == folder_name), None)
    if fid:
        return fid
    proc = _run_bw(cfg, ["create", "folder", _b64({"name": folder_name})],
                   session=session, timeout=60)
    if proc.returncode != 0:
        raise HTTPException(502, f"cannot create folder: {proc.stderr.strip()[:200]}")
    return json.loads(proc.stdout)["id"]


def _is_stale_revision(stderr: str) -> bool:
    """True when bw failed because another client edited the cipher first."""
    return "out of date" in (stderr or "").lower()


def _sync_best_effort(cfg: dict, session: str) -> None:
    """Refresh the local bw cache from the server (best-effort, never raises).

    Another client may have edited a cipher since our last sync; without
    this, `bw edit` sends a stale lastKnownRevisionDate and the server
    rejects it with "client copy of this cipher is out of date".
    """
    try:
        _run_bw(cfg, ["sync"], session=session, timeout=90)
    except Exception:
        pass


def _find_item(cfg: dict, session: str, scope_argv: list,
               name: str) -> Optional[dict]:
    items = _run_bw_json(cfg, scope_argv, session=session, timeout=90)
    return next((i for i in items if (i.get("name") or "") == name), None)


def _scope_label(cfg: dict) -> str:
    """Short scope description for roster rows (no values)."""
    coll = str(cfg.get("collection") or "").strip()
    if coll:
        return f"collection '{coll}'"
    fol = str(cfg.get("folder") or "").strip()
    if fol:
        return f"folder '{fol}'"
    return "whole vault"


def _vault_summary(cfg: dict) -> dict:
    """One vault's roster row; fail-open (locked vault, no raise)."""
    vid = str(cfg.get("id"))
    session = _stored_session(cfg)
    vault_state = "no-session"
    email = None
    server = None
    if session:
        try:
            st = _run_bw_json(cfg, ["status"], session=session, timeout=30)
            vault_state = st.get("status", "unknown")
            email = st.get("userEmail")
            server = st.get("serverUrl")
        except HTTPException:
            vault_state = "unknown"
        except Exception:
            vault_state = "unknown"
    return {
        "id": vid,
        "label": cfg.get("label") or vid,
        "ok": vault_state == "unlocked",
        "vault": vault_state,
        "email": email or (str(cfg.get("email") or "") or None),
        "server": server or (str(cfg.get("server_url") or "") or None),
        "folder": str(cfg.get("folder") or ""),
        "collection": str(cfg.get("collection") or ""),
        "scope": _scope_label(cfg),
        "enabled": bool(cfg.get("enabled", True)),
        "has_ca": bool(cfg.get("ca_cert")),
    }


class UnlockBody(BaseModel):
    password: str
    vault: Optional[str] = None
    # Two-step login (only needed when the account has 2FA enabled):
    # authenticator/email TOTP or email code. Duo/FIDO2 are NOT supported
    # by the `bw` CLI — use an authenticator, email, or YubiKey OTP method.
    method: Optional[int] = None
    code: Optional[str] = None


class SecretBody(BaseModel):
    name: str
    value: str
    notes: Optional[str] = None
    vault: Optional[str] = None


class VaultBody(BaseModel):
    vault: Optional[str] = None


class VaultUpsertBody(BaseModel):
    """Add a vault, or edit an existing one (same id = update).

    Only plain connection fields — never secrets or sessions.
    `id` is [a-z0-9_]+; `server_url` must be http(s); `ca_cert` must be
    an existing file when given. Omit `ca_cert` for public HTTPS.
    Scope: `collection` wins over `folder`; empty string CLEARS that
    scope; both empty = whole vault. Folder is back-compat.
    """

    id: str
    label: Optional[str] = None
    email: Optional[str] = None
    server_url: Optional[str] = None
    folder: Optional[str] = None
    collection: Optional[str] = None
    ca_cert: Optional[str] = None
    enabled: Optional[bool] = None


class VaultRemoveBody(BaseModel):
    vault: Optional[str] = None
    forget_session: Optional[bool] = True


# Resolve string annotations NOW: the dashboard imports this file via
# spec_from_file_location under a synthetic module name
# (hermes_dashboard_plugin_dropvault), and pydantic/FastAPI resolve
# `Optional[...]` against that module's namespace at first request —
# without this, every model fails with "not fully defined".
UnlockBody.model_rebuild(force=True)
SecretBody.model_rebuild(force=True)
VaultBody.model_rebuild(force=True)
VaultUpsertBody.model_rebuild(force=True)
VaultRemoveBody.model_rebuild(force=True)


# ---------------------------------------------------------------------------


@router.get("/vaults")
def list_vaults():
    """Roster of configured vaults with lock state (no values).

    Includes DISABLED vaults (greyed out in the UI with an enable
    toggle) — every other route skips them.
    """
    return {"vaults": [_vault_summary(v) for v in _load_vaults(include_disabled=True)]}


def _status_for(cfg: dict):
    session = _stored_session(cfg)
    vault_state = "no-session"
    email = None
    server = None
    if session:
        st = _run_bw_json(cfg, ["status"], session=session, timeout=30)
        vault_state = st.get("status", "unknown")
        email = st.get("userEmail")
        server = st.get("serverUrl")
    return {
        "ok": vault_state == "unlocked",
        "vault": vault_state,
        "email": email,
        "server": server,
        "cli": bool(_resolve_cli(cfg)),
        "folder": str(cfg.get("folder") or ""),
        "collection": str(cfg.get("collection") or ""),
        "scope": _scope_label(cfg),
        "id": str(cfg.get("id")),
        "label": cfg.get("label") or str(cfg.get("id")),
    }


@router.get("/status")
def status(vid: Optional[str] = None):
    """One-shot health summary for the tab header (default vault)."""
    return _status_for(_vault_cfg(vid))


@router.get("/status/{vid}")
def status_one(vid: str):
    return _status_for(_vault_cfg(vid))


def _secrets_for(cfg: dict):
    """Names + metadata only — values never leave the vault here."""
    session = _require_unlocked(cfg)
    scope_argv, scope_desc = _scope_items_argv(cfg, session)
    if scope_argv is None:
        raise HTTPException(404, f"{scope_desc} not found in vault")
    data = _run_bw_json(cfg, scope_argv, session=session, timeout=60)
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


@router.get("/secrets")
def list_secrets(vid: Optional[str] = None):
    return _secrets_for(_vault_cfg(vid))


@router.get("/secrets/{vid}")
def list_secrets_one(vid: str):
    return _secrets_for(_vault_cfg(vid))


@router.post("/secrets")
def upsert_secret(body: SecretBody):
    """Create or update one secret. Name must look like an env var."""
    cfg = _vault_cfg(body.vault)
    session = _require_unlocked(cfg)
    name = body.name.strip().upper()
    if not NAME_RE.match(name):
        raise HTTPException(422, "name must match ^[A-Z][A-Z0-9_]{0,127}$ (env-var style)")
    if not body.value:
        raise HTTPException(422, "value must not be empty")

    _sync_best_effort(cfg, session)  # another client may have touched the item
    scope = _create_target(cfg, session)
    scope_argv, _ = _scope_items_argv(cfg, session)
    if scope_argv is None:
        scope_argv = ["list", "items"]  # scope not created yet: no dup check
    existing = _find_item(cfg, session, scope_argv, name)

    item = {
        "type": 1,
        "name": name,
        "notes": body.notes or None,
        "login": {"username": None, "password": body.value, "uris": None,
                  "totp": None},
        **scope,
    }
    if existing:
        payload = {**existing, **item, "id": existing["id"]}
        argv = ["edit", "item", existing["id"], _b64(payload)]
    else:
        argv = ["create", "item", _b64(item)]
    proc = _run_bw(cfg, argv, session=session, stdin_data="", timeout=60)
    if proc.returncode != 0 and existing and _is_stale_revision(proc.stderr):
        # Lost a race with another client: refresh local cache, retry once.
        _sync_best_effort(cfg, session)
        existing = _find_item(cfg, session, scope_argv, name) or existing
        payload = {**existing, **item, "id": existing["id"]}
        proc = _run_bw(cfg, ["edit", "item", existing["id"], _b64(payload)],
                       session=session, stdin_data="", timeout=60)
    if proc.returncode != 0:
        raise HTTPException(502, f"bw write failed: {proc.stderr.strip()[:200]}")
    out = json.loads(proc.stdout)
    return {"ok": True, "name": name, "id": out.get("id"),
            "created": existing is None}


@router.post("/unlock")
def unlock(body: UnlockBody):
    """`bw login` (if needed) then `bw unlock` with the posted password.

    After "Deauthorize Sessions" the CLI loses its stored auth token, so
    unlock alone fails with "You are not logged in" — retry as a full
    password login in that case. The password reaches bw via the BW_PASSWORD
    env var (--passwordenv), so it never appears in argv (invisible to `ps`)
    and never in logs. Scoped to one vault: its state dir, server, email.

    Two-step login: accounts with 2FA get a 402 response
    ({detail: "two-factor required", methods}) listing this vault's
    CLI-supported methods — the UI then shows a code field and retries
    with {password, method, code}. The TOTP/email code travels in argv
    (bw offers no --codeenv); it expires in ~30s and is never logged.
    """
    cfg = _vault_cfg(body.vault)
    if _resolve_cli(cfg) is None:
        raise HTTPException(503, "bw CLI not installed")
    env = {**_bw_env(cfg), "BW_PASSWORD": body.password}
    # decoupling: honor this vault's Vaultwarden URL (any reachable server)
    _ensure_bw_server(cfg, env)
    cli = _resolve_cli(cfg) or "bw"
    proc = subprocess.run(
        [cli, "unlock", "--raw", "--passwordenv", "BW_PASSWORD"],
        env=env, capture_output=True, text=True, timeout=90,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        combined_lower = (proc.stderr + proc.stdout).lower()
        if any(m in combined_lower for m in _NOT_LOGGED_IN_MARKERS):
            # full login (stores client auth), then unlock for the session key.
            # bw login needs the email: last-known from bw status in this
            # vault's state dir, else this vault's configured email.
            st = subprocess.run([cli, "status"], env=_bw_env(cfg),
                                capture_output=True, text=True, timeout=30)
            try:
                email = json.loads(st.stdout).get("userEmail")
            except Exception:
                email = None
            if not email:
                email = cfg.get("email")
            if not email:
                raise HTTPException(
                    409, "no known account email — set secrets.dropvault.vaults[].email in config.yaml")
            method = body.method
            if method is not None and method not in TWO_FACTOR_METHODS:
                raise HTTPException(
                    422, f"unsupported two-step method {method} — "
                    f"bw supports {sorted(TWO_FACTOR_METHODS)}")
            proc = subprocess.run(
                login_argv(cli, email, method=method,
                           code=(body.code or None)),
                env=env, capture_output=True, text=True, timeout=120,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                combined = proc.stderr + proc.stdout
                if is_two_factor_challenge(combined) and not body.code:
                    # Account has 2FA: tell the UI to show the code field.
                    # (Returned, not raised, so the methods list survives
                    # as JSON — HTTPException would stringify detail.)
                    from fastapi.responses import JSONResponse

                    return JSONResponse(
                        status_code=402,
                        content={
                            "detail": "two-factor required",
                            "methods": [
                                {"id": mid, "name": name}
                                for mid, name in sorted(TWO_FACTOR_METHODS.items())
                            ],
                        },
                    )
                detail = proc.stderr.strip()[:200] or "login failed"
                raise HTTPException(401, detail)
            proc = subprocess.run(
                [cli, "unlock", "--raw", "--passwordenv", "BW_PASSWORD"],
                env=env, capture_output=True, text=True, timeout=90,
            )
    if proc.returncode != 0 or not proc.stdout.strip():
        detail = proc.stderr.strip()[:200] or "unlock failed"
        raise HTTPException(401, detail)
    session = proc.stdout.strip()
    _store_session(cfg, session)
    return {"ok": True, "email": _status_email(cfg, session)}


@router.post("/lock")
def lock(body: VaultBody = None):
    """Drop one vault's stored session (dashboard + ~/.hermes/.env)."""
    vid = (body.vault if body and body.vault else None)
    _store_session(_vault_cfg(vid), "")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Vault roster management (add / edit / remove / enable). These rewrite
# secrets.dropvault.vaults in config.yaml via ruamel (round-trip: comments
# and layout preserved); legacy flat configs are migrated to vaults[0]
# first. Secrets (passwords, sessions) are never accepted or written here.
# ---------------------------------------------------------------------------

_VAULT_EDITABLE_KEYS = (
    "label", "email", "server_url", "folder", "collection", "ca_cert",
    "enabled",
)


def _read_raw_config() -> dict:
    import yaml
    try:
        data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_raw_config(data: dict) -> None:
    """Atomic config.yaml rewrite via ruamel round-trip (comments kept).

    Falls back to yaml.safe_dump when ruamel is unavailable. Preserves the
    file's mode/owner (0600 hermes-agent in practice).
    """
    st = CONFIG_PATH.stat() if CONFIG_PATH.exists() else None
    tmp = CONFIG_PATH.with_suffix(".tmp.dropvault")
    try:
        from ruamel.yaml import YAML as _YAML

        _rt = _YAML(typ="rt")
        _rt.preserve_quotes = True
        _rt.indent(mapping=2, sequence=4, offset=2)
        with open(tmp, "w", encoding="utf-8") as f:
            _rt.dump(data, f)
    except Exception:
        import yaml as _yaml

        tmp.write_text(_yaml.safe_dump(
            data, default_flow_style=False, sort_keys=False,
            allow_unicode=True))
    os.chmod(tmp, 0o600 if st is None else (st.st_mode & 0o777))
    try:
        import shutil as _shutil
        _shutil.chown(tmp, st.st_uid, st.st_gid)
    except Exception:
        pass
    os.replace(tmp, CONFIG_PATH)


def _migrate_flat_to_vaults(dv: dict) -> list:
    """Return the vaults list, migrating legacy flat keys into vaults[0].

    Mutates `dv` in place (moves flat keys into the vault entry) and
    returns the live list object inside `dv` so callers can edit it.
    Legacy flat `folder:` migrates as-is (no scope default applied —
    a fresh entry gets no scope = whole vault until the user sets one).
    """
    raw = dv.get("vaults")
    if isinstance(raw, list) and raw:
        return raw
    legacy_keys = ("folder", "collection", "email", "server_url", "ca_cert",
                   "cli_path", "cli_data_dir", "cli_timeout_seconds")
    entry: dict = {"id": "default"}
    for k in legacy_keys:
        if k in dv and dv[k] is not None:
            entry[k] = dv.pop(k)
    dv["vaults"] = [entry]
    return dv["vaults"]


def _validate_vault_fields(body: VaultUpsertBody, *, is_new: bool) -> dict:
    """Validate + normalize an add/edit payload. 422 on bad input."""
    vid = (body.id or "").strip().lower()
    if not _valid_vault_id(vid):
        raise HTTPException(
            422, "vault id must match [a-z0-9_]+ (lowercase, digits, underscore)")
    if is_new and vid == "default" and _load_vaults():
        # 'default' is the migrated legacy vault — a second claimant is a
        # user error, not a silent takeover.
        raise HTTPException(
            409, "vault 'default' already exists — edit it instead")
    out: dict = {"id": vid}
    if body.label is not None:
        out["label"] = body.label.strip() or vid
    if body.email is not None:
        email = body.email.strip()
        if email and ("@" not in email or " " in email):
            raise HTTPException(422, "email doesn't look like an email address")
        out["email"] = email
    if body.server_url is not None:
        url = body.server_url.strip().rstrip("/")
        if url and not (url.startswith("https://") or url.startswith("http://")):
            raise HTTPException(422, "server_url must start with https:// (or http://)")
        out["server_url"] = url
    if body.folder is not None:
        folder = body.folder.strip()
        if folder and not re.match(r"^[A-Za-z0-9_][A-Za-z0-9_.\- ]{0,127}$", folder):
            raise HTTPException(422, "folder name looks invalid")
        out["folder"] = folder  # empty string clears the scope
    if body.collection is not None:
        coll = body.collection.strip()
        if coll and not re.match(r"^[A-Za-z0-9_][A-Za-z0-9_.\- ]{0,127}$", coll):
            raise HTTPException(422, "collection name looks invalid")
        out["collection"] = coll  # empty clears; wins over folder at fetch
    if body.ca_cert is not None:
        ca = body.ca_cert.strip()
        if ca and not os.path.isfile(os.path.expanduser(ca)):
            raise HTTPException(422, f"ca_cert file not found: {ca}")
        out["ca_cert"] = ca
    if body.enabled is not None:
        out["enabled"] = bool(body.enabled)
    return out


@router.post("/vaults")
def add_vault(body: VaultUpsertBody):
    """Add a vault (connection fields only), or 409 if the id exists."""
    fields = _validate_vault_fields(body, is_new=True)
    if not fields.get("server_url"):
        raise HTTPException(422, "server_url is required when adding a vault")
    with _CONFIG_LOCK:
        data = _read_raw_config()
        dv = ((data.get("secrets") or {}).get("dropvault") or {})
        if not isinstance(dv, dict):
            raise HTTPException(500, "secrets.dropvault is not a mapping")
        vaults = _migrate_flat_to_vaults(dv)
        if any(isinstance(v, dict) and v.get("id") == fields["id"] for v in vaults):
            raise HTTPException(
                409, f"vault '{fields['id']}' already exists — edit it instead")
        entry = {"id": fields["id"], "enabled": True}
        for k in _VAULT_EDITABLE_KEYS:
            if k in fields:
                entry[k] = fields[k]
        vaults.append(entry)
        data.setdefault("secrets", {})["dropvault"] = dv
        try:
            _write_raw_config(data)
        except Exception as exc:
            raise HTTPException(500, f"cannot save config: {exc}")
    _drop_sync_trigger()
    return {"ok": True, "id": fields["id"], "created": True}


@router.put("/vaults/{vid}")
def edit_vault(vid: str, body: VaultUpsertBody):
    """Edit a vault's connection fields (id in path wins; never the session)."""
    if body.id and body.id.strip().lower() != vid:
        raise HTTPException(422, "vault id is immutable — remove + re-add to rename")
    fields = _validate_vault_fields(body, is_new=False)
    fields["id"] = vid
    with _CONFIG_LOCK:
        data = _read_raw_config()
        dv = ((data.get("secrets") or {}).get("dropvault") or {})
        if not isinstance(dv, dict):
            raise HTTPException(500, "secrets.dropvault is not a mapping")
        vaults = _migrate_flat_to_vaults(dv)
        target = next((v for v in vaults
                       if isinstance(v, dict) and v.get("id") == vid), None)
        if target is None:
            raise HTTPException(404, f"unknown vault '{vid}'")
        for k in _VAULT_EDITABLE_KEYS:
            if k in fields:
                if fields[k] == "" and k in ("label", "email", "server_url", "ca_cert"):
                    target.pop(k, None)
                else:
                    target[k] = fields[k]
        data.setdefault("secrets", {})["dropvault"] = dv
        try:
            _write_raw_config(data)
        except Exception as exc:
            raise HTTPException(500, f"cannot save config: {exc}")
    _drop_sync_trigger()
    return {"ok": True, "id": vid}


@router.delete("/vaults/{vid}")
def remove_vault(vid: str, body: VaultRemoveBody = None):
    """Remove a vault from config.

    Drops its session from ~/.hermes/.env (unless forget_session=false).
    Removes its `secrets.dropvault_<id>` override section if present.
    The CLI state dir is KEPT (client cache only; re-add resumes instantly).
    Refuses to remove the last remaining vault — disable it instead.
    """
    forget = True if body is None else body.forget_session is not False
    with _CONFIG_LOCK:
        data = _read_raw_config()
        secrets = data.get("secrets") or {}
        dv = secrets.get("dropvault") or {}
        if not isinstance(dv, dict):
            raise HTTPException(500, "secrets.dropvault is not a mapping")
        vaults = _migrate_flat_to_vaults(dv)
        ids = [v.get("id") for v in vaults if isinstance(v, dict)]
        if vid not in ids:
            raise HTTPException(404, f"unknown vault '{vid}'")
        if len(ids) <= 1:
            raise HTTPException(
                409, "cannot remove the last vault — disable it instead")
        dv["vaults"] = [v for v in vaults
                        if not (isinstance(v, dict) and v.get("id") == vid)]
        # Drop a per-source override section for the removed vault.
        for key in (f"dropvault_{vid}",):
            if key in secrets:
                del secrets[key]
        data["secrets"]["dropvault"] = dv
        try:
            _write_raw_config(data)
        except Exception as exc:
            raise HTTPException(500, f"cannot save config: {exc}")
    if forget:
        try:
            _store_session({"id": vid,
                            "session_env": _session_env_for(vid)}, "")
        except Exception:
            pass
    _drop_sync_trigger()
    return {"ok": True, "id": vid, "removed": True}


def _drop_sync_trigger() -> None:
    """Nudge the gateway watchdog to re-read config within ~5s."""
    try:
        trigger = Path.home() / ".hermes" / "cache" / "dropvault-sync.trigger"
        trigger.parent.mkdir(parents=True, exist_ok=True)
        trigger.write_text(str(time.time()))
        try:
            trigger.chmod(0o600)
        except Exception:
            pass
    except Exception:
        pass


@router.post("/sync")
def sync(body: VaultBody = None):
    """`bw sync` for one vault (refresh its server cache)."""
    cfg = _vault_cfg(body.vault if body and body.vault else None)
    session = _require_unlocked(cfg)
    proc = _run_bw(cfg, ["sync"], session=session, timeout=90)
    if proc.returncode != 0:
        raise HTTPException(502, f"bw sync failed: {proc.stderr.strip()[:200]}")
    return {"ok": True}


@router.post("/sync-env")
def sync_env():
    """Ask the gateway watchdog to re-apply vault secrets to the OS env now.

    The dashboard runs in a different process than the gateway, so it cannot
    reach the gateway's os.environ directly — instead it drops a trigger
    file that the gateway-side dropvault watchdog notices within ~5 seconds
    and uses to force a re-apply (env + file shims).
    """
    # Any unlocked vault authorizes the global re-apply; try each in turn.
    vaults = _load_vaults()
    last_exc = None
    for v in vaults:
        try:
            _require_unlocked(v)
            break
        except Exception as exc:  # noqa: BLE001 — try next vault
            last_exc = exc
    else:
        raise last_exc
    from pathlib import Path as _P
    trigger = _P.home() / ".hermes" / "cache" / "dropvault-sync.trigger"
    trigger.parent.mkdir(parents=True, exist_ok=True)
    trigger.write_text(str(time.time()))
    try:
        trigger.chmod(0o600)
    except Exception:
        pass
    return {"ok": True, "note": "gateway applies within ~5s"}


# ---------------------------------------------------------------------------


def _b64(obj) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


# Back-compat shims for old internal callers (tests / older dashboard code):
# single-vault helpers delegating to the default vault.
def _stored_session_default() -> str:  # pragma: no cover
    return _stored_session(_vault_cfg("default"))
