#!/usr/bin/env python3
"""Render vault-managed files for non-Hermes consumers.

Reads secrets from each vault's scope (same pattern as
VwVaultSource.fetch: scope → `bw list items` + best-effort base64
decode of names/values) and writes them to plain files that plain
systemd units / scripts consume:

  * ~/.cloudflared/tunnel.env, vaultwarden-tunnel.env  (env format)
  * ~/.decodo.env                                       (env format)
  * ~/uptime-agent/config.json                          (json_patch format)

Templates live in config: `secrets.dropvault.file_shims`, a list of
entries. Each entry has {target, format} plus, depending on format:

  env:        {vault_key, [key]} — write KEY=value line (KEY defaults
              to vault_key). Several entries may share one target; all
              managed lines are applied in a single write.
  json_patch: {vault_key, json_path} or {keys: {path: vault_key}} —
              load target JSON, set dotted paths (integer segments
              index into lists), write back.

Rules:
  * Only write when content differs (mtime-safe, atomic tmp+rename).
  * Target files are always ensured to mode 0600.
  * Values are NEVER logged/printed — logs carry key names only.
  * Fail-open: vault locked/unreachable, or a needed key missing, leaves
    the existing file untouched and exits 0 so services keep running.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HOME = Path.home()
CONFIG_PATH = HOME / ".hermes" / "config.yaml"
HERMES_ENV = HOME / ".hermes" / ".env"
DEFAULT_FOLDER = "hermes"
DEFAULT_CA_CERT = HOME / "vw-certs" / "ca.crt"


# --------------------------------------------------------------------------- #
# vault access (mirrors VwVaultSource.fetch, standalone so cron/systemd and
# the plugin hook can use it without importing Hermes internals)
# --------------------------------------------------------------------------- #

def _resolve_bw(cfg: dict) -> str | None:
    cand = (cfg or {}).get("cli_path")
    if cand and os.path.isfile(cand):
        return cand
    w = shutil.which("bw")
    if w:
        return w
    for c in (HOME / ".local" / "bin" / "bw", "/usr/local/bin/bw", "/usr/bin/bw"):
        if c.is_file():
            return str(c)
    return None


LEGACY_SESSION_ENV = "BW_SESSION"

# Valid vault ids: [a-z0-9_]+ (URL/env/dir safe).
_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_")


def _valid_vault_id(vid) -> bool:
    return isinstance(vid, str) and bool(vid) and all(c in _ID_CHARS for c in vid)


def _session_env_for(vid: str) -> str:
    if vid == "default":
        return LEGACY_SESSION_ENV
    return "BW_SESSION_" + vid.upper()


def _vault_state_dir(vid: str, cli_data_dir: str = "") -> Path:
    """Per-vault CLI state dir (BITWARDENCLI_APPDATA_DIR isolation)."""
    if cli_data_dir:
        return Path(os.path.expanduser(str(cli_data_dir)))
    base = HOME / ".config" / "Bitwarden CLI"
    if vid == "default":
        return base
    return Path(str(base) + "-" + vid)


def _load_vaults(dv: dict) -> list:
    """Return [vault_dict, ...] with legacy flat config migrated to
    [{id: default, ...}]. Invalid entries skipped, never raised.

    Scope (collection/folder) is per entry, no defaults applied — absent
    scope = whole vault. Legacy flat `folder:` migrates as-is.
    """
    if not isinstance(dv, dict):
        return []
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
            if not entry.get("enabled", True):
                continue
            merged = dict(entry)
            merged.setdefault("session_env", _session_env_for(vid))
            out.append(merged)
        return out
    legacy_keys = ("folder", "collection", "email", "server_url", "ca_cert",
                   "cli_path", "cli_data_dir", "cli_timeout_seconds")
    if any(k in dv for k in legacy_keys):
        entry = {"id": "default", "enabled": True}
        for k in legacy_keys:
            if k in dv and dv[k] is not None:
                entry[k] = dv[k]
        entry.setdefault("session_env", LEGACY_SESSION_ENV)
        return [entry]
    return []


def _get_session(session_env: str = LEGACY_SESSION_ENV) -> str:
    sess = (os.environ.get(session_env) or "").strip()
    if sess:
        return sess
    # Dashboard/systemd children often lack the .env in their process env
    # (they read it from disk); the file is the canonical bootstrap store.
    # Never cross-read another vault's session var.
    if session_env == LEGACY_SESSION_ENV:
        legacy = (os.environ.get("BW_SESSION") or "").strip()
        if legacy:
            return legacy
    try:
        for line in HERMES_ENV.read_text().splitlines():
            if line.startswith(session_env + "="):
                return line.partition("=")[2].strip()
    except OSError:
        pass
    return ""


def _bw_env(session: str, cfg: dict, vid: str = "default") -> dict:
    env = dict(os.environ)
    session_env = str((cfg or {}).get("session_env")
                      or _session_env_for(vid))
    env[session_env] = session
    # bw itself only reads BW_SESSION; alias it so the CLI works while the
    # canonical var stays per-vault.
    env["BW_SESSION"] = session
    env["BW_NOINTERACTION"] = "true"
    env["BITWARDENCLI_APPDATA_DIR"] = str(_vault_state_dir(
        vid, str((cfg or {}).get("cli_data_dir") or "")))
    ca = (cfg or {}).get("ca_cert")
    if ca is None:
        # Default-CA path: the historical install always had ~/vw-certs/ca.crt
        # for the loopback vault; harmless for public-HTTPS vaults (file
        # simply won't exist there) and keeps legacy configs working.
        ca = str(DEFAULT_CA_CERT)
    if ca and os.path.isfile(os.path.expanduser(str(ca))):
        env["NODE_EXTRA_CA_CERTS"] = str(ca)
    # bw is a node script (#!/usr/bin/env node). Two hazards in sanitized
    # envs: (a) systemd PATH lacks ~/.local/bin -> node not found (exit 126);
    # (b) /usr/local/bin/node is a DANGLING symlink into /root/.hermes
    # (Permission denied) that shadows the good one. Prepend our node dir,
    # strip /usr/local/bin.
    node = shutil.which("node")
    if not (node and os.access(node, os.X_OK)):
        node = None
    if node is None:
        for cand in (os.path.expanduser("~/.local/bin/node"),
                     os.path.expanduser("~/.hermes/node/bin/node")):
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                node = cand
                break
    parts = [p for p in env.get("PATH", "/usr/bin:/bin").split(":")
             if p and p != "/usr/local/bin"]
    if node:
        env["PATH"] = os.path.dirname(node) + ":" + ":".join(parts)
    else:
        env["PATH"] = ":".join(parts)
    return env


def _maybe_b64_decode(s: str) -> str:
    if not s or ("=" in s and s.count("=") > 2):
        return s
    try:
        dec = base64.b64decode(s, validate=True)
        txt = dec.decode("utf-8")
        return txt if txt.isprintable() else s
    except Exception:
        return s


def fetch_vault_secrets(cfg: dict, vid: str = "default",
                      session: str | None = None) -> dict | None:
    """Return {name: value} or None when the vault is unavailable (fail-open).

    Scope: `collection:` wins, else `folder:`, else whole vault.
    None = locked / not configured / binary missing / network error /
    scope not found. Never raises, never logs values.
    """
    if not session:
        session_env = str((cfg or {}).get("session_env")
                          or _session_env_for(vid))
        session = _get_session(session_env)
    if not session:
        return None
    cli = _resolve_bw(cfg)
    if cli is None:
        return None
    timeout = float((cfg or {}).get("cli_timeout_seconds", 30.0) or 30.0)
    collection = str((cfg or {}).get("collection") or "").strip()
    folder_name = str((cfg or {}).get("folder") or "").strip()
    try:
        env = _bw_env(session, cfg, vid)
        r = subprocess.run([cli, "status"], env=env, capture_output=True,
                           text=True, timeout=30)
        try:
            state = (json.loads(r.stdout or "{}").get("status") or "")
        except Exception:
            state = ""
        if state != "unlocked":
            return None
        argv = ["list", "items"]
        if collection:
            r = subprocess.run([cli, "list", "collections"], env=env,
                               capture_output=True, text=True, timeout=timeout)
            if r.returncode != 0:
                return None
            coll = next((c for c in json.loads(r.stdout or "[]")
                         if c.get("name") == collection), None)
            if coll is None:
                return None  # scope not found (yet) — quiet, not an error
            argv = ["list", "items", "--collectionid", coll.get("id", "")]
        elif folder_name:
            r = subprocess.run([cli, "list", "folders"], env=env, capture_output=True,
                               text=True, timeout=timeout)
            if r.returncode != 0:
                return None
            folders = json.loads(r.stdout or "[]")
            folder = next((f for f in folders if f.get("name") == folder_name), None)
            if folder is None:
                return None  # scope not found (yet) — quiet, not an error
            argv = ["list", "items", "--folderid", folder.get("id", "")]
        r = subprocess.run([cli, *argv], env=env, capture_output=True,
                           text=True, timeout=timeout * 2)
        if r.returncode != 0:
            return None
        secrets: dict[str, str] = {}
        for item in json.loads(r.stdout or "[]"):
            name = _maybe_b64_decode((item.get("name") or "").strip())
            value = (item.get("login") or {}).get("password")
            if value is None:
                value = item.get("notes") or ""
            else:
                value = _maybe_b64_decode(value)
            if not name or not value:
                continue
            secrets[name] = value
        return secrets
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #

def load_shim_config() -> tuple[dict, list, list]:
    """Return (dropvault_cfg, vaults, file_shims). Never raises.

    dropvault_cfg is the legacy flat cfg (for back-compat callers);
    vaults is the per-vault list with legacy→default migration applied.
    """
    try:
        import yaml
        data = yaml.safe_load(CONFIG_PATH.read_text()) or {}
        dv = (data.get("secrets") or {}).get("dropvault") or {}
        shims = dv.get("file_shims") or []
        cfg = {k: v for k, v in dv.items()
               if k not in ("file_shims", "vaults")}
        cfg.setdefault("session_env", LEGACY_SESSION_ENV)
        vaults = _load_vaults(dv)
        return cfg, vaults, shims if isinstance(shims, list) else []
    except Exception as exc:
        print(f"render_files: cannot load {CONFIG_PATH}: {exc}", file=sys.stderr)
        return {"session_env": LEGACY_SESSION_ENV}, [], []


# --------------------------------------------------------------------------- #
# renderers
# --------------------------------------------------------------------------- #

def _parse_env_lines(text: str) -> tuple[list, dict]:
    """Split env text into line records + {KEY: index} for managed lines."""
    records: list = []  # ("kv", key, sep_ws...) or ("raw", line)
    index: dict[str, int] = {}
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k = s.partition("=")[0].strip()
            if k and all(c.isalnum() or c == "_" for c in k):
                index.setdefault(k, len(records))
                records.append(["kv", k])
                continue
        records.append(["raw", line])
    return records, index


def render_env_content(current: str, mapping: dict[str, str]) -> str:
    """Apply {ENV_KEY: value} to KEY=VALUE text, preserving order/comments."""
    records, index = _parse_env_lines(current)
    for key, value in mapping.items():
        if key in index:
            records[index[key]] = ["kv", key, value]
        else:
            records.append(["kv", key, value])
    # Unmanaged kv lines were parsed as ["kv", key] without a value;
    # recover their verbatim original text so we never alter them.
    orig_vals: dict[str, str] = {}
    for line in current.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k = s.partition("=")[0].strip()
            orig_vals.setdefault(k, line)
    final: list[str] = []
    for rec in records:
        if rec[0] == "raw":
            final.append(rec[1])
        else:
            k = rec[1]
            if len(rec) > 2:
                final.append(f"{k}={rec[2]}")
            else:
                final.append(orig_vals.get(k, k + "="))
    return "\n".join(final) + "\n"


def _set_dotted_path(doc, path: str, value: str) -> bool:
    """Set dotted path (int segments = list indices). Returns True if changed."""
    parts = path.split(".")
    node = doc
    for p in parts[:-1]:
        if isinstance(node, list):
            if not p.lstrip("-").isdigit():
                raise ValueError(f"bad path '{path}': '{p}' is not a list index")
            node = node[int(p)]
        elif isinstance(node, dict):
            node = node.get(p)
            if node is None:
                raise ValueError(f"bad path '{path}': missing key '{p}'")
        else:
            raise ValueError(f"bad path '{path}': cannot descend into scalar")
    last = parts[-1]
    if isinstance(node, list):
        if not last.lstrip("-").isdigit():
            raise ValueError(f"bad path '{path}': '{last}' is not a list index")
        i = int(last)
        if node[i] == value:
            return False
        node[i] = value
        return True
    if isinstance(node, dict):
        if node.get(last) == value:
            return False
        node[last] = value
        return True
    raise ValueError(f"bad path '{path}': cannot set key on scalar")


def render_json_content(current: str, mapping: dict[str, str]) -> str:
    """Apply {dotted_path: value} to a JSON doc; keep file's dump style."""
    doc = json.loads(current)
    for path, value in mapping.items():
        _set_dotted_path(doc, path, value)
    trailing_nl = current.endswith("\n")
    return json.dumps(doc, indent=2, ensure_ascii=False) + ("\n" if trailing_nl else "")


def _ensure_mode(path: Path) -> bool:
    """Ensure path is 0600. Returns True if the mode was changed."""
    try:
        if (path.stat().st_mode & 0o777) != 0o600:
            os.chmod(path, 0o600)
            return True
    except OSError:
        pass
    return False


def _write_if_different(path: Path, data: bytes) -> bool:
    """Atomically write data (0600) only when bytes differ. Returns changed."""
    try:
        if path.is_file() and path.read_bytes() == data:
            return False
    except OSError:
        pass
    tmp = path.with_suffix(path.suffix + ".tmp.render")
    tmp.write_bytes(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return True


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #

def _default_vault_id(vaults: list) -> str:
    """Shim entries without `vault:` use 'default' when present, else first."""
    ids = [v.get("id") for v in vaults if isinstance(v, dict)]
    if "default" in ids:
        return "default"
    return ids[0] if ids else "default"


def render_all(secrets: dict | None = None,
               session: str | None = None) -> list[dict]:
    """Render every configured shim. Returns per-target report dicts.

    Each report: {target, format, changed, mode_fixed, skipped, missing}.
    Shim entries may pin a source vault via `vault: <id>` (absent = the
    default vault when present, else the first vault). Only vaults
    actually referenced by shims are fetched; values merge first-wins.
    Fail-open: all vaults locked → files untouched, exit 0; missing-key
    reports carry the vault id. Never logs values.
    """
    cfg, vaults, shims = load_shim_config()
    by_id = {v["id"]: v for v in vaults
             if isinstance(v, dict) and _valid_vault_id(v.get("id"))}
    if secrets is None:
        if not by_id:
            # No vault list (or unparsable config): legacy single fetch.
            fetched = fetch_vault_secrets(cfg)
            if fetched is None:
                print("render_files: vault unavailable (locked?) — files left untouched",
                      file=sys.stderr)
                return [{"target": None, "format": None, "changed": False,
                         "mode_fixed": False, "skipped": "vault_unavailable",
                         "missing": []}]
            return _render_with_secrets(shims, {"default": fetched},
                                        _default_vault_id([]))
        # Fetch only vaults actually referenced by shims.
        want: list[str] = []
        for entry in shims:
            if not isinstance(entry, dict):
                continue
            vid = str(entry.get("vault") or _default_vault_id(vaults))
            if vid in by_id and vid not in want:
                want.append(vid)
        per_vault: dict[str, dict | None] = {}
        for vid in want:
            try:
                per_vault[vid] = fetch_vault_secrets(by_id[vid], vid,
                                                     session=session)
            except Exception:
                per_vault[vid] = None
        live = {vid: s for vid, s in per_vault.items() if s is not None}
        if not live:
            print("render_files: vault unavailable (locked?) — files left untouched",
                  file=sys.stderr)
            return [{"target": None, "format": None, "changed": False,
                     "mode_fixed": False, "skipped": "vault_unavailable",
                     "missing": []}]
        return _render_with_secrets(shims, live, _default_vault_id(vaults))
    return _render_with_secrets(shims, {"default": secrets}, "default")


def _render_with_secrets(shims: list, per_vault: dict, default_vid: str,
                         ) -> list[dict]:
    """Group shim entries, resolve each vault_key against its vault."""
    # merged: first-wins across vaults (for callers passing one dict);
    # per-entry vault resolution below handles the multi-vault case.
    merged: dict[str, str] = {}
    for s in per_vault.values():
        if s:
            for k, v in s.items():
                merged.setdefault(k, v)
    # Group entries by (target, format); collect (file_key -> (vid, key)).
    groups: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for entry in shims:
        if not isinstance(entry, dict):
            continue
        target = os.path.expanduser(str(entry.get("target", "")))
        fmt = str(entry.get("format", "env"))
        if not target or fmt not in ("env", "json_patch"):
            print(f"render_files: ignoring malformed shim entry for target "
                  f"'{target}' format '{fmt}'", file=sys.stderr)
            continue
        vid = str(entry.get("vault") or default_vid)
        if vid not in per_vault:
            # Unknown/unavailable vault: record as missing with vault id.
            vid = default_vid
        gkey = (target, fmt)
        if gkey not in groups:
            groups[gkey] = {}
            order.append(gkey)
        grp = groups[gkey]
        if fmt == "env":
            vk = str(entry.get("vault_key", ""))
            if vk:
                grp[str(entry.get("key", vk) or vk)] = (vid, vk)
        else:
            if isinstance(entry.get("keys"), dict):
                for jp, vk in entry["keys"].items():
                    grp[str(jp)] = (vid, str(vk))
            elif entry.get("vault_key") and entry.get("json_path"):
                grp[str(entry["json_path"])] = (vid, str(entry["vault_key"]))
    reports: list[dict] = []
    for target, fmt in order:
        mapping = groups[(target, fmt)]
        path = Path(target)

        def _lookup(vid: str, vk: str):
            s = per_vault.get(vid)
            if s and vk in s:
                return s[vk]
            if vk in merged:
                return merged[vk]
            return None

        missing = sorted(f"{vid}/{vk}" for _k, (vid, vk) in mapping.items()
                         if _lookup(vid, vk) is None)
        if missing:
            print(f"render_files: skip {target}: missing vault keys "
                  f"{', '.join(missing)} — file left untouched", file=sys.stderr)
            reports.append({"target": target, "format": fmt, "changed": False,
                            "mode_fixed": False, "skipped": "missing_keys",
                            "missing": missing})
            continue
        values = {k: _lookup(vid, vk) for k, (vid, vk) in mapping.items()}
        try:
            current = path.read_text() if path.is_file() else ""
        except OSError as exc:
            print(f"render_files: skip {target}: cannot read ({exc})", file=sys.stderr)
            reports.append({"target": target, "format": fmt, "changed": False,
                            "mode_fixed": False, "skipped": "unreadable",
                            "missing": []})
            continue
        try:
            if fmt == "env":
                new_text = render_env_content(current, values)
            else:
                if not current.strip():
                    raise ValueError("existing JSON file is empty — refusing to create schema from scratch")
                new_text = render_json_content(current, values)
        except Exception as exc:
            print(f"render_files: skip {target}: render failed ({exc}) — "
                  f"file left untouched", file=sys.stderr)
            reports.append({"target": target, "format": fmt, "changed": False,
                            "mode_fixed": False, "skipped": "render_error",
                            "missing": []})
            continue
        changed = _write_if_different(path, new_text.encode())
        mode_fixed = _ensure_mode(path)
        print(f"render_files: {target} [{fmt}] keys={len(values)} "
              f"changed={changed} mode_fixed={mode_fixed}", file=sys.stderr)
        reports.append({"target": target, "format": fmt, "changed": changed,
                        "mode_fixed": mode_fixed, "skipped": None, "missing": []})
    return reports


def main() -> int:
    reports = render_all()
    summary = [
        {"target": r["target"], "format": r["format"],
         "changed": r["changed"], "skipped": r["skipped"]}
        for r in reports
    ]
    print(json.dumps({"rendered": summary}, indent=2))
    return 0  # fail-open: never propagate vault outages to callers


if __name__ == "__main__":
    sys.exit(main())
