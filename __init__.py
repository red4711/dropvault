"""Dropvault — Vaultwarden secret source for Hermes Agent.

Registers one SecretSource per configured vault (``secrets.dropvault.vaults``)
that resolves env vars from a dedicated folder ("hermes" by default) in a
self-hosted Vaultwarden / Bitwarden vault.

Conventions:
  * Every item NAME in the folder is an environment-variable name
    (e.g. ``MY_API_KEY``).
  * The secret value lives in the item's login password field
    (notes carry optional human metadata).
  * Bootstrap auth is per-vault: ``BW_SESSION`` for the migrated default
    vault, ``BW_SESSION_<ID>`` otherwise, stored in ``~/.hermes/.env`` —
    the dropvault dashboard UI manages unlocking.

Config:
  secrets:
    dropvault:
      enabled: true
      auto_sync_minutes: 10
      file_shims: [...]
      vaults:
        - {id: default, folder: hermes, email: ..., server_url: ..., ca_cert: ...}
Legacy single-vault config (flat folder/email/server_url/ca_cert keys, no
``vaults`` list) auto-migrates to ``vaults: [{id: default, ...}]`` in code.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, FrozenSet, List, Tuple

try:
    from .vault_handle import (
        DEFAULT_FOLDER,
        VaultHandle,
        session_env_for,
        valid_vault_id,
    )
except ImportError:  # loaded as top-level module (tests / odd loaders)
    from vault_handle import (  # type: ignore[no-redef]
        DEFAULT_FOLDER,
        VaultHandle,
        session_env_for,
        valid_vault_id,
    )

from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    get_source_environment,
)

log = logging.getLogger(__name__)


def _cfg_get(cfg: dict, key: str, default):
    if not isinstance(cfg, dict):
        return default
    val = cfg.get(key, default)
    return default if val is None else val


def _load_vaults_cfg(dv: dict) -> Tuple[dict, List[dict]]:
    """Split secrets.dropvault into (global_cfg, [vault_dict, ...]).

    Legacy flat config (folder/email/server_url/ca_cert/cli_* without a
    ``vaults`` list) migrates to ``[{id: default, ...}]`` in code — the
    user's config file is never rewritten. Invalid entries (bad id,
    disabled, non-dict) are skipped with a warning, never raised.
    """
    if not isinstance(dv, dict):
        return {}, []
    vaults_raw = dv.get("vaults")
    global_cfg = {k: v for k, v in dv.items() if k != "vaults"}
    out: List[dict] = []
    if isinstance(vaults_raw, list) and vaults_raw:
        seen = set()
        for entry in vaults_raw:
            if not isinstance(entry, dict):
                log.warning("dropvault: ignoring non-dict vault entry")
                continue
            vid = entry.get("id")
            if not valid_vault_id(vid):
                log.warning("dropvault: ignoring vault with bad id %r "
                            "(must match [a-z0-9_]+)", vid)
                continue
            if vid in seen:
                log.warning("dropvault: ignoring duplicate vault id %r", vid)
                continue
            seen.add(vid)
            if not entry.get("enabled", True):
                continue
            merged = dict(entry)
            merged.setdefault("folder", global_cfg.get("folder", DEFAULT_FOLDER))
            merged.setdefault("session_env", session_env_for(vid))
            out.append(merged)
        return global_cfg, out
    # Legacy single-vault migration: flat keys become vault id=default.
    legacy_keys = ("folder", "email", "server_url", "ca_cert",
                   "cli_path", "cli_data_dir", "cli_timeout_seconds")
    if any(k in dv for k in legacy_keys):
        entry = {"id": "default", "label": "Local vault", "enabled": True}
        for k in legacy_keys:
            if k in dv and dv[k] is not None:
                entry[k] = dv[k]
        entry.setdefault("folder", DEFAULT_FOLDER)
        entry.setdefault("session_env", "BW_SESSION")
        return global_cfg, [entry]
    return global_cfg, []


def _handle_from_entry(entry: dict) -> VaultHandle:
    return VaultHandle(
        entry.get("id", "default"),
        email=str(entry.get("email") or ""),
        folder=str(entry.get("folder") or DEFAULT_FOLDER),
        server_url=str(entry.get("server_url") or ""),
        ca_cert=str(entry.get("ca_cert") or ""),
        cli_path=str(entry.get("cli_path") or ""),
        cli_data_dir=str(entry.get("cli_data_dir") or ""),
        cli_timeout_seconds=_cfg_get(entry, "cli_timeout_seconds", 30.0),
        session_env=str(entry.get("session_env")
                        or session_env_for(entry.get("id", "default"))),
    )


class VwVaultSource(SecretSource):
    """Resolve env vars from one Vaultwarden folder via the `bw` CLI."""

    shape = "bulk"  # folder dump; explicit maps elsewhere win precedence

    def __init__(self, handle: VaultHandle | None = None,
                 source_name: str = "", label: str = "",
                 session_env: str = "", folder: str = "",
                 timeout: float = 30.0):
        # Zero-arg construction (watchdog fallback / old call sites) yields
        # the default vault; _ensure_init fills the rest lazily.
        if handle is None:
            self._handle = None  # completed by _ensure_init()
            self.name = "dropvault"
            self.label = "Dropvault (Vaultwarden)"
            self._session_env = "BW_SESSION"
            self._folder = DEFAULT_FOLDER
            self.timeout = 30.0
            self.scheme = "vw-default"
            self._cli = None
            return
        self._handle = handle
        self.name = source_name
        self.label = label
        self._session_env = session_env
        self._folder = folder or DEFAULT_FOLDER
        try:
            self.timeout = float(timeout or 30.0)
        except (TypeError, ValueError):
            self.timeout = 30.0
        if self.timeout <= 0:
            self.timeout = 30.0
        self.scheme = f"vw-{handle.vid}"
        self._cli = None

    # ------------------------------------------------------------------ #
    # compat: zero-arg construction yields the default vault source
    # ------------------------------------------------------------------ #

    def _ensure_init(self):
        if getattr(self, "_handle", None) is not None:
            return
        handle = VaultHandle("default", session_env="BW_SESSION")
        self._handle = handle
        self.name = "dropvault"
        self.label = "Dropvault (Vaultwarden)"
        self._session_env = "BW_SESSION"
        self._folder = DEFAULT_FOLDER
        self.timeout = 30.0
        self.scheme = "vw-default"
        self._cli = None

    # ------------------------------------------------------------------ #
    # helpers (all defensive — fetch() must never raise)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _cfg_get(cfg: dict, key: str, default):
        return _cfg_get(cfg, key, default)

    def _bw_json(self, argv, session: str, timeout: float):
        """Run bw with the session env, parse JSON stdout."""
        proc, parsed = self._handle.run_json(argv, session=session,
                                             timeout=timeout)
        return proc, parsed

    # ------------------------------------------------------------------ #
    # SecretSource contract
    # ------------------------------------------------------------------ #

    @staticmethod
    def _maybe_b64_decode(s: str) -> str:
        return VaultHandle.maybe_b64_decode(s)

    def _ensure_server(self, cfg: dict, env: dict) -> None:
        self._handle.ensure_server(env)

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        self._ensure_init()
        result = FetchResult()
        env = get_source_environment()
        session = (env.get(self._session_env) or "").strip()
        if not session:
            result.error = (
                f"secrets.dropvault vault '{self._handle.vid}' is enabled "
                f"but {self._session_env} is not set (vault locked). "
                "Unlock via the Dropvault dashboard tab."
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        cli = self._handle.resolve_cli()
        if cli is None:
            result.error = "The `bw` CLI is not installed or not on PATH."
            result.error_kind = ErrorKind.BINARY_MISSING
            return result

        folder_name = str(self._cfg_get(cfg, "folder", self._folder)
                          or self._folder)
        # cfg slice wins when the orchestrator passes per-source config.
        timeout = self.timeout
        try:
            timeout = float(self._cfg_get(cfg, "cli_timeout_seconds",
                                          timeout) or timeout)
        except (TypeError, ValueError):
            pass

        try:
            # 0. pin bw to the configured server (any reachable Vaultwarden)
            self._handle.ensure_server(dict(env))

            # 1. vault must be unlocked
            _, status = self._bw_json(["status"], session, timeout)
            state = status.get("status")
            if state != "unlocked":
                result.error = f"Vault is '{state}', not 'unlocked'. Unlock via the Dropvault dashboard tab."
                result.error_kind = (
                    ErrorKind.AUTH_EXPIRED if state == "locked" else ErrorKind.NOT_CONFIGURED
                )
                return result

            # 2. locate the managed folder
            _, folders = self._bw_json(["list", "folders"], session, timeout)
            folder = next((f for f in folders if f.get("name") == folder_name), None)
            if folder is None:
                result.error = f"Folder '{folder_name}' not found in vault. Add a secret from the Dropvault tab (it creates the folder)."
                result.error_kind = ErrorKind.NOT_CONFIGURED
                return result
            folder_id = folder.get("id")

            # 3. dump the folder; item name = env var name
            _, items = self._bw_json(["list", "items", "--folderid", folder_id],
                                     session, timeout * 2)
            secrets: Dict[str, str] = {}
            for item in items:
                name = self._maybe_b64_decode((item.get("name") or "").strip())
                value = (item.get("login") or {}).get("password")
                if value is None:
                    value = item.get("notes") or ""
                else:
                    value = self._maybe_b64_decode(value)
                if not name:
                    continue
                if not value:
                    result.warnings.append(f"item '{name}' has an empty value — skipped (never overwrite with '')")
                    continue
                secrets[name] = value
            result.secrets = secrets
            return result

        except RuntimeError as exc:
            msg = str(exc)
            result.error = msg
            lowered = msg.lower()
            if "timed out" in lowered:
                result.error_kind = ErrorKind.TIMEOUT
            elif "exited" in lowered and ("not logged in" in lowered or "locked" in lowered or "failed to decrypt" in lowered or "username or password is incorrect" in lowered):
                result.error_kind = ErrorKind.AUTH_FAILED
            elif "exited" in lowered and ("failed to fetch" in lowered or "connection" in lowered or "error sending request" in lowered):
                result.error_kind = ErrorKind.NETWORK
            else:
                result.error_kind = ErrorKind.INTERNAL
            return result
        except json.JSONDecodeError:
            result.error = "bw produced non-JSON output"
            result.error_kind = ErrorKind.INTERNAL
            return result
        except Exception as exc:  # absolute last resort — still never raise
            result.error = f"unexpected dropvault source error: {exc}"
            result.error_kind = ErrorKind.INTERNAL
            return result

    def protected_env_vars(self, cfg: dict) -> FrozenSet[str]:
        self._ensure_init()
        # A vault item named like a session var must never clobber it.
        return frozenset({self._session_env})

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Enable the Dropvault secret source", "default": False},
            "folder": {"description": "Vault folder whose item names are env vars", "default": DEFAULT_FOLDER},
            "cli_timeout_seconds": {"description": "Per bw-call timeout", "default": 30.0},
        }

    def remediation(self, kind, cfg: dict) -> str:
        if kind == ErrorKind.NOT_CONFIGURED:
            return "Open the Hermes dashboard → Dropvault tab → unlock the vault (stores the session in ~/.hermes/.env), then restart Hermes."
        if kind == ErrorKind.BINARY_MISSING:
            return "Install the Bitwarden CLI: npm install -g @bitwarden/cli (or build from bitwarden/clients)."
        if kind == ErrorKind.AUTH_EXPIRED:
            return "Vault session expired or password changed — re-unlock via the Dropvault dashboard tab."
        if kind == ErrorKind.AUTH_FAILED:
            return "bw rejected the session — re-unlock via the Dropvault dashboard tab."
        if kind == ErrorKind.NETWORK:
            return "Cannot reach Vaultwarden — check the server URL (bw config server <url>) and that the server is up."
        return ""

    # `is_enabled` and `override_existing` use the base defaults, which read
    # cfg["enabled"] / cfg.get("override_existing", False) — exactly right.


def _source_name_for(vid: str, lone_default: bool) -> str:
    """Back-compat: lone default vault keeps source name 'dropvault' so
    existing secrets.sources lists and provenance keep working."""
    if lone_default and vid == "default":
        return "dropvault"
    return f"dropvault_{vid}"


def _build_sources(dv_cfg: dict) -> List[VwVaultSource]:
    _, vaults = _load_vaults_cfg(dv_cfg or {})
    lone_default = len(vaults) == 1 and vaults[0].get("id") == "default"
    sources = []
    for entry in vaults:
        vid = entry["id"]
        handle = _handle_from_entry(entry)
        label = entry.get("label") or (
            "Dropvault (Vaultwarden)" if vid == "default"
            else f"Dropvault ({vid})")
        try:
            timeout = float(entry.get("cli_timeout_seconds", 30.0) or 30.0)
        except (TypeError, ValueError):
            timeout = 30.0
        sources.append(VwVaultSource(
            handle,
            _source_name_for(vid, lone_default),
            label,
            str(entry.get("session_env") or session_env_for(vid)),
            str(entry.get("folder") or DEFAULT_FOLDER),
            timeout,
        ))
    return sources


def _read_dropvault_section() -> dict:
    import yaml
    try:
        data = yaml.safe_load((Path.home() / ".hermes" / "config.yaml").read_text()) or {}
        dv = (data.get("secrets") or {}).get("dropvault") or {}
        return dv if isinstance(dv, dict) else {}
    except Exception:
        return {}


def register(ctx):
    dv_cfg = _read_dropvault_section()
    for src in _build_sources(dv_cfg):
        try:
            ctx.register_secret_source(src)
        except Exception:
            continue


# ---------------------------------------------------------------------------
# Auto-sync watchdog (opt-out via secrets.dropvault.auto_sync_minutes: 0)
# ---------------------------------------------------------------------------

def _load_dv_cfg() -> dict:
    """Read secrets.dropvault config without raising (folder default 'hermes')."""
    dv = _read_dropvault_section()
    return {k: v for k, v in dv.items() if k != "enabled"} or {"folder": "hermes"}


def _maybe_render_file_shims() -> None:
    """Render vault-managed files for non-Hermes consumers (fail-open).

    Loads dropvault/tools/render_files.py (plugin-relative first, then the
    workspace copy) and calls render_all(). Never raises; never logs values.
    """
    import importlib.util
    rlog = logging.getLogger("dropvault.file-shims")
    candidates = [
        Path(__file__).resolve().parent / "tools" / "render_files.py",
        Path.home() / "workspace" / "dropvault" / "tools" / "render_files.py",
    ]
    script = next((c for c in candidates if c.is_file()), None)
    if script is None:
        return
    try:
        spec = importlib.util.spec_from_file_location(
            "dropvault_render_files", str(script))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        reports = mod.render_all()
        changed = sum(1 for r in reports if r.get("changed"))
        rlog.info("file shims rendered: %d targets, %d changed",
                  len(reports), changed)
    except Exception as exc:
        rlog.warning("file shim render skipped: %s", exc)


def _vault_hash_for(handle: VaultHandle, session_env: str, folder: str,
                    timeout: float, env) -> str | None:
    """Hash of (name, value) pairs for one vault; None when unavailable."""
    session = ((env.get(session_env) or "").strip()
               if hasattr(env, "get") else "")
    if not session:
        return None
    try:
        _, status = handle.run_json(["status"], session=session,
                                    timeout=timeout)
        if status.get("status") != "unlocked":
            return None
        _, folders = handle.run_json(["list", "folders"], session=session,
                                     timeout=timeout)
        folder_obj = next((f for f in folders
                           if f.get("name") == folder), None)
        if folder_obj is None:
            return None
        _, items = handle.run_json(
            ["list", "items", "--folderid", folder_obj.get("id")],
            session=session, timeout=timeout * 2)
        h = hashlib.sha256()
        pairs = []
        for item in items:
            name = VaultHandle.maybe_b64_decode(
                (item.get("name") or "").strip())
            value = (item.get("login") or {}).get("password")
            if value is None:
                value = item.get("notes") or ""
            else:
                value = VaultHandle.maybe_b64_decode(value)
            if name and value:
                pairs.append((name, value))
        for k, v in sorted(pairs):
            h.update(k.encode())
            h.update(b"=")
            h.update(v.encode())
        return handle.vid + ":" + h.hexdigest()
    except Exception:
        return None


def _auto_sync_loop(mins: int) -> None:
    """Watch all vault folders; re-apply env secrets on change (no restart).

    Hash per vault (names+values, never logged). Stays silent when vaults
    are locked. On any change — or when the dashboard drops the sync
    trigger file — resets the secret-source cache and re-applies so the
    running gateway picks up new values without a restart.
    """
    import time
    wlog = logging.getLogger("dropvault.watchdog")
    trigger = Path.home() / ".hermes" / "cache" / "dropvault-sync.trigger"
    last_hash = None
    last_trigger = ""
    while True:
        time.sleep(max(1, mins) * 60 if mins > 0 else 5)
        try:
            try:
                trig = trigger.read_text().strip() if trigger.is_file() else ""
            except OSError:
                trig = ""
            forced = bool(trig) and trig != last_trigger
            dv_cfg = _read_dropvault_section()
            _, vaults = _load_vaults_cfg(dv_cfg)
            env = get_source_environment()
            digests = []
            for entry in vaults:
                handle = _handle_from_entry(entry)
                d = _vault_hash_for(
                    handle,
                    str(entry.get("session_env")
                        or session_env_for(entry.get("id"))),
                    str(entry.get("folder") or DEFAULT_FOLDER),
                    float(entry.get("cli_timeout_seconds", 30.0) or 30.0),
                    env,
                )
                if d is not None:
                    digests.append(d)
            if not digests and not forced:
                continue  # locked / not configured — stay quiet
            cur = "|".join(sorted(digests))
            if last_hash is None:
                last_hash = cur  # first tick = baseline, no action
                last_trigger = trig
                if not forced:
                    continue
            if forced or cur != last_hash:
                last_hash = cur
                last_trigger = trig
                wlog.info("vault change detected — re-applying secrets to env")
                from hermes_cli.env_loader import (reset_secret_source_cache,
                                                   _apply_external_secret_sources)
                reset_secret_source_cache()
                _apply_external_secret_sources(Path.home())
                wlog.info("dropvault auto-sync: changed vault re-applied to env")
                try:
                    _maybe_render_file_shims()
                except Exception:
                    pass  # render is fail-open; never crash the loop
        except Exception:
            continue


def _start_auto_sync() -> None:
    """Start the watchdog unless disabled via secrets.dropvault.auto_sync_minutes."""
    import yaml
    import threading
    try:
        data = yaml.safe_load((Path.home() / ".hermes" / "config.yaml").read_text()) or {}
        mins = int(((data.get("secrets") or {}).get("dropvault") or {})
                   .get("auto_sync_minutes", 10))
    except Exception:
        mins = 10
    if mins <= 0:
        return
    threading.Thread(target=_auto_sync_loop, args=(mins,),
                     name="dropvault-auto-sync", daemon=True).start()
    # One-shot render shortly after startup hydration (fail-open, guarded).
    def _delayed_startup_render() -> None:
        import time
        time.sleep(45)
        try:
            _maybe_render_file_shims()
        except Exception:
            pass
    threading.Thread(target=_delayed_startup_render,
                     name="dropvault-file-shims-startup", daemon=True).start()


if not globals().get("_DV_WATCHDOG_STARTED"):
    globals()["_DV_WATCHDOG_STARTED"] = True
    try:
        _start_auto_sync()
    except Exception:
        pass  # never block plugin import
