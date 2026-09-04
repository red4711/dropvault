"""Dropvault — Vaultwarden secret source for Hermes Agent.

Registers a SecretSource that resolves env vars from a dedicated folder
("hermes" by default) in a self-hosted Vaultwarden / Bitwarden vault.

Conventions:
  * Every item NAME in the folder is an environment-variable name
    (e.g. ``MY_API_KEY``).
  * The secret value lives in the item's login password field
    (notes carry optional human metadata).
  * Bootstrap auth is ``BW_SESSION`` (the `bw` CLI session key), stored in
    ``~/.hermes/.env`` — the dropvault dashboard UI manages unlocking.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Dict, FrozenSet

from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    get_source_environment,
    run_secret_cli,
)

DEFAULT_FOLDER = "hermes"


class VwVaultSource(SecretSource):
    """Resolve env vars from a Vaultwarden folder via the `bw` CLI."""

    name = "dropvault"
    label = "Dropvault (Vaultwarden)"
    shape = "bulk"  # folder dump; explicit maps elsewhere win precedence
    scheme = "vw"

    # ------------------------------------------------------------------ #
    # helpers (all defensive — fetch() must never raise)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _cfg_get(cfg: dict, key: str, default):
        if not isinstance(cfg, dict):
            return default
        val = cfg.get(key, default)
        return default if val is None else val

    def _bw_env(self, session: str, cfg: dict) -> dict:
        extra = {
            "BW_NOINTERACTION": "true",
            "BW_SESSION": session,
        }
        ca = self._cfg_get(cfg, "ca_cert", None)
        if ca:
            extra["NODE_EXTRA_CA_CERTS"] = str(ca)
        # bw is a node script with #!/usr/bin/env node; sanitized child envs may
        # lack the dir holding node. Resolve it once and prepend to PATH.
        import shutil, os as _os
        node = shutil.which("node") or (
            _os.path.expanduser("~/.local/bin/node")
            if _os.path.isfile(_os.path.expanduser("~/.local/bin/node")) else None
        )
        if node:
            extra["PATH"] = _os.path.dirname(node) + ":" + _os.environ.get("PATH", "/usr/bin:/bin")
        return extra

    def _bw_json(self, argv, session: str, timeout: float, cfg: dict = None):
        """Run bw with the session env, parse JSON stdout. RuntimeError on
        spawn problems per run_secret_cli contract; returns (proc, parsed)."""
        cli = getattr(self, "_cli", None) or self._resolve_cli(cfg or {})
        proc = run_secret_cli(
            [cli, *argv],
            allow_env=["BW_SESSION", "NODE_EXTRA_CA_CERTS"],
            extra_env=self._bw_env(session, cfg or {}),
            timeout=timeout,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"bw {' '.join(argv[:2])} exited {proc.returncode}: {proc.stderr[:300]}")
        return proc, json.loads(proc.stdout)

    # ------------------------------------------------------------------ #
    # SecretSource contract
    # ------------------------------------------------------------------ #

    def _resolve_cli(self, cfg: dict):
        """Find bw: explicit cfg path > PATH > common install locations."""
        import os, shutil
        cand = cfg.get("cli_path")
        if cand and os.path.isfile(cand):
            return cand
        w = shutil.which("bw")
        if w:
            return w
        for c in (
            os.path.expanduser("~/.local/bin/bw"),
            "/usr/local/bin/bw",
            "/usr/bin/bw",
        ):
            if os.path.isfile(c):
                return c
        return None

    @staticmethod
    def _maybe_b64_decode(s: str) -> str:
        """bw's item JSON carries pre-encoded fields; decode if it is valid b64."""
        import base64 as _b64
        if not s or "=" in s and s.count("=") > 2:
            return s
        try:
            dec = _b64.b64decode(s, validate=True)
            txt = dec.decode("utf-8")
            return txt if txt.isprintable() else s
        except Exception:
            return s

    def _ensure_server(self, cfg: dict, env: dict) -> None:
        """Point `bw` at the configured Vaultwarden URL (decoupling: any
        reachable Vaultwarden/Bitwarden server works — not just the local
        one). No-op when the server already matches; never raises."""
        url = (self._cfg_get(cfg or {}, "server_url", None) or "").strip()
        if not url:
            return
        try:
            cli = self._resolve_cli(cfg or {}) or "bw"
            st = subprocess.run([cli, "status"], env=env,
                                capture_output=True, text=True, timeout=30)
            cur = ""
            try:
                cur = (json.loads(st.stdout).get("serverUrl") or "")
            except Exception:
                pass
            if cur.rstrip("/") == url.rstrip("/"):
                return
            run_secret_cli([cli, "config", "server", url],
                           allow_env=(), extra_env=env, timeout=30)
        except Exception:
            pass  # best-effort; fetch surfaces real errors

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        env = get_source_environment()
        session = (env.get("BW_SESSION") or "").strip()
        if not session:
            result.error = (
                "secrets.dropvault.enabled is true but BW_SESSION is not set "
                "(vault locked). Unlock via the Dropvault dashboard tab."
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        cli = self._resolve_cli(cfg or {})
        self._cli = cli
        if cli is None:
            result.error = "The `bw` CLI is not installed or not on PATH."
            result.error_kind = ErrorKind.BINARY_MISSING
            return result

        folder_name = str(self._cfg_get(cfg, "folder", DEFAULT_FOLDER))
        timeout = float(self._cfg_get(cfg, "cli_timeout_seconds", 30.0))

        try:
            # 0. pin bw to the configured server (any reachable Vaultwarden)
            self._ensure_server(cfg, get_source_environment())

            # 1. vault must be unlocked
            _, status = self._bw_json(["status"], session, timeout, cfg)
            state = status.get("status")
            if state != "unlocked":
                result.error = f"Vault is '{state}', not 'unlocked'. Unlock via the Dropvault dashboard tab."
                result.error_kind = (
                    ErrorKind.AUTH_EXPIRED if state == "locked" else ErrorKind.NOT_CONFIGURED
                )
                return result

            # 2. locate the managed folder
            _, folders = self._bw_json(["list", "folders"], session, timeout, cfg)
            folder = next((f for f in folders if f.get("name") == folder_name), None)
            if folder is None:
                result.error = f"Folder '{folder_name}' not found in vault. Add a secret from the Dropvault tab (it creates the folder)."
                result.error_kind = ErrorKind.NOT_CONFIGURED
                return result
            folder_id = folder.get("id")

            # 3. dump the folder; item name = env var name
            _, items = self._bw_json(["list", "items", "--folderid", folder_id], session, timeout * 2, cfg)
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
        # A vault item named BW_SESSION must never clobber the real session key.
        return frozenset({"BW_SESSION"})

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Enable the Dropvault secret source", "default": False},
            "folder": {"description": "Vault folder whose item names are env vars", "default": DEFAULT_FOLDER},
            "cli_timeout_seconds": {"description": "Per bw-call timeout", "default": 30.0},
        }

    def remediation(self, kind, cfg: dict) -> str:
        if kind == ErrorKind.NOT_CONFIGURED:
            return "Open the Hermes dashboard → Dropvault tab → unlock the vault (stores BW_SESSION in ~/.hermes/.env), then restart Hermes."
        if kind == ErrorKind.BINARY_MISSING:
            return "Install the Bitwarden CLI: npm install -g @bitwarden/cli (or build from bitwarden/clients)."
        if kind == ErrorKind.AUTH_EXPIRED:
            return "Vault session expired or password changed — re-unlock via the Dropvault dashboard tab."
        if kind == ErrorKind.AUTH_FAILED:
            return "bw rejected the session — re-unlock via the Dropvault dashboard tab."
        if kind == ErrorKind.NETWORK:
            return "Cannot reach Vaultwarden — check that the vaultwarden container is up and the server URL is configured (bw config server <url>)."
        return ""

    # `is_enabled` and `override_existing` use the base defaults, which read
    # cfg["enabled"] / cfg.get("override_existing", False) — exactly right.


def register(ctx):
    ctx.register_secret_source(VwVaultSource())


# ---------------------------------------------------------------------------
# Auto-sync watchdog (opt-out via secrets.dropvault.auto_sync_minutes: 0)
# ---------------------------------------------------------------------------

def _load_dv_cfg() -> dict:
    """Read secrets.dropvault config without raising (folder default 'hermes')."""
    import yaml
    try:
        data = yaml.safe_load((Path.home() / ".hermes" / "config.yaml").read_text()) or {}
        dv = (data.get("secrets") or {}).get("dropvault") or {}
        return {k: v for k, v in dv.items() if k != "enabled"} or {"folder": "hermes"}
    except Exception:
        return {"folder": "hermes"}


def _maybe_render_file_shims() -> None:
    """Render vault-managed files for non-Hermes consumers (fail-open).

    Loads dropvault/tools/render_files.py (plugin-relative first, then the
    workspace copy) and calls render_all(). Never raises; never logs values.
    """
    import importlib.util
    import logging
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


def _auto_sync_loop(mins: int) -> None:
    """Watch the vault folder; re-apply env secrets on change (no restart).

    Cheap poll: hash of (name, value) pairs, computed locally — values never
    logged. Stays silent when the vault is locked. On change, resets the
    secret-source cache and re-applies so the running gateway picks up new
    values without a restart.
    """
    import time, hashlib, logging
    wlog = logging.getLogger("dropvault.watchdog")
    src = VwVaultSource()
    cfg = _load_dv_cfg()
    last_hash = None
    while True:
        time.sleep(max(1, mins) * 60)
        try:
            res = src.fetch(cfg, Path.home())
            if not res.ok or not res.secrets:
                continue  # locked / not configured — stay quiet
            h = hashlib.sha256()
            for k in sorted(res.secrets):
                h.update(k.encode()); h.update(b"=")
                h.update(res.secrets[k].encode())
            cur = h.hexdigest()
            if last_hash is None:
                last_hash = cur  # first tick = baseline, no action
                continue
            if cur != last_hash:
                last_hash = cur
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
    import yaml, threading
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
