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
        return extra

    def _bw_json(self, argv, session: str, timeout: float, cfg: dict = None):
        """Run bw with the session env, parse JSON stdout. RuntimeError on
        spawn problems per run_secret_cli contract; returns (proc, parsed)."""
        proc = run_secret_cli(
            ["bw", *argv],
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

        if shutil.which("bw") is None:
            result.error = "The `bw` CLI is not installed or not on PATH."
            result.error_kind = ErrorKind.BINARY_MISSING
            return result

        folder_name = str(self._cfg_get(cfg, "folder", DEFAULT_FOLDER))
        timeout = float(self._cfg_get(cfg, "cli_timeout_seconds", 30.0))

        try:
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
                name = (item.get("name") or "").strip()
                value = (item.get("login") or {}).get("password")
                if value is None:
                    value = item.get("notes") or ""
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
