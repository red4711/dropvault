"""Per-vault bw mechanics shared by SecretSource, dashboard API, render_files.

One VaultHandle owns everything that differs between vaults: the CLI
state dir (BITWARDENCLI_APPDATA_DIR isolation), the session env var,
the CA bundle, the server URL, and the folder. Fail-open everywhere:
helpers never raise for missing config, only run()/run_json() surface
spawn problems as RuntimeError per the run_secret_cli contract.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

DEFAULT_FOLDER = "hermes"

_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_")


def valid_vault_id(vid: object) -> bool:
    """True when vid matches [a-z0-9_]+ (URL/env/dir safe)."""
    return isinstance(vid, str) and bool(vid) and all(c in _ID_CHARS for c in vid)


def session_env_for(vid: str) -> str:
    """Per-vault session var; 'default' keeps the legacy BW_SESSION."""
    if vid == "default":
        return "BW_SESSION"
    return "BW_SESSION_" + "".join(
        c.upper() if c in _ID_CHARS else "_" for c in vid
    )


class VaultHandle:
    """All per-vault bw mechanics for one configured vault."""

    def __init__(self, vid, email="", folder=DEFAULT_FOLDER,
                 server_url="", ca_cert="", cli_path="",
                 cli_data_dir="", cli_timeout_seconds=30.0,
                 session_env=""):
        self.vid = vid
        self.email = email or ""
        self.folder = folder or DEFAULT_FOLDER
        self.server_url = (server_url or "").strip()
        self.ca_cert = ca_cert or ""
        self.cli_path = cli_path or ""
        self.cli_data_dir = cli_data_dir or ""
        try:
            self.timeout = float(cli_timeout_seconds or 30.0)
        except (TypeError, ValueError):
            self.timeout = 30.0
        if self.timeout <= 0:
            self.timeout = 30.0
        self.session_env = session_env or session_env_for(vid)

    # ------------------------------------------------------------------ #

    @property
    def state_dir(self) -> Path:
        """CLI state dir: explicit override, else per-vault default.

        The default vault keeps the legacy shared dir so existing logins
        survive migration; every other vault gets its own suffix.
        """
        if self.cli_data_dir:
            return Path(os.path.expanduser(str(self.cli_data_dir)))
        base = Path.home() / ".config" / "Bitwarden CLI"
        if self.vid == "default":
            return base
        return Path(str(base) + "-" + self.vid)

    def bw_env(self, session: str = "") -> dict:
        """Child env for bw: session + isolation + CA + node PATH fix."""
        extra = {
            "BW_NOINTERACTION": "true",
            "BITWARDENCLI_APPDATA_DIR": str(self.state_dir),
        }
        if session:
            extra[self.session_env] = session
            # bw itself only reads BW_SESSION; alias it so the CLI works
            # while the canonical var stays per-vault.
            extra["BW_SESSION"] = session
        ca = self.ca_cert
        if ca and os.path.isfile(os.path.expanduser(str(ca))):
            extra["NODE_EXTRA_CA_CERTS"] = str(ca)
        node = shutil.which("node") or (
            os.path.expanduser("~/.local/bin/node")
            if os.path.isfile(os.path.expanduser("~/.local/bin/node")) else None
        )
        if node:
            extra["PATH"] = os.path.dirname(node) + ":" + os.environ.get(
                "PATH", "/usr/bin:/bin")
        return extra

    def resolve_cli(self) -> str | None:
        """Find bw: explicit cfg path > PATH > common install locations."""
        if self.cli_path and os.path.isfile(self.cli_path):
            return self.cli_path
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

    def run(self, argv, session: str = "",
            timeout: float | None = None):
        """Run bw with this vault's env. RuntimeError on spawn problems."""
        from agent.secret_sources.base import run_secret_cli
        cli = self.resolve_cli()
        if cli is None:
            raise RuntimeError("The `bw` CLI is not installed or not on PATH.")
        allow = [self.session_env, "NODE_EXTRA_CA_CERTS",
                 "BITWARDENCLI_APPDATA_DIR"]
        if self.session_env != "BW_SESSION":
            allow.append("BW_SESSION")
        proc = run_secret_cli(
            [cli, *argv],
            allow_env=allow,
            extra_env=self.bw_env(session),
            timeout=self.timeout if timeout is None else timeout,
        )
        return proc

    def run_json(self, argv, session: str = "", timeout: float | None = None):
        """Run bw, parse JSON stdout. RuntimeError on spawn/non-zero output."""
        proc = self.run(argv, session=session, timeout=timeout)
        if proc.returncode != 0:
            raise RuntimeError(
                f"bw {' '.join(argv[:2])} exited {proc.returncode}: "
                f"{proc.stderr[:300]}")
        return proc, json.loads(proc.stdout)

    def ensure_server(self, env: dict | None = None) -> None:
        """Point this vault's CLI state at server_url (best-effort).

        No-op when server_url is empty ("don't touch CLI server config":
        BYO users may have set it already; bitwarden.com otherwise).
        Never raises.
        """
        if not self.server_url:
            return
        try:
            cli = self.resolve_cli() or "bw"
            base = dict(env) if env else None
            if base is None:
                from agent.secret_sources.base import source_child_env
                try:
                    base = source_child_env()
                except Exception:
                    base = dict(os.environ)
            base = dict(base)
            base.update(self.bw_env())
            base.pop("BW_SESSION", None)
            base.pop(self.session_env, None)
            st = subprocess.run([cli, "status"], env=base,
                                capture_output=True, text=True, timeout=30)
            cur = ""
            try:
                cur = (json.loads(st.stdout).get("serverUrl") or "")
            except Exception:
                pass
            if cur.rstrip("/") == self.server_url.rstrip("/"):
                return
            subprocess.run([cli, "config", "server", self.server_url],
                           env=base, capture_output=True, text=True,
                           timeout=30)
        except Exception:
            pass  # best-effort; fetch surfaces real errors

    @staticmethod
    def maybe_b64_decode(s: str) -> str:
        """bw's item JSON carries pre-encoded fields; decode if valid b64."""
        import base64 as _b64
        if not s or "=" in s and s.count("=") > 2:
            return s
        try:
            dec = _b64.b64decode(s, validate=True)
            txt = dec.decode("utf-8")
            return txt if txt.isprintable() else s
        except Exception:
            return s
