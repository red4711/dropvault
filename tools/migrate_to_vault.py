#!/usr/bin/env python3
"""Migrate secrets from a source into the Dropvault vault ('hermes' folder).

Design rules:
- Values are piped to `bw` via stdin (bw create with encoded JSON on stdin).
- Values are NEVER printed, logged, or included in argv.
- The source .env is only rewritten AFTER the vault item is confirmed.
- Idempotent: re-running updates existing items (created:false path).

Usage:
  migrate_to_vault.py --from-env ~/.hermes/.env --only NAME1,NAME2
  migrate_to_vault.py --from-env ~/.hermes/.env --exclude BW_SESSION,DASHBOARD_BASIC_AUTH
  migrate_to_vault.py --dry-run --from-env ~/.hermes/.env
"""
import argparse
import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path

BW = os.path.expanduser("~/.local/bin/bw")
CA_CERT = os.path.expanduser("~/vw-certs/ca.crt")
FOLDER = "hermes"


def bw_env(session: str) -> dict:
    env = dict(os.environ)
    env["BW_SESSION"] = session
    env["BW_NOINTERACTION"] = "true"
    if os.path.exists(CA_CERT):
        env["NODE_EXTRA_CA_CERTS"] = CA_CERT
    return env


def bw_json(argv, session, timeout=60):
    r = subprocess.run([BW] + argv, env=bw_env(session), timeout=timeout,
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"bw {' '.join(argv[:3])} failed rc={r.returncode}: {r.stderr[:200]}")
    return json.loads(r.stdout)


def parse_env(path: Path):
    out = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def encode_item(name, value, folder_id, item_id=None):
    data = {
        "type": 1,
        "name": base64.b64encode(name.encode()).decode(),
        "notes": None,
        "login": {
            "username": None,
            "password": base64.b64encode(value.encode()).decode(),
            "totp": None,
        },
        "folderId": folder_id if item_id is None else None,
    }
    return base64.b64encode(json.dumps(data).encode()).decode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-env", required=True)
    ap.add_argument("--only")
    ap.add_argument("--exclude", default="")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--keep-source", action="store_true",
                    help="do not remove migrated lines from the source file")
    args = ap.parse_args()

    session = os.environ.get("BW_SESSION") or ""
    if not session:
        for line in Path(os.path.expanduser("~/.hermes/.env")).read_text().splitlines():
            if line.startswith("BW_SESSION="):
                session = line.partition("=")[2]
                break
    if not session:
        sys.exit("no BW_SESSION available — unlock first")

    only = set(args.only.split(",")) if args.only else None
    exclude = set(args.exclude.split(",")) if args.exclude else set()

    # BW_SESSION and session-ish vars stay in the env file by design (chicken/egg)
    exclude |= {"BW_SESSION", "BW_CLIENTID", "BW_CLIENTSECRET"}

    src = Path(args.from_env).expanduser()
    env = parse_env(src)

    folders = bw_json(["list", "folders"], session)
    folder_id = next((f["id"] for f in folders if f["name"] == FOLDER), None)
    if not folder_id:
        sys.exit(f"folder '{FOLDER}' not found")

    existing = {i["name"]: i["id"] for i in bw_json(["list", "items", "--folderid", folder_id], session)}

    migrated, skipped, failed = [], [], []
    for name in sorted(env):
        if only and name not in only:
            continue
        if name in exclude:
            skipped.append((name, "excluded (session/local-only)"))
            continue
        value = env[name]
        if not value:
            skipped.append((name, "empty"))
            continue
        if args.dry_run:
            print(f"would migrate: {name} (len={len(value)})")
            migrated.append(name)
            continue
        try:
            if name in existing:
                item = bw_json(["get", "item", existing[name]], session)
                item["login"]["password"] = base64.b64encode(value.encode()).decode()
                enc = base64.b64encode(json.dumps(item).encode()).decode()
                subprocess.run([BW, "edit", "item", existing[name], enc],
                               env=bw_env(session),
                               capture_output=True, text=True, timeout=90, check=True)
                print(f"updated: {name}")
            else:
                enc = encode_item(name, value, folder_id)
                subprocess.run([BW, "create", "item", enc],
                               env=bw_env(session),
                               capture_output=True, text=True, timeout=90, check=True)
                print(f"created: {name}")
            migrated.append(name)
        except Exception as e:
            failed.append((name, str(e)[:120]))
            print(f"FAILED: {name}: {str(e)[:120]}", file=sys.stderr)

    print(f"\nmigrated: {len(migrated)} | skipped: {len(skipped)} | failed: {len(failed)}")
    if failed:
        for name, err in failed:
            print(f"  FAILED {name}: {err}", file=sys.stderr)

    # rewrite source without migrated lines only if everything succeeded
    if not args.dry_run and not args.keep_source and migrated and not failed:
        keep = []
        for line in src.read_text().splitlines():
            key = line.partition("=")[0].strip()
            if key in migrated:
                continue
            keep.append(line)
        tmp = src.with_suffix(".tmp")
        tmp.write_text("\n".join(keep) + "\n")
        os.chmod(tmp, 0o600)
        tmp.rename(src)
        print(f"source rewritten: {len(migrated)} lines removed from {src}")
    elif not args.keep_source and failed:
        print("source NOT rewritten — failures present, nothing lost")


if __name__ == "__main__":
    main()
