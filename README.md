# Dropvault

**A Vaultwarden-backed secret source and dashboard drop-in for [Hermes Agent](https://github.com/NousResearch/hermes-agent).**

Drop secrets into a self-hosted Vaultwarden from your browser — no SSH, no
editing `.env` files by hand, and **no secret value ever entering your LLM
context, chat transcript, or logs**.

## Why

Hermes can *use* secrets (env vars → tools, `security.redact_secrets` output
redaction), but getting a new API key onto the box meant SSH + editing
`~/.hermes/.env`. Dropvault closes that loop:

```
browser (dashboard tab) ──> local Vaultwarden ──> bw CLI ──> Hermes env at startup
   you type the secret          encrypted at rest       subprocess       tools read env
        here                (value never in chat)    (value never      (value never in
                                                      in LLM context)   LLM context)
```

## What's in the box

Two plugins in one package:

1. **SecretSource plugin** (`__init__.py`) — one Hermes secret source per
   configured vault (`secrets.dropvault.vaults`; legacy flat config still
   works as `id: default`). At Hermes startup, each dumps its scope
   (`collection:` wins, else `folder:`, else the whole vault) through the
   `bw` CLI — isolated CLI state dirs, so vaults never fight — and applies
   every item as an environment variable. Item **name** = env-var name;
   item **password** = value.
2. **Dashboard plugin** (`dashboard/`) — a "Dropvault" tab in the Hermes
   dashboard with a vault switcher (one vault = the familiar single-vault
   UI, no extra chrome):
   - unlock / lock the vault (master password → `bw unlock`, session stored
     in `~/.hermes/.env` with `0600`),
   - list secret **names** (values are never returned by the list endpoint),
   - add / update a secret via a form (value posted once to the backend,
     piped to `bw`, never logged),
   - one-click vault sync.

Also included: `tools/register_account.py` — a dependency-light script that
provisions a Vaultwarden account *programmatically* (the Bitwarden 2026
client's crypto: PBKDF2-600k master key, HKDF-Expand-SHA256 `enc`/`mac`
stretch, AES-256-CBC + HMAC-SHA256 EncStrings type 2). Useful for
infra-as-code provisioning of throwaway service accounts.

## Requirements

- [Hermes Agent](https://hermes-agent.nousresearch.com/docs) with the
  plugin system (user plugins + dashboard plugin API)
- A Vaultwarden server — **any Bitwarden-compatible server works, including
  one you already have** (just `server_url` + `email` + unlock; no local
  container needed). Prefer a box-local vault? The included `deploy/`
  compose file runs one with TLS on loopback (optional).
- Node.js + `bw` CLI: `npm install -g @bitwarden/cli`
- `cryptography` in the Hermes venv (for the register tool only)

## Install

### 1. (Optional) Run a local Vaultwarden

Skip this if you already have a server — Option A under step 3 only needs
its URL. For a box-local vault:

```bash
cd deploy
docker compose up -d          # Vaultwarden on https://127.0.0.1:8443 (self-signed CA included in ./certs after gen)
```

Generate certs and register an account:

```bash
./certs/gen-ca.sh             # creates ~/vw-certs/{ca.crt,server.crt,server.key}
pip install cryptography
python tools/register_account.py \
  --server https://127.0.0.1:8443 \
  --email you@dropvault.local \
  --password-file /path/to/master.pw \
  --ca-cert ~/vw-certs/ca.crt
```

### 2. The bw CLI needs no manual setup

Each vault pins its own CLI state dir automatically, and `ca_cert` is only
needed for self-signed TLS (skip it for public HTTPS — system CAs apply):

### 3. Install the plugin

```bash
git clone https://github.com/red4711/dropvault.git ~/.hermes/plugins/dropvault
```

**Option A — your own Vaultwarden/Bitwarden server (no local container).**
Point at any reachable server and unlock from the dashboard:

```yaml
plugins:
  enabled:
    - dropvault

secrets:
  dropvault:
    enabled: true
    vaults:
      - id: default
        enabled: true
        collection: hermes   # Bitwarden collection; item names become env vars (needs an org)
        email: you@example.com
        server_url: https://vault.example.com   # omit ca_cert: public HTTPS uses system CAs
        # server_url empty = leave the bw CLI's server config alone
```

Scope per vault is yours to choose — `collection:` wins, else `folder:`
(legacy personal-vault folder, back-compat), else the whole vault when
neither is set. That last mode is the dedicated-service-account shape:
every login-type item in the account becomes an env var. A big personal
vault stays quiet by naming a collection (or folder) and exposing only
that slice to Hermes.

**Option B — a second vault** (e.g. family server, work org). Add another
entry; each vault gets its own CLI state dir, session var
(`BW_SESSION_<ID>`), unlock, scope (`collection:` / `folder:` / whole
vault), and optional `ca_cert`:

```yaml
secrets:
  dropvault:
    enabled: true
    vaults:
      - {id: default, collection: hermes, email: you@local, server_url: https://127.0.0.1:8443, ca_cert: ~/vw-certs/ca.crt}
      - {id: primary, folder: oldhermes, email: you@example.com, server_url: https://vault.example.com}
      - {id: svc, email: svc@example.com, server_url: https://vault.example.com}   # no scope = whole vault
```

Same env var in two vaults = first source wins (order via
`secrets.sources: [dropvault_default, dropvault_primary]`); distinct
scopes per vault avoid surprises. One vault configured? Its source keeps
the plain `dropvault` name, so existing setups keep working untouched —
the flat single-vault config (`folder`/`collection`/`email`/`server_url`/
`ca_cert` at the top level, no `vaults:` list) still works and means
`id: default` (stored `folder: hermes` entries keep resolving as before;
new vaults get no scope = whole vault until you set one).

**Option C — local Vaultwarden (optional).** Only if you want a vault on
this box: `cd deploy && docker compose up -d` (loopback TLS via
self-signed CA), `./certs/gen-ca.sh`, then `tools/register_account.py`
to provision an account. Normal setups skip this entirely.

### 4. Use it

Open the Hermes dashboard → **Dropvault** tab → unlock with the master
password → **Add secret**. Restart Hermes (or press Sync) — the secret is
now an environment variable your tools can read.

```
hermes  →  os.environ["MY_API_KEY"]   # value came from the vault, never from chat
```

## Threat model

- **Values never enter LLM context.** The dashboard backend accepts a value
  once per write and pipes it straight to `bw` over stdin. Reads list names
  only. The SecretSource applies values directly to the process environment.
- **Master password handling.** The unlock route forwards the posted
  password to `bw` via the `BW_PASSWORD` environment variable
  (`--passwordenv`), so it never appears in `ps` output, argv, or logs.
- **Two-step login.** Accounts with 2FA: first unlock attempt returns
  402 with the CLI-supported methods (authenticator 0, email 1, YubiKey
  OTP 3 — Duo/FIDO2 are NOT supported by `bw`); the UI reveals a
  method + code field and retries. The TOTP/email code travels in argv
  (`bw` offers no `--codeenv`), expires in ~30s, and is never logged.
  Email codes are delivered by the server after the first attempt —
  check inbox, then Verify & unlock.
- **At rest.** Secrets live encrypted in Vaultwarden (the same encryption
  bw clients use). The only on-disk plaintext-capable artifacts are the
  per-vault session keys in `~/.hermes/.env` (`BW_SESSION` for `default`,
  `BW_SESSION_<ID>` otherwise, `0600`) — same trust level as
  Hermes' own `.env`, but each revocable via its vault's Lock button.
- **Dashboard auth.** Plugin API routes ride behind the Hermes dashboard's
  session-token auth middleware, like all `/api/plugins/...` routes.
- **Not multi-user.** Like the Hermes dashboard itself, this assumes a
  single trusted operator. Don't expose it unauthenticated to a LAN.

## Configuration reference

| Key | Default | Meaning |
|-----|---------|---------|
| `secrets.dropvault.enabled` | `false` | Turn the sources on |
| `secrets.dropvault.auto_sync_minutes` | `10` | Watchdog re-apply interval (`0` = off) |
| `secrets.dropvault.vaults` | – | List of vaults (below); omit for legacy flat single-vault config |
| `secrets.dropvault.vaults[].id` | required | `[a-z0-9_]+`; `default` keeps legacy `BW_SESSION` + state dir |
| `secrets.dropvault.vaults[].label` | id | Display name in the dashboard switcher |
| `secrets.dropvault.vaults[].enabled` | `true` | Per-vault kill switch |
| `secrets.dropvault.vaults[].folder` | – (whole vault) | Legacy vault folder whose item names are env vars (back-compat; empty = whole vault unless `collection` set) |
| `secrets.dropvault.vaults[].collection` | – (whole vault) | Bitwarden collection whose items become env vars (needs an org; wins over `folder`; empty = whole vault unless `folder` set) |
| `secrets.dropvault.vaults[].email` | – | Account email (login fallback + display) |
| `secrets.dropvault.vaults[].server_url` | – | Vaultwarden URL; empty = don't touch CLI server config |
| `secrets.dropvault.vaults[].ca_cert` | – | CA bundle for self-signed TLS; omit for public HTTPS |
| `secrets.dropvault.vaults[].cli_data_dir` | `~/.config/Bitwarden CLI[-<id>]` | CLI state-dir override |
| `secrets.dropvault.vaults[].cli_timeout_seconds` | `30` | Per-`bw`-call timeout |
| `secrets.dropvault.vaults[].session_env` | `BW_SESSION[_<ID>]` | Session var override (rarely needed) |
| `secrets.dropvault.file_shims[].vault` | default/first | Which vault a file-shim entry reads from |

Legacy flat keys (`secrets.dropvault.folder` / `collection` / `email` /
`server_url` / `ca_cert` / `cli_*`, no `vaults:` list) still configure
the `default` vault (`folder:` migrates as-is).

## Files

```
__init__.py             SecretSource plugin (dropvault source)
plugin.yaml             Hermes plugin manifest
dashboard/
  manifest.json         Dashboard tab manifest
  dist/index.js         Tab UI (plain IIFE, no build step)
  plugin_api.py         FastAPI routes mounted at /api/plugins/dropvault/
tools/register_account.py  Programmatic Vaultwarden account provisioning
deploy/docker-compose.yml  Vaultwarden + TLS on loopback
deploy/certs/gen-ca.sh     Self-signed CA + server cert generator
```

## License

MIT
