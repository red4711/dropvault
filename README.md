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

1. **SecretSource plugin** (`__init__.py`) — a Hermes secret source named
   `dropvault`. At Hermes startup, it dumps a managed vault folder (default:
   `hermes`) through the `bw` CLI and applies every item as an environment
   variable. Item **name** = env-var name; item **password** = value.
2. **Dashboard plugin** (`dashboard/`) — a "Dropvault" tab in the Hermes
   dashboard:
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
- A Vaultwarden server (any Bitwarden-compatible server works; the included
  `deploy/` compose file runs one with TLS on loopback)
- Node.js + `bw` CLI: `npm install -g @bitwarden/cli`
- `cryptography` in the Hermes venv (for the register tool only)

## Install

### 1. Run Vaultwarden

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

### 2. Point the bw CLI at your server

```bash
export NODE_EXTRA_CA_CERTS=~/vw-certs/ca.crt   # self-signed CA; skip if using a real cert
bw config server https://127.0.0.1:8443
```

### 3. Install the plugin

```bash
git clone https://github.com/red4711/dropvault.git ~/.hermes/plugins/dropvault
```

Enable it in `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - dropvault

secrets:
  dropvault:
    enabled: true
    folder: hermes                      # vault folder whose items become env vars
    ca_cert: /home/you/vw-certs/ca.crt  # optional, for self-signed TLS
```

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
- **At rest.** Secrets live encrypted in Vaultwarden (the same encryption
  bw clients use). The only on-disk plaintext-capable artifact is the
  `BW_SESSION` key in `~/.hermes/.env` (`0600`) — same trust level as
  Hermes' own `.env`, but revocable via the Lock button.
- **Dashboard auth.** Plugin API routes ride behind the Hermes dashboard's
  session-token auth middleware, like all `/api/plugins/...` routes.
- **Not multi-user.** Like the Hermes dashboard itself, this assumes a
  single trusted operator. Don't expose it unauthenticated to a LAN.

## Configuration reference

| Key | Default | Meaning |
|-----|---------|---------|
| `secrets.dropvault.enabled` | `false` | Turn the source on |
| `secrets.dropvault.folder` | `hermes` | Vault folder whose item names are env vars |
| `secrets.dropvault.cli_timeout_seconds` | `30` | Per-`bw`-call timeout |
| `secrets.dropvault.ca_cert` | – | Path to a CA bundle for self-signed Vaultwarden TLS |

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
