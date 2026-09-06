# Configuration reference

Merge order (lowest → highest): compiled `defaults` → `config.edn` → environment → CLI flags.
Unset CLI flags are dropped (not merged), so env/file values survive unless explicitly overridden.

## Config file

Default path `./config.edn` (override with `--config PATH`). Copy the template:

```bash
cp config.edn.example config.edn
```

`config.edn` is git-ignored — it may hold secrets. Keys use kebab-case keywords
(`:cyberark-mode`, `:tenable-scan-id`, …).

## Environment variables

| Variable | Config key | Example |
|---|---|---|
| `CYBERARK_MODE` | `:cyberark-mode` | `ccp` / `conjur` |
| `CYBERARK_BASE_URL` | `:cyberark-base-url` | `https://ccp.corp.example` |
| `CYBERARK_APP_ID` | `:cyberark-app-id` | `BridgeGateApp` |
| `CYBERARK_SAFE` | `:cyberark-safe` | `CI-CD-Safe` |
| `CYBERARK_OBJECT` | `:cyberark-object` | `deploy-svc` |
| `CONJUR_APPLIANCE_URL` | `:conjur-appliance-url` | `https://conjur.corp.example` |
| `CONJUR_ACCOUNT` | `:conjur-account` | `default` |
| `CONJUR_AUTHN_LOGIN` | `:conjur-authn-login` | `host/bridge/ci` |
| `CONJUR_API_KEY` | `:conjur-api-key` | `…` |
| `CONJUR_SECRET_VAR` | `:conjur-secret-var` | `ci/deploy/key` |
| `TENABLE_MODE` | `:tenable-mode` | `tenable-io` / `tenable-sc` (`_` also accepted) |
| `TENABLE_BASE_URL` | `:tenable-base-url` | `https://cloud.tenable.com` |
| `TENABLE_ACCESS_KEY` | `:tenable-access-key` | `…` |
| `TENABLE_SECRET_KEY` | `:tenable-secret-key` | `…` |
| `TENABLE_SCAN_ID` | `:tenable-scan-id` | `123` (launch existing scan) |
| `TENABLE_TEMPLATE_UUID` | `:tenable-template-uuid` | `…` (Tenable.io: create-then-launch) |
| `BRIDGE_POLICY` | `:policy` | `policies/mas_trm.edn` |
| `BRIDGE_FINDINGS` | `:findings` | `.bridge/findings.json` |
| `BRIDGE_REPORT` | `:report` | `.bridge/block.json` |
| `BRIDGE_MOCK` | `:mock` | `true` / `1` (offline fixtures, no network) |

## CLI flags

`--target`, `--policy`, `--input` (`-` forces stdin), `--out`, `--report`,
`--config`, `--notify-webhook`, `--mock`, `-h/--help`. Flags come **after** the subcommand.

## Backend notes

- **CCP**: `GET {base}/AIMWebService/api/Accounts?AppID=&Safe=&Object=` → normalizes
  `UserName`/`Content`/`Expiry` to `{:username :secret :expiry}`.
- **Conjur**: `POST {appliance}/authn/{account}/{login}/authenticate` (api key in body) →
  `GET {appliance}/secrets/{account}/variable/{var}` with `Token token="…"` header.
- **Tenable.io**: launch existing scan (`POST /api/v3/scans/{id}/launch`) or create from template;
  poll `GET /scans/{id}` to `completed`; `POST …/export` → poll `ready` → download JSON.
- **Tenable.sc**: `POST /rest/token` (or reuse token) → `POST /rest/scan/{id}/launch` →
  poll `/rest/scanResult/{id}` to `Completed` → `POST /rest/analysis` (`vulndetails`).
- Polling honors `:poll-interval-ms` (default 10000) / `:poll-max-attempts` (default 60).
- Severities coerce fail-closed: unknown vendor values become `:critical`.
