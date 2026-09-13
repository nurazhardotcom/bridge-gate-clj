# bridge-gate-clj

> **Status:** Active — maintained. Unofficial project, no affiliation with CyberArk/Tenable; synthetic fixtures only.

**Enterprise Compliance-as-Code Engine** — a single, fast [Babashka](https://babashka.org) CLI that orchestrates
CyberArk dynamic credential fetching, triggers a targeted Tenable scan, and runs a pure-Clojure policy check
before permitting a CI/CD infrastructure deployment.

Legacy enterprise platforms have terrible CLI DX: CyberArk has a complex REST API, Tenable outputs bloated
JSON/XML, ServiceNow requires manual ticket tracking. Security teams are forced to write 500-line fragile Bash
scripts or pay millions for heavy enterprise orchestrators. `bridge` replaces that glue with one zero-dependency
`bb` tool and a machine-enforced gate.

```
bridge cyberark-auth  →  bridge tenable-scan --target 10.10.50.12  →  bridge enforce-gate
   short-lived creds         scan + normalized findings               exit 0 PASS / 1 BLOCK / 2 ERROR
```

## Quickstart (offline, no credentials needed)

Requires [Babashka](https://babashka.org) v1.12+ (bundles every dependency: no `deps.edn` resolution, no `opa` binary).

```bash
bb cyberark-auth --mock
bb tenable-scan --target 10.10.50.12 --mock
bb enforce-gate --mock          # mock findings contain 1 HIGH → BLOCK, exit 1
echo $?                         # 1 — pipeline halts, .bridge/block.json written
```

## Commands

| Command | Purpose |
|---|---|
| `bridge cyberark-auth` | Fetch short-lived credential via CyberArk CCP or Conjur; prints JSON |
| `bridge tenable-scan --target IP` | Launch scan, poll to completion, save normalized findings JSON |
| `bridge enforce-gate [--policy P] [--input F] [--report R]` | Evaluate findings; exit **0** PASS · **1** BLOCK (writes `block.json`) · **2** error |

Flags come after the subcommand. Common flags: `--mock` (offline fixtures, also `BRIDGE_MOCK=true`),
`--input -` (force stdin), `--out PATH`, `--notify-webhook URL` (POST the Slack block payload on BLOCK),
`--config PATH`, `-h/--help`.

```bash
# Compose in a pipeline: findings flow scan → gate over stdin
bb tenable-scan --target 10.10.50.12 --mock --out /tmp/f.json
cat /tmp/f.json | bb enforce-gate --input - --mock
```

## Configuration

Precedence: **defaults < `config.edn` < environment < CLI flags**. Copy `config.edn.example` → `config.edn`
(git-ignored). Full reference: [docs/CONFIG.md](docs/CONFIG.md).

| Backend | Select via | Needs |
|---|---|---|
| CyberArk CCP | `CYBERARK_MODE=ccp` | `CYBERARK_BASE_URL/APP_ID/SAFE/OBJECT` |
| CyberArk Conjur | `CYBERARK_MODE=conjur` | `CONJUR_APPLIANCE_URL/ACCOUNT/AUTHN_LOGIN/API_KEY/SECRET_VAR` |
| Tenable.io | `TENABLE_MODE=tenable-io` | `TENABLE_BASE_URL/ACCESS_KEY/SECRET_KEY` + `TENABLE_SCAN_ID` or `TENABLE_TEMPLATE_UUID` |
| Tenable.sc | `TENABLE_MODE=tenable-sc` | same base/keys + `TENABLE_SCAN_ID` |

## Policy

The gate evaluates an **EDN policy spec** with a pure-Clojure engine (`bridge.policy`) — no `opa` binary.
`policies/mas_trm.rego` documents the same rules for Rego readers but is **reference only, never parsed**.
Format reference: [docs/POLICY.md](docs/POLICY.md). Default `policies/mas_trm.edn`:

```edn
{:rules {:max-criticals 0 :max-highs 0 :max-mediums 50
         :max-severity :high :blocked-plugins #{10001 20002}
         :required-fields [:host :plugin-id :severity]}}
```

On violation, `enforce-gate` writes a structured ServiceNow + Slack payload (`BRIDGE_REPORT`,
default `.bridge/block.json`) and exits 1.

## CI usage

```yaml
- run: bb tenable-scan --target ${{ secrets.SCAN_TARGET }}
- run: bb enforce-gate --policy policies/mas_trm.edn
```

The step fails (exit 1) exactly when policy is violated — the deploy job never runs.

## Architecture

- [Runtime architecture (interactive)](docs/architecture/bridge-gate-clj.architecture.html) · [source IR](docs/architecture/bridge-gate-clj.architecture.json)
- [Gate pipeline (interactive)](docs/architecture/gate-pipeline.workflow.html) · [source IR](docs/architecture/gate-pipeline.workflow.json)
- Notes: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — diagrams generated with [archify](https://github.com/tt-a1i/archify), validated 9/9 showcase checks.

## Development

```bash
bb test            # 21 tests / 80 assertions, offline mock-based, must be green
```

Layout: `src/bridge/{core,config,cyberark,tenable,policy}.clj`, `test/bridge/*_test.clj`,
`policies/{mas_trm.edn,mas_trm.rego}`. `deps.edn` exists for Clojure-CLI parity only; `bb` is the runner.

## AI disclosure

This repository — including source code, tests, policies, documentation, and architecture diagrams —
was **designed and written with AI assistance** (an OpenCode agent session driven by a human operator).
All behavior was verified by execution: the `bb test` suite runs green, every CLI command and exit code
was exercised end-to-end in `--mock` mode, and both architecture diagrams passed archify's 9/9 showcase
validation receipts before delivery. Live CyberArk/Tenable paths are contract-tested against mock HTTP
fixtures (no live enterprise credentials were available); review the connector namespaces and your
vendor's API docs before pointing them at production. Human review of generated code before production
use is strongly recommended.

## License

MIT — see [LICENSE](LICENSE). Archify (tooling only, not distributed here) is MIT © tt-a1i.
