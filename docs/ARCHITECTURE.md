# Architecture

Interactive diagrams (open in a browser; dark/light themes, search, route tracing, PNG/SVG export
built into the viewer):

- [Runtime architecture](architecture/bridge-gate-clj.architecture.html) — components, trust flow,
  credential/scan/policy paths. ([typed source](architecture/bridge-gate-clj.architecture.json))
- [Gate pipeline](architecture/gate-pipeline.workflow.html) — the three commands across lanes with
  happy-path and block-path views. ([typed source](architecture/gate-pipeline.workflow.json))

## How they were made

Generated with [archify](https://github.com/tt-a1i/archify) (MIT): hand-authored typed JSON IR →
`validate … --quality showcase` → `deliver` to self-contained HTML. Both passed **9/9 showcase
checks, 0 errors, 0 warnings** (receipts: SHA-256 recorded at delivery; see release assets).
Tooling lives outside this repo (`archify` is not vendored here).

## Component map (text fallback)

```
CI/CD Pipeline ──invoke──▶ bridge CLI (core.clj dispatcher)
                              │ auth                    │ gates (exit code)
                              ▼                         ▼
                    bridge.cyberark ──creds──▶ CyberArk Vault (CCP/Conjur)
                              │ inject (credential)
                              ▼
                    bridge.tenable ──launch/poll/export──▶ Tenable (io / sc)
                              │ write findings.json
                              ▼
                    .bridge artifacts ──eval──▶ bridge.policy (pure-Clojure EDN eval)
                                                     │ exit 0 PASS ──▶ CLI ──▶ CI deploys
                                                     │ BLOCK ──▶ ServiceNow + Slack payload
```

Namespaces: `bridge.core` (dispatch, exit codes), `bridge.config` (defaults < file < env < CLI),
`bridge.cyberark` + `bridge.tenable` (injectable-HTTP connectors, mock-capable), `bridge.policy`
(pure evaluation + block payloads). Data contracts: credential `{:username :secret :expiry}`,
scan `{:scan-id :target :status :findings [{:host :plugin-id :name :severity :port}]}`,
gate `{:passed? :violations :summary}`.
