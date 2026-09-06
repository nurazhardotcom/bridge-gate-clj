# Changelog

## v0.1.0 — 2026-09-06

Initial public release.

- Three-command Babashka CLI: `cyberark-auth`, `tenable-scan --target`, `enforce-gate`
  (exit codes 0 PASS / 1 BLOCK + `block.json` / 2 error).
- Swappable connectors: CyberArk CCP + Conjur; Tenable.io + Tenable.sc — via
  `config.edn` / env / CLI flags, with injectable HTTP client for tests.
- Pure-Clojure EDN policy engine (`policies/mas_trm.edn`); `.rego` kept as reference only.
- ServiceNow + Slack block-payload generation with optional `--notify-webhook` POST.
- Offline `--mock` / `BRIDGE_MOCK=true` mode across all commands.
- Test suite: 21 tests / 80 assertions, `bb test`, zero network.
- Docs: README, CONFIG, POLICY, ARCHITECTURE + two archify-validated interactive diagrams
  (9/9 showcase checks, 0 errors/warnings).
