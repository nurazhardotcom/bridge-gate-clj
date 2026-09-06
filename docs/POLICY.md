# Policy reference

## Source of truth

`policies/mas_trm.edn` is **evaluated**. `policies/mas_trm.rego` is a human-readable mirror of the
same rules for OPA/Rego reviewers — it is **reference only and never parsed** (the tool has zero
external dependencies, so no `opa` binary is required). Any rule added to the `.rego` must have an
equivalent in the `.edn`.

## Spec format

```edn
{:name "MAS TRM Deployment Gate"
 :version "0.1.0"
 :description "…"
 :rules {:max-criticals 0        ; hard fail above this count (default 0)
         :max-highs 0            ; hard fail above this count (default 0)
         :max-mediums 50         ; enforced only when present
         :max-severity :high     ; any finding strictly above this fails (default :high)
         :blocked-plugins #{10001 20002}  ; plugin IDs that always fail (strings/numbers)
         :required-fields [:host :plugin-id :severity]}}
```

Severity order: `:info < :low < :medium < :high < :critical`. Finding severities arriving as
strings (`"High"`), numbers (`3`), or keywords (`:high`) are coerced; unrecognized values fail
closed to `:critical`.

## Evaluation result

`bridge.policy/evaluate` is pure (no I/O) and returns:

```edn
{:passed? false
 :violations [{:rule :max-highs :threshold 0 :actual 1
               :detail "1 high finding(s) exceed max of 0"} …]
 :summary {:info 2 :low 1 :medium 2 :high 1 :critical 0 :total 6}}
```

`enforce-gate` maps this to exit codes (`0` pass / `1` violation / `2` error). On violation it calls
`build-block-payload`, emitting `{:event :tool :timestamp :target :scan-id :policy :summary
:violations :servicenow {:short_description :urgency "1" :impact "1" …} :slack {:text :blocks […]}}`
to the report path (default `.bridge/block.json`), optionally POSTing the Slack section to
`--notify-webhook`.
