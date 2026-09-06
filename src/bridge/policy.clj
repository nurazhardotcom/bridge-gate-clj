(ns bridge.policy
  "Pure-Clojure policy evaluation engine (no I/O except load-policy).
   Evaluates normalized findings against an EDN policy spec
   (policies/mas_trm.edn). The .rego file is reference documentation only."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]))

(def severity-rank
  {:info 0 :low 1 :medium 2 :high 3 :critical 4})

(defn severity-of
  "Coerce keyword/string/number severity to a keyword.
   Fail-closed: anything unrecognized becomes :critical."
  [s]
  (cond
    (keyword? s) (if (contains? severity-rank s) s :critical)
    (number? s) (case (int s)
                  0 :info 1 :low 2 :medium 3 :high 4 :critical
                  :critical)
    (string? s) (let [t (str/lower-case (str/trim s))]
                  (cond (contains? #{"0" "info" "none"} t) :info
                        (contains? #{"1" "low"} t) :low
                        (contains? #{"2" "medium" "med"} t) :medium
                        (contains? #{"3" "high"} t) :high
                        (contains? #{"4" "critical" "crit"} t) :critical
                        :else :critical))
    :else :critical))

(defn load-policy
  "Load an EDN policy spec from a file path (falls back to classpath resource)."
  [path]
  (let [p (str path)
        f (io/file p)]
    (cond
      (.exists f) (edn/read-string (slurp f))
      (io/resource p) (edn/read-string (slurp (io/resource p)))
      :else (throw (ex-info (str "Policy file not found: " p) {:path p})))))

(defn- over-budget
  [rule threshold actual noun]
  (when (> actual threshold)
    [{:rule rule
      :threshold threshold
      :actual actual
      :detail (str actual " " noun " finding(s) exceed max of " threshold)}]))

(defn evaluate
  "Evaluate findings (seq of {:host :plugin-id :name :severity ...}) against
   policy. Returns {:passed? :violations [...] :summary {...}}."
  [findings policy]
  (let [rules (or (:rules policy) {})
        fs (mapv (fn [f] (assoc f :severity (severity-of (:severity f))))
                 (or findings []))
        counts (reduce (fn [m f] (update m (:severity f) (fnil inc 0)))
                       {:info 0 :low 0 :medium 0 :high 0 :critical 0}
                       fs)
        max-crit (get rules :max-criticals 0)
        max-high (get rules :max-highs 0)
        max-sev (severity-of (get rules :max-severity :high))
        sev-limit (get severity-rank max-sev 3)
        over-sev (filterv #(> (get severity-rank (:severity %) 0) sev-limit) fs)
        blocked (set (map str (or (:blocked-plugins rules) #{})))
        hit-blocked (filterv #(contains? blocked (str (:plugin-id %))) fs)
        req-fields (or (:required-fields rules) [:host :plugin-id :severity])
        missing (filterv (fn [f] (some #(str/blank? (str (get f %))) req-fields)) fs)
        violations
        (vec (concat
              (over-budget :max-criticals max-crit (:critical counts) "critical")
              (over-budget :max-highs max-high (:high counts) "high")
              (when (contains? rules :max-mediums)
                (over-budget :max-mediums (:max-mediums rules) (:medium counts) "medium"))
              (when (seq over-sev)
                [{:rule :max-severity
                  :threshold max-sev
                  :actual (count over-sev)
                  :detail (str (count over-sev) " finding(s) above max severity " (name max-sev)
                               ": " (str/join ", " (distinct (map #(str (:plugin-id %)) over-sev))))}])
              (when (seq hit-blocked)
                [{:rule :blocked-plugins
                  :threshold (vec (sort blocked))
                  :actual (vec (sort (distinct (map #(str (:plugin-id %)) hit-blocked))))
                  :detail (str (count hit-blocked) " finding(s) match blocked plugins: "
                               (str/join ", " (sort (distinct (map #(str (:plugin-id %)) hit-blocked)))))}])
              (when (seq missing)
                [{:rule :required-fields
                  :threshold (mapv name req-fields)
                  :actual (count missing)
                  :detail (str (count missing) " finding(s) missing required fields "
                               (str/join ", " (map name req-fields)))}])))]
    {:passed? (empty? violations)
     :violations violations
     :summary (assoc counts :total (count fs))}))

(defn build-block-payload
  "Build the structured ServiceNow/Slack block payload for a failed evaluation.
   meta: {:target :scan-id :policy}."
  [eval-result meta]
  (let [ts (str (java.time.Instant/now))
        target (str (or (:target meta) "unknown"))
        scan-id (str (or (:scan-id meta) "unknown"))
        pol (str (or (:policy meta) "policies/mas_trm.edn"))
        n (count (:violations eval-result))
        headline (str "bridge-gate BLOCKED deploy to " target ": "
                      n " policy violation(s)")]
    {:event "bridge-gate.policy-violation"
     :tool "bridge-gate-clj"
     :timestamp ts
     :target target
     :scan-id scan-id
     :policy pol
     :passed? false
     :summary (:summary eval-result)
     :violations (:violations eval-result)
     :servicenow {:short_description headline
                  :description (str headline "\nScan: " scan-id
                                    "\nPolicy: " pol
                                    "\nSummary: " (pr-str (:summary eval-result)))
                  :urgency "1"
                  :impact "1"
                  :category "Security"
                  :assignment_group "Security Operations"
                  :cmdb_ci target}
     :slack {:text headline
             :blocks [{:type "header"
                       :text {:type "plain_text" :text "bridge-gate: deploy BLOCKED"}}
                      {:type "section"
                       :text {:type "mrkdwn"
                              :text (str "*Target:* " target "\n*Scan:* " scan-id
                                         "\n*Policy:* " pol "\n*Violations:* " n)}}
                      {:type "section"
                       :text {:type "mrkdwn"
                              :text (str "```" (pr-str (:violations eval-result)) "```")}}]}}))
