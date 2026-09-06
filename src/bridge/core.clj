(ns bridge.core
  "CLI dispatcher.
   Commands:
     bridge cyberark-auth
     bridge tenable-scan --target <IP>
     bridge enforce-gate [--policy P] [--input F] [--report R] [--mock]
   Exit codes: 0 = gate passed, 1 = policy violation (writes block.json),
               2 = usage/execution error."
  (:gen-class)
  (:require [babashka.http-client :as http]
            [bridge.config :as config]
            [bridge.cyberark :as cyberark]
            [bridge.tenable :as tenable]
            [bridge.policy :as policy]
            [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.tools.cli :refer [parse-opts]]))

(def cli-spec
  [[nil "--target TARGET" "Scan target IP/hostname (tenable-scan)" :id :target]
   [nil "--policy PATH" "Policy spec path (.edn)" :id :policy]
   [nil "--input PATH" "Findings JSON input file ('-' forces stdin)" :id :input]
   [nil "--out PATH" "Where tenable-scan writes findings JSON" :id :out]
   [nil "--report PATH" "Where enforce-gate writes block.json on violation" :id :report]
   [nil "--config PATH" "Optional EDN config file" :id :config-file]
   [nil "--notify-webhook URL" "Optional webhook URL to POST the block payload" :id :notify-webhook]
   [nil "--mock" "Use built-in mock data (no network)" :id :mock :default nil]
   ["-h" "--help" "Show help" :id :help :default false]])

(def commands ["cyberark-auth" "tenable-scan" "enforce-gate"])

(defn- usage
  [summary]
  (str/join "\n"
            ["bridge-gate-clj — Enterprise Compliance-as-Code Engine"
             ""
             "Usage: bridge <command> [options]"
             ""
             "Commands:"
             "  cyberark-auth    Fetch short-lived credential via CyberArk"
             "  tenable-scan     Trigger scan for --target and save findings JSON"
             "  enforce-gate     Evaluate findings against policy (exit 0/1/2)"
             ""
             "Options:"
             summary
             ""
             "Exit codes: 0 gate passed · 1 policy violation · 2 usage/execution error"
             "Examples:"
             "  bridge cyberark-auth --mock"
             "  bridge tenable-scan --target 10.10.50.12 --mock"
             "  bridge enforce-gate --policy policies/mas_trm.edn --mock"]))

(defn- errln [& xs] (binding [*out* *err*] (apply println xs)))

(defn- spit-json
  [path data]
  (let [f (io/file (str path))]
    (when-let [parent (.getParentFile f)]
      (.mkdirs parent))
    (spit f (json/generate-string data {:pretty true}))))

(defn- stdin-available?
  []
  (try (pos? (.available System/in))
       (catch Exception _ false)))

(defn- extract-findings
  "Accept a full scan map {:findings [...]} or a bare findings vector."
  [raw]
  (cond
    (sequential? raw) (vec raw)
    (and (map? raw) (sequential? (:findings raw))) (vec (:findings raw))
    (and (map? raw) (sequential? (get raw "findings"))) (vec (get raw "findings"))
    :else (throw (ex-info "Findings input must be a scan map with :findings or a vector" {}))))

(defn- read-findings
  [cfg]
  (let [explicit (:input cfg)
        path (str (or explicit (:findings cfg)))]
    (cond
      (and (not= path "-") (.exists (io/file path)))
      (json/parse-string (slurp path) true)

      (or (= path "-") (= explicit "-") (stdin-available?))
      (json/parse-string (slurp *in*) true)

      :else
      (throw (ex-info (str "No findings input: file not found (" path ") and stdin is empty. "
                           "Run tenable-scan first or pipe findings via stdin / --input -.")
                      {:path path})))))

(defn- cmd-cyberark-auth
  [cfg]
  (let [cred (cyberark/fetch-credential cfg)]
    (println (json/generate-string cred {:pretty true}))
    0))

(defn- cmd-tenable-scan
  [cfg]
  (when (str/blank? (str (:target cfg)))
    (throw (ex-info "tenable-scan requires --target <IP/hostname>" {})))
  (let [scan (tenable/run-scan cfg (:target cfg))
        out (str (or (:out cfg) (:findings cfg)))
        counts (frequencies (map :severity (:findings scan)))]
    (spit-json out scan)
    (println (json/generate-string {:scan-id (:scan-id scan)
                                    :target (:target scan)
                                    :status (:status scan)
                                    :counts counts
                                    :total (count (:findings scan))
                                    :out out}
                                   {:pretty true}))
    0))

(defn- notify-webhook!
  [url payload]
  (try
    (let [resp (http/request {:method :post
                              :uri (str url)
                              :headers {"Content-Type" "application/json"}
                              :body (json/generate-string (:slack payload))
                              :throw false})]
      (errln (str "notify-webhook: HTTP " (:status resp))))
    (catch Exception e
      (errln (str "notify-webhook failed (non-fatal): " (.getMessage e))))))

(defn- cmd-enforce-gate
  [cfg]
  (let [pol (policy/load-policy (:policy cfg))
        raw (read-findings cfg)
        findings (extract-findings raw)
        res (policy/evaluate findings pol)
        meta {:target (or (:target cfg)
                          (:target raw)
                          (get raw "target"))
              :scan-id (or (:scan-id raw) (get raw "scan_id") (get raw "scan-id"))
              :policy (:policy cfg)}]
    (if (:passed? res)
      (do (println (json/generate-string (assoc res :gate "PASS") {:pretty true}))
          0)
      (let [payload (policy/build-block-payload res meta)
            report (str (:report cfg))]
        (spit-json report payload)
        (when (:notify-webhook cfg)
          (notify-webhook! (:notify-webhook cfg) payload))
        (println (json/generate-string (assoc res :gate "BLOCK") {:pretty true}))
        (errln (str "GATE BLOCKED: " (count (:violations res))
                    " violation(s). Report written to " report))
        1))))

(defn- split-command
  "Split argv into [subcommand opt-args]. Flags must come after the subcommand."
  [args]
  (let [args (vec args)]
    (if (or (empty? args) (str/starts-with? (str (first args)) "-"))
      [nil args]
      [(first args) (rest args)])))

(defn -main
  [& args]
  (let [[cmd opt-args] (split-command args)
        {:keys [options errors summary]} (parse-opts opt-args cli-spec)
        exit-code
        (try
          (cond
            errors (do (doseq [e errors] (errln "Error:" e))
                       (errln (usage summary))
                       2)
            (:help options) (do (println (usage summary)) 0)
            (nil? cmd) (do (errln "Error: missing command.")
                           (errln (usage summary))
                           2)
            (not (contains? (set commands) cmd)) (do (errln (str "Unknown command: " cmd))
                                                     (errln (usage summary))
                                                     2)
            :else (let [cfg (config/load-config options)]
                    (case cmd
                      "cyberark-auth" (cmd-cyberark-auth cfg)
                      "tenable-scan" (cmd-tenable-scan cfg)
                      "enforce-gate" (cmd-enforce-gate cfg))))
          (catch clojure.lang.ExceptionInfo e
            (errln (str "Error: " (.getMessage e)))
            (when-let [d (ex-data e)] (errln (str "Detail: " (pr-str d))))
            2)
          (catch Exception e
            (errln (str "Error: " (.getMessage e)))
            2))]
    (System/exit exit-code)))
