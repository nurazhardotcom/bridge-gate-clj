(ns bridge.tenable
  "Tenable scan triggering, polling, and findings normalization.
   Backends (selected by :tenable-mode):
     :tenable-io - Tenable Vulnerability Management cloud (/api/v3/scans)
     :tenable-sc - Tenable Security Center on-prem (/rest/...)
   The `client` arg is an injectable (fn [req-map] {:status :body :headers})
   defaulting to babashka.http-client — tests substitute a mock."
  (:require [babashka.http-client :as http]
            [cheshire.core :as json]
            [clojure.string :as str]))

(def severity-rank
  {:info 0 :low 1 :medium 2 :high 3 :critical 4})

(defn coerce-severity
  "Coerce a vendor severity (keyword/string/number) to a keyword.
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

(defn default-client
  [req]
  (http/request (assoc req :throw false)))

(defn- parse-json-body
  [body]
  (cond
    (nil? body) {}
    (map? body) body
    (sequential? body) body
    (string? body) (try (json/parse-string body)
                        (catch Exception _ {}))
    :else {}))

(defn- check!
  [resp label]
  (when-not (contains? #{200 201 202} (:status resp))
    (throw (ex-info (str label " failed")
                    {:status (:status resp)
                     :body (parse-json-body (:body resp))})))
  resp)

(defn- normalize-finding
  [target v]
  {:host (str (or (get v "hostname") (get v "host") (get v "ip") target))
   :plugin-id (str (or (get v "plugin_id") (get v "pluginID") (get v "pluginId") "0"))
   :name (str (or (get v "plugin_name") (get v "name") "unknown"))
   :severity (coerce-severity (or (get v "severity") (get v "severity_id") "info"))
   :port (or (get v "port") 0)})

(defn mock-scan
  "Canned offline payload: 1 high, 2 medium, 0 critical."
  [target]
  {:scan-id "mock-scan-0001"
   :target target
   :status "completed"
   :findings [{:host target :plugin-id "19506" :name "Nessus Scan Information" :severity :info :port 0}
              {:host target :plugin-id "10180" :name "Ping the remote host" :severity :info :port 0}
              {:host target :plugin-id "11219" :name "Nessus SYN scanner" :severity :low :port 22}
              {:host target :plugin-id "51192" :name "SSL Certificate Cannot Be Trusted" :severity :medium :port 443}
              {:host target :plugin-id "57582" :name "SSL Self-Signed Certificate" :severity :medium :port 443}
              {:host target :plugin-id "33850" :name "Unix Operating System Unsupported Version Detection" :severity :high :port 0}]})

;; ---- Tenable.io (Vulnerability Management) ----

(defn- io-headers
  [cfg]
  {"X-ApiKeys" (str "accessKey=" (:tenable-access-key cfg)
                    "; secretKey=" (:tenable-secret-key cfg))
   "Accept" "application/json"
   "Content-Type" "application/json"})

(defn- poll-until
  "Poll (status-fn) until (done?-pred status) or attempts run out."
  [cfg status-fn done?-pred fail-states label]
  (let [max-attempts (or (:poll-max-attempts cfg) 60)
        interval (or (:poll-interval-ms cfg) 10000)]
    (loop [n 0]
      (let [status (status-fn)]
        (cond
          (done?-pred status) status
          (contains? fail-states status)
          (throw (ex-info (str label " entered failure state: " status) {:status status}))
          (>= n max-attempts)
          (throw (ex-info (str label " timed out after " max-attempts " polls")
                          {:last-status status}))
          :else (do (Thread/sleep interval) (recur (inc n))))))))

(defn- run-io
  [cfg client target]
  (when (str/blank? (str (:tenable-base-url cfg)))
    (throw (ex-info "Missing required Tenable.io config: :tenable-base-url" {})))
  (when (or (str/blank? (str (:tenable-access-key cfg)))
            (str/blank? (str (:tenable-secret-key cfg))))
    (throw (ex-info "Missing Tenable.io API keys (:tenable-access-key/:tenable-secret-key)" {})))
  (let [base (str/replace (:tenable-base-url cfg) #"/$" "")
        headers (io-headers cfg)
        scan-id
        (if (:tenable-scan-id cfg)
          ;; Launch a pre-configured scan.
          (let [resp (check! (client {:method :post
                                      :uri (str base "/api/v3/scans/" (:tenable-scan-id cfg) "/launch")
                                      :headers headers})
                             "Tenable.io scan launch")]
            (str (or (get (parse-json-body (:body resp)) "scan_uuid")
                     (:tenable-scan-id cfg))))
          ;; Create a scan from a template, then launch it.
          (do
            (when (str/blank? (str (:tenable-template-uuid cfg)))
              (throw (ex-info "Set :tenable-scan-id or :tenable-template-uuid for Tenable.io" {})))
            (let [create-resp (check!
                               (client {:method :post
                                        :uri (str base "/api/v3/scans")
                                        :headers headers
                                        :body (json/generate-string
                                               {"uuid" (:tenable-template-uuid cfg)
                                                "settings" {"name" (str "bridge-gate " target)
                                                            "text_targets" target
                                                            "launch" "ON_DEMAND"}})})
                               "Tenable.io scan create")
                  new-id (str (get-in (parse-json-body (:body create-resp)) ["scan" "id"]))]
              (check! (client {:method :post
                               :uri (str base "/api/v3/scans/" new-id "/launch")
                               :headers headers})
                      "Tenable.io scan launch")
              new-id)))
        _ (poll-until cfg
                      #(get-in (parse-json-body
                                (:body (check! (client {:method :get
                                                       :uri (str base "/api/v3/scans/" scan-id)
                                                       :headers headers})
                                              "Tenable.io scan status")))
                              ["info" "status"] "unknown")
                      #{"completed"} #{"aborted" "canceled" "cancelled" "imported"}
                      "Tenable.io scan")
        export-id (str (get (parse-json-body
                             (:body (check!
                                     (client {:method :post
                                              :uri (str base "/api/v3/scans/" scan-id "/export")
                                              :headers headers
                                              :body (json/generate-string {"format" "json"})})
                                     "Tenable.io export")))
                            "file"))
        _ (poll-until cfg
                      #(get (parse-json-body
                             (:body (check! (client {:method :get
                                                    :uri (str base "/api/v3/scans/" scan-id "/export/" export-id "/status")
                                                    :headers headers})
                                           "Tenable.io export status")))
                           "status" "unknown")
                      #{"ready"} #{"failure" "error"}
                      "Tenable.io export")
        raw (parse-json-body
             (:body (check! (client {:method :get
                                    :uri (str base "/api/v3/scans/" scan-id "/export/" export-id "/download")
                                    :headers headers})
                           "Tenable.io export download")))
        vulns (cond (sequential? raw) raw
                    (map? raw) (or (get raw "vulnerabilities") (get raw "results") [])
                    :else [])]
    {:scan-id scan-id
     :target target
     :status "completed"
     :findings (mapv #(normalize-finding target %) vulns)}))

;; ---- Tenable.sc (Security Center) ----

(defn- run-sc
  [cfg client target]
  (when (str/blank? (str (:tenable-base-url cfg)))
    (throw (ex-info "Missing required Tenable.sc config: :tenable-base-url" {})))
  (let [base (str/replace (:tenable-base-url cfg) #"/$" "")
        token (if (:tenable-token cfg)
                (:tenable-token cfg)
                (do
                  (when (or (str/blank? (str (:tenable-access-key cfg)))
                            (str/blank? (str (:tenable-secret-key cfg))))
                    (throw (ex-info "Missing Tenable.sc credentials (:tenable-access-key/:tenable-secret-key or :tenable-token)" {})))
                  (let [resp (check!
                              (client {:method :post
                                       :uri (str base "/rest/token")
                                       :headers {"Accept" "application/json"
                                                 "Content-Type" "application/json"}
                                       :body (json/generate-string
                                              {"username" (:tenable-access-key cfg)
                                               "password" (:tenable-secret-key cfg)})})
                              "Tenable.sc token")]
                    (str (get-in (parse-json-body (:body resp)) ["response" "token"])))))
        headers {"X-SecurityCenter" token
                 "Accept" "application/json"
                 "Content-Type" "application/json"}]
    (when (str/blank? (str (:tenable-scan-id cfg)))
      (throw (ex-info "Set :tenable-scan-id (Tenable.sc scan ID) to launch" {})))
    (let [launch (parse-json-body
                  (:body (check! (client {:method :post
                                          :uri (str base "/rest/scan/" (:tenable-scan-id cfg) "/launch")
                                          :headers headers
                                          :body (json/generate-string {"targets" target})})
                                 "Tenable.sc scan launch")))
          result-id (str (get-in launch ["response" "scanResultID"] (:tenable-scan-id cfg)))
          _ (poll-until cfg
                        #(get-in (parse-json-body
                                  (:body (check! (client {:method :get
                                                         :uri (str base "/rest/scanResult/" result-id)
                                                         :headers headers})
                                                "Tenable.sc scan status")))
                                ["response" "status"] "unknown")
                        #{"Completed"} #{"Error" "Aborted" "Canceled"}
                        "Tenable.sc scan")
          analysis (parse-json-body
                    (:body (check!
                            (client {:method :post
                                     :uri (str base "/rest/analysis")
                                     :headers headers
                                     :body (json/generate-string
                                            {"query" {"name" ""
                                                      "tool" "vulndetails"
                                                      "type" "vuln"
                                                      "filters" [{"filterName" "scanID"
                                                                   "operator" "="
                                                                   "value" result-id}]}
                                             "sourceType" "cumulative"
                                             "columns" []})})
                            "Tenable.sc analysis")))
          vulns (or (get-in analysis ["response" "results"]) [])]
      {:scan-id result-id
       :target target
       :status "completed"
       :findings (mapv #(normalize-finding target %) vulns)})))

(defn run-scan
  "Run a scan against target and return a normalized scan map
   {:scan-id :target :status :findings [...]}.
   With (:mock cfg) truthy, returns canned data without any network."
  ([cfg target] (run-scan cfg default-client target))
  ([cfg client target]
   (when (str/blank? (str target))
     (throw (ex-info "Scan target is required (--target)" {})))
   (if (:mock cfg)
     (mock-scan (str target))
     (case (:tenable-mode cfg)
       :tenable-io (run-io cfg client (str target))
       :tenable-sc (run-sc cfg client (str target))
       (throw (ex-info "Unknown TENABLE_MODE (want :tenable-io or :tenable-sc)"
                       {:mode (:tenable-mode cfg)}))))))
