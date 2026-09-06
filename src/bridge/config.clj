(ns bridge.config
  "Configuration loading.
   Precedence (lowest to highest): defaults < config.edn file < env vars < CLI opts."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]))

(def defaults
  {:cyberark-mode :ccp
   :cyberark-base-url nil
   :cyberark-app-id nil
   :cyberark-safe nil
   :cyberark-object nil
   :conjur-appliance-url nil
   :conjur-account "default"
   :conjur-authn-login nil
   :conjur-api-key nil
   :conjur-secret-var nil
   :tenable-mode :tenable-io
   :tenable-base-url nil
   :tenable-access-key nil
   :tenable-secret-key nil
   :tenable-scan-id nil
   :tenable-template-uuid nil
   :tenable-repo-id nil
   :poll-interval-ms 10000
   :poll-max-attempts 60
   :policy "policies/mas_trm.edn"
   :findings ".bridge/findings.json"
   :report ".bridge/block.json"
   :out nil
   :input nil
   :target nil
   :notify-webhook nil
   :mock false
   :config-file "config.edn"})

(defn- getenv
  [k]
  (let [v (System/getenv k)]
    (when (and v (not (str/blank? v))) v)))

(defn- truthy?
  [s]
  (contains? #{"1" "true" "yes" "y" "on"} (str/lower-case (str/trim (str s)))))

(defn env-config
  "Read BRIDGE_*/CYBERARK_*/CONJUR_*/TENABLE_* env vars into a config map."
  []
  (let [g getenv]
    (cond-> {}
      (g "CYBERARK_MODE")        (assoc :cyberark-mode (keyword (str/lower-case (g "CYBERARK_MODE"))))
      (g "CYBERARK_BASE_URL")    (assoc :cyberark-base-url (g "CYBERARK_BASE_URL"))
      (g "CYBERARK_APP_ID")      (assoc :cyberark-app-id (g "CYBERARK_APP_ID"))
      (g "CYBERARK_SAFE")        (assoc :cyberark-safe (g "CYBERARK_SAFE"))
      (g "CYBERARK_OBJECT")      (assoc :cyberark-object (g "CYBERARK_OBJECT"))
      (g "CONJUR_APPLIANCE_URL") (assoc :conjur-appliance-url (g "CONJUR_APPLIANCE_URL"))
      (g "CONJUR_ACCOUNT")       (assoc :conjur-account (g "CONJUR_ACCOUNT"))
      (g "CONJUR_AUTHN_LOGIN")   (assoc :conjur-authn-login (g "CONJUR_AUTHN_LOGIN"))
      (g "CONJUR_API_KEY")       (assoc :conjur-api-key (g "CONJUR_API_KEY"))
      (g "CONJUR_SECRET_VAR")    (assoc :conjur-secret-var (g "CONJUR_SECRET_VAR"))
      (g "TENABLE_MODE")         (assoc :tenable-mode (keyword (str/lower-case (str/replace (g "TENABLE_MODE") "_" "-"))))
      (g "TENABLE_BASE_URL")     (assoc :tenable-base-url (g "TENABLE_BASE_URL"))
      (g "TENABLE_ACCESS_KEY")   (assoc :tenable-access-key (g "TENABLE_ACCESS_KEY"))
      (g "TENABLE_SECRET_KEY")   (assoc :tenable-secret-key (g "TENABLE_SECRET_KEY"))
      (g "TENABLE_SCAN_ID")      (assoc :tenable-scan-id (g "TENABLE_SCAN_ID"))
      (g "TENABLE_TEMPLATE_UUID") (assoc :tenable-template-uuid (g "TENABLE_TEMPLATE_UUID"))
      (g "BRIDGE_POLICY")        (assoc :policy (g "BRIDGE_POLICY"))
      (g "BRIDGE_FINDINGS")      (assoc :findings (g "BRIDGE_FINDINGS"))
      (g "BRIDGE_REPORT")        (assoc :report (g "BRIDGE_REPORT"))
      (g "BRIDGE_MOCK")          (assoc :mock (truthy? (g "BRIDGE_MOCK"))))))

(defn file-config
  "Read an EDN config file. Returns {} when the file is absent or invalid."
  [path]
  (try
    (let [f (io/file (str path))]
      (if (.exists f)
        (let [m (edn/read-string (slurp f))]
          (if (map? m) m {}))
        {}))
    (catch Exception _ {})))

(defn- compact
  "Drop nil-valued entries so unset CLI flags don't clobber env/file config."
  [m]
  (into {} (remove (comp nil? val) m)))

(defn load-config
  "Merge defaults <- config.edn <- env <- cli-opts into one config map."
  ([] (load-config {}))
  ([cli-opts]
   (let [cli (compact (or cli-opts {}))
         cfg-file (or (:config-file cli) "config.edn")]
     (merge defaults
            (file-config cfg-file)
            (env-config)
            (dissoc cli :config-file :help)))))
