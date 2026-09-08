(ns bridge.tenable-test
  (:require [clojure.test :refer [deftest is testing are]]
            [clojure.string :as str]
            [bridge.tenable :as tn]
            [cheshire.core :as json]))

(deftest severity-coercion
  (testing "vendor severities coerce to keywords, fail-closed on unknown"
    (are [in out] (= out (tn/coerce-severity in))
      :critical :critical
      :high :high
      "Critical" :critical
      "HIGH" :high
      "medium" :medium
      "Med" :medium
      "low" :low
      "info" :info
      "none" :info
      4 :critical
      3 :high
      2 :medium
      1 :low
      0 :info
      "bogus-string" :critical
      99 :critical
      nil :critical
      :weird-kw :critical)))

(deftest mock-scan-shape
  (testing "mock payload has 1 high, 2 medium, 0 critical"
    (let [scan (tn/run-scan {:mock true} "10.10.50.12")]
      (is (= "10.10.50.12" (:target scan)))
      (is (= "completed" (:status scan)))
      (let [freq (frequencies (map :severity (:findings scan)))]
        (is (= 1 (get freq :high 0)))
        (is (= 2 (get freq :medium 0)))
        (is (= 0 (get freq :critical 0))))
      (is (every? #(contains? % :host) (:findings scan)))
      (is (every? #(contains? % :plugin-id) (:findings scan))))))

(deftest missing-target-throws
  (testing "blank target throws"
    (is (thrown? clojure.lang.ExceptionInfo (tn/run-scan {:mock false} "")))))

(def io-cfg
  {:mock false
   :tenable-mode :tenable-io
   :tenable-base-url "https://cloud.tenable.com"
   :tenable-access-key "AK"
   :tenable-secret-key "SK"
   :tenable-scan-id 42
   :poll-interval-ms 0
   :poll-max-attempts 10})

(defn- io-client
  "Queued Tenable.io responses: launch -> queued -> running -> completed,
   export -> loading -> ready -> download."
  []
  (let [states (atom ["queued" "running" "completed"])
        estates (atom ["loading" "ready"])]
    (fn [{:keys [method uri]}]
      (cond
        (str/ends-with? uri "/launch")
        {:status 200 :body "{\"scan_uuid\":\"uuid-42\"}"}

        (str/includes? uri "/export/")
        (if (str/ends-with? uri "/status")
          {:status 200 :body (str "{\"status\":\"" (first (swap! estates rest)) "\"}")}
          {:status 200 :body (json/generate-string
                              [{"plugin_id" 10001 "plugin_name" "Bad Plugin"
                                "severity" "Critical" "hostname" "10.0.0.9" "port" 0}
                               {"plugin_id" 10180 "plugin_name" "Ping"
                                "severity" 0 "hostname" "10.0.0.9" "port" 0}])})

        (str/ends-with? uri "/export")
        {:status 200 :body "{\"file\":7}"}

        :else
        {:status 200 :body (str "{\"info\":{\"status\":\""
                                (let [s (first @states)] (swap! states rest) s)
                                "\"}}")}))))

(deftest tenable-io-full-loop
  (testing "launch -> poll -> export -> download normalizes findings"
    (let [scan (tn/run-scan io-cfg (io-client) "10.0.0.9")]
      (is (= "uuid-42" (:scan-id scan)))
      (is (= "completed" (:status scan)))
      (is (= 2 (count (:findings scan))))
      (is (= :critical (:severity (first (:findings scan)))))
      (is (= "10001" (:plugin-id (first (:findings scan)))))
      (is (= :info (:severity (second (:findings scan))))))))

(deftest tenable-io-poll-timeout
  (testing "scan that never completes throws after max attempts"
    (let [client (fn [{:keys [uri]}]
                   (if (str/ends-with? uri "/launch")
                     {:status 200 :body "{\"scan_uuid\":\"u\"}"}
                     {:status 200 :body "{\"info\":{\"status\":\"running\"}}"}))]
      (is (thrown? clojure.lang.ExceptionInfo
                   (tn/run-scan (assoc io-cfg :poll-max-attempts 2) client "10.0.0.9"))))))

(def sc-cfg
  {:mock false
   :tenable-mode :tenable-sc
   :tenable-base-url "https://sc.example.com"
   :tenable-access-key "admin"
   :tenable-secret-key "pw"
   :tenable-scan-id 7
   :poll-interval-ms 0
   :poll-max-attempts 10})

(deftest tenable-sc-full-loop
  (testing "token -> launch -> poll -> analysis normalizes findings"
    (let [states (atom ["Running" "Completed"])
          seen (atom [])
          client (fn [req]
                   (swap! seen conj req)
                   (let [uri (:uri req)]
                     (cond
                       (str/ends-with? uri "/rest/token")
                       {:status 200 :body "{\"response\":{\"token\":\"TOK\"}}"}
                       (str/ends-with? uri "/launch")
                       {:status 200 :body "{\"response\":{\"scanResultID\":99}}"}
                       (str/starts-with? uri "https://sc.example.com/rest/scanResult/")
                       {:status 200 :body (str "{\"response\":{\"status\":\""
                                                (let [s (first @states)] (swap! states rest) s)
                                                "\"}}")}
                       :else
                       {:status 200 :body "{\"response\":{\"results\":[{\"pluginID\":\"20002\",\"name\":\"SC Vuln\",\"severity\":\"High\",\"host\":\"10.0.0.5\",\"port\":443}]}}"})))
          scan (tn/run-scan sc-cfg client "10.0.0.5")]
      (is (= "99" (:scan-id scan)))
      (is (= 1 (count (:findings scan))))
      (is (= :high (:severity (first (:findings scan)))))
      (is (= "20002" (:plugin-id (first (:findings scan)))))
      (is (some #(= "TOK" (get-in % [:headers "X-SecurityCenter"])) (rest @seen))))))
