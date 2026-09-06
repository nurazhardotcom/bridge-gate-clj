(ns bridge.policy-test
  (:require [clojure.test :refer [deftest is testing]]
            [bridge.policy :as pol]))

(def base-policy
  {:name "test gate"
   :rules {:max-criticals 0
           :max-highs 0
           :max-mediums 50
           :max-severity :high
           :blocked-plugins #{10001 20002}
           :required-fields [:host :plugin-id :severity]}})

(def clean-findings
  [{:host "10.0.0.1" :plugin-id "10180" :name "Ping" :severity :info :port 0}
   {:host "10.0.0.1" :plugin-id "11219" :name "SYN" :severity :low :port 22}])

(def dirty-findings
  [{:host "10.0.0.2" :plugin-id "10001" :name "Bad Plugin" :severity :critical :port 0}
   {:host "10.0.0.2" :plugin-id "33850" :name "Unsupported OS" :severity :high :port 0}
   {:host "10.0.0.2" :plugin-id "51192" :name "SSL" :severity :medium :port 443}
   {:host "10.0.0.2" :name "No plugin id" :severity :low :port 0}])

(deftest clean-findings-pass
  (testing "clean findings produce :passed? true with zero violations"
    (let [res (pol/evaluate clean-findings base-policy)]
      (is (true? (:passed? res)))
      (is (empty? (:violations res)))
      (is (= 2 (get-in res [:summary :total])))
      (is (= 1 (get-in res [:summary :low]))))))

(deftest dirty-findings-fail
  (testing "criticals, highs, blocked plugins, and missing fields all violate"
    (let [res (pol/evaluate dirty-findings base-policy)
          rules (set (map :rule (:violations res)))]
      (is (false? (:passed? res)))
      (is (contains? rules :max-criticals))
      (is (contains? rules :max-highs))
      (is (contains? rules :blocked-plugins))
      (is (contains? rules :required-fields)))))

(deftest medium-budget
  (testing ":max-mediums is enforced only when present"
    (let [meds (mapv #(hash-map :host "h" :plugin-id (str 9000 %) :severity :medium) (range 3))]
      (is (false? (:passed? (pol/evaluate meds (assoc-in base-policy [:rules :max-mediums] 1)))))
      (is (true? (:passed? (pol/evaluate meds (update (:rules base-policy) dissoc :max-mediums)
                                          )))))))

(deftest max-severity-rule
  (testing ":max-severity flags anything above the threshold"
    (let [highs [{:host "h" :plugin-id "1" :severity :high}]
          pol (assoc base-policy :rules {:max-severity :medium})]
      (is (false? (:passed? (pol/evaluate highs pol))))
      (is (contains? (set (map :rule (:violations (pol/evaluate highs pol))))
                     :max-severity)))))

(deftest string-severities-coerced
  (testing "string severities from JSON round-trips are coerced before evaluation"
    (let [res (pol/evaluate [{:host "h" :plugin-id "9" :severity "CRITICAL"}] base-policy)]
      (is (false? (:passed? res)))
      (is (= 1 (get-in res [:summary :critical]))))))

(deftest shipped-policy-loads
  (testing "policies/mas_trm.edn loads and gates the mock shape correctly"
    (let [p (pol/load-policy "policies/mas_trm.edn")]
      (is (= 0 (get-in p [:rules :max-criticals])))
      (is (= 0 (get-in p [:rules :max-highs])))
      (is (contains? (get-in p [:rules :blocked-plugins]) 10001)))))

(deftest missing-policy-throws
  (testing "unknown policy path throws"
    (is (thrown? clojure.lang.ExceptionInfo (pol/load-policy "policies/nope.edn")))))

(deftest block-payload-shape
  (testing "build-block-payload emits ServiceNow + Slack structures"
    (let [res (pol/evaluate dirty-findings base-policy)
          payload (pol/build-block-payload res {:target "10.0.0.2"
                                                :scan-id "s-1"
                                                :policy "policies/mas_trm.edn"})]
      (is (false? (:passed? payload)))
      (is (= "10.0.0.2" (:target payload)))
      (is (= "1" (get-in payload [:servicenow :urgency])))
      (is (= "Security Operations" (get-in payload [:servicenow :assignment_group])))
      (is (string? (get-in payload [:slack :text])))
      (is (seq (get-in payload [:slack :blocks]))))))
