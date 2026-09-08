(ns bridge.cyberark-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [bridge.cyberark :as ca]))

(def ccp-cfg
  {:mock false
   :cyberark-mode :ccp
   :cyberark-base-url "https://ccp.example.com"
   :cyberark-app-id "App1"
   :cyberark-safe "Safe1"
   :cyberark-object "Obj1"})

(def conjur-cfg
  {:mock false
   :cyberark-mode :conjur
   :conjur-appliance-url "https://conjur.example.com"
   :conjur-account "default"
   :conjur-authn-login "host/bridge/ci"
   :conjur-api-key "APIKEY"
   :conjur-secret-var "ci/deploy/key"})

(deftest ccp-normalizes-account
  (testing "CCP JSON response is normalized to {:username :secret :expiry}"
    (let [seen (atom nil)
          client (fn [req]
                   (reset! seen req)
                   {:status 200
                    :body "{\"UserName\":\"svc-deploy\",\"Content\":\"s3cret!\",\"Expiry\":\"2030-01-01\"}"})
          cred (ca/fetch-credential ccp-cfg client)]
      (is (= "svc-deploy" (:username cred)))
      (is (= "s3cret!" (:secret cred)))
      (is (= "2030-01-01" (:expiry cred)))
      (is (= :get (:method @seen)))
      (is (str/ends-with? (:uri @seen) "/AIMWebService/api/Accounts"))
      (is (= {"AppID" "App1" "Safe" "Safe1" "Object" "Obj1"} (:query-params @seen))))))

(deftest ccp-failure-throws
  (testing "non-200 CCP response throws with status"
    (let [client (fn [_] {:status 401 :body "unauthorized"})]
      (is (thrown? clojure.lang.ExceptionInfo (ca/fetch-credential ccp-cfg client))))))

(deftest ccp-missing-config-throws
  (testing "missing CCP config keys throw before any HTTP call"
    (let [called (atom false)
          client (fn [_] (reset! called true) {:status 200 :body "{}"})]
      (is (thrown? clojure.lang.ExceptionInfo
                   (ca/fetch-credential (dissoc ccp-cfg :cyberark-safe) client)))
      (is (false? @called)))))

(deftest conjur-two-step-auth
  (testing "Conjur authenticates then fetches the secret with the token header"
    (let [calls (atom [])
          client (fn [req]
                   (swap! calls conj req)
                   (if (str/ends-with? (:uri req) "/authenticate")
                     {:status 200 :body "TOKEN-ABC"}
                     {:status 200 :body " siêu-secret "}))
          cred (ca/fetch-credential conjur-cfg client)]
      (is (= 2 (count @calls)))
      (is (= "host/bridge/ci" (:username cred)))
      (is (= "siêu-secret" (:secret cred)))
      (is (= "Token token=\"TOKEN-ABC\""
             (get-in (second @calls) [:headers "Authorization"]))))))

(deftest conjur-auth-failure-throws
  (testing "failed Conjur authn throws"
    (let [client (fn [_] {:status 403 :body "forbidden"})]
      (is (thrown? clojure.lang.ExceptionInfo (ca/fetch-credential conjur-cfg client))))))

(deftest mock-mode-returns-static-credential
  (testing "--mock returns static creds and never touches the client"
    (let [client (fn [_] (throw (ex-info "must not be called" {})))
          cred (ca/fetch-credential {:mock true :cyberark-mode :ccp} client)]
      (is (= "svc-deploy" (:username cred)))
      (is (string? (:secret cred))))))

(deftest unknown-mode-throws
  (testing "unknown :cyberark-mode throws"
    (is (thrown? clojure.lang.ExceptionInfo
                 (ca/fetch-credential {:mock false :cyberark-mode :nope}
                                      (fn [_] {:status 200 :body "{}"}))))))
