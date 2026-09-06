(ns bridge.cyberark
  "CyberArk credential fetching.
   Backends (selected by :cyberark-mode):
     :ccp    - Central Credential Provider (AIMWebService) REST API
     :conjur - Conjur authn + secrets REST API
   The `client` arg is an injectable (fn [req-map] {:status :body :headers})
   defaulting to babashka.http-client — tests substitute a mock."
  (:require [babashka.http-client :as http]
            [cheshire.core :as json]
            [clojure.string :as str]))

(def mock-credential
  {:username "svc-deploy"
   :secret "M0ck-S3cret-0ffl1ne-0nly"
   :expiry "2030-01-01T00:00:00Z"})

(defn default-client
  [req]
  (http/request (assoc req :throw false)))

(defn- parse-body
  [body]
  (cond
    (nil? body) {}
    (map? body) body
    (string? body) (try (json/parse-string body)
                        (catch Exception _ {}))
    :else {}))

(defn- require-keys
  [cfg ks label]
  (doseq [k ks]
    (when (str/blank? (str (get cfg k)))
      (throw (ex-info (str "Missing required " label " config: " (name k))
                      {:missing k})))))

(defn- fetch-ccp
  [cfg client]
  (require-keys cfg [:cyberark-base-url :cyberark-app-id :cyberark-safe :cyberark-object]
                "CyberArk CCP")
  (let [uri (str (str/replace (:cyberark-base-url cfg) #"/$" "")
                 "/AIMWebService/api/Accounts")
        resp (client {:method :get
                      :uri uri
                      :query-params {"AppID" (:cyberark-app-id cfg)
                                     "Safe" (:cyberark-safe cfg)
                                     "Object" (:cyberark-object cfg)}
                      :headers {"Accept" "application/json"}})
        body (parse-body (:body resp))]
    (when (not= 200 (:status resp))
      (throw (ex-info "CyberArk CCP request failed"
                      {:status (:status resp) :body body})))
    {:username (get body "UserName")
     :secret (get body "Content")
     :expiry (get body "Expiry" "unknown")}))

(defn- fetch-conjur
  [cfg client]
  (require-keys cfg [:conjur-appliance-url :conjur-authn-login
                     :conjur-api-key :conjur-secret-var]
                "CyberArk Conjur")
  (let [base (str/replace (:conjur-appliance-url cfg) #"/$" "")
        account (or (:conjur-account cfg) "default")
        login (:conjur-authn-login cfg)
        auth-resp (client {:method :post
                           :uri (str base "/authn/" account "/" login "/authenticate")
                           :headers {"Content-Type" "text/plain"
                                     "Accept" "application/json"}
                           :body (:conjur-api-key cfg)})]
    (when (not= 200 (:status auth-resp))
      (throw (ex-info "Conjur authentication failed"
                      {:status (:status auth-resp)})))
    (let [token (str/trim (str (:body auth-resp)))
          var-path (str/replace (:conjur-secret-var cfg) #"^/+" "")
          sec-resp (client {:method :get
                            :uri (str base "/secrets/" account "/variable/" var-path)
                            :headers {"Authorization" (str "Token token=\"" token "\"")
                                      "Accept" "application/json"}})]
      (when (not= 200 (:status sec-resp))
        (throw (ex-info "Conjur secret fetch failed"
                        {:status (:status sec-resp)})))
      {:username login
       :secret (str/trim (str (:body sec-resp)))
       :expiry "session"})))

(defn fetch-credential
  "Fetch a credential map {:username :secret :expiry}.
   With (:mock cfg) truthy, returns static mock data without any network."
  ([cfg] (fetch-credential cfg default-client))
  ([cfg client]
   (if (:mock cfg)
     mock-credential
     (case (:cyberark-mode cfg)
       :ccp (fetch-ccp cfg client)
       :conjur (fetch-conjur cfg client)
       (throw (ex-info "Unknown CYBERARK_MODE (want :ccp or :conjur)"
                       {:mode (:cyberark-mode cfg)}))))))
