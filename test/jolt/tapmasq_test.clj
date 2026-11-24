;; Pure-function smoke test for jolt-tapmasq: exercises the string- and
;; lease-parsing logic that needs no privileges, so it runs on hosted CI
;; (the TAP/dnsmasq/nftables side needs sudo + a TAP device, exercised by
;; jolt-microvm's boot tests on a KVM runner).
(ns jolt.test.tapmasq
  (:require [jolt.tapmasq :as net]
            [clojure.string :as str]
            [clojure.java.shell :as shell]))

;; --- dnsmasq-config --------------------------------------------------------
(let [cfg (net/dnsmasq-config {:interface "jolt0"
                               :subnet-cidr "192.168.44.1/24"
                               :range-start "192.168.44.10"
                               :range-end "192.168.44.200"
                               :dns "192.168.44.1"})]
  (assert (str/includes? cfg "interface=jolt0"))
  (assert (str/includes? cfg "dhcp-range=192.168.44.10,192.168.44.200"))
  (assert (str/includes? cfg "dhcp-option=3,192.168.44.1"))
  (assert (str/includes? cfg "dhcp-option=6,192.168.44.1"))
  (assert (str/includes? cfg "no-resolv")))

;; :upstream turns dnsmasq into a forwarding resolver (guest -> AdGuard or a
;; public resolver), and drops no-resolv.
(let [cfg (net/dnsmasq-config {:interface "jolt0"
                               :subnet-cidr "192.168.44.1/24"
                               :range-start "192.168.44.10"
                               :range-end "192.168.44.200"
                               :dns "192.168.44.1"
                               :upstream "1.1.1.1"})]
  (assert (str/includes? cfg "server=1.1.1.1"))
  (assert (str/includes? cfg "no-resolv")))

;; --- lease-ip --------------------------------------------------------------
(let [f "/tmp/jolt-tapmasq-test.leases"]
  (spit f (str "0 02:00:00:00:00:01 192.168.44.17 guest1 *\n"))
  (assert (= "192.168.44.17" (net/lease-ip f "02:00:00:00:00:01")))
  (assert (nil? (net/lease-ip f "02:00:00:00:00:99")))
  ;; wait-lease returns the already-present lease immediately
  (assert (= "192.168.44.17" (net/wait-lease f "02:00:00:00:00:01" 1000)))
  (.delete (java.io.File. f)))

;; --- nftables-rules (pure) ------------------------------------------------
(let [r (net/nftables-rules {:table "jolt" :subnet "192.168.44.0/24"
                              :dns "192.168.44.1"
                              :allow-cidrs ["1.1.1.1/32"]
                              :allow-ports [80 443]})]
  (assert (str/includes? r "ip saddr 192.168.44.0/24 ip daddr 192.168.44.1 udp dport 53 accept"))
  (assert (str/includes? r "ip saddr 192.168.44.0/24 ip daddr 1.1.1.1/32 accept"))
  (assert (str/includes? r "tcp dport 80 accept"))
  (assert (str/includes? r "tcp dport 443 accept"))
  (assert (str/includes? r "ip saddr 192.168.44.0/24 drop")))

;; --- dnsmasq-config domain allow-list --------------------------------------
(let [cfg (net/dnsmasq-config {:interface "jolt0" :subnet-cidr "192.168.44.1/24"
                               :range-start "192.168.44.10" :range-end "192.168.44.200"
                               :dns "192.168.44.1" :upstream "1.1.1.1"
                               :allow-domains ["github.com" "crates.io"]})]
  (assert (str/includes? cfg "server=/github.com/1.1.1.1"))
  (assert (str/includes? cfg "server=/crates.io/1.1.1.1"))
  (assert (str/includes? cfg "address=/#/0.0.0.0"))
  (assert (not (str/includes? cfg "server=1.1.1.1\n"))))

;; --- adguard-allowlist -----------------------------------------------------
(let [al (net/adguard-allowlist ["registry-1.docker.io" "nodejs.org"])]
  (assert (str/starts-with? al "@@||registry-1.docker.io^"))
  (assert (str/includes? al "@@||nodejs.org^")))

(println "jolt-tapmasq: dnsmasq-config + lease-ip + adguard-allowlist OK")