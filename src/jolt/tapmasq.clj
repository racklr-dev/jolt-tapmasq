;; jolt.tapmasq — host-side networking for jolt-microvm sandboxes: the TAP +
;; dnsmasq + nftables layer every VM mode needs now that libkrun 2.0 has no
;; port-map/TSI. Default policy is DENY: forwarded traffic from the guest
;; subnet is dropped except DNS to the resolver and allow-listed CIDRs.
(ns jolt.tapmasq
  (:require [clojure.java.shell :as shell]
            [clojure.string :as str]))

(defn- sudo [& args]
  (let [r (apply shell/sh "sudo" args)]
    (when-not (zero? (:exit r))
      (throw (ex-info (str "sudo " (str/join " " args) " failed") {:stderr (:err r)})))
    r))

(defn- user [] (str/trim (:out (shell/sh "id" "-un"))))

;; --- TAP -------------------------------------------------------------------
(defn tap-create!
  "Create and bring up a TAP device owned by the current user. Returns name."
  [name]
  (sudo "ip" "tuntap" "add" "dev" name "mode" "tap" "user" (user))
  (sudo "ip" "link" "set" name "up")
  name)

(defn tap-delete!
  "Delete a TAP device. Returns :ok."
  [name]
  (sudo "ip" "link" "delete" name)
  :ok)

(defn tap-ip!
  "Assign the host-side IP of a TAP subnet, e.g. 192.168.44.1/24."
  [name cidr]
  (sudo "ip" "addr" "add" cidr "dev" name)
  :ok)

;; --- dnsmasq ---------------------------------------------------------------
(defn dnsmasq-config
  "The dhcpd.conf we own: DHCP on the TAP, default route to the host TAP IP,
  and DNS pointed at the allow-list resolver (AdGuard). opts:
  :interface :subnet-cidr (host side, e.g. 192.168.44.1/24)
  :range-start :range-end :dns (resolver IP)."
  [{:keys [interface subnet-cidr range-start range-end dns]}]
  (let [host-ip (first (str/split subnet-cidr #"/"))]
    (str "interface=" interface "\n"
         "bind-interfaces\n"
         "dhcp-range=" range-start "," range-end ",255.255.255.0,12h\n"
         "dhcp-option=3," host-ip "\n"
         "dhcp-option=6," dns "\n"
         "no-resolv\n")))

(defn dnsmasq-start!
  "Start dnsmasq with a config file. Returns the pid. opts: :config-file
  :pid-file :lease-file."
  [{:keys [config-file pid-file lease-file]}]
  (sudo "dnsmasq" "--no-daemon" "-C" config-file "--pid-file" pid-file
        "--dhcp-leasefile" lease-file "-k" & )
  pid-file)

(defn dnsmasq-stop!
  "Stop the dnsmasq named by a pid file."
  [pid-file]
  (shell/sh "sudo" "kill" "$(cat " pid-file ")")
  :stopped)

;; --- nftables --------------------------------------------------------------
(defn nftables-apply!
  "Default-DENY egress for the guest subnet: drop all forwarded traffic except
  DNS to :dns and allow-listed :allow-cidrs. Uses table inet <table>."
  [{:keys [table subnet dns allow-cidrs]}]
  (let [rules (str
               "add table inet " table "\n"
               "flush table inet " table "\n"
               "add chain inet " table " forward { type filter hook forward priority 0; policy drop; }\n"
               "add rule inet " table " forward ip saddr " subnet " ct state established,related accept\n"
               "add rule inet " table " forward ip saddr " subnet " ip daddr " dns " udp dport 53 accept\n"
               "add rule inet " table " forward ip saddr " subnet " ip daddr " dns " tcp dport 53 accept\n"
               (apply str (for [c allow-cidrs]
                            (str "add rule inet " table " forward ip saddr " subnet
                                 " ip daddr " c " accept\n"))))]
    (shell/sh "bash" "-c" (str "printf '%s' " (pr-str rules) " | sudo nft -f -"))
    :applied))

(defn nftables-clear!
  "Remove the egress table."
  [table]
  (shell/sh "sudo" "nft" "delete" "table" "inet" table)
  :cleared)

;; --- AdGuard ---------------------------------------------------------------
(defn adguard-allowlist
  "AdGuard Home custom-filtering allow-list for a default-deny resolver.
  Every other domain is NXDOMAIN/blackholed."
  [domains]
  (str "@@||" (str/join "^\n@@||" domains) "^\n"))
