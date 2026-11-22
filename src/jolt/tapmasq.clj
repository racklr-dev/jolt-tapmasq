;; jolt.tapmasq — host-side networking for jolt-microvm sandboxes: the TAP +
;; dnsmasq + nftables layer every VM mode needs on libkrun 2.0 (no port-map/TSI).
;; Default policy is DENY: forwarded traffic from the guest subnet is dropped
;; except DNS to the resolver and allow-listed CIDRs.
(ns jolt.tapmasq
  (:require [clojure.java.shell :as shell]
            [clojure.string :as str]))

(defn- sudo [& args]
  (let [r (apply shell/sh "sudo" args)]
    (when-not (zero? (:exit r))
      (throw (ex-info (str "sudo " (str/join " " args) " failed")
                      {:stderr (:err r)})))
    r))

(defn- user [] (str/trim (:out (shell/sh "id" "-un"))))

;; --- TAP -------------------------------------------------------------------
(defn tap-create!
  "Create and bring up a TAP device owned by the current user (with vnet_hdr,
  which libkrun's tap backend expects). Returns name."
  [name]
  (shell/sh "sudo" "ip" "link" "delete" name)
  (sudo "ip" "tuntap" "add" "dev" name "mode" "tap" "user" (user) "vnet_hdr")
  (sudo "ip" "link" "set" name "up")
  name)

(defn tap-delete!
  "Delete a TAP device. Returns :ok."
  [name]
  (shell/sh "sudo" "ip" "link" "delete" name)
  :ok)

(defn tap-ip!
  "Assign the host-side IP of a TAP subnet, e.g. 192.168.44.1/24."
  [name cidr]
  (sudo "ip" "addr" "add" cidr "dev" name)
  :ok)

(defn ip-forward!
  "Enable/disable IPv4 forwarding on the host (needed for guest egress)."
  [on?]
  (sudo "sysctl" "-w" (str "net.ipv4.ip_forward=" (if on? 1 0)))
  :ok)

;; --- dnsmasq ---------------------------------------------------------------
(defn dnsmasq-config
  "The dhcpd.conf we own: DHCP on the TAP, default route to the host TAP IP,
  and DNS pointed at the allow-list resolver (AdGuard). opts: :interface
  :subnet-cidr (host side) :range-start :range-end :dns, and optionally
  :upstream (a resolver dnsmasq forwards queries to; omit to stay DHCP-only)."
  [{:keys [interface subnet-cidr range-start range-end dns upstream]}]
  (let [host-ip (first (str/split subnet-cidr #"/"))]
    (str "interface=" interface "\n"
         "bind-interfaces\n"
         "dhcp-range=" range-start "," range-end ",255.255.255.0,12h\n"
         "dhcp-option=3," host-ip "\n"
         "dhcp-option=6," dns "\n"
         "no-resolv\n"
         (when upstream (str "server=" upstream "\n")))))

(defn dnsmasq-stop!
  "Stop one dnsmasq instance by pid-file (when given), else every dnsmasq."
  ([] (shell/sh "sudo" "pkill" "-x" "dnsmasq") :stopped)
  ([pid-file]
   (shell/sh "sudo" "bash" "-c"
             (str "[ -f " pid-file " ] && sudo kill \"$(cat " pid-file ")\" 2>/dev/null; true"))
   :stopped))

(defn dnsmasq-start!
  "Start one dnsmasq instance with a config file. Several instances can
  coexist as long as each binds its own interface; this kills only a stale
  instance from its own pid-file first. Returns the pid file path."
  [{:keys [config-file pid-file lease-file log-file]}]
  (dnsmasq-stop! pid-file)
  (shell/sh "sudo" "bash" "-c"
            (str "sudo nohup /usr/sbin/dnsmasq -C " config-file
                 " --pid-file=" pid-file " -k --log-dhcp --log-facility=-"
                 " --dhcp-leasefile=" lease-file
                 " > " log-file " 2>&1 < /dev/null &"))
  (Thread/sleep 1500)
  pid-file)

(defn lease-ip
  "Read the dnsmasq lease file and return the leased IP for a MAC, or nil."
  [lease-file mac]
  (let [f (java.io.File. lease-file)]
    (when (.isFile f)
      (some (fn [line]
              (let [parts (str/split (str/trim line) #"\s+")]
                (when (and (>= (count parts) 3)
                           (= mac (str/lower-case (nth parts 1))))
                  (nth parts 2))))
            (str/split-lines (slurp f))))))

(defn wait-lease
  "Poll the lease file until mac has a lease or timeout-ms elapses."
  [lease-file mac timeout-ms]
  (let [start (System/currentTimeMillis)]
    (loop []
      (let [ip (lease-ip lease-file mac)]
        (cond
          ip ip
          (> (- (System/currentTimeMillis) start) timeout-ms)
          (throw (ex-info "timed out waiting for DHCP lease" {:mac mac}))
          :else (do (Thread/sleep 100) (recur)))))))

;; --- nftables --------------------------------------------------------------
(defn nftables-apply!
  "Default-DENY egress for the guest subnet: the forward chain accepts by
  default (it never touches unrelated forwarded traffic), then drops any new
  egress from :subnet that is not DNS to :dns or an allow-listed :allow-cidrs
  CIDR. Established/related reply traffic is accepted up front so answers
  flow back to the guest. Uses table inet <table>."
  [{:keys [table subnet dns allow-cidrs rules-file]}]
  (let [rules (str
               "add table inet " table "\n"
               "flush table inet " table "\n"
               "add chain inet " table " forward { type filter hook forward priority 0; policy accept; }\n"
               "add rule inet " table " forward ct state established,related accept\n"
               "add rule inet " table " forward ip saddr " subnet " ip daddr " dns " udp dport 53 accept\n"
               "add rule inet " table " forward ip saddr " subnet " ip daddr " dns " tcp dport 53 accept\n"
               (apply str (for [c allow-cidrs]
                            (str "add rule inet " table " forward ip saddr " subnet
                                 " ip daddr " c " accept\n")))
               "add rule inet " table " forward ip saddr " subnet " drop\n")]
    (spit rules-file rules)
    (sudo "nft" "-f" rules-file)
    :applied))

(defn nftables-clear!
  "Remove the egress table."
  [table]
  (shell/sh "sudo" "nft" "delete" "table" "inet" table)
  :cleared)

(defn nat-enable!
  "MASQUERADE the guest subnet out the host's egress interface (for
  allow-listed outbound). Idempotent: adds the rule only when absent."
  [subnet egress-iface]
  (let [r (shell/sh "sudo" "iptables" "-t" "nat" "-C" "POSTROUTING" "-s" subnet
                    "-o" egress-iface "-j" "MASQUERADE")]
    (when-not (zero? (:exit r))
      (sudo "iptables" "-t" "nat" "-A" "POSTROUTING" "-s" subnet
            "-o" egress-iface "-j" "MASQUERADE")))
  :enabled)

(defn nat-disable!
  "Remove the MASQUERADE rule for the guest subnet. Idempotent."
  [subnet egress-iface]
  (let [r (shell/sh "sudo" "iptables" "-t" "nat" "-C" "POSTROUTING" "-s" subnet
                    "-o" egress-iface "-j" "MASQUERADE")]
    (when (zero? (:exit r))
      (sudo "iptables" "-t" "nat" "-D" "POSTROUTING" "-s" subnet
            "-o" egress-iface "-j" "MASQUERADE")))
  :disabled)

;; --- AdGuard ---------------------------------------------------------------
(defn adguard-allowlist
  "AdGuard Home custom-filtering allow-list for a default-deny resolver."
  [domains]
  (str "@@||" (str/join "^\n@@||" domains) "^\n"))
