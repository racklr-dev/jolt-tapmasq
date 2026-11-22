# jolt-tapmasq

[![tests](https://github.com/racklr-dev/jolt-tapmasq/actions/workflows/ci.yml/badge.svg)](https://github.com/racklr-dev/jolt-tapmasq/actions/workflows/ci.yml)

Host-side networking for [jolt-microvm](https://github.com/racklr-dev/jolt-microvm)
sandboxes: the **TAP + dnsmasq + nftables** layer that gives a VM its network on
[libkrun](https://github.com/containers/libkrun) 2.0, which has no
`port_map`/TSI. The guest instead DHCPs on a TAP and the host reaches it at its
leased IP.

Default policy is **DENY**: forwarded traffic from the guest subnet is dropped
except DNS to the resolver and allow-listed CIDRs.

## Quickstart

```clojure
{:deps {racklr-dev/jolt-tapmasq
        {:git/url "https://github.com/racklr-dev/jolt-tapmasq"
         :git/sha "<latest sha>"}}}
```

```clojure
(require '[jolt.tapmasq :as net])

;; create the TAP and give the host its subnet IP
(net/tap-create! "jolt0")            ; vnet_hdr on, owned by you
(net/tap-ip! "jolt0" "192.168.44.1/24")
(net/ip-forward! true)                ; allow forwarded egress

;; DHCP for the guest (default route + DNS to the resolver)
(net/dnsmasq-start!
  {:config-file (net/dnsmasq-config
                  {:interface "jolt0"
                   :subnet-cidr "192.168.44.1/24"
                   :range-start "192.168.44.10"
                   :range-end   "192.168.44.200"
                   :dns "192.168.44.1"})
   :pid-file "/tmp/dnsmasq.pid"
   :lease-file "/tmp/dnsmasq.leases"
   :log-file "/tmp/dnsmasq.log"})

;; wait for the guest's DHCP lease, then talk to it at that IP
(net/wait-lease "/tmp/dnsmasq.leases" "02:00:00:00:00:01" 30000)

;; egress: default-deny, DNS + allow-list only, then NAT the allow-list out
(net/nftables-apply!
  {:table "jolt" :subnet "192.168.44.0/24" :dns "192.168.44.1"
   :allow-cidrs ["199.232.0.0/16"]   ; e.g. fastly (docker registry)
   :rules-file "/tmp/jolt-nft.rules"})
(net/nat-enable! "192.168.44.0/24" "eth0")

;; teardown
(net/dnsmasq-stop!)
(net/nftables-clear! "jolt")
(net/tap-delete! "jolt0")
```

`jolt-microvm` composes these calls for you. This library is the plumbing to use
when you want to wire the network layer by hand, or build your own
VM runner on top of [jolt-libkrun](https://github.com/racklr-dev/jolt-libkrun).

## The pieces

- **TAP**: `tap-create!` makes a `vnet_hdr` TAP owned by the current user
  (what libkrun's tap backend expects), `tap-ip!` assigns the host-side IP,
  `ip-forward!` toggles IPv4 forwarding.
- **dnsmasq**: `dnsmasq-config` builds the `dhcpd.conf` we own;
  `dnsmasq-start!`/`dnsmasq-stop!` run it with a pid/lease/log file, and
  `lease-ip`/`wait-lease` read the guest's IP out of the lease file.
- **nftables**: `nftables-apply!` writes and applies a default-`drop` forward
  chain: established/related, DNS to the resolver, then one accept rule per
  allow-listed CIDR. `nat-enable!` MASQUERADEs the subnet out an egress
  interface.
- **AdGuard**: `adguard-allowlist` renders the `@@||domain^` custom-filtering
  allow-list for a default-deny AdGuard Home resolver.

## Modules

- `jolt.tapmasq`: everything above, in one namespace.

## Requirements

- `ip`, `sysctl`, `nft`, `iptables`, `dnsmasq` on the host.
- `sudo`: every state-changing call runs through it.

## License

EPL-2.0