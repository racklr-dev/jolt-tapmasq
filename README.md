# jolt-tapmasq — host-side networking for jolt-microvm

Host-side networking for [jolt-microvm](https://github.com/racklr-dev/jolt-microvm)
sandboxes: the TAP + dnsmasq + nftables layer that gives a VM its network on
[libkrun](https://github.com/containers/libkrun) 2.0, which has no
`port_map`/TSI. The guest DHCPs on a TAP and the host reaches it at its leased
IP.

Default policy is DENY: forwarded traffic from the guest subnet is dropped
except DNS to the resolver and allow-listed CIDRs.

## Requirements

- `ip`, `sysctl`, `nft`, `iptables`, `dnsmasq` on the host
- `sudo` (every state-changing call runs through it)
- [jolt](https://github.com/jolt-lang/jolt) 0.8.28+ to run the tests

## Build

Nothing to compile. Run the suite:

```sh
jolt run test/jolt/tapmasq_test.clj
```

## Usage

```clojure
{:deps {racklr-dev/jolt-tapmasq
        {:git/url "https://github.com/racklr-dev/jolt-tapmasq"
         :git/sha "<pinned sha>"}}}
```

```clojure
(require '[jolt.tapmasq :as net])

(net/tap-create! "jolt0")               ; vnet_hdr on, owned by you
(net/tap-ip! "jolt0" "192.168.44.1/24")
(net/ip-forward! true)

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

(net/wait-lease "/tmp/dnsmasq.leases" "02:00:00:00:00:01" 30000)

(net/nftables-apply!
  {:table "jolt" :subnet "192.168.44.0/24" :dns "192.168.44.1"
   :allow-cidrs ["199.232.0.0/16"]
   :rules-file "/tmp/jolt-nft.rules"})
(net/nat-enable! "192.168.44.0/24" "eth0")

;; teardown
(net/dnsmasq-stop!)
(net/nftables-clear! "jolt")
(net/tap-delete! "jolt0")
```

`jolt-microvm` composes these calls for you; use this library directly to wire
the network layer by hand or build your own runner on
[jolt-libkrun](https://github.com/racklr-dev/jolt-libkrun).

## API

| Function | Args | Returns | Errors |
|---|---|---|---|
| `tap-create!` | `name` | nil | throws on failure |
| `tap-delete!` | `name` | nil | throws on failure |
| `tap-ip!` | `name cidr` | nil | throws on failure |
| `ip-forward!` | `on?` | nil | throws on failure |
| `dnsmasq-config` | `opts` | config file text | — |
| `dnsmasq-start!` | `opts` | nil | throws on failure |
| `dnsmasq-stop!` | — | `:stopped` | — |
| `lease-ip` | `lease-file mac` | the leased IP, or nil | — |
| `wait-lease` | `lease-file mac timeout-ms` | the leased IP | throws on timeout |
| `nftables-apply!` | `opts` | nil | throws on failure |
| `nftables-clear!` | `table` | nil | throws on failure |
| `nat-enable!` / `nat-disable!` | `subnet egress-iface` | nil | throws on failure |
| `adguard-allowlist` | `domains` | the rendered allow-list text | — |

`nftables-apply!` writes a default-drop forward chain: established/related, DNS
to the resolver, then one accept rule per allow-listed CIDR. `nat-enable!`
MASQUERADEs the subnet out an egress interface.

## Status

beta — TAP/dnsmasq/nftables round-trips are tested
(`test/jolt/tapmasq_test.clj`); the AdGuard allow-list renderer is unit-tested
only.

## License

EPL-2.0

## Learn more

- [jolt-lang](https://github.com/jolt-lang/jolt) — the language and toolchain
- [jolt-microvm](https://github.com/racklr-dev/jolt-microvm) — the consumer that composes these calls
- [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) — the DHCP/DNS daemon
- [nftables](https://netfilter.org/projects/nftables/) — the firewall layer
