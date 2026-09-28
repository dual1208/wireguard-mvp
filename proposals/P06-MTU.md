# P06 current-MTU runner

`tools/mtu_probe.py` now runs the **current configured MTU** through the guarded launcher. It never changes runtime MTU, persistent configuration, keys, or canonical state. The earlier `proposals/mtu-lease.sh` is unused and must not be deployed for this workflow.

Dry-run examples (no SSH):

```sh
python3 tools/mtu_probe.py --scope cave --mtu 1380
python3 tools/mtu_probe.py --scope all --mtu 1420
```

After the root coordinator has installed the reviewed `benchmark.sh` revision and created the matching reviewed security gate, explicit execution is:

```sh
python3 tools/mtu_probe.py --scope cave --apply
python3 tools/mtu_probe.py --scope all --apply
```

The Cave scope uses only gz and Cave, the separate scoped security gate, and reports full P06 incomplete even when its selected scope passes. The all scope tests both router legs. Evidence is written to the launcher's private run directory as `mtu-results.json`; a passing all-scope run is `MEASURED`, with `validated_current_mtu`, never a claim that a higher setting cannot work. Pending leases remain pending; nothing auto-commits.

The runner checks inventory/config/live MTU equality, installed diagnostic-worker SHA256, DF-option availability, security evidence, policy, explicit-source pings and recovery. It sends three gz DF echoes per selected router. For each leg direction it opens the existing finite exact benchmark ACL, starts registered bounded inner/outer captures and a one-off overlay-bound server, then runs `client udp-df 1`: current-MTU-minus28 UDP payload, DF, 1Mbps,10seconds, no omitted warmup. The diagnostic worker accepts no arbitrary MTU, payload size or DF test bitrate.

Both endpoint captures must contain repeated full-size inner DF packets and outer WireGuard packets of the expected size. Outer filters include noninitial fragments, which have no UDP ports. An observed owned outer fragment fails; missing/unattributed data, packet loss, capture drops, incomplete capture coverage, and offload-sized ambiguous packets block validation. Cleanup collects/removes exact owned capture files, stops their matching registered processes, revokes the kernel gate and removes its temporary rules. Health and recovery precede renewal.

To test a different MTU, use the ordinary reviewed O04 removal/reapplication or a reviewed configuration revision under the root coordinator, then rerun this same helper. The current policy cap is1420; a1500-byte IPv4 underlay suggests1440 before other encapsulation but does not authorize or validate it. Validate Villa after its unrelated work completes before selecting a common value.

## What the available probes establish

For a candidate inner IPv4 MTU `M`, ordinary ICMP and UDP both use `M-28` payload bytes (20-byte IPv4 header plus8-byte ICMP/UDP header). At1380 the payload is1352; at1420 it is1392. The gz command uses `ping -4 -M do -s PAYLOAD` inside `wgmvp`, bound to the G overlay address. The iputils `do` mode sets inner DF and remains subject to the kernel's cached PMTU. `probe` bypasses that cache and should only be a separately recorded follow-up when a stale cache is actually suspected; do not flush host routes. [iputils ping manual](https://man7.org/linux/man-pages/man8/ping.8.html)

That echo exchange is insufficient for a bidirectional no-fragmentation claim. The upstream Linuxv6.12 ICMP reply socket uses `IP_PMTUDISC_DONT`; the reply need not copy request DF. More significantly, native WireGuard sets `skb->ignore_df=1` and supplies outer IPv4 DF=0 to its UDP tunnel transmit function. Inner DF therefore does not forbid outer fragmentation. The installed vendor kernels must be checked through capture, not assumed identical to this reference source. [ICMP source](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/net/ipv4/icmp.c#L1526), [WireGuard socket source](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/drivers/net/wireguard/socket.c#L84)

iperf3 supports IPv4 UDP `--dont-fragment`, so BusyBox ping's missing DF option does not require installing another ping binary. Confirm each installed binary advertises the option: the3.17.1 source puts the socket option behind `HAVE_DONT_FRAGMENT`. That source sets Linux `IP_MTU_DISCOVER=IP_PMTUDISC_DO`. Use separate client/server runs in both directions, `-u --dont-fragment -b 1M -l (M-28) -t10 -O0 -J`, with client timeout20seconds and one-off, overlay-bound receiver timeout45seconds. [ESnet invoking guide](https://software.es.net/iperf/invoking.html), [iperf3.17.1 implementation](https://github.com/esnet/iperf/blob/2acfcfe94e928e74542c9f107e02aa6dd4748a79/src/iperf_api.c#L4557)

Linux WireGuard rounds plaintext toward a16-byte boundary but clamps padding to the interface MTU. At exactly `M` inner bytes, the expected IPv4 outer IP size is `M+60`; smaller packets may have padding. Capture the actual lengths. The two hub legs are serial decapsulation/re-encapsulation, so do not subtract two WireGuard overheads from one leg's MTU. [WireGuard padding source](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/drivers/net/wireguard/send.c#L141), [protocol format](https://www.wireguard.com/protocol/)


Source references checked locally: Linuxv6.12 commit `adc218676eef25575469234709c2d87185ca223a`; iperf3.17.1 commit `2acfcfe94e928e74542c9f107e02aa6dd4748a79`. Runtime DF behavior and wire sizes require the runner's captures; source inspection alone is not packet evidence.
