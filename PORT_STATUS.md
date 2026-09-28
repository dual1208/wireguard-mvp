# gz UDP 51820: closed

Closed at the user's explicit request on 2026-09-27, 14:37 UTC. This disconnected the new Villa–gz–Cave tunnel.

The listener was owned by Linux's native WireGuard implementation. It had no userspace PID in `ss`. Removing the owned WireGuard interface closed its IPv4 and IPv6 UDP sockets. The project controller was set to rolled-back state, so its running supervisor will not recreate the endpoint. The exact project cloud ingress rule was also revoked.

Observed after closure:

```text
WATCH healthy
STATE rolledback
hub: absent
UDP51820_CLOSED
CLOUD {"status": "ABSENT", "changed": true}
```

The socket check was `ss -H -ulnp '( sport = :51820 )'`; it returned no listeners. Existing SSH, camouflage, Matrix and other services were not changed. The router configurations remain installed, but cannot communicate through the stopped hub.

The networking distinction matters: the small controller process manages configuration; kernel WireGuard owns the packet-processing endpoint. Closing that endpoint does not require killing SSH or the independent HTTPS camouflage service. WireGuard's [namespace documentation](https://www.wireguard.com/netns/) explains why its outer UDP socket stays in the host namespace while its decrypted interface can live elsewhere.

Private closure evidence: `.local/runs/20260927T143742Z-g6ids_la/user-closure.json`. The earlier live read-only inspection is retained in `.local/runs/20260927T143710Z-yqsoit3i/security-observations.json`; it describes the state before closure, not the present state.

`apply --apply` would reopen the endpoint. Do not run it unless reopening is intended.
