# Network address and reachability

The admin-only **Network** page stores an optional public hostname, such as `play.example.com`. Docklight removes an `http://` or `https://` scheme and a trailing slash. Enter the hostname only; the port comes from the server template and its allocated host-port mapping. Clearing this field uses the automatically detected public IP.

If no hostname is saved, Docklight calls `https://api.ipify.org?format=json` with a three-second timeout and caches a valid IP for one hour. When a refresh fails, it keeps the last successful address. The Network page shows both the detected value and effective host. Detection is initiated when a signed-in user opens that page or a server's reachability check runs; a detected address is not saved as a configuration value unless an administrator explicitly enters it.

Running and starting servers show **Online from outside** on their Overview tab. A declared Rune query protocol is probed at its allocated query/game port; otherwise Docklight attempts a TCP connection to the game port or first declared non-RCON port. The check has a four-second timeout and caches its result for 30 seconds. DNS results are resolved before connecting; loopback, unspecified, and multicast addresses are never probed.

This check runs from the Docklight host. Routers that do not support NAT loopback can report a false negative even while clients on the public internet can connect. A positive result confirms only that the tested protocol or TCP port responded from the panel host; it does not test every client network or guarantee a firewall permits every user.

## UPnP port forwarding

The **Router port forwarding** section uses UPnP Internet Gateway Device discovery on the host's IPv4 LAN. It reports the LAN address used by Docklight, the router's WAN address, the number of saved Docklight mappings, and servers with cleanup still pending. UPnP must be enabled on the router and the host must be able to discover it on the same LAN.

There are two independent switches. The administrator's global switch is off by default. Each server's **Forward eligible ports automatically** preference is on by default, but has no effect until the global switch is enabled. Enabling the global switch applies mappings to currently running opted-in servers; newly started servers are mapped after Docker starts them.

Docklight forwards each declared game port using its allocated host port as both the external and internal port. TCP and UDP declarations are mapped separately. RCON, admin, management, and console ports are excluded. Mappings use a permanent router lease. If a router port already belongs to another rule, Docklight leaves it alone and reports the conflict.

Docklight saves the target and a unique `Docklight:` description for every rule it creates. On stop, confirmed container exit, explicit per-server opt-out, global opt-out, and deletion, Docklight checks the router's current protocol, ports, internal client, and description before deleting a saved rule. If the router is unavailable, it keeps cleanup records for a later attempt. Deleting a server is paused while its recorded mappings cannot be safely cleared, so the host ports are not released for another server while a stale router rule may remain.

UPnP mapping behavior is covered with fake-router tests. No physical router was available for discovery or host-level acceptance in this environment. A local reachability probe can still report a false negative when the router lacks NAT loopback.
