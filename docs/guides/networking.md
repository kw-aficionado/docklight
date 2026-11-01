# Network address and reachability

The admin-only **Network** page stores an optional public hostname, such as `play.example.com`. Docklight removes an `http://` or `https://` scheme and a trailing slash. Enter the hostname only; the port comes from the server template and its allocated host-port mapping. Clearing this field uses the automatically detected public IP.

If no hostname is saved, Docklight calls `https://api.ipify.org?format=json` with a three-second timeout and caches a valid IP for one hour. When a refresh fails, it keeps the last successful address. The Network page shows both the detected value and effective host. Detection is initiated when a signed-in user opens that page or a server's reachability check runs; a detected address is not saved as a configuration value unless an administrator explicitly enters it.

Running and starting servers show **Online from outside** on their Overview tab. A declared Rune query protocol is probed at its allocated query/game port; otherwise Docklight attempts a TCP connection to the game port or first declared non-RCON port. The check has a four-second timeout and caches its result for 30 seconds. DNS results are resolved before connecting; loopback, unspecified, and multicast addresses are never probed.

This check runs from the Docklight host. Routers that do not support NAT loopback can report a false negative even while clients on the public internet can connect. A positive result confirms only that the tested protocol or TCP port responded from the panel host; it does not test every client network or guarantee a firewall permits every user.

## UPnP port forwarding

The **Router port forwarding** section uses UPnP Internet Gateway Device discovery on the host's IPv4 LAN. It reports the LAN address used by Docklight, the router's WAN address, the number of saved Docklight mappings, and servers with cleanup still pending. UPnP must be enabled on the router and the host must be able to discover it on the same LAN.

The UPnP administrator switch is off by default. Each server's **Forward eligible ports automatically** preference is on by default, but has no effect until an administrator enables a forwarding provider. UniFi has its own separate administrator switch, also off by default. Enabling either provider applies mappings to currently running opted-in servers; newly started servers are mapped after Docker starts them.

Docklight forwards each declared game port using its allocated host port as both the external and internal port. TCP and UDP declarations are mapped separately. RCON, admin, management, and console ports are excluded. Mappings use a permanent router lease. If a router port already belongs to another rule, Docklight leaves it alone and reports the conflict.

Docklight saves the target and a unique `Docklight:` description for every rule it creates. On stop, confirmed container exit, explicit per-server opt-out, global opt-out, and deletion, Docklight checks the router's current protocol, ports, internal client, and description before deleting a saved rule. If the router is unavailable, it keeps cleanup records for a later attempt. Deleting a server is paused while its recorded mappings cannot be safely cleared, so the host ports are not released for another server while a stale router rule may remain.

UPnP mapping behavior is covered with fake-router tests. No physical router was available for discovery or host-level acceptance in this environment. A local reachability probe can still report a false negative when the router lacks NAT loopback.

## UniFi port forwarding

The **UniFi port forwarding** section connects directly to a local UniFi Network controller. Enter its URL, a local controller account, and a site name (usually `default`); save the settings and test the connection. The integration accepts a controller's self-signed HTTPS certificate. The username and password are encrypted with the panel secret, never returned by the settings API, and should use a dedicated account with only the rights needed to manage port-forward rules.

The global switch starts off. Each server uses the existing **Forward eligible ports automatically** preference. When enabled, Docklight clears old rules carrying that server's exact tag before starting it, then forwards declared game ports to the host's LAN address. RCON, admin, management, and console ports are excluded. Stop, confirmed container exit, per-server opt-out, and deletion remove only rules with that exact server tag. Other controller rules are left unchanged. If the controller cannot be reached during cleanup, server deletion is held until the rules can be checked and removed.

**Review rules** lists the controller's current port-forward rules. Docklight-tagged entries targeting this host's LAN address that cannot be matched to a local server are shown as strays; deleting them requires selecting the individual rules and confirming the action. Rules from other panels and Docklight rules targeting other hosts are not included in that delete action.

UniFi's local API documentation varies by Network version and is available in **Network > Integrations**. Docklight currently uses the controller's classic local login and site port-forward endpoints; the connection tests use a simulated controller. A real controller and its installed Network version still need acceptance testing against the [official local API guidance](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API).
