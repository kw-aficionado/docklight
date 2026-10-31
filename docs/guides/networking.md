# Network address and reachability

The admin-only **Network** page stores an optional public hostname, such as `play.example.com`. Docklight removes an `http://` or `https://` scheme and a trailing slash. Enter the hostname only; the port comes from the server template and its allocated host-port mapping. Clearing this field uses the automatically detected public IP.

If no hostname is saved, Docklight calls `https://api.ipify.org?format=json` with a three-second timeout and caches a valid IP for one hour. When a refresh fails, it keeps the last successful address. The Network page shows both the detected value and effective host. Detection is initiated when a signed-in user opens that page or a server's reachability check runs; a detected address is not saved as a configuration value unless an administrator explicitly enters it.

Running and starting servers show **Online from outside** on their Overview tab. A declared Rune query protocol is probed at its allocated query/game port; otherwise Docklight attempts a TCP connection to the game port or first declared non-RCON port. The check has a four-second timeout and caches its result for 30 seconds. DNS results are resolved before connecting; loopback, unspecified, and multicast addresses are never probed.

This check runs from the Docklight host. Routers that do not support NAT loopback can report a false negative even while clients on the public internet can connect. A positive result confirms only that the tested protocol or TCP port responded from the panel host; it does not test every client network or guarantee a firewall permits every user.

UPnP, UniFi, Cloudflare routes and DNS, and reverse-proxy integrations are separate controls and are not configured by this page.
