# Docklight Proxmox Backup Client helper

This minimal Linux/amd64 image packages the official statically linked `proxmox-backup-client` from Proxmox's Debian Trixie client-only APT repository. The Dockerfile verifies Proxmox's published archive-key checksum before using APT signature verification, and pins the package version.

Build and publish the version used by the Docklight default configuration:

```sh
docker buildx build \
  --platform linux/amd64 \
  --build-arg PBS_CLIENT_VERSION=4.2.8-1 \
  --tag ghcr.io/docklight/pbs-client:4.2.8 \
  --push deploy/pbs-client
```

Authenticate to GitHub Container Registry first. If you publish under another registry or namespace, set `docker.pbs_client_image` in `/etc/yggdrasil/config.yaml` to that image. Docklight requests the image as `linux/amd64` and does not support PBS backups from an ARM64 panel host.

The helper's entrypoint is the Proxmox client itself. Docklight creates a short-lived container, passes the repository password and optional TLS fingerprint at runtime, and mounts only the server data directory for backup or a private staging directory for restore. PBS archive data is not encrypted by Docklight; configure datastore security and PBS verification jobs.
