FROM debian:trixie-slim

ARG PBS_CLIENT_VERSION=4.2.8-1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    curl -fsSL https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg \
      -o /usr/share/keyrings/proxmox-archive-keyring.gpg; \
    echo '136673be77aba35dcce385b28737689ad64fd785a797e57897589aed08db6e45  /usr/share/keyrings/proxmox-archive-keyring.gpg' \
      | sha256sum -c -; \
    printf '%s\n' \
      'Types: deb' \
      'URIs: http://download.proxmox.com/debian/pbs-client' \
      'Suites: trixie' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg' \
      > /etc/apt/sources.list.d/pbs-client.sources; \
    apt-get update; \
    apt-get install -y --no-install-recommends "proxmox-backup-client-static=${PBS_CLIENT_VERSION}"; \
    apt-get purge -y --auto-remove curl; \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/bin/proxmox-backup-client"]
