#!/usr/bin/env bash
set -euo pipefail

log() { printf '[yggdrasil] %s\n' "$*"; }
die() { printf '[yggdrasil] ERROR: %s\n' "$*" >&2; exit 1; }

if [[ "${EUID}" -ne 0 ]]; then
  die "run this installer as root, for example: sudo bash install.sh"
fi
if [[ ! -r /etc/os-release ]]; then
  die "this installer supports Debian and Ubuntu; /etc/os-release is unavailable"
fi
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
  *debian*|*ubuntu*) ;;
  *) die "this installer supports Debian 12 and Ubuntu 24.04 or newer" ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture $(uname -m); use amd64 or arm64" ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl

if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker Engine"
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker

source_dir="${YGG_SOURCE_DIR:-}"
if [[ -z "$source_dir" && -f "$(pwd)/go.mod" && -d "$(pwd)/cmd/yggdrasil" ]]; then
  source_dir="$(pwd)"
fi
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
release_repo="${YGG_REPO:-}"
if [[ -z "$release_repo" && -n "$source_dir" ]]; then
  remote_url="$(git -C "$source_dir" remote get-url origin 2>/dev/null || true)"
  remote_path=""
  case "$remote_url" in
    https://github.com/*) remote_path="${remote_url#https://github.com/}" ;;
    git@github.com:*) remote_path="${remote_url#git@github.com:}" ;;
  esac
  remote_path="${remote_path%.git}"
  if [[ "$remote_path" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    release_repo="$remote_path"
  fi
fi
if [[ -n "$release_repo" && ! "$release_repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  die "YGG_REPO must be a GitHub owner/repository name"
fi
tmp_binary="$(mktemp /tmp/yggdrasil.XXXXXX)"
checksums_file=""
trap 'rm -f "$tmp_binary"; [[ -z "$checksums_file" ]] || rm -f "$checksums_file"' EXIT
if [[ -n "$source_dir" && -f "$source_dir/go.mod" ]]; then
  command -v go >/dev/null 2>&1 || die "Go 1.27 or newer is required when installing from source; provide YGG_BINARY_URL or YGG_REPO instead"
  log "Building Yggdrasil from $source_dir for linux/$arch"
  ldflags='-s -w'
  [[ -z "$release_repo" ]] || ldflags+=" -X main.repository=$release_repo"
  (cd "$source_dir" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags="$ldflags" -o "$tmp_binary" ./cmd/yggdrasil)
elif [[ -n "${YGG_BINARY_FILE:-}" ]]; then
  [[ -f "$YGG_BINARY_FILE" ]] || die "YGG_BINARY_FILE does not exist: $YGG_BINARY_FILE"
  install -m 0755 "$YGG_BINARY_FILE" "$tmp_binary"
elif [[ -n "${YGG_BINARY_URL:-}" ]]; then
  log "Downloading binary from YGG_BINARY_URL"
  curl -fL --retry 3 --connect-timeout 15 "$YGG_BINARY_URL" -o "$tmp_binary"
  if [[ -n "${YGG_SHA256:-}" ]]; then
    printf '%s  %s\n' "$YGG_SHA256" "$tmp_binary" | sha256sum --check --status || die "the downloaded binary does not match YGG_SHA256"
  else
    log "No YGG_SHA256 was provided; using the explicitly configured binary URL as the trust source"
  fi
elif [[ -n "${YGG_REPO:-}" ]]; then
  version="${YGG_VERSION:-latest}"
  if [[ "$version" == "latest" ]]; then
    binary_url="https://github.com/${YGG_REPO}/releases/latest/download/yggdrasil-linux-${arch}"
  else
    binary_url="https://github.com/${YGG_REPO}/releases/download/${version}/yggdrasil-linux-${arch}"
  fi
  log "Downloading Yggdrasil ${version} from ${YGG_REPO}"
  curl -fL --retry 3 --connect-timeout 15 "$binary_url" -o "$tmp_binary"
  checksums_file="$(mktemp /tmp/yggdrasil-checksums.XXXXXX)"
  if [[ "$version" == "latest" ]]; then
    checksum_url="https://github.com/${YGG_REPO}/releases/latest/download/SHA256SUMS"
  else
    checksum_url="https://github.com/${YGG_REPO}/releases/download/${version}/SHA256SUMS"
  fi
  curl -fL --retry 3 --connect-timeout 15 "$checksum_url" -o "$checksums_file"
  expected="$(awk -v file="yggdrasil-linux-${arch}" '$2 == file {print $1}' "$checksums_file")"
  rm -f "$checksums_file"
  checksums_file=""
  [[ -n "$expected" ]] || die "the release SHA256SUMS file does not contain yggdrasil-linux-${arch}"
  printf '%s  %s\n' "$expected" "$tmp_binary" | sha256sum --check --status || die "the downloaded binary failed its SHA-256 check"
else
  die "provide a source checkout, YGG_BINARY_FILE, YGG_BINARY_URL, or YGG_REPO (and optionally YGG_VERSION)"
fi
chmod 0755 "$tmp_binary"
install -m 0755 "$tmp_binary" /usr/local/bin/yggdrasil
if [[ -z "$release_repo" ]]; then
  release_repo="$(/usr/local/bin/yggdrasil release-repo 2>/dev/null || true)"
fi
if [[ -n "$release_repo" && ! "$release_repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  release_repo=""
fi

if ! getent group yggdrasil >/dev/null; then
  groupadd --system yggdrasil
fi
if ! id yggdrasil >/dev/null 2>&1; then
  useradd --system --gid yggdrasil --home-dir /var/lib/yggdrasil --shell /usr/sbin/nologin yggdrasil
else
  usermod --gid yggdrasil --home /var/lib/yggdrasil --shell /usr/sbin/nologin yggdrasil
fi
if ! getent group docker >/dev/null; then
  die "Docker installed but its docker group is missing; check the Docker Engine installation"
fi
usermod -aG docker yggdrasil
install -d -o yggdrasil -g yggdrasil -m 0750 /var/lib/yggdrasil
install -d -o root -g yggdrasil -m 0750 /etc/yggdrasil

if [[ -x "$script_dir/deploy/yggdrasil-update" && -f "$script_dir/deploy/yggdrasil-update.service" && -f "$script_dir/deploy/yggdrasil-update.path" ]]; then
  install -o root -g root -m 0755 "$script_dir/deploy/yggdrasil-update" /usr/local/bin/yggdrasil-update
  install -o root -g root -m 0644 "$script_dir/deploy/yggdrasil-update.service" /etc/systemd/system/yggdrasil-update.service
  install -o root -g root -m 0644 "$script_dir/deploy/yggdrasil-update.path" /etc/systemd/system/yggdrasil-update.path
  if [[ -n "$release_repo" ]]; then
    printf 'YGG_REPO=%s\n' "$release_repo" >/etc/yggdrasil/update.conf
    chown root:root /etc/yggdrasil/update.conf
    chmod 0644 /etc/yggdrasil/update.conf
  fi
else
  log "Self-update helper assets are absent; panel self-update will remain unavailable."
fi

first_install=0
bootstrap_output=""
if [[ ! -e /etc/yggdrasil/config.yaml ]]; then
  first_install=1
  bootstrap_output="$(/usr/local/bin/yggdrasil gen-config /etc/yggdrasil/config.yaml)"
  chown root:yggdrasil /etc/yggdrasil/config.yaml
  chmod 0640 /etc/yggdrasil/config.yaml
fi

cat > /etc/systemd/system/yggdrasil.service <<'UNIT'
[Unit]
Description=Yggdrasil game and app server panel
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=yggdrasil
Group=yggdrasil
SupplementaryGroups=docker
WorkingDirectory=/var/lib/yggdrasil
StateDirectory=yggdrasil
StateDirectoryMode=0750
ExecStart=/usr/local/bin/yggdrasil --config /etc/yggdrasil/config.yaml
Restart=on-failure
RestartSec=5s
TimeoutStopSec=20s
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/yggdrasil /etc/yggdrasil
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
UMask=0027

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable yggdrasil.service
if [[ -x /usr/local/bin/yggdrasil-update && -f /etc/systemd/system/yggdrasil-update.path ]]; then
  systemctl enable --now yggdrasil-update.path
fi

ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ -n "$ip" ]] || ip="<server-ip>"
log "Yggdrasil is installed at http://${ip}:8080"
if [[ "$first_install" == 1 ]]; then
  printf '%s\n' "$bootstrap_output"
  log "Sign in with the one-time administrator password above, then change it in your password manager."
else
  log "Existing configuration and panel data were preserved."
  log "Service status: systemctl status yggdrasil"
fi
systemctl restart yggdrasil.service
