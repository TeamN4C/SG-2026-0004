#!/usr/bin/env bash
set -euo pipefail

echo "=== CVE-2025-52881 lab setup ==="
echo "=== analysis/reporting use only ==="

RUNC_VULN_VERSION="${RUNC_VULN_VERSION:-v1.2.7}"
RUNC_FIXED_VERSION="${RUNC_FIXED_VERSION:-v1.2.8}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SETUP_FIXED="${SETUP_FIXED:-1}"

if [ -z "${ARCH:-}" ]; then
  case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7l|armhf) ARCH="armhf" ;;
    ppc64le) ARCH="ppc64le" ;;
    s390x) ARCH="s390x" ;;
    *) ARCH="amd64" ;;
  esac
fi

WORK_DIR="${WORK_DIR:-$SCRIPT_DIR}"
BIN_DIR="$WORK_DIR/bin"
VULN_BIN="$BIN_DIR/runc-${RUNC_VULN_VERSION}.${ARCH}"
FIXED_BIN="$BIN_DIR/runc-${RUNC_FIXED_VERSION}.${ARCH}"
PATCHED_LINK="${PATCHED_LINK:-$BIN_DIR/runc-patched}"
SYSTEM_RUNC="${SYSTEM_RUNC:-/usr/bin/runc}"
EXTRA_RUNC_PATHS="${EXTRA_RUNC_PATHS:-/usr/sbin/runc}"

die() {
  echo "[-] $*" >&2
  exit 1
}

require_container_lab() {
  if [ "${ALLOW_NON_DIND:-0}" = "1" ]; then
    return
  fi
  if [ -f /.dockerenv ]; then
    return
  fi
  if grep -qaE 'docker|containerd|kubepods|libpod' /proc/1/cgroup 2>/dev/null; then
    return
  fi
  die "Refusing to replace runc outside an apparent container lab. Set ALLOW_NON_DIND=1 to override."
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y \
    ca-certificates curl jq procps strace util-linux coreutils build-essential \
    busybox-static docker.io containerd runc
  rm -rf /var/lib/apt/lists/*
}

download_runc() {
  local version="$1"
  local output="$2"
  local url="https://github.com/opencontainers/runc/releases/download/${version}/runc.${ARCH}"

  if [ -x "$output" ]; then
    echo "[*] already present: $output"
    return
  fi

  echo "[*] downloading $url"
  curl -fL --retry 3 --retry-delay 2 -o "$output" "$url"
  chmod 0755 "$output"
}

require_container_lab
mkdir -p "$BIN_DIR"

if [ -d "$PATCHED_LINK" ]; then
  echo "[!] PATCHED_LINK is a directory, using a binary path under $BIN_DIR instead: $PATCHED_LINK"
  PATCHED_LINK="$BIN_DIR/runc-patched-${RUNC_FIXED_VERSION}.${ARCH}"
fi

echo "[*] installing lab packages"
install_packages

download_runc "$RUNC_VULN_VERSION" "$VULN_BIN"
if [ "$SETUP_FIXED" = "1" ]; then
  download_runc "$RUNC_FIXED_VERSION" "$FIXED_BIN"
fi

if [ -e "$SYSTEM_RUNC" ] && [ ! -e "$BIN_DIR/runc-system-backup" ]; then
  echo "[*] backing up existing $SYSTEM_RUNC"
  cp -a "$SYSTEM_RUNC" "$BIN_DIR/runc-system-backup"
fi

echo "[*] installing vulnerable runc to $SYSTEM_RUNC"
cp "$VULN_BIN" "$SYSTEM_RUNC"
chmod 0755 "$SYSTEM_RUNC"
for extra_path in $EXTRA_RUNC_PATHS; do
  if [ -e "$extra_path" ]; then
    echo "[*] installing vulnerable runc to $extra_path"
    cp "$VULN_BIN" "$extra_path"
    chmod 0755 "$extra_path"
  fi
done

if [ "$SETUP_FIXED" = "1" ]; then
  echo "[*] installing patched runc link to $PATCHED_LINK"
  cp "$FIXED_BIN" "$PATCHED_LINK"
  chmod 0755 "$PATCHED_LINK"
fi

echo
echo "[*] vulnerable runc:"
"$SYSTEM_RUNC" --version
if [ "$SETUP_FIXED" = "1" ]; then
  echo
  echo "[*] patched runc:"
  "$PATCHED_LINK" --version
fi
echo
echo "[+] setup complete"
