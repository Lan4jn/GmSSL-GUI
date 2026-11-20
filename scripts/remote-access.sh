#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Remote Access Manager for GmSSL-GUI via Cloudflare Quick Tunnel and Loopback Proxy
set +x
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
RUNTIME="$ROOT/.runtime"
TOOLS="$ROOT/.tools"
PROXY_PORT="${REMOTE_PROXY_PORT:-5180}"

mkdir -p "$RUNTIME"
chmod 700 "$RUNTIME"

pid_file() { printf '%s/%s.pid' "$RUNTIME" "$1"; }

owned_pid() {
  local service=$1 cmd_pattern=$2 file pid expected started args
  file=$(pid_file "$service")
  [[ -f "$file" && ! -L "$file" ]] || return 1
  pid=$(sed -n '1p' "$file")
  expected=$(sed -n '2p' "$file")
  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
  started=$(ps -p "$pid" -o lstart= 2>/dev/null) || return 1
  [[ "$started" == "$expected" ]] || return 1
  args=$(ps -p "$pid" -o command= 2>/dev/null) || return 1
  [[ "$args" == *"$cmd_pattern"* ]] || return 1
  printf '%s' "$pid"
}

stop_proxy() {
  if owned_pid "remote-proxy" "proxy_server.py" >/dev/null; then
    python3 "$ROOT/ops/stop-process.py" --pid-file "$(pid_file "remote-proxy")" --cmd-contains "proxy_server.py"
    printf 'remote proxy stopped\n'
  else
    printf 'remote proxy has no matching managed process\n'
  fi
}

stop_tunnel() {
  if owned_pid "remote-tunnel" "cloudflared" >/dev/null; then
    python3 "$ROOT/ops/stop-process.py" --pid-file "$(pid_file "remote-tunnel")" --cmd-contains "cloudflared"
    printf 'remote tunnel stopped\n'
  else
    printf 'remote tunnel has no matching managed process\n'
  fi
}

start_proxy() {
  local pid index ready=0
  if owned_pid "remote-proxy" "proxy_server.py" >/dev/null; then
    printf 'remote proxy already running (managed PID %s)\n' "$(owned_pid "remote-proxy" "proxy_server.py")"
    return 0
  fi
  if curl -sS --max-time 1 "http://127.0.0.1:$PROXY_PORT/" >/dev/null 2>&1; then
    printf 'Port %s already has a listener; not starting remote proxy.\n' "$PROXY_PORT" >&2
    return 1
  fi
  (
    cd -- "$ROOT"
    nohup python3 "$ROOT/ops/proxy_server.py" \
      --host 127.0.0.1 \
      --port "$PROXY_PORT" \
      --dist "$ROOT/web/dist" \
      --api-host 127.0.0.1 \
      --api-port 8080 > >(python3 "$ROOT/ops/redact-log.py" "$RUNTIME/remote-proxy.log") 2>&1 &
    pid=$!
    printf '%s\n' "$pid" > "$(pid_file "remote-proxy")"
    ps -p "$pid" -o lstart= >> "$(pid_file "remote-proxy")"
  )
  for ((index=0; index<40; index++)); do
    if ! owned_pid "remote-proxy" "proxy_server.py" >/dev/null; then
      printf 'remote proxy exited; inspect private log %s/remote-proxy.log\n' "$RUNTIME" >&2
      return 1
    fi
    if curl -fsS --max-time 1 "http://127.0.0.1:$PROXY_PORT/" >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 0.25
  done
  [[ "$ready" == 1 ]] || { stop_proxy; printf 'remote proxy readiness timed out\n' >&2; return 1; }
  printf 'remote proxy ready on http://127.0.0.1:%s/\n' "$PROXY_PORT"
}

start_tunnel() {
  local cf_bin="$TOOLS/cloudflared/cloudflared" pid index url=""
  [[ -x "$cf_bin" ]] || {
    printf 'cloudflared binary not found at %s. Please install it first.\n' "$cf_bin" >&2
    return 1
  }
  if owned_pid "remote-tunnel" "cloudflared" >/dev/null; then
    printf 'remote tunnel already running (managed PID %s)\n' "$(owned_pid "remote-tunnel" "cloudflared")"
    return 0
  fi
  # Clean old tunnel log before start to capture fresh URL
  : > "$RUNTIME/remote-tunnel.log"
  (
    cd -- "$ROOT"
    nohup "$cf_bin" tunnel --url "http://127.0.0.1:$PROXY_PORT" --no-autoupdate > >(python3 "$ROOT/ops/redact-log.py" "$RUNTIME/remote-tunnel.log") 2>&1 &
    pid=$!
    printf '%s\n' "$pid" > "$(pid_file "remote-tunnel")"
    ps -p "$pid" -o lstart= >> "$(pid_file "remote-tunnel")"
  )
  for ((index=0; index<60; index++)); do
    if ! owned_pid "remote-tunnel" "cloudflared" >/dev/null; then
      printf 'cloudflared tunnel exited; inspect private log %s/remote-tunnel.log\n' "$RUNTIME" >&2
      return 1
    fi
    url=$(grep -oE "https://[a-zA-Z0-9-]+\.trycloudflare\.com" "$RUNTIME/remote-tunnel.log" | head -n 1 || true)
    if [[ -n "$url" ]]; then
      break
    fi
    sleep 0.5
  done
  if [[ -z "$url" ]]; then
    stop_tunnel
    printf 'Failed to acquire Cloudflare tunnel URL within timeout; inspect %s/remote-tunnel.log\n' "$RUNTIME" >&2
    return 1
  fi

  python3 -c '
import json, sys
from datetime import datetime, timezone
data = {
    "status": "RUNNING",
    "public_url": sys.argv[1],
    "proxy_port": int(sys.argv[2]),
    "upstream_platform": "http://127.0.0.1:8080",
    "provider": "Cloudflare Quick Tunnel (Third-party transit)",
    "started_at": datetime.now(timezone.utc).isoformat(),
    "pid_proxy": int(sys.argv[3]),
    "pid_tunnel": int(sys.argv[4])
}
with open(sys.argv[5], "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
' "$url" "$PROXY_PORT" "$(owned_pid "remote-proxy" "proxy_server.py")" "$(owned_pid "remote-tunnel" "cloudflared")" "$RUNTIME/remote-access.json"

  printf '\n=======================================================\n'
  printf 'Remote Access Established!\n'
  printf 'Public URL: %s\n' "$url"
  printf 'Provider:   Cloudflare Quick Tunnel (trycloudflare.com)\n'
  printf 'Loopback:   127.0.0.1:%s -> 127.0.0.1:8080\n' "$PROXY_PORT"
  printf 'Metadata:   %s/remote-access.json\n' "$RUNTIME"
  printf '=======================================================\n\n'
}

case "${1:-status}" in
  start)
    start_proxy
    start_tunnel
    ;;
  stop)
    stop_tunnel
    stop_proxy
    python3 -c '
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
if p.exists():
    p.write_text(json.dumps({"status": "STOPPED"}, indent=2))
' "$RUNTIME/remote-access.json"
    ;;
  status)
    proxy_pid=$(owned_pid "remote-proxy" "proxy_server.py" || true)
    tunnel_pid=$(owned_pid "remote-tunnel" "cloudflared" || true)
    if [[ -n "$proxy_pid" ]]; then
      printf 'remote proxy:  RUNNING (managed PID %s)\n' "$proxy_pid"
    else
      printf 'remote proxy:  STOPPED\n'
    fi
    if [[ -n "$tunnel_pid" ]]; then
      printf 'remote tunnel: RUNNING (managed PID %s)\n' "$tunnel_pid"
    else
      printf 'remote tunnel: STOPPED\n'
    fi
    if [[ -f "$RUNTIME/remote-access.json" ]]; then
      cat "$RUNTIME/remote-access.json"
    fi
    ;;
  *)
    printf 'Usage: %s [start|stop|status]\n' "$0" >&2
    exit 1
    ;;
esac
