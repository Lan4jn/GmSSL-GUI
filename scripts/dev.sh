#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
RUNTIME="$ROOT/.runtime"
WEB_DIR="$ROOT/web"
mkdir -p "$RUNTIME" "$ROOT/.data/platform" "$ROOT/.data/vault" "$RUNTIME/engine-work"
chmod 700 "$RUNTIME" "$ROOT/.data" "$ROOT/.data/platform" "$ROOT/.data/vault" "$RUNTIME/engine-work"

jar_path() { printf '%s/%s/target/%s-0.1.0-SNAPSHOT.jar' "$ROOT" "$1" "$1"; }
pid_file() { printf '%s/%s.pid' "$RUNTIME" "$1"; }
owned_pid() {
  local service=$1 file pid expected started args jar
  file=$(pid_file "$service")
  [[ -f "$file" && ! -L "$file" ]] || return 1
  pid=$(sed -n '1p' "$file")
  expected=$(sed -n '2p' "$file")
  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
  started=$(ps -p "$pid" -o lstart= 2>/dev/null) || return 1
  [[ "$started" == "$expected" ]] || return 1
  args=$(ps -p "$pid" -o command= 2>/dev/null) || return 1
  jar=$(jar_path "$service")
  [[ "$args" == *" -jar $jar"* ]] || return 1
  printf '%s' "$pid"
}
stop_service() {
  local service=$1
  if owned_pid "$service" >/dev/null; then
    python3 "$ROOT/ops/stop-process.py" --pid-file "$(pid_file "$service")" --jar "$(jar_path "$service")"
    printf '%s stopped\n' "$service"
  else
    printf '%s has no matching managed process\n' "$service"
  fi
}
start_service() {
  local service=$1 port=$2 jar pid index ready=0
  jar=$(jar_path "$service")
  if owned_pid "$service" >/dev/null; then printf '%s already running\n' "$service"; return; fi
  [[ -f "$jar" ]] || { printf 'Missing %s; run scripts/dev.sh build first.\n' "$jar" >&2; return 1; }
  if curl -sS --max-time 1 "http://127.0.0.1:$port/" >/dev/null 2>&1; then
    printf 'Port %s already has a listener; not starting %s.\n' "$port" "$service" >&2; return 1
  fi
  (
    cd -- "$ROOT"
    export SERVER_PORT="$port"
    nohup "$JAVA_HOME/bin/java" -jar "$jar" > >(python3 "$ROOT/ops/redact-log.py" "$RUNTIME/$service.log") 2>&1 &
    pid=$!
    printf '%s\n' "$pid" > "$(pid_file "$service")"
    ps -p "$pid" -o lstart= >> "$(pid_file "$service")"
  )
  for ((index=0; index<90; index++)); do
    if ! owned_pid "$service" >/dev/null; then
      printf '%s exited; inspect private log %s/%s.log\n' "$service" "$RUNTIME" "$service" >&2; return 1
    fi
    if curl -fsS --max-time 2 "http://127.0.0.1:$port/actuator/health" >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  [[ "$ready" == 1 ]] || { stop_service "$service"; printf '%s readiness timed out\n' "$service" >&2; return 1; }
  printf '%s ready on 127.0.0.1:%s\n' "$service" "$port"
}

find_node() {
  if [[ -n "${NODE_BIN:-}" && -x "$NODE_BIN" ]]; then
    printf '%s' "$NODE_BIN"; return 0
  fi
  local runtime_node="/Users/mewcapoo/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/node/bin/node"
  if [[ -x "$runtime_node" ]]; then
    printf '%s' "$runtime_node"; return 0
  fi
  if command -v node >/dev/null 2>&1; then
    command -v node; return 0
  fi
  return 1
}

owned_web_pid() {
  local file pid expected started args
  file=$(pid_file "web")
  [[ -f "$file" && ! -L "$file" ]] || return 1
  pid=$(sed -n '1p' "$file")
  expected=$(sed -n '2p' "$file")
  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
  started=$(ps -p "$pid" -o lstart= 2>/dev/null) || return 1
  [[ "$started" == "$expected" ]] || return 1
  args=$(ps -p "$pid" -o command= 2>/dev/null) || return 1
  [[ "$args" == *"vite"* ]] || return 1
  printf '%s' "$pid"
}

stop_web() {
  if owned_web_pid >/dev/null; then
    python3 "$ROOT/ops/stop-process.py" --pid-file "$(pid_file "web")" --cmd-contains "vite"
    printf 'web stopped\n'
  else
    printf 'web has no matching managed process\n'
  fi
}

start_web() {
  local port=5173 host="${GMSSL_WEB_HOST:-::}" node_bin vite_bin pid index ready=0
  if owned_web_pid >/dev/null; then printf 'web already running (managed PID %s)\n' "$(owned_web_pid)"; return; fi
  node_bin=$(find_node) || { printf 'Node.js runtime not found; please ensure Node is in PATH or set NODE_BIN.\n' >&2; return 1; }
  vite_bin="$WEB_DIR/node_modules/vite/bin/vite.js"
  [[ -f "$vite_bin" ]] || {
    printf 'Missing %s; please run scripts/web-install.sh first.\n' "$vite_bin" >&2
    return 1
  }
  if curl -sS --max-time 1 "http://127.0.0.1:$port/" >/dev/null 2>&1 || curl -sS -6 --max-time 1 "http://[::1]:$port/" >/dev/null 2>&1; then
    printf 'Port %s already has a listener; not starting web.\n' "$port" >&2; return 1
  fi
  (
    cd -- "$WEB_DIR"
    nohup "$node_bin" "$vite_bin" --host "$host" --port "$port" --strictPort > >(python3 "$ROOT/ops/redact-log.py" "$RUNTIME/web.log") 2>&1 &
    pid=$!
    printf '%s\n' "$pid" > "$(pid_file "web")"
    ps -p "$pid" -o lstart= >> "$(pid_file "web")"
  )
  for ((index=0; index<60; index++)); do
    if ! owned_web_pid >/dev/null; then
      printf 'web exited; inspect private log %s/web.log\n' "$RUNTIME" >&2; return 1
    fi
    if curl -fsS --max-time 1 "http://127.0.0.1:$port/" >/dev/null 2>&1 || curl -fsS -6 --max-time 1 "http://[::1]:$port/" >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.5
  done
  [[ "$ready" == 1 ]] || { stop_web; printf 'web readiness timed out\n' >&2; return 1; }
  printf 'web ready on host %s port %s (IPv6: http://[::1]:%s/, IPv4: http://127.0.0.1:%s/)\n' "$host" "$port" "$port" "$port"
}

case "${1:-status}" in
  build)
    exec "$ROOT/scripts/mvn.sh" -f "$ROOT/pom.xml" verify
    ;;
  stop)
    stop_service platform-service
    stop_service engine-service
    ;;
  status)
    for service in engine-service platform-service; do
      if pid=$(owned_pid "$service"); then printf '%s running (managed PID %s)\n' "$service" "$pid"; else printf '%s stopped\n' "$service"; fi
    done
    if pid=$(owned_web_pid); then printf 'web running (managed PID %s)\n' "$pid"; else printf 'web stopped\n'; fi
    if curl -sS --max-time 1 "http://127.0.0.1:8081/internal/v1/capabilities" >/dev/null 2>&1; then
      printf 'engine capabilities: active (GmSSL native + OpenSSL dual-engine)\n'
    fi
    ;;
  start)
    [[ -f "$ROOT/.tools/env.sh" ]] || { printf 'Run scripts/bootstrap-tools.sh first.\n' >&2; exit 1; }
    [[ -f "$ROOT/.env.local" ]] || { printf 'Run scripts/bootstrap-config.sh dev first.\n' >&2; exit 1; }
    source "$ROOT/.tools/env.sh"
    set -a
    source "$ROOT/.env.local"
    set +a
    : "${GMSSL_ENGINE_TOKEN:?Missing engine token}" "${GMSSL_VAULT_MASTER_KEY:?Missing master key}" "${GMSSL_BOOTSTRAP_PASSWORD:?Missing bootstrap password}"
    [[ -x "${GMSSL_RUNNER_PATH:?Missing runner path}" ]] || { printf 'Build native runner first; see ops/README.md.\n' >&2; exit 1; }
    start_service engine-service 8081
    if ! start_service platform-service 8080; then stop_service engine-service; exit 1; fi
    printf 'Local Java services ready. Start the web Vite development server with scripts/dev.sh web-start; see ops/README.md.\n'
    ;;
  web-start)
    start_web
    ;;
  web-stop)
    stop_web
    ;;
  web-status)
    if pid=$(owned_web_pid); then printf 'web running (managed PID %s)\n' "$pid"; else printf 'web stopped\n'; fi
    ;;
  *) printf 'Usage: %s [build|start|stop|status|web-start|web-stop|web-status]\n' "$0" >&2; exit 1 ;;
esac
