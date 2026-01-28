#!/usr/bin/env bash
# 适用系统: Debian 系 / Alpine（Alpine 需先安装 bash: apk add bash）
# 适用架构: amd64/arm64/armv7
# 功能概述: Realm 一键安装/管理（端口转发增查删改 + 服务管理）
set -euo pipefail

REALM_BIN="/usr/local/bin/realm"
CONFIG_DIR="/etc/realm"
ENV_FILE="${CONFIG_DIR}/realm.env"
ENDPOINTS_FILE="${CONFIG_DIR}/endpoints.db"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
SERVICE_FILE="/etc/systemd/system/realm.service"
LOG_DIR="/var/log/realm"
LOG_FILE="${LOG_DIR}/realm.log"
LOGROTATE_FILE="/etc/logrotate.d/realm"
PID_FILE="/run/realm.pid"
OPENRC_SERVICE="/etc/init.d/realm"

BACKUP_DIR="/etc/realm/backups"
BACKUP_CONF="/etc/realm/backup.conf"
CRON_FILE="/etc/cron.d/realm-rules-export"
EXPORT_HELPER="/usr/local/bin/realm-export-rules.sh"
CRON_TAG="# realm-rules-export"

TMP_DIR="/tmp/realm-onekey"
TMP_TARBALL="${TMP_DIR}/realm.tar.gz"
TMP_EXTRACT="${TMP_DIR}/realm_extract"
APT_CACHE_DIR="/tmp/apt-cache"
APT_STATE_DIR="/tmp/apt-state"
APT_LISTS_DIR="/tmp/apt-state/lists"

C_RESET=""
C_BOLD=""
C_DIM=""
C_RED=""
C_GREEN=""
C_YELLOW=""
C_BLUE=""
C_CYAN=""
OS_ID=""
OS_LIKE=""

msg() { printf '%s\n' "$*"; }
ui() { printf '%s\n' "$*" >&2; }
err() { printf '%s\n' "${C_RED}错误: $*${C_RESET}" >&2; }
die() { err "$*"; exit 1; }

cmd_exists() { command -v "$1" >/dev/null 2>&1; }
systemd_available() { cmd_exists systemctl && [ -d /run/systemd/system ]; }
openrc_available() { cmd_exists rc-service && [ -d /etc/init.d ]; }

ensure_bash() {
  if [ -z "${BASH_VERSION:-}" ]; then
    err "请使用 bash 运行脚本 (bash $0)。"
    exit 1
  fi
}

process_running() {
  if cmd_exists pgrep; then
    if pgrep -x realm >/dev/null 2>&1; then
      return 0
    fi
    if pgrep -f "$REALM_BIN" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi
  ps -eo comm,args 2>/dev/null | awk -v bin="$REALM_BIN" '
    $1=="realm" {found=1}
    $2 ~ bin {found=1}
    END{exit !found}
  '
}

init_colors() {
  if [ -t 1 ] || [ -t 2 ]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'
    C_CYAN=$'\033[36m'
  fi
}

menu_title() { msg "${C_BOLD}${C_CYAN}$1${C_RESET}"; }
menu_sep() { msg "${C_DIM}----------------------------------------${C_RESET}"; }
menu_item() { printf "  ${C_YELLOW}%2s)${C_RESET} %s\n" "$1" "$2"; }

clear_screen() {
  if cmd_exists clear; then
    clear
  else
    printf '\033[2J\033[H'
  fi
}

pause_return() {
  read -r -n 1 -s -p "按任意键返回菜单..." _key || true
  echo
}

run_and_pause() {
  "$@" || true
  pause_return
}

install_status() {
  if [ -x "$REALM_BIN" ]; then
    echo "${C_GREEN}已安装${C_RESET}"
  else
    echo "${C_RED}未安装${C_RESET}"
  fi
}

runtime_status() {
  if systemd_available; then
    if systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "realm.service"; then
      local state
      state="$(systemctl is-active realm 2>/dev/null || true)"
      if [ "$state" = "active" ]; then
        echo "${C_GREEN}运行中${C_RESET}"
      elif [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
        echo "${C_GREEN}运行中${C_RESET}"
      elif process_running; then
        echo "${C_GREEN}运行中${C_RESET}"
      else
        case "$state" in
          inactive|failed|activating|deactivating) echo "${C_YELLOW}未运行(${state})${C_RESET}" ;;
          *) echo "${C_YELLOW}未知(${state})${C_RESET}" ;;
        esac
      fi
    else
      if openrc_available; then
        if [ -f "$OPENRC_SERVICE" ]; then
          if rc-service realm status >/dev/null 2>&1; then
            echo "${C_GREEN}运行中${C_RESET}"
          else
            if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
              echo "${C_GREEN}运行中${C_RESET}"
            elif process_running; then
              echo "${C_GREEN}运行中${C_RESET}"
            else
              echo "${C_YELLOW}未运行${C_RESET}"
            fi
          fi
        else
          echo "${C_RED}未注册${C_RESET}"
        fi
      else
        if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
          echo "${C_GREEN}运行中${C_RESET}"
        elif process_running; then
          echo "${C_GREEN}运行中${C_RESET}"
        else
          echo "${C_RED}未注册${C_RESET}"
        fi
      fi
    fi
  elif openrc_available; then
    if [ -f "$OPENRC_SERVICE" ]; then
      if rc-service realm status >/dev/null 2>&1; then
        echo "${C_GREEN}运行中${C_RESET}"
      else
        if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
          echo "${C_GREEN}运行中${C_RESET}"
        elif process_running; then
          echo "${C_GREEN}运行中${C_RESET}"
        else
          echo "${C_YELLOW}未运行${C_RESET}"
        fi
      fi
    else
      echo "${C_RED}未注册${C_RESET}"
    fi
  else
    if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
      echo "${C_GREEN}运行中${C_RESET}"
    else
      echo "${C_YELLOW}未运行${C_RESET}"
    fi
  fi
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "请用 root 运行。"
  fi
}

check_os() {
  if [ ! -r /etc/os-release ]; then
    die "无法识别系统版本，仅支持 Debian 系/Alpine。"
  fi
  # shellcheck source=/etc/os-release
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_LIKE="${ID_LIKE:-}"
  if [ "$OS_ID" = "alpine" ]; then
    return 0
  fi
  if [ "$OS_ID" != "debian" ] && ! echo "$OS_LIKE" | grep -qi "debian"; then
    die "仅支持 Debian 系/Alpine 发行版。"
  fi
}

is_alpine() {
  [ "${OS_ID:-}" = "alpine" ]
}

detect_libc() {
  if cmd_exists ldd && ldd --version 2>&1 | grep -qi musl; then
    echo "musl"
  else
    echo "gnu"
  fi
}

get_arch_asset() {
  local libc
  libc="$(detect_libc)"
  case "$(uname -m)" in
    x86_64|amd64) echo "realm-x86_64-unknown-linux-${libc}.tar.gz" ;;
    aarch64|arm64) echo "realm-aarch64-unknown-linux-${libc}.tar.gz" ;;
    armv7l|armv7|armhf|armv6l)
      if [ "$libc" = "musl" ]; then
        echo "realm-armv7-unknown-linux-musleabihf.tar.gz"
      else
        echo "realm-armv7-unknown-linux-gnueabihf.tar.gz"
      fi
      ;;
    *) die "不支持的架构: $(uname -m)。"
  esac
}

ensure_tmp_dir() {
  if [ ! -d /tmp ]; then
    mkdir -p /tmp
  fi
  chmod 1777 /tmp 2>/dev/null || true
  mkdir -p "$TMP_DIR"
}

install_deps() {
  msg "安装依赖中..."
  ensure_tmp_dir
  if is_alpine; then
    cmd_exists apk || die "未找到 apk，无法安装依赖。"
    apk add --no-cache curl ca-certificates tar gzip logrotate
    return 0
  fi
  mkdir -p "$APT_CACHE_DIR/archives" "$APT_LISTS_DIR"
  DEBIAN_FRONTEND=noninteractive \
    apt-get -y \
      -o Dir::Cache="$APT_CACHE_DIR" \
      -o Dir::Cache::archives="$APT_CACHE_DIR/archives" \
      -o Dir::State="$APT_STATE_DIR" \
      -o Dir::State::lists="$APT_LISTS_DIR" \
      -o Dir::Etc::sourcelist="/etc/apt/sources.list" \
      -o Dir::Etc::sourceparts="/etc/apt/sources.list.d" \
      -o APT::Get::List-Cleanup=0 \
      update
  DEBIAN_FRONTEND=noninteractive \
    apt-get -y \
      -o Dir::Cache="$APT_CACHE_DIR" \
      -o Dir::Cache::archives="$APT_CACHE_DIR/archives" \
      -o Dir::State="$APT_STATE_DIR" \
      -o Dir::State::lists="$APT_LISTS_DIR" \
      -o Dir::Etc::sourcelist="/etc/apt/sources.list" \
      -o Dir::Etc::sourceparts="/etc/apt/sources.list.d" \
      install curl ca-certificates tar gzip logrotate
  rm -rf "$APT_CACHE_DIR" "$APT_STATE_DIR"
}

ensure_downloader() {
  if cmd_exists curl || cmd_exists wget || cmd_exists python3; then
    return 0
  fi
  install_deps
}

ensure_tools() {
  if ! cmd_exists tar || ! cmd_exists gzip || ! cmd_exists logrotate; then
    install_deps
  fi
}

download_file() {
  local url="$1" dest="$2"
  ensure_tmp_dir
  rm -f "$dest"
  if cmd_exists curl; then
    curl -fL --retry 3 --connect-timeout 10 -o "$dest" "$url"
  elif cmd_exists wget; then
    wget -qO "$dest" "$url"
  elif cmd_exists python3; then
    python3 - <<'PY' "$url" "$dest"
import sys
from urllib.request import urlopen

url = sys.argv[1]
dest = sys.argv[2]
with urlopen(url) as resp, open(dest, "wb") as f:
    f.write(resp.read())
PY
  else
    die "缺少下载工具 (curl/wget/python3)。"
  fi
}

ensure_dirs() {
  mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$BACKUP_DIR"
  touch "$LOG_FILE" 2>/dev/null || true
}

setup_logrotate() {
  mkdir -p "$(dirname "$LOGROTATE_FILE")"
  cat > "$LOGROTATE_FILE" <<'EOF'
/var/log/realm/*.log {
  size 4M
  rotate 3
  compress
  delaycompress
  missingok
  notifempty
  copytruncate
  su root root
}
EOF
}

create_default_env() {
  cat > "$ENV_FILE" <<'EOF'
LOG_LEVEL=warn
LOG_OUTPUT=/var/log/realm/realm.log
NO_TCP=false
USE_UDP=true
IPV6_ONLY=false
EOF
}

load_env() {
  LOG_LEVEL="warn"
  LOG_OUTPUT="/var/log/realm/realm.log"
  NO_TCP="false"
  USE_UDP="true"
  IPV6_ONLY="false"
  if [ -f "$ENV_FILE" ]; then
    # shellcheck source=/etc/realm/realm.env
    . "$ENV_FILE"
  fi
}

migrate_endpoints_file() {
  if [ ! -f "$ENDPOINTS_FILE" ]; then
    return 0
  fi
  local first_line fields
  first_line="$(awk -F'|' 'NF>0 && $1 !~ /^#/ {print; exit}' "$ENDPOINTS_FILE")"
  [ -z "$first_line" ] && return 0
  fields="$(printf '%s' "$first_line" | awk -F'|' '{print NF}')"
  if [ "$fields" -eq 6 ]; then
    ensure_tmp_dir
    local tmp="${TMP_DIR}/endpoints.migrate.$$"
    awk -F'|' -v OFS='|' '
      BEGIN{
        print "# 格式: ID|ENABLED|NAME|LISTEN|REMOTE|TYPE|LISTEN_TRANSPORT|REMOTE_TRANSPORT|THROUGH"
        print "# ENABLED: 1启用 0停用"
        print "# TYPE: tcp/udp/tcp+udp"
        print "# 示例:"
        print "# 1|1|demo|0.0.0.0:5000|1.1.1.1:443|tcp+udp|||"
      }
      $1 ~ /^#/ {next}
      NF==0 {next}
      {
        id=$1; listen=$2; remote=$3; lt=$4; rt=$5; through=$6
        print id, 1, "未命名", listen, remote, "tcp+udp", lt, rt, through
      }
    ' "$ENDPOINTS_FILE" > "$tmp"
    mv "$tmp" "$ENDPOINTS_FILE"
  fi
}

ensure_endpoints_file() {
  if [ ! -f "$ENDPOINTS_FILE" ]; then
    cat > "$ENDPOINTS_FILE" <<'EOF'
# 格式: ID|ENABLED|NAME|LISTEN|REMOTE|TYPE|LISTEN_TRANSPORT|REMOTE_TRANSPORT|THROUGH
# ENABLED: 1启用 0停用
# TYPE: tcp/udp/tcp+udp
# 示例:
# 1|1|demo|0.0.0.0:5000|1.1.1.1:443|tcp+udp|||
EOF
  else
    migrate_endpoints_file
  fi
}

toml_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

generate_config() {
  ensure_dirs
  [ -f "$ENV_FILE" ] || create_default_env
  load_env
  ensure_endpoints_file

  local no_tcp use_udp ipv6_only
  no_tcp="$(printf '%s' "$NO_TCP" | tr '[:upper:]' '[:lower:]')"
  use_udp="$(printf '%s' "$USE_UDP" | tr '[:upper:]' '[:lower:]')"
  ipv6_only="$(printf '%s' "$IPV6_ONLY" | tr '[:upper:]' '[:lower:]')"

  cat > "$CONFIG_FILE" <<EOF
[log]
level = "$(toml_escape "$LOG_LEVEL")"
output = "$(toml_escape "$LOG_OUTPUT")"

[network]
no_tcp = ${no_tcp}
use_udp = ${use_udp}
ipv6_only = ${ipv6_only}
EOF

  while IFS='|' read -r id enabled name listen remote type lt rt through; do
    [ -z "${id:-}" ] && continue
    case "$id" in
      \#*) continue ;;
    esac
    enabled="${enabled:-1}"
    [ "$enabled" = "0" ] && continue
    if [ -z "${listen:-}" ] || [ -z "${remote:-}" ]; then
      continue
    fi
    [ -z "${name:-}" ] && name="未命名"
    [ -z "${type:-}" ] && type="tcp+udp"
    cat >> "$CONFIG_FILE" <<EOF

[[endpoints]]
name = "$(toml_escape "$name")"
listen = "$(toml_escape "$listen")"
remote = "$(toml_escape "$remote")"
type = "$(toml_escape "$type")"
EOF
    if [ -n "${lt:-}" ]; then
      printf 'listen_transport = "%s"\n' "$(toml_escape "$lt")" >> "$CONFIG_FILE"
    fi
    if [ -n "${rt:-}" ]; then
      printf 'remote_transport = "%s"\n' "$(toml_escape "$rt")" >> "$CONFIG_FILE"
    fi
    if [ -n "${through:-}" ]; then
      printf 'through = "%s"\n' "$(toml_escape "$through")" >> "$CONFIG_FILE"
    fi
  done < "$ENDPOINTS_FILE"

  msg "${C_GREEN}配置已生成: ${CONFIG_FILE}${C_RESET}"
}

service_is_active() {
  if systemd_available; then
    if systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "realm.service"; then
      if systemctl is-active realm >/dev/null 2>&1; then
        return 0
      fi
      if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
        return 0
      fi
      process_running
    elif openrc_available; then
      if rc-service realm status >/dev/null 2>&1; then
        return 0
      fi
      if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
        return 0
      fi
      process_running
    else
      if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
        return 0
      fi
      process_running
    fi
  elif openrc_available; then
    if rc-service realm status >/dev/null 2>&1; then
      return 0
    fi
    if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
      return 0
    fi
    process_running
  else
    if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
      return 0
    fi
    process_running
  fi
}

apply_changes() {
  generate_config
  if service_is_active; then
    restart_service
  else
    msg "${C_YELLOW}服务未运行，仅更新配置。${C_RESET}"
  fi
}

install_realm() {
  need_root
  check_os
  ensure_downloader
  ensure_tools
  ensure_dirs
  ensure_endpoints_file
  [ -f "$ENV_FILE" ] || create_default_env

  local asset url
  asset="$(get_arch_asset)"
  url="https://github.com/zhboner/realm/releases/latest/download/${asset}"

  ensure_tmp_dir
  rm -rf "$TMP_EXTRACT"
  mkdir -p "$TMP_EXTRACT"

  msg "下载 Realm: ${asset}"
  download_file "$url" "$TMP_TARBALL"

  tar -xzf "$TMP_TARBALL" -C "$TMP_EXTRACT"

  local bin_path
  bin_path="$(find "$TMP_EXTRACT" -maxdepth 2 -type f -name realm | head -n 1 || true)"
  if [ -z "$bin_path" ]; then
    die "解压失败，未找到 realm 可执行文件。"
  fi
  install -m 755 "$bin_path" "$REALM_BIN"

  generate_config
  setup_logrotate
  rm -rf "$TMP_EXTRACT" "$TMP_TARBALL"

  if "$REALM_BIN" --version >/dev/null 2>&1; then
    msg "${C_GREEN}安装完成: $("$REALM_BIN" --version)${C_RESET}"
  else
    msg "${C_GREEN}安装完成。${C_RESET}"
  fi
  start_service
}

write_service() {
  if ! systemd_available; then
    ui "当前系统未检测到 systemd，将使用前台/后台方式运行。"
    return 0
  fi
  if [ ! -x "$REALM_BIN" ]; then
    ui "Realm 未安装，仍将写入服务文件。"
  fi
  cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=Realm Port Forwarding Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/realm -c /etc/realm/config.toml
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  msg "${C_GREEN}已写入 systemd 服务文件。${C_RESET}"
}

write_openrc_service() {
  if ! openrc_available; then
    ui "当前系统未检测到 OpenRC，将使用前台/后台方式运行。"
    return 0
  fi
  cat > "$OPENRC_SERVICE" <<'EOF'
#!/sbin/openrc-run
name="realm"
description="Realm Port Forwarding Service"
command="/usr/local/bin/realm"
command_args="-c /etc/realm/config.toml"
command_background="yes"
pidfile="/run/realm.pid"

depend() {
  need net
}
EOF
  chmod +x "$OPENRC_SERVICE"
  msg "${C_GREEN}已写入 OpenRC 服务文件。${C_RESET}"
}

start_service() {
  ensure_dirs
  if systemd_available; then
    if [ ! -f "$CONFIG_FILE" ]; then
      generate_config
    fi
    write_service
    setup_logrotate
    systemctl enable --now realm
  elif openrc_available; then
    if [ ! -x "$REALM_BIN" ]; then
      die "Realm 未安装。"
    fi
    if [ ! -f "$CONFIG_FILE" ]; then
      generate_config
    fi
    write_openrc_service
    setup_logrotate
    rc-update add realm default >/dev/null 2>&1 || true
    rc-service realm start
  else
    if [ ! -x "$REALM_BIN" ]; then
      die "Realm 未安装。"
    fi
    if [ ! -f "$CONFIG_FILE" ]; then
      generate_config
    fi
    nohup "$REALM_BIN" -c "$CONFIG_FILE" >/dev/null 2>&1 &
    echo $! > "$PID_FILE"
    msg "${C_GREEN}已后台启动 (PID: $(cat "$PID_FILE")).${C_RESET}"
  fi
}

stop_service() {
  if systemd_available; then
    systemctl stop realm || true
  elif openrc_available; then
    rc-service realm stop >/dev/null 2>&1 || true
  else
    if [ -f "$PID_FILE" ]; then
      kill "$(cat "$PID_FILE")" >/dev/null 2>&1 || true
      rm -f "$PID_FILE"
    fi
  fi
}

restart_service() {
  if systemd_available; then
    systemctl restart realm
  elif openrc_available; then
    rc-service realm restart
  else
    stop_service
    start_service
  fi
}

status_service() {
  if systemd_available; then
    systemctl status realm --no-pager -l || true
  elif openrc_available; then
    rc-service realm status || true
  else
    if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
      msg "Realm 运行中 (PID: $(cat "$PID_FILE"))."
    else
      msg "Realm 未运行。"
    fi
  fi
}

next_endpoint_id() {
  local next
  next="$(awk -F'|' 'BEGIN{max=0} $1 ~ /^[0-9]+$/ {if($1>max) max=$1} END{print max+1}' "$ENDPOINTS_FILE" 2>/dev/null || true)"
  if [ -z "$next" ] || ! echo "$next" | grep -qE '^[0-9]+$'; then
    next="1"
  fi
  echo "$next"
}

normalize_enabled() {
  case "${1:-}" in
    0|false|no|off) echo "0" ;;
    *) echo "1" ;;
  esac
}

listen_mode() {
  case "$1" in
    \[*\]*) echo "v6" ;;
    *) echo "v4" ;;
  esac
}

extract_port() {
  local listen="$1"
  if echo "$listen" | grep -qE '^\[.*\]:[0-9]+$'; then
    echo "${listen##*:}"
  elif echo "$listen" | grep -qE ':[0-9]+$'; then
    echo "${listen##*:}"
  else
    echo ""
  fi
}

port_in_use_system() {
  local port="$1"
  [ -z "$port" ] && return 1
  if cmd_exists ss; then
    ss -H -lntu 2>/dev/null | awk '{print $4}' | awk -v p=":${port}" '$0 ~ (p"$") {found=1} END{exit found?0:1}'
    return $?
  fi
  if cmd_exists netstat; then
    netstat -lntu 2>/dev/null | awk '{print $4}' | awk -v p=":${port}" '$0 ~ (p"$") {found=1} END{exit found?0:1}'
    return $?
  fi
  return 1
}

listen_in_config() {
  local listen="$1" exclude_id="${2:-}"
  awk -F'|' -v l="$listen" -v ex="$exclude_id" '
    $1 ~ /^[0-9]+$/ {
      if ($1!=ex && $4==l) {found=1}
    }
    END{exit !found}
  ' "$ENDPOINTS_FILE"
}

port_conflict_in_rules() {
  local port="$1" mode="$2" exclude_id="${3:-}"
  [ -z "$port" ] && return 1
  awk -F'|' -v p="$port" -v m="$mode" -v ex="$exclude_id" '
    $1 ~ /^[0-9]+$/ {
      if ($1==ex) next
      listen=$4
      if (listen ~ /^\[/) lm="v6"; else lm="v4"
      sub(/^.*:/,"",listen)
      if (lm==m && listen==p) {found=1}
    }
    END{exit !found}
  ' "$ENDPOINTS_FILE"
}

warn_port_conflict() {
  local listen="$1" exclude_id="${2:-}"
  local port mode ans
  mode="$(listen_mode "$listen")"
  port="$(extract_port "$listen")"
  if listen_in_config "$listen" "$exclude_id"; then
    read -r -p "监听地址已存在，仍继续？[y/N]: " ans
    case "$ans" in y|Y) ;; *) return 1 ;; esac
  fi
  if [ -n "$port" ] && port_conflict_in_rules "$port" "$mode" "$exclude_id"; then
    read -r -p "同协议端口可能冲突，仍继续？[y/N]: " ans
    case "$ans" in y|Y) ;; *) return 1 ;; esac
  fi
  if [ -n "$port" ] && port_in_use_system "$port"; then
    read -r -p "系统检测到端口占用，仍继续？[y/N]: " ans
    case "$ans" in y|Y) ;; *) return 1 ;; esac
  fi
  return 0
}

prompt_type() {
  local t
  while true; do
    read -r -p "转发类型 [tcp/udp/tcp+udp] (默认 tcp+udp): " t
    t="${t:-tcp+udp}"
    case "$t" in
      tcp|udp|tcp+udp) echo "$t"; return 0 ;;
      *) ui "类型无效。" ;;
    esac
  done
}

list_endpoints() {
  ensure_endpoints_file
  if ! grep -qE '^[0-9]+\|' "$ENDPOINTS_FILE"; then
    msg "暂无转发规则。"
    return 0
  fi
  printf "%-4s %-6s %-12s %-22s %-22s %-10s %-10s %-10s %-12s\n" "ID" "启用" "名称" "LISTEN" "REMOTE" "TYPE" "L-TPT" "R-TPT" "THROUGH"
  awk -F'|' 'BEGIN{OFS=" ";}
    $1 ~ /^[0-9]+$/ {
      en=($2==1?"ON":"OFF")
      name=$3
      listen=$4
      remote=$5
      type=$6
      lt=$7
      rt=$8
      through=$9
      printf "%-4s %-6s %-12s %-22s %-22s %-10s %-10s %-10s %-12s\n", $1, en, name, listen, remote, type, lt, rt, through
    }' "$ENDPOINTS_FILE"
}

prompt_nonempty() {
  local prompt="$1" val
  while true; do
    read -r -p "$prompt" val
    if [ -n "$val" ]; then
      echo "$val"
      return 0
    fi
    ui "不能为空。"
  done
}

prompt_name() {
  local val
  while true; do
    read -r -p "规则名称: " val
    if [ -z "$val" ]; then
      ui "不能为空。"
      continue
    fi
    if echo "$val" | grep -q '|'; then
      ui "名称不能包含 | 字符。"
      continue
    fi
    echo "$val"
    return 0
  done
}

add_endpoint() {
  ensure_endpoints_file
  local name listen remote type lt rt through id enabled
  name="$(prompt_name)"
  listen="$(prompt_nonempty '监听地址 (如 0.0.0.0:5000 或 [::]:5000): ')"
  if ! warn_port_conflict "$listen" ""; then
    ui "已取消添加。"
    return 1
  fi
  remote="$(prompt_nonempty '转发地址 (如 1.1.1.1:443 或 example.com:443): ')"
  type="$(prompt_type)"
  read -r -p "监听传输 (listen_transport，回车跳过): " lt
  read -r -p "远端传输 (remote_transport，回车跳过): " rt
  read -r -p "through (回车跳过): " through
  read -r -p "是否启用该规则？[Y/n]: " enabled
  case "$enabled" in
    n|N) enabled="0" ;;
    *) enabled="1" ;;
  esac
  id="$(next_endpoint_id)"
  echo "${id}|${enabled}|${name}|${listen}|${remote}|${type}|${lt}|${rt}|${through}" >> "$ENDPOINTS_FILE"
  apply_changes
  msg "${C_GREEN}已添加规则 ID=${id}.${C_RESET}"
}

search_endpoints() {
  ensure_endpoints_file
  local key
  read -r -p "输入关键字 (ID/监听/目标任意字段): " key
  if [ -z "$key" ]; then
    ui "关键字为空。"
    return 1
  fi
  awk -F'|' -v kw="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')" '
    $1 ~ /^[0-9]+$/ {
      line=tolower($0)
      if (index(line, kw)) {
        en=($2==1?"ON":"OFF")
        printf "ID=%s  EN=%s  NAME=%s  LISTEN=%s  REMOTE=%s  TYPE=%s  L-TPT=%s  R-TPT=%s  THROUGH=%s\n", $1, en, $3, $4, $5, $6, $7, $8, $9
      }
    }' "$ENDPOINTS_FILE" || true
}

update_endpoint() {
  ensure_endpoints_file
  ensure_tmp_dir
  list_endpoints
  read -r -p "输入要修改的 ID: " id
  if ! awk -F'|' -v id="$id" '$1==id {found=1} END{exit !found}' "$ENDPOINTS_FILE"; then
    ui "未找到 ID=${id}。"
    return 1
  fi

  local old enabled name listen remote type lt rt through
  old="$(awk -F'|' -v id="$id" '$1==id {print; exit}' "$ENDPOINTS_FILE")"
  IFS='|' read -r _old_id enabled name listen remote type lt rt through <<< "$old"

  local new_enabled new_name new_listen new_remote new_type new_lt new_rt new_through
  read -r -p "启用状态(1/0) [${enabled}]: " new_enabled
  read -r -p "规则名称 [${name}]: " new_name
  read -r -p "监听地址 [${listen}]: " new_listen
  read -r -p "转发地址 [${remote}]: " new_remote
  read -r -p "转发类型(tcp/udp/tcp+udp) [${type}]: " new_type
  read -r -p "监听传输 [${lt}]: " new_lt
  read -r -p "远端传输 [${rt}]: " new_rt
  read -r -p "through [${through}]: " new_through

  enabled="$(normalize_enabled "${new_enabled:-$enabled}")"
  if [ -n "${new_name:-}" ] && echo "$new_name" | grep -q '|'; then
    ui "名称不能包含 | 字符，保留原值。"
    new_name=""
  fi
  name="${new_name:-$name}"
  listen="${new_listen:-$listen}"
  remote="${new_remote:-$remote}"
  type="${new_type:-$type}"
  lt="${new_lt:-$lt}"
  rt="${new_rt:-$rt}"
  through="${new_through:-$through}"

  if ! warn_port_conflict "$listen" "$id"; then
    ui "已取消修改。"
    return 1
  fi

  local tmp="${TMP_DIR}/endpoints.tmp"
  awk -F'|' -v OFS='|' -v id="$id" -v en="$enabled" -v n="$name" -v l="$listen" -v r="$remote" -v t="$type" -v lt="$lt" -v rt="$rt" -v th="$through" '
    $1==id {print id, en, n, l, r, t, lt, rt, th; next}
    {print}
  ' "$ENDPOINTS_FILE" > "$tmp"
  mv "$tmp" "$ENDPOINTS_FILE"
  apply_changes
  msg "${C_GREEN}已更新规则 ID=${id}.${C_RESET}"
}

delete_endpoint() {
  ensure_endpoints_file
  ensure_tmp_dir
  list_endpoints
  read -r -p "输入要删除的 ID: " id
  if ! awk -F'|' -v id="$id" '$1==id {found=1} END{exit !found}' "$ENDPOINTS_FILE"; then
    ui "未找到 ID=${id}。"
    return 1
  fi
  local tmp="${TMP_DIR}/endpoints.tmp"
  awk -F'|' -v id="$id" '$1!=id {print}' "$ENDPOINTS_FILE" > "$tmp"
  mv "$tmp" "$ENDPOINTS_FILE"
  apply_changes
  msg "${C_GREEN}已删除规则 ID=${id}.${C_RESET}"
}

toggle_endpoint() {
  ensure_endpoints_file
  ensure_tmp_dir
  list_endpoints
  read -r -p "输入要启停的 ID: " id
  if ! awk -F'|' -v id="$id" '$1==id {found=1} END{exit !found}' "$ENDPOINTS_FILE"; then
    ui "未找到 ID=${id}。"
    return 1
  fi
  local tmp="${TMP_DIR}/endpoints.tmp"
  awk -F'|' -v OFS='|' -v id="$id" '
    $1==id {
      if ($2==1) {$2=0} else {$2=1}
    }
    {print}
  ' "$ENDPOINTS_FILE" > "$tmp"
  mv "$tmp" "$ENDPOINTS_FILE"
  apply_changes
  msg "${C_GREEN}已切换规则 ID=${id} 启停状态。${C_RESET}"
}

clear_endpoints() {
  ensure_endpoints_file
  read -r -p "确认清空全部规则？[y/N]: " ans
  case "$ans" in
    y|Y) ;;
    *) msg "已取消。"; return 0 ;;
  esac
  cat > "$ENDPOINTS_FILE" <<'EOF'
# 格式: ID|ENABLED|NAME|LISTEN|REMOTE|TYPE|LISTEN_TRANSPORT|REMOTE_TRANSPORT|THROUGH
# ENABLED: 1启用 0停用
# TYPE: tcp/udp/tcp+udp
# 示例:
# 1|1|demo|0.0.0.0:5000|1.1.1.1:443|tcp+udp|||
EOF
  apply_changes
  msg "${C_GREEN}已清空全部规则。${C_RESET}"
}

edit_globals() {
  load_env
  read -r -p "日志级别 [${LOG_LEVEL}]: " new_level
  read -r -p "日志输出 [${LOG_OUTPUT}]: " new_output
  read -r -p "禁用TCP (true/false) [${NO_TCP}]: " new_no_tcp
  read -r -p "启用UDP (true/false) [${USE_UDP}]: " new_use_udp
  read -r -p "仅IPv6 (true/false) [${IPV6_ONLY}]: " new_ipv6_only

  LOG_LEVEL="${new_level:-$LOG_LEVEL}"
  LOG_OUTPUT="${new_output:-$LOG_OUTPUT}"
  NO_TCP="${new_no_tcp:-$NO_TCP}"
  USE_UDP="${new_use_udp:-$USE_UDP}"
  IPV6_ONLY="${new_ipv6_only:-$IPV6_ONLY}"

  cat > "$ENV_FILE" <<EOF
LOG_LEVEL=${LOG_LEVEL}
LOG_OUTPUT=${LOG_OUTPUT}
NO_TCP=${NO_TCP}
USE_UDP=${USE_UDP}
IPV6_ONLY=${IPV6_ONLY}
EOF
  apply_changes
  msg "${C_GREEN}已更新全局配置。${C_RESET}"
}

export_rules() {
  ensure_endpoints_file
  local out
  read -r -p "导出文件路径 [默认 ${BACKUP_DIR}/realm-rules.backup.db]: " out
  out="${out:-${BACKUP_DIR}/realm-rules.backup.db}"
  mkdir -p "$(dirname "$out")"
  cp "$ENDPOINTS_FILE" "$out"
  msg "${C_GREEN}导出完成: ${out}${C_RESET}"
}

import_rules() {
  ensure_endpoints_file
  ensure_tmp_dir
  local in mode
  read -r -p "导入文件路径 [默认 ${BACKUP_DIR}/realm-rules.backup.db]: " in
  in="${in:-${BACKUP_DIR}/realm-rules.backup.db}"
  if [ ! -f "$in" ]; then
    ui "导入文件不存在: $in"
    return 1
  fi
  msg "导入模式："
  msg "1) 覆盖（清空现有规则后导入）"
  msg "2) 追加（保留现有规则）"
  read -r -p "请选择 [1-2]: " mode
  case "$mode" in
    1)
      cp "$in" "$ENDPOINTS_FILE"
      migrate_endpoints_file
      ;;
    2)
      local next_id
      next_id="$(next_endpoint_id)"
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in \#*) continue ;; esac
        local nf
        nf="$(printf '%s' "$line" | awk -F'|' '{print NF}')"
        if [ "$nf" -eq 6 ]; then
          local id listen remote lt rt through
          IFS='|' read -r id listen remote lt rt through <<< "$line"
          echo "${next_id}|1|未命名|${listen}|${remote}|tcp+udp|${lt}|${rt}|${through}" >> "$ENDPOINTS_FILE"
        else
          local id enabled name listen remote type lt rt through
          IFS='|' read -r id enabled name listen remote type lt rt through <<< "$line"
          enabled="$(normalize_enabled "${enabled:-1}")"
          [ -z "$name" ] && name="未命名"
          [ -z "$type" ] && type="tcp+udp"
          echo "${next_id}|${enabled}|${name}|${listen}|${remote}|${type}|${lt}|${rt}|${through}" >> "$ENDPOINTS_FILE"
        fi
        next_id=$((next_id+1))
      done < "$in"
      ;;
    *) ui "无效选项。"; return 1 ;;
  esac
  apply_changes
  msg "${C_GREEN}导入完成。${C_RESET}"
}

has_cron() {
  cmd_exists crontab || cmd_exists cron || cmd_exists crond
}

cron_target_file() {
  if is_alpine; then
    if cmd_exists crontab; then
      echo "crontab"
      return 0
    fi
    if [ -d /etc/crontabs ]; then
      echo "/etc/crontabs/root"
      return 0
    fi
  fi
  echo "$CRON_FILE"
}

cron_is_running() {
  if cmd_exists pgrep; then
    pgrep -x crond >/dev/null 2>&1
    return $?
  fi
  if cmd_exists pidof; then
    pidof crond >/dev/null 2>&1
    return $?
  fi
  return 1
}

ensure_cron_running() {
  if is_alpine; then
    if openrc_available; then
      rc-update add crond default >/dev/null 2>&1 || true
      rc-service crond start >/dev/null 2>&1 || true
    else
      if cmd_exists crond && ! cron_is_running; then
        crond -b >/dev/null 2>&1 || crond >/dev/null 2>&1 || true
      fi
    fi
    return 0
  fi
  if systemd_available; then
    systemctl enable --now cron >/dev/null 2>&1 || true
  fi
}

install_cron() {
  msg "系统未检测到 cron，尝试安装..."
  ensure_tmp_dir
  if is_alpine; then
    cmd_exists apk || die "未找到 apk，无法安装 cron。"
    apk add --no-cache cronie
    ensure_cron_running
    return 0
  fi
  mkdir -p "$APT_CACHE_DIR/archives" "$APT_LISTS_DIR"
  DEBIAN_FRONTEND=noninteractive \
    apt-get -y \
      -o Dir::Cache="$APT_CACHE_DIR" \
      -o Dir::Cache::archives="$APT_CACHE_DIR/archives" \
      -o Dir::State="$APT_STATE_DIR" \
      -o Dir::State::lists="$APT_LISTS_DIR" \
      -o Dir::Etc::sourcelist="/etc/apt/sources.list" \
      -o Dir::Etc::sourceparts="/etc/apt/sources.list.d" \
      -o APT::Get::List-Cleanup=0 \
      update
  DEBIAN_FRONTEND=noninteractive \
    apt-get -y \
      -o Dir::Cache="$APT_CACHE_DIR" \
      -o Dir::Cache::archives="$APT_CACHE_DIR/archives" \
      -o Dir::State="$APT_STATE_DIR" \
      -o Dir::State::lists="$APT_LISTS_DIR" \
      -o Dir::Etc::sourcelist="/etc/apt/sources.list" \
      -o Dir::Etc::sourceparts="/etc/apt/sources.list.d" \
      install cron
  rm -rf "$APT_CACHE_DIR" "$APT_STATE_DIR"
  ensure_cron_running
}

ensure_cron_ready() {
  if has_cron; then
    ensure_cron_running
    return 0
  fi
  install_cron
  ensure_cron_running
  has_cron || { ui "cron 不可用，无法创建定时任务。"; return 1; }
  return 0
}

write_export_helper() {
  cat > "$EXPORT_HELPER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ENDPOINTS_FILE="/etc/realm/endpoints.db"
BACKUP_DIR="/etc/realm/backups"
BACKUP_CONF="/etc/realm/backup.conf"
mkdir -p "$BACKUP_DIR"
ts="$(date +%F_%H%M%S)"
out="$BACKUP_DIR/realm-rules.${ts}.db"
cp "$ENDPOINTS_FILE" "$out"
if [ -f "$BACKUP_CONF" ]; then
  # shellcheck source=/etc/realm/backup.conf
  . "$BACKUP_CONF"
fi
if [ -n "${REMOTE_BACKUP_URL:-}" ]; then
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -T "$out" "$REMOTE_BACKUP_URL"
  fi
fi
EOF
  chmod +x "$EXPORT_HELPER"
}

setup_export_cron() {
  ensure_cron_ready || return 1
  write_export_helper
  msg "定时类型："
  msg "1) 每天"
  msg "2) 每周"
  read -r -p "请选择 [1-2]: " t
  local dow="*"
  if [ "$t" = "2" ]; then
    read -r -p "周几 [1=周一 .. 7=周日]: " wd
    case "$wd" in
      1) dow="1" ;;
      2) dow="2" ;;
      3) dow="3" ;;
      4) dow="4" ;;
      5) dow="5" ;;
      6) dow="6" ;;
      7) dow="0" ;;
      *) ui "周几输入无效。"; return 1 ;;
    esac
  elif [ "$t" != "1" ]; then
    ui "无效选项。"
    return 1
  fi
  read -r -p "小时 [0-23]: " hh
  read -r -p "分钟 [0-59]: " mm
  hh="${hh:-0}"
  mm="${mm:-0}"
  local cron_file
  cron_file="$(cron_target_file)"
  if [ "$cron_file" = "crontab" ]; then
    ensure_tmp_dir
    local tmp="${TMP_DIR}/crontab.root"
    local cur
    cur="$(crontab -l 2>/dev/null || true)"
    printf '%s\n' "$cur" | awk -v tag="$CRON_TAG" -v cmd="$EXPORT_HELPER" '
      $0 ~ tag {next}
      $0 ~ cmd {next}
      {print}
    ' > "$tmp"
    {
      printf "%s\n" "$CRON_TAG"
      printf "%s %s * * %s %s\n" "$mm" "$hh" "$dow" "$EXPORT_HELPER"
    } >> "$tmp"
    crontab "$tmp"
  elif [ "$cron_file" = "/etc/crontabs/root" ]; then
    ensure_tmp_dir
    local tmp="${TMP_DIR}/crontab.root"
    if [ -f "$cron_file" ]; then
      awk -v tag="$CRON_TAG" -v cmd="$EXPORT_HELPER" '
        $0 ~ tag {next}
        $0 ~ cmd {next}
        {print}
      ' "$cron_file" > "$tmp"
    else
      : > "$tmp"
    fi
    {
      printf "%s\n" "$CRON_TAG"
      printf "%s %s * * %s %s\n" "$mm" "$hh" "$dow" "$EXPORT_HELPER"
    } >> "$tmp"
    mv "$tmp" "$cron_file"
    chmod 600 "$cron_file" 2>/dev/null || true
    chown root:root "$cron_file" 2>/dev/null || true
  else
    cat > "$cron_file" <<EOF
# Realm rules auto backup
$mm $hh * * $dow root $EXPORT_HELPER
EOF
  fi
  msg "${C_GREEN}定时备份已设置: ${cron_file}${C_RESET}"
}

remove_export_cron() {
  local cron_file
  cron_file="$(cron_target_file)"
  if [ "$cron_file" = "crontab" ]; then
    ensure_tmp_dir
    local tmp="${TMP_DIR}/crontab.root"
    local cur
    cur="$(crontab -l 2>/dev/null || true)"
    printf '%s\n' "$cur" | awk -v tag="$CRON_TAG" -v cmd="$EXPORT_HELPER" '
      $0 ~ tag {next}
      $0 ~ cmd {next}
      {print}
    ' > "$tmp"
    crontab "$tmp"
  elif [ "$cron_file" = "/etc/crontabs/root" ]; then
    if [ -f "$cron_file" ]; then
      ensure_tmp_dir
      local tmp="${TMP_DIR}/crontab.root"
      awk -v tag="$CRON_TAG" -v cmd="$EXPORT_HELPER" '
        $0 ~ tag {next}
        $0 ~ cmd {next}
        {print}
      ' "$cron_file" > "$tmp"
      mv "$tmp" "$cron_file"
      chmod 600 "$cron_file" 2>/dev/null || true
      chown root:root "$cron_file" 2>/dev/null || true
    fi
  else
    rm -f "$cron_file"
  fi
  msg "${C_GREEN}已移除定时备份。${C_RESET}"
}

configure_remote_backup() {
  read -r -p "远程备份 URL (支持 ftp/sftp，留空禁用): " url
  if [ -z "$url" ]; then
    rm -f "$BACKUP_CONF"
    msg "${C_GREEN}已禁用远程备份。${C_RESET}"
    return 0
  fi
  printf 'REMOTE_BACKUP_URL=%q\n' "$url" > "$BACKUP_CONF"
  msg "${C_GREEN}已保存远程备份配置。${C_RESET}"
}

view_logs() {
  if [ ! -f "$LOG_FILE" ]; then
    ui "日志文件不存在: $LOG_FILE"
    return 1
  fi
  tail -n 200 "$LOG_FILE"
}

show_config() {
  if [ ! -f "$CONFIG_FILE" ]; then
    generate_config
  fi
  msg "当前配置文件：$CONFIG_FILE"
  msg "----------------------------------------"
  sed -n '1,200p' "$CONFIG_FILE"
}

uninstall_realm() {
  need_root
  read -r -p "确认卸载 Realm 并删除配置？[y/N]: " ans
  case "$ans" in
    y|Y) ;;
    *) msg "已取消。"; return 0 ;;
  esac
  stop_service || true
  if systemd_available; then
    systemctl disable realm >/dev/null 2>&1 || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload >/dev/null 2>&1 || true
  elif openrc_available; then
    rc-service realm stop >/dev/null 2>&1 || true
    rc-update del realm default >/dev/null 2>&1 || true
    rm -f "$OPENRC_SERVICE"
  fi
  rm -f "$REALM_BIN"
  rm -f "$LOGROTATE_FILE" "$EXPORT_HELPER" "$CRON_FILE" "$BACKUP_CONF"
  rm -rf "$CONFIG_DIR" "$LOG_DIR" "$BACKUP_DIR" "$PID_FILE"
  msg "${C_GREEN}已卸载。${C_RESET}"
}

menu() {
  while true; do
    clear_screen
    menu_sep
    menu_title "Realm 一键管理"
    msg "状态: 安装 $(install_status) | 运行 $(runtime_status)"
    menu_sep
    menu_item 1 "安装/更新 Realm"
    menu_item 2 "添加端口转发"
    menu_item 3 "列出端口转发"
    menu_item 4 "查询端口转发"
    menu_item 5 "修改端口转发"
    menu_item 6 "启停端口转发"
    menu_item 7 "删除端口转发"
    menu_item 8 "清空全部规则"
    menu_item 9 "导出规则"
    menu_item 10 "导入规则"
    menu_item 11 "设置定时备份"
    menu_item 12 "关闭定时备份"
    menu_item 13 "远程备份设置(FTP/SFTP)"
    menu_item 14 "编辑全局配置"
    menu_item 15 "生成/更新配置文件(不重启)"
    menu_item 16 "查看配置文件"
    menu_item 17 "查看日志"
    menu_item 18 "启动服务(自动注册)"
    menu_item 19 "停止服务"
    menu_item 20 "重启服务"
    menu_item 21 "服务状态"
    menu_item 22 "卸载 Realm(停止并删除服务)"
    menu_item 0 "退出"
    menu_sep
    read -r -p "请选择: " choice
    case "$choice" in
      1) run_and_pause install_realm ;;
      2) run_and_pause add_endpoint ;;
      3) run_and_pause list_endpoints ;;
      4) run_and_pause search_endpoints ;;
      5) run_and_pause update_endpoint ;;
      6) run_and_pause toggle_endpoint ;;
      7) run_and_pause delete_endpoint ;;
      8) run_and_pause clear_endpoints ;;
      9) run_and_pause export_rules ;;
      10) run_and_pause import_rules ;;
      11) run_and_pause setup_export_cron ;;
      12) run_and_pause remove_export_cron ;;
      13) run_and_pause configure_remote_backup ;;
      14) run_and_pause edit_globals ;;
      15) run_and_pause generate_config ;;
      16) run_and_pause show_config ;;
      17) run_and_pause view_logs ;;
      18) run_and_pause start_service ;;
      19) run_and_pause stop_service ;;
      20) run_and_pause restart_service ;;
      21) run_and_pause status_service ;;
      22) run_and_pause uninstall_realm ;;
      0) exit 0 ;;
      *) ui "无效选择。"; pause_return ;;
    esac
  done
}

main() {
  ensure_bash
  init_colors
  check_os
  menu
}

main "$@"
