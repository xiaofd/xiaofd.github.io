#!/usr/bin/env bash
# 适用系统: Debian 11~13 / Ubuntu 20.04~24.04 / Alpine（Alpine 需先安装 bash: apk add bash）
# 适用架构: x86/x64/arm64/arm32
# 适用环境: 物理机 / KVM / LXC / Docker（容器场景会使用保守的加速参数）
# 功能概述: Xray Reality 一键部署/管理，支持多入口与多出口
# DNS 说明: 内置 DNS（DoH），默认优先 IPv4；IPv6-only 会自动切换；强制参与解析
set -euo pipefail

XRAY_BIN="/usr/local/bin/xray"
CONFIG_DIR="/etc/xray"
MANAGER_CONF="${CONFIG_DIR}/manager.conf"
INBOUNDS_FILE="${CONFIG_DIR}/inbounds.list"
OUTBOUNDS_DIR="${CONFIG_DIR}/outbounds.d"
SERVICE_FILE="/etc/systemd/system/xray.service"
LOGROTATE_FILE="/etc/logrotate.d/xray"
PID_FILE="/run/xray.pid"
OPENRC_SERVICE="/etc/init.d/xray"
TMP_DIR="/tmp/xray-onekey"
XRAY_ZIP="${TMP_DIR}/xray.zip"
XRAY_UNPACK_DIR="${TMP_DIR}/xray_unpack"
WGCF_BIN="${TMP_DIR}/wgcf"
WGCF_DST="/usr/local/bin/wgcf"
WGCF_DIR="${TMP_DIR}/wgcf_work"
DEFAULT_SNI="www.apple.com"

C_RESET=""
C_BOLD=""
C_DIM=""
C_RED=""
C_GREEN=""
C_YELLOW=""
C_BLUE=""
C_CYAN=""
OS_VERSION=""
ARCH_LABEL=""
OS_ID=""
OS_NAME=""

msg() { printf '%s\n' "$*"; }
ui() { printf '%s\n' "$*" >&2; }
err() { printf '%s\n' "${C_RED}错误: $*${C_RESET}" >&2; }
die() { err "$*"; exit 1; }

cmd_exists() { command -v "$1" >/dev/null 2>&1; }
systemd_available() { cmd_exists systemctl && [ -d /run/systemd/system ]; }
openrc_available() { cmd_exists rc-service && [ -d /etc/init.d ]; }
ipv6_only() {
  if cmd_exists ip; then
    if ip -4 addr show scope global 2>/dev/null | grep -q "inet "; then
      return 1
    fi
    if ip -6 addr show scope global 2>/dev/null | grep -q "inet6 "; then
      return 0
    fi
  fi
  return 1
}

ensure_bash() {
  if [ -z "${BASH_VERSION:-}" ]; then
    err "请使用 bash 运行脚本 (bash $0)。"
    exit 1
  fi
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
menu_item() { msg "  ${C_YELLOW}$1)${C_RESET} $2"; }

check_os() {
  if [ ! -r /etc/os-release ]; then
    die "无法识别系统版本，仅支持 Debian 11~13/Ubuntu 20.04~24.04/Alpine。"
  fi
  # shellcheck source=/etc/os-release
  . /etc/os-release
  OS_ID="${ID:-}"
  if [ "$OS_ID" = "alpine" ]; then
    OS_NAME="Alpine"
    OS_VERSION="${VERSION_ID:-unknown}"
    return 0
  fi
  if [ "$OS_ID" != "debian" ] && [ "$OS_ID" != "ubuntu" ]; then
    die "仅支持 Debian 11~13/Ubuntu 20.04~24.04/Alpine。"
  fi
  local major
  major="$(echo "${VERSION_ID:-}" | awk -F. '{print $1}')"
  if ! echo "$major" | grep -qE '^[0-9]+$'; then
    if [ "$OS_ID" = "ubuntu" ]; then
      die "无法识别 Ubuntu 版本，仅支持 Ubuntu 20.04~24.04。"
    fi
    die "无法识别 Debian 版本，仅支持 Debian 11~13。"
  fi
  if [ "$OS_ID" = "ubuntu" ]; then
    if [ "$major" -lt 20 ] || [ "$major" -gt 24 ]; then
      die "仅支持 Ubuntu 20.04~24.04 (当前: ${VERSION_ID:-unknown})。"
    fi
    OS_NAME="Ubuntu"
    OS_VERSION="${VERSION_ID:-20.04-24.04}"
  else
    if [ "$major" -lt 11 ] || [ "$major" -gt 13 ]; then
      die "仅支持 Debian 11~13 (当前: ${VERSION_ID:-unknown})。"
    fi
    OS_NAME="Debian"
    OS_VERSION="${VERSION_ID:-11-13}"
  fi
}

is_alpine() {
  [ "${OS_ID:-}" = "alpine" ]
}

get_arch_label() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x64" ;;
    i386|i486|i586|i686|x86) echo "x86" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7|armhf|arm) echo "arm32" ;;
    *) echo "$(uname -m)" ;;
  esac
}

ensure_tmp_dir() {
  if [ ! -d /tmp ]; then
    mkdir -p /tmp
  fi
  chmod 1777 /tmp 2>/dev/null || true
  mkdir -p "$TMP_DIR"
}

tmp_path() {
  local name="$1"
  ensure_tmp_dir
  echo "${TMP_DIR}/${name}.$$.${RANDOM}"
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "请用 root 运行。"
  fi
}

ensure_dirs() {
  mkdir -p "$CONFIG_DIR" "$OUTBOUNDS_DIR" /var/log/xray
}

install_deps() {
  msg "安装依赖中..."
  ensure_tmp_dir
  if is_alpine; then
    cmd_exists apk || die "未找到 apk，无法安装依赖。"
    apk add --no-cache curl unzip ca-certificates logrotate
    return 0
  fi
  apt-get update -y
  apt-get install -y curl unzip ca-certificates logrotate
}

detect_arch_xray() {
  case "$(uname -m)" in
    x86_64|amd64) echo "Xray-linux-64.zip" ;;
    i386|i486|i586|i686|x86) echo "Xray-linux-32.zip" ;;
    aarch64|arm64) echo "Xray-linux-arm64-v8a.zip" ;;
    armv7l|armv7|armhf|arm) echo "Xray-linux-arm32-v7a.zip" ;;
    armv6l) echo "Xray-linux-arm32-v6.zip" ;;
    *) die "不支持的架构: $(uname -m)，仅支持 x86/x64/arm64/arm32。" ;;
  esac
}

detect_arch_wgcf() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    i386|i486|i586|i686|x86) echo "386" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7|armhf|arm) echo "armv7" ;;
    *) die "wgcf 不支持的架构: $(uname -m)，仅支持 x86/x64/arm64/arm32。" ;;
  esac
}

install_xray() {
  local file url
  file="$(detect_arch_xray)"
  url="https://github.com/XTLS/Xray-core/releases/latest/download/${file}"
  ensure_tmp_dir
  rm -rf "$XRAY_UNPACK_DIR"
  mkdir -p "$XRAY_UNPACK_DIR"

  msg "下载 Xray 中: ${XRAY_ZIP}"
  curl -fsSL -o "$XRAY_ZIP" "$url"
  unzip -q -o "$XRAY_ZIP" -d "$XRAY_UNPACK_DIR"

  install -m 755 "${XRAY_UNPACK_DIR}/xray" "$XRAY_BIN"
  mkdir -p /usr/local/share/xray
  if [ -f "${XRAY_UNPACK_DIR}/geoip.dat" ]; then
    install -m 644 "${XRAY_UNPACK_DIR}/geoip.dat" /usr/local/share/xray/geoip.dat
  fi
  if [ -f "${XRAY_UNPACK_DIR}/geosite.dat" ]; then
    install -m 644 "${XRAY_UNPACK_DIR}/geosite.dat" /usr/local/share/xray/geosite.dat
  fi
}

write_service() {
  if ! systemd_available; then
    return 0
  fi
  cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=root
ExecStart=/usr/local/bin/xray run -c /etc/xray/config.json
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

write_openrc_service() {
  if ! openrc_available; then
    return 0
  fi
  cat > "$OPENRC_SERVICE" <<'EOF'
#!/sbin/openrc-run
name="xray"
description="Xray Service"
command="/usr/local/bin/xray"
command_args="run -c /etc/xray/config.json"
command_background="yes"
pidfile="/run/xray.pid"
output_log="/var/log/xray/xray.log"
error_log="/var/log/xray/xray.log"

depend() {
  need net
}
EOF
  chmod +x "$OPENRC_SERVICE"
}

setup_logrotate() {
  mkdir -p "$(dirname "$LOGROTATE_FILE")"
  cat > "$LOGROTATE_FILE" <<'EOF'
/var/log/xray/*.log {
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

start_xray() {
  ensure_dirs
  if systemd_available; then
    systemctl enable --now xray
  elif openrc_available; then
    write_openrc_service
    rc-update add xray default >/dev/null 2>&1 || true
    rc-service xray start
  else
    nohup "$XRAY_BIN" run -c "${CONFIG_DIR}/config.json" >/var/log/xray/xray.log 2>&1 &
    echo $! > "$PID_FILE"
  fi
}

stop_xray() {
  if systemd_available; then
    systemctl stop xray || true
  elif openrc_available; then
    rc-service xray stop >/dev/null 2>&1 || true
  else
    if [ -f "$PID_FILE" ]; then
      kill "$(cat "$PID_FILE")" >/dev/null 2>&1 || true
      rm -f "$PID_FILE"
    fi
  fi
}

restart_xray() {
  if systemd_available; then
    systemctl enable xray >/dev/null 2>&1 || true
    systemctl restart xray
  elif openrc_available; then
    rc-service xray restart
  else
    stop_xray
    start_xray
  fi
}

restart_xray_with_check() {
  local port="$1"
  restart_xray
  if [ -n "$port" ] && ! wait_port_listen "$port"; then
    ui "检测到端口未监听，尝试再次重启 Xray..."
    restart_xray
    if ! wait_port_listen "$port"; then
      ui "重启后端口仍未监听，请检查服务状态/日志/防火墙。"
    fi
  fi
}

enable_accel() {
  local virt cc qdisc
  if ! cmd_exists systemd-detect-virt; then
    return 0
  fi
  virt="$(systemd-detect-virt || true)"
  case "$virt" in
    kvm|qemu)
      modprobe tcp_bbr >/dev/null 2>&1 || true
      cat > /etc/sysctl.d/99-xray-accel.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
fs.inotify.max_user_instances=1024
fs.inotify.max_user_watches=1048576
fs.inotify.max_queued_events=65536
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
net.ipv4.conf.default.forwarding=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
EOF
      apply_sysctl_changes /etc/sysctl.d/99-xray-accel.conf
      ;;
    lxc|container)
      if [ -r /proc/sys/net/ipv4/tcp_available_congestion_control ] && \
         grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control; then
        cc="bbr"
      else
        cc="cubic"
      fi
      qdisc="fq_codel"
      cat > /etc/sysctl.d/99-xray-accel.conf <<EOF
net.core.default_qdisc=${qdisc}
net.ipv4.tcp_congestion_control=${cc}
EOF
      apply_sysctl_changes /etc/sysctl.d/99-xray-accel.conf
      ;;
  esac
}

show_tuning_effective() {
  msg "当前内核参数："
  msg "  net.core.default_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo N/A)"
  msg "  net.ipv4.tcp_congestion_control=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo N/A)"
  msg "  fs.inotify.max_user_instances=$(sysctl -n fs.inotify.max_user_instances 2>/dev/null || echo N/A)"
  msg "  fs.inotify.max_user_watches=$(sysctl -n fs.inotify.max_user_watches 2>/dev/null || echo N/A)"
  msg "  fs.inotify.max_queued_events=$(sysctl -n fs.inotify.max_queued_events 2>/dev/null || echo N/A)"
  msg "  net.ipv4.ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo N/A)"
  msg "  net.ipv6.conf.all.forwarding=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo N/A)"
}

apply_sysctl_changes() {
  local profile="${1:-}" out rc=0
  if [ -n "$profile" ] && [ -f "$profile" ]; then
    out="$(sysctl -p "$profile" 2>&1)" || rc=$?
  else
    out="$(sysctl --system 2>&1)" || rc=$?
  fi
  if [ "$rc" -eq 0 ]; then
    msg "sysctl 应用成功。"
  else
    ui "sysctl 返回非 0 (可能部分键在当前环境不可用): ${rc}"
  fi
  if [ -n "$out" ]; then
    msg "sysctl 输出："
    printf '%s\n' "$out" | sed 's/^/  /'
  fi
  show_tuning_effective
}

apply_tuning_profile() {
  local choice
  ui "${C_BOLD}${C_BLUE}网络调优：${C_RESET}"
  ui "  ${C_YELLOW}1)${C_RESET} 默认(清除脚本调优)"
  ui "  ${C_YELLOW}2)${C_RESET} 保守(BBR+转发)"
  ui "  ${C_YELLOW}3)${C_RESET} 激进(高性能参数)"
  read -r -p "请选择 [1-3]: " choice
  case "$choice" in
    1)
      rm -f /etc/sysctl.d/99-xray-accel.conf
      apply_sysctl_changes
      msg "已恢复默认(删除脚本调优)。"
      ;;
    2)
      modprobe tcp_bbr >/dev/null 2>&1 || true
      cat > /etc/sysctl.d/99-xray-accel.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
fs.inotify.max_user_instances=1024
fs.inotify.max_user_watches=1048576
fs.inotify.max_queued_events=65536
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
net.ipv4.conf.default.forwarding=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
EOF
      apply_sysctl_changes /etc/sysctl.d/99-xray-accel.conf
      msg "已应用保守调优。"
      ;;
    3)
      modprobe tcp_bbr >/dev/null 2>&1 || true
      cat > /etc/sysctl.d/99-xray-accel.conf <<'EOF'
fs.file-max = 6815744
fs.inotify.max_user_instances=1024
fs.inotify.max_user_watches=1048576
fs.inotify.max_queued_events=65536
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_ecn=0
net.ipv4.tcp_frto=0
net.ipv4.tcp_mtu_probing=0
net.ipv4.tcp_rfc1337=0
net.ipv4.tcp_sack=1
net.ipv4.tcp_fack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_adv_win_scale=1
net.ipv4.tcp_moderate_rcvbuf=1
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 16384 33554432
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
net.ipv4.conf.default.forwarding=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
EOF
      apply_sysctl_changes /etc/sysctl.d/99-xray-accel.conf
      msg "已应用激进调优。"
      ;;
    *)
      msg "已取消。"
      ;;
  esac
}
gen_short_id() {
  if cmd_exists od; then
    od -An -N4 -tx1 /dev/urandom | tr -d ' \n'
  elif cmd_exists hexdump; then
    hexdump -n 4 -e '4/1 "%02x"' /dev/urandom
  else
    dd if=/dev/urandom bs=4 count=1 2>/dev/null | xxd -p | tr -d '\n'
  fi
}

gen_uuid() {
  cat /proc/sys/kernel/random/uuid
}

gen_reality_keys() {
  local out
  out="$("$XRAY_BIN" x25519)"
  PRIVATE_KEY="$(echo "$out" | awk -F': *' '/^Private([ ]?key|Key)/ {print $2; exit}')"
  PUBLIC_KEY="$(echo "$out" | awk -F': *' '/^Public([ ]?key|Key)/ {print $2; exit}')"
  if [ -z "${PUBLIC_KEY:-}" ]; then
    PUBLIC_KEY="$(echo "$out" | awk -F': *' '/^Password/ {print $2; exit}')"
  fi
  if [ -z "${PRIVATE_KEY:-}" ] || [ -z "${PUBLIC_KEY:-}" ]; then
    err "xray x25519 输出:"
    err "$out"
    die "生成 Reality 密钥失败。"
  fi
}

save_manager_conf() {
  cat > "$MANAGER_CONF" <<EOF
UUID=${UUID}
PRIVATE_KEY=${PRIVATE_KEY}
PUBLIC_KEY=${PUBLIC_KEY}
SHORT_ID=${SHORT_ID}
SERVER_NAME=${SERVER_NAME}
DEST=${DEST}
FINGERPRINT=${FINGERPRINT}
SHARE_HOST=${SHARE_HOST}
EOF
}

load_manager_conf() {
  if [ ! -f "$MANAGER_CONF" ]; then
    die "未初始化，请先安装。"
  fi
  # shellcheck source=/etc/xray/manager.conf
  . "$MANAGER_CONF"
}

ensure_direct_outbounds() {
  cat > "${OUTBOUNDS_DIR}/direct4.json" <<'EOF'
{
  "tag": "direct4",
  "protocol": "freedom",
  "settings": {
    "domainStrategy": "UseIPv4"
  }
}
EOF
  cat > "${OUTBOUNDS_DIR}/direct6.json" <<'EOF'
{
  "tag": "direct6",
  "protocol": "freedom",
  "settings": {
    "domainStrategy": "UseIPv6"
  }
}
EOF
}

port_in_config() {
  local port="$1"
  if [ -f "$INBOUNDS_FILE" ] && awk -F'|' -v p="$port" '$2==p {found=1} END{exit !found}' "$INBOUNDS_FILE"; then
    return 0
  fi
  return 1
}

port_is_listening() {
  local port="$1"
  if cmd_exists ss; then
    ss -lnt | awk '{print $4}' | grep -qE "(:|\\])${port}$"
  else
    return 1
  fi
}

pick_free_port() {
  local port i
  for i in $(seq 1 50); do
    port=$((RANDOM % 20000 + 30000))
    if ! port_is_listening "$port"; then
      echo "$port"
      return 0
    fi
  done
  echo "39000"
}

wait_port_listen() {
  local port="$1" i
  if ! cmd_exists ss; then
    sleep 0.6
    return 0
  fi
  for i in $(seq 1 20); do
    if port_is_listening "$port"; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

test_outbound() {
  local tag="$1"
  [ -n "$tag" ] || return 0
  if [ ! -f "${OUTBOUNDS_DIR}/${tag}.json" ]; then
    ui "跳过出口测试：未找到配置 ${tag}"
    return 0
  fi
  if [ ! -x "$XRAY_BIN" ]; then
    ui "跳过出口测试：未找到 xray"
    return 0
  fi
  if ! cmd_exists curl; then
    ui "跳过出口测试：未安装 curl"
    return 0
  fi
  local port cfg logf pid ip
  port="$(pick_free_port)"
  cfg="$(tmp_path outbound-test.json)"
  logf="$(tmp_path outbound-test.log)"
  cat > "$cfg" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "tag": "test-in",
      "listen": "127.0.0.1",
      "port": ${port},
      "protocol": "socks",
      "settings": {"udp": true}
    }
  ],
  "outbounds": [
$(sed 's/^/    /' "${OUTBOUNDS_DIR}/${tag}.json")
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": ["test-in"],
        "outboundTag": "${tag}"
      }
    ]
  }
}
EOF
  "$XRAY_BIN" run -c "$cfg" >"$logf" 2>&1 &
  pid=$!
  wait_port_listen "$port" || true
  ip="$(curl -fsSL --max-time 8 --socks5-hostname 127.0.0.1:${port} https://ip.sb 2>/dev/null || true)"
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
  rm -f "$cfg" "$logf"
  if [ -n "$ip" ]; then
    msg "出口 ${tag} 测试成功，出口 IP: ${ip}"
  else
    ui "出口 ${tag} 测试失败（无法访问 ip.sb）"
  fi
}

prompt_port() {
  local port ans
  while true; do
    read -r -p "监听端口 [1-65535]: " port
    if ! echo "$port" | grep -qE '^[0-9]+$'; then
      ui "端口无效。"
      continue
    fi
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
      ui "端口范围错误。"
      continue
    fi
    if port_in_config "$port"; then
      ui "该端口已在当前配置中使用。"
      continue
    fi
    if port_is_listening "$port"; then
      read -r -p "端口疑似被占用，继续使用？[y/N]: " ans
      case "$ans" in
        y|Y) ;;
        *) continue ;;
      esac
    fi
    echo "$port"
    return 0
  done
}

urldecode() {
  local data="${1//+/ }"
  printf '%b' "${data//%/\\x}"
}

get_query_param() {
  local key="$1" qs="$2"
  echo "$qs" | tr '&' '\n' | awk -F= -v k="$key" '$1==k {print $2; exit}'
}

json_array_from_csv() {
  local csv="$1"
  echo "$csv" | tr ',' '\n' | awk 'BEGIN{printf "["} {gsub(/^[ \t]+|[ \t]+$/,""); if($0!=""){if(NR>1)printf ","; printf "\"%s\"", $0}} END{printf "]"}'
}

normalize_hy_rate() {
  local v
  v="$(printf '%s' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [ -z "$v" ] && return 0
  if [ "$v" = "0" ]; then
    echo "0"
    return 0
  fi
  if echo "$v" | grep -qE '^[0-9]+([.][0-9]+)?$'; then
    # hy2 links typically carry upmbps/downmbps as plain Mbps numbers.
    echo "${v} mbps"
    return 0
  fi
  echo "$v"
}

parse_hostport() {
  local in="$1" host="" port=""
  if echo "$in" | grep -q '^\['; then
    host="${in#\[}"
    host="${host%%]*}"
    if echo "$in" | grep -q ']:[0-9]'; then
      port="${in##*]:}"
    fi
  elif echo "$in" | grep -q '.*:.*:.*'; then
    host="$in"
    port=""
  elif echo "$in" | grep -q ':'; then
    host="${in%:*}"
    port="${in##*:}"
  else
    host="$in"
    port=""
  fi
  echo "${host}|${port}"
}

urlencode() {
  local s="$1" out="" i c hex
  LC_ALL=C
  for ((i=0; i<${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) out+="$c" ;;
      *)
        printf -v hex '%02X' "'$c"
        out+="%${hex}"
        ;;
    esac
  done
  echo "$out"
}

json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

is_ip_addr() {
  local v="$1"
  if echo "$v" | grep -qE '^[0-9]+(\.[0-9]+){3}$'; then
    return 0
  fi
  if echo "$v" | grep -q ":"; then
    return 0
  fi
  return 1
}

is_domain_name() {
  local v="$1"
  echo "$v" | grep -qiE '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$'
}

normalize_domain_candidate() {
  local v="$1"
  [ -z "$v" ] && return 1
  v="$(urldecode "$v" 2>/dev/null || printf '%s' "$v")"
  v="$(printf '%s' "$v" | tr -d '\r')"
  v="${v#http://}"
  v="${v#https://}"
  v="${v#*@}"
  v="${v%%/*}"
  v="${v%%\?*}"
  v="${v%%#*}"
  v="$(printf '%s' "$v" | sed 's/^\[//;s/\]$//;s/^[[:space:]]*//;s/[[:space:]]*$//')"
  if echo "$v" | grep -q ':' && ! echo "$v" | grep -qE '^[0-9a-fA-F:]+$'; then
    v="${v%%:*}"
  fi
  [ -z "$v" ] && return 1
  printf '%s\n' "$v"
}

get_outbound_domains() {
  local tag="$1" f
  if [ -f "${OUTBOUNDS_DIR}/${tag}.json" ]; then
    f="${OUTBOUNDS_DIR}/${tag}.json"
  else
    f=""
  fi
  if [ -n "$f" ]; then
    for key in server address server_name serverName sni host Host; do
      sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\\([^\"]\\+\\)\".*/\\1/p" "$f"
    done
  fi
  if [ -f "${OUTBOUNDS_DIR}/${tag}.link" ]; then
    sed -n 's/.*@\([^:/?#]*\).*/\1/p' "${OUTBOUNDS_DIR}/${tag}.link"
    sed -n 's/.*[?&]sni=\([^&]*\).*/\1/p' "${OUTBOUNDS_DIR}/${tag}.link"
    sed -n 's/.*[?&]host=\([^&]*\).*/\1/p' "${OUTBOUNDS_DIR}/${tag}.link"
  fi
}

validate_xray_config() {
  [ -x "$XRAY_BIN" ] || return 0
  local cfg check_log
  cfg="${CONFIG_DIR}/config.json"
  check_log="$(tmp_path xray_check.log)"
  if "$XRAY_BIN" run -test -config "$cfg" >"$check_log" 2>&1 || "$XRAY_BIN" run -test -c "$cfg" >"$check_log" 2>&1; then
    rm -f "$check_log"
    return 0
  fi
  err "Xray 配置校验失败："
  sed 's/^/  /' "$check_log" >&2 || true
  rm -f "$check_log"
  return 1
}

base64_decode() {
  local in="$1" pad padstr
  in="${in//-/+}"
  in="${in//_/\/}"
  pad=$(( (4 - ${#in} % 4) % 4 ))
  if [ "$pad" -gt 0 ]; then
    printf -v padstr '%*s' "$pad" ''
    padstr="${padstr// /=}"
    in="${in}${padstr}"
  fi
  printf '%s' "$in" | base64 -d 2>/dev/null
}

json_get() {
  local key="$1" json="$2"
  local val
  val="$(echo "$json" | sed -n "s/.*\"${key}\"[ ]*:[ ]*\"\\([^\"]*\\)\".*/\\1/p")"
  if [ -n "$val" ]; then
    echo "$val"
    return 0
  fi
  val="$(echo "$json" | sed -n "s/.*\"${key}\"[ ]*:[ ]*\\([0-9.]*\\).*/\\1/p")"
  if [ -n "$val" ]; then
    echo "$val"
    return 0
  fi
  echo "$json" | sed -n "s/.*\"${key}\"[ ]*:[ ]*\\(true\\|false\\).*/\\1/p"
}

build_vless_outbound() {
  local link="$1" tag="$2"
  local base qs uuid hostport host port
  local network security flow sni fp pbk sid spx path param_host service alpn insecure

  link="${link#vless://}"
  if echo "$link" | grep -q '#'; then
    link="${link%%#*}"
  fi
  if echo "$link" | grep -q '\?'; then
    qs="${link#*\?}"
    base="${link%%\?*}"
  else
    qs=""
    base="$link"
  fi

  uuid="${base%%@*}"
  hostport="${base#*@}"
  IFS='|' read -r host port <<< "$(parse_hostport "$hostport")"

  if [ -z "$uuid" ] || [ -z "$host" ] || [ -z "$port" ]; then
    die "VLESS 链接无效。"
  fi

  network="$(get_query_param type "$qs")"
  [ -z "$network" ] && network="tcp"
  security="$(get_query_param security "$qs")"
  [ -z "$security" ] && security="none"
  flow="$(get_query_param flow "$qs")"
  sni="$(urldecode "$(get_query_param sni "$qs")")"
  fp="$(get_query_param fp "$qs")"
  pbk="$(get_query_param pbk "$qs")"
  sid="$(get_query_param sid "$qs")"
  spx="$(urldecode "$(get_query_param spx "$qs")")"
  path="$(urldecode "$(get_query_param path "$qs")")"
  param_host="$(urldecode "$(get_query_param host "$qs")")"
  service="$(urldecode "$(get_query_param serviceName "$qs")")"
  alpn="$(urldecode "$(get_query_param alpn "$qs")")"
  insecure="$(get_query_param allowInsecure "$qs")"

  case "$network" in
    tcp|ws|grpc) ;;
    *) die "不支持的 VLESS network 类型: $network" ;;
  esac

  local stream="\"network\":\"${network}\",\"security\":\"${security}\""

  if [ "$security" = "tls" ]; then
    local tls_items=""
    local tls_sni="${sni:-$host}"
    tls_items="\"serverName\":\"${tls_sni}\""
    if [ -n "$fp" ]; then
      tls_items="${tls_items},\"fingerprint\":\"${fp}\""
    fi
    if [ -n "$alpn" ]; then
      tls_items="${tls_items},\"alpn\":$(json_array_from_csv "$alpn")"
    fi
    if [ "$insecure" = "1" ] || [ "$insecure" = "true" ]; then
      tls_items="${tls_items},\"allowInsecure\":true"
    fi
    stream="${stream},\"tlsSettings\":{${tls_items}}"
  elif [ "$security" = "reality" ]; then
    local r_sni="${sni:-$host}"
    local r_fp="${fp:-chrome}"
    [ -z "$pbk" ] && die "Reality 出口需要 pbk。"
    [ -z "$sid" ] && die "Reality 出口需要 sid。"
    [ -z "$spx" ] && spx="/"
    stream="${stream},\"realitySettings\":{\"serverName\":\"${r_sni}\",\"publicKey\":\"${pbk}\",\"shortId\":\"${sid}\",\"fingerprint\":\"${r_fp}\",\"spiderX\":\"${spx}\"}"
  fi

  if [ "$network" = "ws" ]; then
    [ -z "$path" ] && path="/"
    if [ -n "$param_host" ]; then
      stream="${stream},\"wsSettings\":{\"path\":\"${path}\",\"headers\":{\"Host\":\"${param_host}\"}}"
    else
      stream="${stream},\"wsSettings\":{\"path\":\"${path}\"}"
    fi
  elif [ "$network" = "grpc" ]; then
    [ -z "$service" ] && die "gRPC 需要 serviceName。"
    stream="${stream},\"grpcSettings\":{\"serviceName\":\"${service}\"}"
  fi

  cat > "${OUTBOUNDS_DIR}/${tag}.json" <<EOF
{
  "tag": "${tag}",
  "protocol": "vless",
  "settings": {
    "vnext": [
      {
        "address": "${host}",
        "port": ${port},
        "users": [
          {
            "id": "${uuid}",
            "encryption": "none"$( [ -n "$flow" ] && printf ',\n            "flow": "%s"' "$flow" )
          }
        ]
      }
    ]
  },
  "streamSettings": {
    ${stream}
  }
}
EOF
}

build_vmess_outbound() {
  local link="$1" tag="$2"
  local payload json host port uuid aid net tls host_header path scy sni fp alpn insecure type

  payload="${link#vmess://}"
  json="$(base64_decode "$payload")"
  [ -z "$json" ] && die "VMess 链接解析失败。"

  host="$(json_get add "$json")"
  port="$(json_get port "$json")"
  uuid="$(json_get id "$json")"
  aid="$(json_get aid "$json")"
  net="$(json_get net "$json")"
  tls="$(json_get tls "$json")"
  host_header="$(json_get host "$json")"
  path="$(json_get path "$json")"
  scy="$(json_get scy "$json")"
  sni="$(json_get sni "$json")"
  fp="$(json_get fp "$json")"
  alpn="$(json_get alpn "$json")"
  insecure="$(json_get allowInsecure "$json")"
  type="$(json_get type "$json")"

  if [ "$tls" = "true" ]; then
    tls="tls"
  elif [ "$tls" = "false" ]; then
    tls=""
  fi

  [ -z "$host" ] && die "VMess 链接缺少地址。"
  [ -z "$port" ] && die "VMess 链接缺少端口。"
  [ -z "$uuid" ] && die "VMess 链接缺少 UUID。"
  [ -z "$aid" ] && aid="0"
  [ -z "$net" ] && net="tcp"
  [ -z "$scy" ] && scy="auto"

  case "$net" in
    tcp|ws|grpc) ;;
    *) die "不支持的 VMess network 类型: $net" ;;
  esac

  local stream="\"network\":\"${net}\""
  if [ "$tls" = "tls" ]; then
    local tls_items=""
    local tls_sni="${sni:-$host}"
    tls_items="\"serverName\":\"${tls_sni}\""
    if [ -n "$fp" ]; then
      tls_items="${tls_items},\"fingerprint\":\"${fp}\""
    fi
    if [ -n "$alpn" ]; then
      tls_items="${tls_items},\"alpn\":$(json_array_from_csv "$alpn")"
    fi
    if [ "$insecure" = "1" ] || [ "$insecure" = "true" ]; then
      tls_items="${tls_items},\"allowInsecure\":true"
    fi
    stream="${stream},\"security\":\"tls\",\"tlsSettings\":{${tls_items}}"
  else
    stream="${stream},\"security\":\"none\""
  fi

  if [ "$net" = "ws" ]; then
    [ -z "$path" ] && path="/"
    if [ -n "$host_header" ]; then
      stream="${stream},\"wsSettings\":{\"path\":\"${path}\",\"headers\":{\"Host\":\"${host_header}\"}}"
    else
      stream="${stream},\"wsSettings\":{\"path\":\"${path}\"}"
    fi
  elif [ "$net" = "grpc" ]; then
    [ -z "$path" ] && die "VMess gRPC 缺少 serviceName。"
    stream="${stream},\"grpcSettings\":{\"serviceName\":\"${path}\"}"
  elif [ "$net" = "tcp" ] && [ -n "$type" ] && [ "$type" != "none" ]; then
    stream="${stream},\"tcpSettings\":{\"header\":{\"type\":\"${type}\"}}"
  fi

  cat > "${OUTBOUNDS_DIR}/${tag}.json" <<EOF
{
  "tag": "${tag}",
  "protocol": "vmess",
  "settings": {
    "vnext": [
      {
        "address": "${host}",
        "port": ${port},
        "users": [
          {
            "id": "${uuid}",
            "alterId": ${aid},
            "security": "${scy}"
          }
        ]
      }
    ]
  },
  "streamSettings": {
    ${stream}
  }
}
EOF
}

build_trojan_outbound() {
  local link="$1" tag="$2"
  local base qs pass hostport host port
  local network security sni fp path param_host service alpn insecure

  link="${link#trojan://}"
  if echo "$link" | grep -q '#'; then
    link="${link%%#*}"
  fi
  if echo "$link" | grep -q '\?'; then
    qs="${link#*\?}"
    base="${link%%\?*}"
  else
    qs=""
    base="$link"
  fi

  pass="${base%%@*}"
  hostport="${base#*@}"
  IFS='|' read -r host port <<< "$(parse_hostport "$hostport")"

  pass="$(urldecode "$pass")"
  if [ -z "$pass" ] || [ -z "$host" ] || [ -z "$port" ]; then
    die "Trojan 链接无效。"
  fi

  network="$(get_query_param type "$qs")"
  [ -z "$network" ] && network="tcp"
  security="$(get_query_param security "$qs")"
  [ -z "$security" ] && security="tls"
  sni="$(urldecode "$(get_query_param sni "$qs")")"
  fp="$(get_query_param fp "$qs")"
  path="$(urldecode "$(get_query_param path "$qs")")"
  param_host="$(urldecode "$(get_query_param host "$qs")")"
  service="$(urldecode "$(get_query_param serviceName "$qs")")"
  alpn="$(urldecode "$(get_query_param alpn "$qs")")"
  insecure="$(get_query_param allowInsecure "$qs")"

  case "$network" in
    tcp|ws|grpc) ;;
    *) die "不支持的 Trojan network 类型: $network" ;;
  esac

  local stream="\"network\":\"${network}\",\"security\":\"${security}\""
  if [ "$security" = "tls" ]; then
    local tls_items=""
    local tls_sni="${sni:-$host}"
    tls_items="\"serverName\":\"${tls_sni}\""
    if [ -n "$fp" ]; then
      tls_items="${tls_items},\"fingerprint\":\"${fp}\""
    fi
    if [ -n "$alpn" ]; then
      tls_items="${tls_items},\"alpn\":$(json_array_from_csv "$alpn")"
    fi
    if [ "$insecure" = "1" ] || [ "$insecure" = "true" ]; then
      tls_items="${tls_items},\"allowInsecure\":true"
    fi
    stream="${stream},\"tlsSettings\":{${tls_items}}"
  fi

  if [ "$network" = "ws" ]; then
    [ -z "$path" ] && path="/"
    if [ -n "$param_host" ]; then
      stream="${stream},\"wsSettings\":{\"path\":\"${path}\",\"headers\":{\"Host\":\"${param_host}\"}}"
    else
      stream="${stream},\"wsSettings\":{\"path\":\"${path}\"}"
    fi
  elif [ "$network" = "grpc" ]; then
    [ -z "$service" ] && die "Trojan gRPC 需要 serviceName。"
    stream="${stream},\"grpcSettings\":{\"serviceName\":\"${service}\"}"
  fi

  cat > "${OUTBOUNDS_DIR}/${tag}.json" <<EOF
{
  "tag": "${tag}",
  "protocol": "trojan",
  "settings": {
    "servers": [
      {
        "address": "${host}",
        "port": ${port},
        "password": "${pass}"
      }
    ]
  },
  "streamSettings": {
    ${stream}
  }
}
EOF
}

build_ss_outbound() {
  local link="$1" tag="$2"
  local base creds hostport method password host port decoded

  link="${link#ss://}"
  if echo "$link" | grep -q '#'; then
    link="${link%%#*}"
  fi
  if echo "$link" | grep -q '\?'; then
    link="${link%%\?*}"
  fi

  if echo "$link" | grep -q '@'; then
    creds="${link%%@*}"
    hostport="${link#*@}"
    if echo "$creds" | grep -q ':'; then
      method="${creds%%:*}"
      password="${creds#*:}"
    else
      decoded="$(base64_decode "$creds")"
      method="${decoded%%:*}"
      password="${decoded#*:}"
    fi
  else
    decoded="$(base64_decode "$link")"
    if ! echo "$decoded" | grep -q '@'; then
      die "SS 链接无效。"
    fi
    creds="${decoded%%@*}"
    hostport="${decoded#*@}"
    method="${creds%%:*}"
    password="${creds#*:}"
  fi

  IFS='|' read -r host port <<< "$(parse_hostport "$hostport")"
  if [ -z "$method" ] || [ -z "$password" ] || [ -z "$host" ] || [ -z "$port" ]; then
    die "SS 链接无效。"
  fi
  password="$(urldecode "$password")"

  cat > "${OUTBOUNDS_DIR}/${tag}.json" <<EOF
{
  "tag": "${tag}",
  "protocol": "shadowsocks",
  "settings": {
    "servers": [
      {
        "address": "${host}",
        "port": ${port},
        "method": "${method}",
        "password": "${password}"
      }
    ]
  }
}
EOF
}

build_hy2_outbound() {
  local link="$1" tag="$2"
  local base qs userinfo hostport host port password
  local sni insecure alpn up down auth

  link="${link#hysteria2://}"
  link="${link#hy2://}"
  if echo "$link" | grep -q '#'; then
    link="${link%%#*}"
  fi
  if echo "$link" | grep -q '\?'; then
    qs="${link#*\?}"
    base="${link%%\?*}"
  else
    qs=""
    base="$link"
  fi

  userinfo="${base%%@*}"
  hostport="${base#*@}"
  IFS='|' read -r host port <<< "$(parse_hostport "$hostport")"

  if echo "$userinfo" | grep -q ':'; then
    password="${userinfo#*:}"
  else
    password="$userinfo"
  fi

  auth="$(urldecode "$(get_query_param auth "$qs")")"
  [ -n "$auth" ] && password="$auth"
  sni="$(urldecode "$(get_query_param sni "$qs")")"
  alpn="$(urldecode "$(get_query_param alpn "$qs")")"
  insecure="$(get_query_param insecure "$qs")"
  [ -z "$insecure" ] && insecure="$(get_query_param allowInsecure "$qs")"
  up="$(get_query_param upmbps "$qs")"
  [ -z "$up" ] && up="$(get_query_param up_mbps "$qs")"
  down="$(get_query_param downmbps "$qs")"
  [ -z "$down" ] && down="$(get_query_param down_mbps "$qs")"

  [ -z "$host" ] && die "HY2 缺少地址。"
  [ -z "$port" ] && die "HY2 缺少端口。"
  password="$(urldecode "$password")"
  [ -z "$password" ] && die "HY2 缺少密码。"
  up="$(normalize_hy_rate "$up")"
  down="$(normalize_hy_rate "$down")"

  local tls_items=""
  local tls_sni="${sni:-$host}"
  tls_items="\"serverName\":\"${tls_sni}\""
  if [ -n "$alpn" ]; then
    tls_items="${tls_items},\"alpn\":$(json_array_from_csv "$alpn")"
  fi
  if [ "$insecure" = "1" ] || [ "$insecure" = "true" ]; then
    tls_items="${tls_items},\"allowInsecure\":true"
  fi

  local hy_items="\"version\":2,\"auth\":\"${password}\""
  if [ -n "$up" ]; then
    hy_items="${hy_items},\"up\":\"${up}\""
  fi
  if [ -n "$down" ]; then
    hy_items="${hy_items},\"down\":\"${down}\""
  fi

  cat > "${OUTBOUNDS_DIR}/${tag}.json" <<EOF
{
  "tag": "${tag}",
  "protocol": "hysteria",
  "settings": {
    "version": 2,
    "address": "${host}",
    "port": ${port}
  },
  "streamSettings": {
    "network": "hysteria",
    "security": "tls",
    "hysteriaSettings": {
      ${hy_items}
    },
    "tlsSettings": {
      ${tls_items}
    }
  }
}
EOF
}

build_socks_outbound() {
  local link="$1" tag="$2"
  local scheme base qs userinfo hostport host port user pass version

  scheme="${link%%://*}"
  link="${link#*://}"
  if echo "$link" | grep -q '#'; then
    link="${link%%#*}"
  fi
  if echo "$link" | grep -q '\?'; then
    qs="${link#*\?}"
    base="${link%%\?*}"
  else
    qs=""
    base="$link"
  fi

  if echo "$base" | grep -q '@'; then
    userinfo="${base%%@*}"
    hostport="${base#*@}"
  else
    userinfo=""
    hostport="$base"
  fi

  IFS='|' read -r host port <<< "$(parse_hostport "$hostport")"
  [ -z "$port" ] && port="1080"
  [ -z "$host" ] && die "SOCKS 缺少地址。"

  if [ -n "$userinfo" ]; then
    if echo "$userinfo" | grep -q ':'; then
      user="${userinfo%%:*}"
      pass="${userinfo#*:}"
    else
      user="$userinfo"
      pass=""
    fi
    user="$(urldecode "$user")"
    pass="$(urldecode "$pass")"
  else
    user=""
    pass=""
  fi

  case "$scheme" in
    socks4) version="4" ;;
    socks4a) version="4a" ;;
    socks5|socks) version="5" ;;
    *) version="5" ;;
  esac

  if [ "$version" != "5" ]; then
    ui "提示: Xray Socks 出站文档存在差异，Socks4/4a 可能不被支持。"
  fi

  local users_block=""
  if [ -n "$user" ]; then
    users_block="\"users\":[{\"user\":\"${user}\",\"pass\":\"${pass}\"}]"
  fi

  local version_block=""
  if [ "$version" != "5" ]; then
    version_block="\"version\":\"${version}\""
  fi

  cat > "${OUTBOUNDS_DIR}/${tag}.json" <<EOF
{
  "tag": "${tag}",
  "protocol": "socks",
  "settings": {
    "servers": [
      {
        "address": "${host}",
        "port": ${port}$( [ -n "$users_block" ] && printf ',\n        %s' "$users_block" )
      }
    ]$( [ -n "$version_block" ] && printf ',\n    %s' "$version_block" )
  }
}
EOF
}

build_http_outbound() {
  local link="$1" tag="$2"
  local scheme base qs userinfo hostport host port user pass sni alpn insecure

  scheme="${link%%://*}"
  link="${link#*://}"
  if echo "$link" | grep -q '#'; then
    link="${link%%#*}"
  fi
  if echo "$link" | grep -q '\?'; then
    qs="${link#*\?}"
    base="${link%%\?*}"
  else
    qs=""
    base="$link"
  fi

  if echo "$base" | grep -q '@'; then
    userinfo="${base%%@*}"
    hostport="${base#*@}"
  else
    userinfo=""
    hostport="$base"
  fi

  IFS='|' read -r host port <<< "$(parse_hostport "$hostport")"
  if [ -z "$port" ]; then
    if [ "$scheme" = "https" ]; then
      port="443"
    else
      port="80"
    fi
  fi
  [ -z "$host" ] && die "HTTP 代理缺少地址。"

  if [ -n "$userinfo" ]; then
    if echo "$userinfo" | grep -q ':'; then
      user="${userinfo%%:*}"
      pass="${userinfo#*:}"
    else
      user="$userinfo"
      pass=""
    fi
    user="$(urldecode "$user")"
    pass="$(urldecode "$pass")"
  else
    user=""
    pass=""
  fi

  sni="$(urldecode "$(get_query_param sni "$qs")")"
  alpn="$(urldecode "$(get_query_param alpn "$qs")")"
  insecure="$(get_query_param insecure "$qs")"
  [ -z "$insecure" ] && insecure="$(get_query_param allowInsecure "$qs")"

  local users_block=""
  if [ -n "$user" ]; then
    users_block="\"users\":[{\"user\":\"${user}\",\"pass\":\"${pass}\"}]"
  fi

  local stream_block=""
  if [ "$scheme" = "https" ]; then
    local tls_items="\"serverName\":\"${sni:-$host}\""
    if [ -n "$alpn" ]; then
      tls_items="${tls_items},\"alpn\":$(json_array_from_csv "$alpn")"
    fi
    if [ "$insecure" = "1" ] || [ "$insecure" = "true" ]; then
      tls_items="${tls_items},\"allowInsecure\":true"
    fi
    stream_block=",\n  \"streamSettings\": {\n    \"security\": \"tls\",\n    \"tlsSettings\": {\n      ${tls_items}\n    }\n  }"
  fi

  msg "提示: HTTP/HTTPS 代理仅支持 TCP，UDP 流量会被拒绝。"

  cat > "${OUTBOUNDS_DIR}/${tag}.json" <<EOF
{
  "tag": "${tag}",
  "protocol": "http",
  "settings": {
    "servers": [
      {
        "address": "${host}",
        "port": ${port}$( [ -n "$users_block" ] && printf ',\n        %s' "$users_block" )
      }
    ]
  }${stream_block}
}
EOF
}

build_outbound_from_link() {
  local link="$1" tag="$2"
  case "$link" in
    vless://*) build_vless_outbound "$link" "$tag" ;;
    vmess://*) build_vmess_outbound "$link" "$tag" ;;
    trojan://*) build_trojan_outbound "$link" "$tag" ;;
    ss://*) build_ss_outbound "$link" "$tag" ;;
    hysteria2://*|hy2://*) build_hy2_outbound "$link" "$tag" ;;
    socks://*|socks4://*|socks4a://*|socks5://*) build_socks_outbound "$link" "$tag" ;;
    http://*|https://*) build_http_outbound "$link" "$tag" ;;
    *) die "不支持的链接协议。" ;;
  esac
}

get_wgcf_version() {
  local ver loc
  ver="$(curl -fsSL https://api.github.com/repos/ViRb3/wgcf/releases/latest 2>/dev/null | sed -n 's/.*"tag_name": *"v\\([^"]*\\)".*/\\1/p')"
  if [ -z "$ver" ]; then
    loc="$(curl -fsSLI https://github.com/ViRb3/wgcf/releases/latest 2>/dev/null | awk 'tolower($0) ~ /^location:/ {print $2; exit}' | tr -d '\r')"
    ver="$(echo "$loc" | awk -F'/' '{print $NF}' | sed 's/^v//')"
  fi
  if [ -z "$ver" ]; then
    ui "无法自动获取 wgcf 版本。"
    read -r -p "请手动输入 wgcf 版本(如 2.2.23)，留空取消: " ver
  fi
  echo "$ver"
}

setup_warp() {
  local ver arch url priv addr peer_pub endpoint mtu reserved addr4 addr6 res_json
  if [ -f "${OUTBOUNDS_DIR}/warp.json" ]; then
    return 0
  fi
  ensure_tmp_dir
  rm -rf "$WGCF_DIR"
  mkdir -p "$WGCF_DIR"
  ver="$(get_wgcf_version)"
  [ -z "$ver" ] && die "已取消 WARP 配置。"
  arch="$(detect_arch_wgcf)"
  url="https://github.com/ViRb3/wgcf/releases/latest/download/wgcf_${ver}_linux_${arch}"
  ui "下载 wgcf 中: ${WGCF_BIN}"
  curl -fsSL -o "$WGCF_BIN" "$url"
  install -m 755 "$WGCF_BIN" "$WGCF_DST"
  rm -f "$WGCF_BIN"

  (cd "$WGCF_DIR" && "$WGCF_DST" register --accept-tos >/dev/null 2>&1 && "$WGCF_DST" generate >/dev/null 2>&1) || die "wgcf 执行失败。"
  rm -f "$WGCF_DST" >/dev/null 2>&1 || true

  priv="$(awk -F' = ' '/^PrivateKey/ {print $2; exit}' "${WGCF_DIR}/wgcf-profile.conf")"
  addr="$(awk -F' = ' '/^Address/ {print $2; exit}' "${WGCF_DIR}/wgcf-profile.conf" | tr -d ' ')"
  peer_pub="$(awk -F' = ' '/^PublicKey/ {print $2; exit}' "${WGCF_DIR}/wgcf-profile.conf")"
  endpoint="$(awk -F' = ' '/^Endpoint/ {print $2; exit}' "${WGCF_DIR}/wgcf-profile.conf")"
  mtu="$(awk -F' = ' '/^MTU/ {print $2; exit}' "${WGCF_DIR}/wgcf-profile.conf")"
  reserved="$(awk -F' = ' '/^Reserved/ {print $2; exit}' "${WGCF_DIR}/wgcf-profile.conf")"

  IFS=',' read -r addr4 addr6 <<< "$addr"
  [ -z "$mtu" ] && mtu="1280"

  if [ -n "$reserved" ]; then
    reserved="$(echo "$reserved" | tr -d ' ')"
    res_json="$(echo "$reserved" | awk -F',' '{printf "[%s,%s,%s]",$1,$2,$3}')"
  else
    res_json=""
  fi

  cat > "${OUTBOUNDS_DIR}/warp.json" <<EOF
{
  "tag": "warp",
  "protocol": "wireguard",
  "settings": {
    "secretKey": "${priv}",
    "address": ["${addr4}"$( [ -n "$addr6" ] && printf ', "%s"' "$addr6" )],
    "peers": [
      {
        "publicKey": "${peer_pub}",
        "endpoint": "${endpoint}"
      }
    ],
    "mtu": ${mtu}$( [ -n "$res_json" ] && printf ',\n    "reserved": %s' "$res_json" )
  }
}
EOF

  mkdir -p "${CONFIG_DIR}/warp"
  cp "${WGCF_DIR}/wgcf-account.toml" "${CONFIG_DIR}/warp/" || true
  cp "${WGCF_DIR}/wgcf-profile.conf" "${CONFIG_DIR}/warp/" || true
}

list_custom_outbounds() {
  local f base
  for f in "${OUTBOUNDS_DIR}"/*.json; do
    [ -e "$f" ] || continue
    base="$(basename "$f" .json)"
    case "$base" in
      direct4|direct6|warp) continue ;;
    esac
    echo "$base"
  done
}

save_outbound_link() {
  local tag="$1" link="$2"
  echo "$link" > "${OUTBOUNDS_DIR}/${tag}.link"
}

read_outbound_link() {
  local tag="$1"
  if [ -f "${OUTBOUNDS_DIR}/${tag}.link" ]; then
    cat "${OUTBOUNDS_DIR}/${tag}.link"
  else
    echo ""
  fi
}

has_custom_outbounds() {
  local f base
  for f in "${OUTBOUNDS_DIR}"/*.json; do
    [ -e "$f" ] || continue
    base="$(basename "$f" .json)"
    case "$base" in
      direct4|direct6|warp) continue ;;
      *) return 0 ;;
    esac
  done
  return 1
}

outbound_in_use() {
  local tag="$1"
  if [ -f "$INBOUNDS_FILE" ] && awk -F'|' -v t="$tag" '$3==t {found=1} END{exit !found}' "$INBOUNDS_FILE"; then
    return 0
  fi
  return 1
}

select_existing_custom_outbound() {
  local tags=() i=0 choice
  while IFS= read -r tag; do
    tags+=("$tag")
  done < <(list_custom_outbounds)

  if [ "${#tags[@]}" -eq 0 ]; then
    die "没有自定义出口。"
  fi

  ui "已有自定义出口："
  for tag in "${tags[@]}"; do
    i=$((i+1))
    ui "  ${i}) ${tag}"
  done
  while true; do
    read -r -p "请选择: " choice
    if echo "$choice" | grep -qE '^[0-9]+$' && [ "$choice" -ge 1 ] && [ "$choice" -le "${#tags[@]}" ]; then
      echo "${tags[$((choice-1))]}"
      return 0
    fi
  done
}

add_custom_outbound() {
  local tag link
  while true; do
    read -r -p "出口标签(字母/数字/_，留空自动): " tag
    if [ -z "$tag" ]; then
      tag="out_$(date +%s)"
      break
    fi
    if ! echo "$tag" | grep -qE '^[A-Za-z0-9_]+$'; then
      ui "标签无效。"
      continue
    fi
    if [ -f "${OUTBOUNDS_DIR}/${tag}.json" ]; then
      ui "标签已存在。"
      continue
    fi
    break
  done
  read -r -p "请输入出口链接(VLESS/VMess/Trojan/SS/HY2/SOCKS/HTTP/HTTPS): " link
  build_outbound_from_link "$link" "$tag"
  save_outbound_link "$tag" "$link"
  echo "$tag"
}

add_custom_outbound_only() {
  local tag
  tag="$(add_custom_outbound)"
  if [ -s "$INBOUNDS_FILE" ]; then
    build_config
    restart_xray
    test_outbound "$tag"
    msg "自定义出口已添加: ${tag}"
  else
    test_outbound "$tag"
    msg "自定义出口已添加: ${tag} (当前无入口，未重启)"
  fi
}

update_custom_outbound() {
  local tag link
  if ! has_custom_outbounds; then
    msg "暂无自定义出口。"
    return 0
  fi
  tag="$(select_existing_custom_outbound)"
  read -r -p "请输入新的出口链接: " link
  build_outbound_from_link "$link" "$tag"
  save_outbound_link "$tag" "$link"
  if [ -s "$INBOUNDS_FILE" ]; then
    build_config
    restart_xray
  fi
  test_outbound "$tag"
  msg "自定义出口已更新: ${tag}"
}

delete_custom_outbound() {
  local tag
  if ! has_custom_outbounds; then
    msg "暂无自定义出口。"
    return 0
  fi
  tag="$(select_existing_custom_outbound)"
  if outbound_in_use "$tag"; then
    msg "该出口仍被入口使用，请先修改入口出口。"
    return 0
  fi
  rm -f "${OUTBOUNDS_DIR}/${tag}.json"
  rm -f "${OUTBOUNDS_DIR}/${tag}.link"
  if [ -s "$INBOUNDS_FILE" ]; then
    build_config
    restart_xray
  fi
  msg "自定义出口已删除: ${tag}"
}

show_custom_outbounds() {
  local tag link
  if ! has_custom_outbounds; then
    msg "暂无自定义出口。"
    return 0
  fi
  msg "自定义出口列表："
  while IFS= read -r tag; do
    link="$(read_outbound_link "$tag")"
    if [ -n "$link" ]; then
      msg "  ${tag}: ${link}"
    else
      msg "  ${tag}: (未记录原始链接)"
    fi
  done < <(list_custom_outbounds)
}

manage_custom_outbounds() {
  local choice
  while true; do
    ui "${C_BOLD}${C_BLUE}自定义出口管理：${C_RESET}"
    ui "  ${C_YELLOW}1)${C_RESET} 新增出口"
    ui "  ${C_YELLOW}2)${C_RESET} 更新已有出口"
    ui "  ${C_YELLOW}3)${C_RESET} 删除自定义出口"
    ui "  ${C_YELLOW}4)${C_RESET} 查看现有出口"
    ui "  ${C_YELLOW}0)${C_RESET} 返回"
    read -r -p "请选择: " choice
    case "$choice" in
      1) add_custom_outbound_only ;;
      2) update_custom_outbound ;;
      3) delete_custom_outbound ;;
      4) show_custom_outbounds ;;
      0) return 0 ;;
    esac
  done
}

choose_outbound() {
  local choice tag has_custom
  ensure_direct_outbounds
  if has_custom_outbounds; then
    has_custom=1
  else
    has_custom=0
  fi
  ui "${C_BOLD}${C_BLUE}出口模式：${C_RESET}"
  ui "  ${C_YELLOW}1)${C_RESET} 本机 IPv4"
  ui "  ${C_YELLOW}2)${C_RESET} 本机 IPv6"
  ui "  ${C_YELLOW}3)${C_RESET} WARP"
  ui "  ${C_YELLOW}4)${C_RESET} 新增出口链接"
  ui "  ${C_YELLOW}5)${C_RESET} 使用已有自定义出口"
  while true; do
    read -r -p "请选择: " choice
    case "$choice" in
      1) echo "direct4"; return 0 ;;
      2) echo "direct6"; return 0 ;;
      3) setup_warp 1>&2; echo "warp"; return 0 ;;
      4) tag="$(add_custom_outbound)"; echo "$tag"; return 0 ;;
      5)
        if [ "$has_custom" -eq 1 ]; then
          tag="$(select_existing_custom_outbound)"
          echo "$tag"
          return 0
        else
          ui "暂无自定义出口，请先添加。"
        fi
        ;;
    esac
  done
}

next_inbound_tag() {
  local n=0
  if [ -f "$INBOUNDS_FILE" ]; then
    n="$(awk 'END{print NR}' "$INBOUNDS_FILE")"
  fi
  echo "in_$((n+1))"
}

add_inbound() {
  local port out_tag tag remark
  if [ ! -f "$MANAGER_CONF" ]; then
    init_base_config
  fi
  port="$(prompt_port)"
  out_tag="$(choose_outbound)"
  if ! echo "$out_tag" | grep -qE '^[A-Za-z0-9_]+$'; then
    die "出口选择异常，请重试。"
  fi
  read -r -p "别名(用于分享链接，留空默认 xray-${port}): " remark
  if [ -z "$remark" ]; then
    remark="xray-${port}"
  fi
  tag="$(next_inbound_tag)"
  echo "${tag}|${port}|${out_tag}|${remark}" >> "$INBOUNDS_FILE"
  build_config
  restart_xray_with_check "$port"
  test_outbound "$out_tag"
  msg "入口已添加。"
}

sanitize_inbounds() {
  local tmp
  [ -f "$INBOUNDS_FILE" ] || return 0
  tmp="$(tmp_path inbounds.list)"
  > "$tmp"
  while IFS='|' read -r tag port out remark; do
    [ -z "$tag" ] && continue
    if ! echo "$tag" | grep -qE '^[A-Za-z0-9_]+$'; then
      continue
    fi
    if ! echo "$port" | grep -qE '^[0-9]+$'; then
      continue
    fi
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
      continue
    fi
    if [ -z "$out" ] || ! echo "$out" | grep -qE '^[A-Za-z0-9_]+$'; then
      continue
    fi
    echo "${tag}|${port}|${out}|${remark}" >> "$tmp"
  done < "$INBOUNDS_FILE"
  mv "$tmp" "$INBOUNDS_FILE"
}

list_inbounds() {
  local i=0
  sanitize_inbounds
  if [ ! -f "$INBOUNDS_FILE" ] || [ ! -s "$INBOUNDS_FILE" ]; then
    ui "暂无入口。"
    return 1
  fi
  while IFS='|' read -r tag port out remark; do
    [ -z "$tag" ] && continue
    i=$((i+1))
    ui "  ${i}) ${tag}  端口=${port}  出口=${out}"
  done < "$INBOUNDS_FILE"
  return 0
}

select_inbound_index() {
  local idx
  list_inbounds || return 1
  while true; do
    read -r -p "请选择入口: " idx
    if echo "$idx" | grep -qE '^[0-9]+$'; then
      echo "$idx"
      return 0
    fi
  done
}

update_inbound_line() {
  local idx="$1" new_port="$2" new_out="$3"
  local tmp
  tmp="$(tmp_path inbounds.list)"
  : > "$tmp"
  local i=0
  while IFS='|' read -r tag port out remark; do
    [ -z "$tag" ] && continue
    i=$((i+1))
    if [ "$i" -eq "$idx" ]; then
      echo "${tag}|${new_port:-$port}|${new_out:-$out}|${remark}" >> "$tmp"
    else
      echo "${tag}|${port}|${out}|${remark}" >> "$tmp"
    fi
  done < "$INBOUNDS_FILE"
  mv "$tmp" "$INBOUNDS_FILE"
}

remove_inbound_line() {
  local idx="$1"
  local tmp
  tmp="$(tmp_path inbounds.list)"
  : > "$tmp"
  local i=0
  while IFS='|' read -r tag port out remark; do
    [ -z "$tag" ] && continue
    i=$((i+1))
    if [ "$i" -ne "$idx" ]; then
      echo "${tag}|${port}|${out}|${remark}" >> "$tmp"
    fi
  done < "$INBOUNDS_FILE"
  mv "$tmp" "$INBOUNDS_FILE"
}

change_port() {
  local idx new_port
  idx="$(select_inbound_index)" || return 0
  new_port="$(prompt_port)"
  update_inbound_line "$idx" "$new_port" ""
  build_config
  restart_xray_with_check "$new_port"
  msg "端口已更新。"
}

change_outbound() {
  local idx new_out
  idx="$(select_inbound_index)" || return 0
  new_out="$(choose_outbound)"
  update_inbound_line "$idx" "" "$new_out"
  build_config
  restart_xray
  test_outbound "$new_out"
  msg "出口已更新。"
}

change_protocol() {
  msg "Xray 当前仅支持 VLESS Reality (TCP)，暂无可切换协议。"
}

remove_inbound() {
  local idx
  idx="$(select_inbound_index)" || return 0
  remove_inbound_line "$idx"
  if [ ! -s "$INBOUNDS_FILE" ]; then
    stop_xray
    msg "已无入口，Xray 已停止。"
    return 0
  fi
  build_config
  restart_xray
  msg "入口已删除。"
}

build_config() {
  load_manager_conf
  ensure_direct_outbounds
  sanitize_inbounds

  if [ ! -s "$INBOUNDS_FILE" ]; then
    die "未配置任何入口。"
  fi

  local tmp dns_query_strategy
  dns_query_strategy="UseIPv4"
  if ipv6_only; then
    dns_query_strategy="UseIPv6"
  fi
  tmp="$(tmp_path config.json)"
  local used_outbounds dns_bootstrap_domains
  used_outbounds="$(awk -F'|' 'NF>=3{print $3}' "$INBOUNDS_FILE" | awk '!seen[$0]++')"
  dns_bootstrap_domains=""
  if [ -n "$used_outbounds" ]; then
    while IFS= read -r out_tag; do
      [ -z "$out_tag" ] && continue
      while IFS= read -r raw_srv; do
        local srv
        [ -z "$raw_srv" ] && continue
        srv="$(normalize_domain_candidate "$raw_srv" || true)"
        [ -z "$srv" ] && continue
        if ! is_ip_addr "$srv" && is_domain_name "$srv"; then
          dns_bootstrap_domains="${dns_bootstrap_domains}${srv}\n"
        fi
      done < <(get_outbound_domains "$out_tag")
    done <<< "$used_outbounds"
    if [ -n "$dns_bootstrap_domains" ]; then
      dns_bootstrap_domains="$(printf "%b" "$dns_bootstrap_domains" | awk '!seen[$0]++')"
    fi
  fi
  local inbound_count=0 outbound_count=0 rule_count=0
  {
    echo '{'
    echo '  "log": {'
    echo '    "loglevel": "warning",'
    echo '    "access": "/var/log/xray/access.log",'
    echo '    "error": "/var/log/xray/error.log"'
    echo '  },'
    echo '  "dns": {'
    echo '    "servers": ['
    if [ -n "$dns_bootstrap_domains" ]; then
      echo '      { "address": "https://1.1.1.1/dns-query", "domains": ['
      local dns_domain_count=0
      while IFS= read -r domain; do
        [ -z "$domain" ] && continue
        if [ "$dns_domain_count" -gt 0 ]; then
          echo '        ,'
        fi
        dns_domain_count=$((dns_domain_count+1))
        echo "        \"domain:$(json_escape "$domain")\""
      done <<< "$dns_bootstrap_domains"
      echo '      ] },'
    fi
    echo '      "https://1.1.1.1/dns-query",'
    echo '      "https://8.8.8.8/dns-query",'
    echo '      "https://223.5.5.5/dns-query",'
    echo '      "https://[2606:4700:4700::1111]/dns-query",'
    echo '      "https://[2001:4860:4860::8888]/dns-query"'
    echo '    ],'
    echo "    \"queryStrategy\": \"${dns_query_strategy}\""
    echo '  },'
    echo '  "inbounds": ['
    while IFS='|' read -r tag port out remark; do
      [ -z "$tag" ] && continue
      inbound_count=$((inbound_count+1))
      if [ "$inbound_count" -gt 1 ]; then
        echo '    ,'
      fi
      cat <<EOF
    {
      "tag": "${tag}",
      "listen": "0.0.0.0",
      "port": ${port},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${DEST}",
          "xver": 0,
          "serverNames": ["${SERVER_NAME}"],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": ["${SHORT_ID}"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
EOF
    done < "$INBOUNDS_FILE"
    echo '  ],'
    echo '  "outbounds": ['
    for f in "${OUTBOUNDS_DIR}"/*.json; do
      [ -e "$f" ] || continue
      outbound_count=$((outbound_count+1))
      if [ "$outbound_count" -gt 1 ]; then
        echo '    ,'
      fi
      sed 's/^/    /' "$f"
    done
    echo '  ],'
    echo '  "routing": {'
    echo '    "domainStrategy": "IPIfNonMatch",'
    echo '    "rules": ['
    while IFS='|' read -r tag port out remark; do
      [ -z "$tag" ] && continue
      if [ ! -f "${OUTBOUNDS_DIR}/${out}.json" ]; then
        die "未找到出口: ${out}"
      fi
      rule_count=$((rule_count+1))
      if [ "$rule_count" -gt 1 ]; then
        echo '      ,'
      fi
      cat <<EOF
      {
        "type": "field",
        "inboundTag": ["${tag}"],
        "outboundTag": "${out}"
      }
EOF
    done < "$INBOUNDS_FILE"
    echo '    ]'
    echo '  }'
    echo '}'
  } > "$tmp"

  mv "$tmp" "${CONFIG_DIR}/config.json"
  validate_xray_config
}

get_public_ip4() {
  curl -4 -fsSL --max-time 6 https://api.ipify.org 2>/dev/null || true
}

get_public_ip6() {
  curl -6 -fsSL --max-time 6 https://api64.ipify.org 2>/dev/null || true
}

update_base_config() {
  load_manager_conf
  local ans
  read -r -p "Reality SNI [${SERVER_NAME}]: " SERVER_NAME_NEW
  SERVER_NAME="${SERVER_NAME_NEW:-$SERVER_NAME}"
  read -r -p "Reality 目标 [${DEST}]: " DEST_NEW
  DEST="${DEST_NEW:-$DEST}"
  read -r -p "分享地址 [${SHARE_HOST}]: " SHARE_HOST_NEW
  SHARE_HOST="${SHARE_HOST_NEW:-$SHARE_HOST}"
  read -r -p "重新生成 UUID？[y/N]: " ans
  case "$ans" in
    y|Y) UUID="$(gen_uuid)" ;;
  esac
  read -r -p "重新生成 Reality 密钥？[y/N]: " ans
  case "$ans" in
    y|Y)
      gen_reality_keys
      SHORT_ID="$(gen_short_id)"
      ;;
  esac
  save_manager_conf
  build_config
  restart_xray
  msg "基础配置已更新。"
}

init_base_config() {
  need_root
  ensure_dirs
  UUID="$(gen_uuid)"
  SHORT_ID="$(gen_short_id)"
  FINGERPRINT="chrome"
  gen_reality_keys

  read -r -p "Reality SNI(建议常见 TLS 域名，默认: ${DEFAULT_SNI}): " SERVER_NAME
  SERVER_NAME="${SERVER_NAME:-${DEFAULT_SNI}}"
  read -r -p "Reality 目标(默认: ${SERVER_NAME}:443): " DEST
  DEST="${DEST:-${SERVER_NAME}:443}"
  read -r -p "分享地址(域名或IP，留空自动获取): " SHARE_HOST

  save_manager_conf
  > "$INBOUNDS_FILE"
}

install_flow() {
  need_root
  install_deps
  install_xray
  ensure_dirs
  enable_accel
  write_service
  write_openrc_service
  setup_logrotate

  msg "安装完成。"
  msg "请在菜单中新增入口。"
}

uninstall_all() {
  need_root
  stop_xray
  if systemd_available; then
    systemctl disable xray >/dev/null 2>&1 || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload || true
  elif openrc_available; then
    rc-service xray stop >/dev/null 2>&1 || true
    rc-update del xray default >/dev/null 2>&1 || true
    rm -f "$OPENRC_SERVICE"
  fi
  rm -rf "$CONFIG_DIR"
  rm -f /etc/sysctl.d/99-xray-accel.conf
  sysctl --system >/dev/null 2>&1 || true
  rm -f "$XRAY_BIN"
  rm -f "$LOGROTATE_FILE"
  rm -f "$PID_FILE"
  rm -f "$WGCF_DST"
  rm -rf /var/log/xray
  rm -rf /usr/local/share/xray
  rm -rf "$TMP_DIR"
  msg "已卸载。"
}

show_status() {
  local active enabled pid
  if systemd_available; then
    if systemctl is-active --quiet xray; then
      active="运行中"
    else
      active="未运行"
    fi
    if systemctl is-enabled --quiet xray; then
      enabled="已设置开机自启"
    else
      enabled="未设置开机自启"
    fi
    pid="$(systemctl show -p MainPID --value xray 2>/dev/null || true)"
    [ -z "$pid" ] && pid="0"
    msg "服务状态: ${active}"
    msg "自启状态: ${enabled}"
    msg "主进程 PID: ${pid}"
  elif openrc_available; then
    if rc-service xray status >/dev/null 2>&1; then
      active="运行中"
    else
      active="未运行"
    fi
    if rc-update show default 2>/dev/null | awk '{print $1}' | grep -qx "xray"; then
      enabled="已设置开机自启"
    else
      enabled="未设置开机自启"
    fi
    pid="0"
    if [ -f "$PID_FILE" ]; then
      pid="$(cat "$PID_FILE" 2>/dev/null || echo 0)"
    fi
    msg "服务状态: ${active}"
    msg "自启状态: ${enabled}"
    msg "主进程 PID: ${pid}"
  else
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" >/dev/null 2>&1; then
      msg "服务状态: 运行中 (PID $(cat "$PID_FILE"))"
    else
      msg "服务状态: 未运行"
    fi
  fi
  if [ -f /var/log/xray/xray.log ]; then
    msg "日志路径: /var/log/xray/xray.log"
    msg "日志大小: $(stat -c %s /var/log/xray/xray.log 2>/dev/null || echo 0) 字节"
  fi
}

show_info() {
  if [ ! -f "$MANAGER_CONF" ]; then
    msg "未初始化，请先新增入口或更新基础配置。"
    return 0
  fi
  load_manager_conf
  local host4 host6 host link_host have_share
  link_host=""
  have_share=0
  if [ -n "${SHARE_HOST:-}" ]; then
    link_host="$SHARE_HOST"
    have_share=1
  else
    host4="$(get_public_ip4)"
    host6="$(get_public_ip6)"
  fi

  msg "Reality 参数："
  msg "  UUID: ${UUID}"
  msg "  公钥: ${PUBLIC_KEY}"
  msg "  ShortID: ${SHORT_ID}"
  msg "  SNI: ${SERVER_NAME}"
  msg "  目标: ${DEST}"

  if [ ! -f "$INBOUNDS_FILE" ] || [ ! -s "$INBOUNDS_FILE" ]; then
    msg "入口列表：暂无入口。"
    return 0
  fi

  if [ "$have_share" -eq 1 ]; then
    host="$link_host"
  fi

  msg "入口列表："
  while IFS='|' read -r tag port out remark; do
    [ -z "$tag" ] && continue
    local alias frag
    alias="${remark:-$tag}"
    frag="$(urlencode "$alias")"
    msg "  ${tag}  端口=${port}  出口=${out}"
    if [ "$have_share" -eq 1 ]; then
      msg "  vless://${UUID}@${host}:${port}?encryption=none&security=reality&sni=${SERVER_NAME}&fp=${FINGERPRINT}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&flow=xtls-rprx-vision#${frag}"
    else
      if [ -n "$host4" ]; then
        msg "  vless://${UUID}@${host4}:${port}?encryption=none&security=reality&sni=${SERVER_NAME}&fp=${FINGERPRINT}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&flow=xtls-rprx-vision#${frag}"
      fi
      if [ -n "$host6" ]; then
        msg "  vless://${UUID}@[${host6}]:${port}?encryption=none&security=reality&sni=${SERVER_NAME}&fp=${FINGERPRINT}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&flow=xtls-rprx-vision#${frag}"
      fi
      if [ -z "$host4" ] && [ -z "$host6" ]; then
        msg "  vless://${UUID}@SERVER_IP:${port}?encryption=none&security=reality&sni=${SERVER_NAME}&fp=${FINGERPRINT}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&flow=xtls-rprx-vision#${frag}"
      fi
    fi
  done < "$INBOUNDS_FILE"
}

restart_service() {
  restart_xray
  msg "服务已重启。"
  show_status
}

main_menu() {
  local choice
  while true; do
    msg ""
    menu_title "Xray Reality 一键脚本"
    msg "${C_DIM}(${OS_NAME} ${OS_VERSION} / ${ARCH_LABEL})${C_RESET}"
    menu_sep
    if [ -x "$XRAY_BIN" ]; then
      sanitize_inbounds
      setup_logrotate
      menu_item 1 "新增入口"
      menu_item 2 "修改入口端口"
      menu_item 3 "修改入口协议"
      menu_item 4 "修改入口出口"
      menu_item 5 "自定义出口管理"
      menu_item 6 "删除入口"
      menu_item 7 "更新基础配置(SNI/UUID/密钥)"
      menu_item 8 "显示连接信息"
      menu_item 9 "查看运行状态"
      menu_item 10 "重启服务"
      menu_item 11 "网络调优切换"
      menu_item 12 "卸载"
      menu_item 0 "退出"
      read -r -p "请选择: " choice
      if [ ! -f "$MANAGER_CONF" ] && [ "$choice" != "1" ] && [ "$choice" != "0" ] && [ "$choice" != "11" ] && [ "$choice" != "12" ]; then
        msg "请先通过“新增入口”初始化基础配置。"
        continue
      fi
      case "$choice" in
        1) add_inbound ;;
        2) change_port ;;
        3) change_protocol ;;
        4) change_outbound ;;
        5) manage_custom_outbounds ;;
        6) remove_inbound ;;
        7) update_base_config ;;
        8) show_info ;;
        9) show_status ;;
        10) restart_service ;;
        11) apply_tuning_profile ;;
        12) uninstall_all ;;
        0) exit 0 ;;
      esac
    else
      menu_item 1 "安装"
      menu_item 0 "退出"
      read -r -p "请选择: " choice
      case "$choice" in
        1) install_flow ;;
        0) exit 0 ;;
      esac
    fi
  done
}

need_root
ensure_bash
init_colors
check_os
ARCH_LABEL="$(get_arch_label)"
main_menu
