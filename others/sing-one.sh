#!/usr/bin/env bash
# 适用系统: Debian 11~13 / Ubuntu 20.04~24.04 / Alpine（Alpine 需先安装 bash: apk add bash）
# 适用架构: x86/x64/arm64/arm32
# 适用环境: 物理机 / KVM / LXC / Docker（容器场景会使用保守的加速参数）
# 功能概述: sing-box + Reality 一键部署/管理，支持多入口与多出口
# DNS 说明: 内置 DNS，默认优先 IPv4；IPv6-only 会自动切换；DNS 可随出口分流
set -euo pipefail

SB_BIN="/usr/local/bin/sing-box"
CONFIG_DIR="/etc/sing-box"
MANAGER_CONF="${CONFIG_DIR}/manager.conf"
INBOUNDS_FILE="${CONFIG_DIR}/inbounds.list"
OUTBOUNDS_DIR="${CONFIG_DIR}/outbounds.d"
ENDPOINTS_DIR="${CONFIG_DIR}/endpoints.d"
FEATURE_ROUTES_FILE="${CONFIG_DIR}/feature-routes.list"
HY2_CERT="${CONFIG_DIR}/hy2.crt"
HY2_KEY="${CONFIG_DIR}/hy2.key"
SERVICE_FILE="/etc/systemd/system/sing-box.service"
SERVICE_DROPIN_DIR="/etc/systemd/system/sing-box.service.d"
SERVICE_DROPIN_FILE="${SERVICE_DROPIN_DIR}/zzzz-onekey.conf"
LOGROTATE_FILE="/etc/logrotate.d/sing-box"
PID_FILE="/run/sing-box.pid"
OPENRC_SERVICE="/etc/init.d/sing-box"
TMP_DIR="/tmp/singbox-onekey"
SB_TGZ="${TMP_DIR}/sing-box.tar.gz"
SB_UNPACK_DIR="${TMP_DIR}/sing-box_unpack"
WGCF_BIN="${TMP_DIR}/wgcf"
WGCF_DST="/usr/local/bin/wgcf"
WGCF_DIR="${TMP_DIR}/wgcf_work"
ACME_BIN="/root/.acme.sh/acme.sh"
DEFAULT_SNI="www.apple.com"
HY2_CERT_MODE="self"
HY2_DOMAIN=""
DEFAULT_HY2_MASQUERADE="https://www.cloudflare.com"
AUTO_PROTO=""
SB_HAS_DNS_NEW=""
SB_HAS_DOMAIN_RESOLVER=""
SB_HAS_ROUTE_DEFAULT_DOMAIN_RESOLVER=""
SB_HAS_WG_NEW=""
SB_HAS_HY2_MASQ=""
SB_HAS_HY2_IGNORE_BW=""
SB_HAS_TLS_PIN=""

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
version_ge() {
  local a b
  a="$(printf '%s' "$1" | sed 's/[^0-9.].*//')"
  b="$(printf '%s' "$2" | sed 's/[^0-9.].*//')"
  awk -v A="$a" -v B="$b" 'BEGIN{
    split(A, a, ".");
    split(B, b, ".");
    for (i=1; i<=4; i++) {
      ai = (a[i] == "" ? 0 : a[i]) + 0;
      bi = (b[i] == "" ? 0 : b[i]) + 0;
      if (ai > bi) exit 0;
      if (ai < bi) exit 1;
    }
    exit 0;
  }'
}
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
  mkdir -p "$CONFIG_DIR" "$OUTBOUNDS_DIR" "$ENDPOINTS_DIR" /var/log/sing-box
}

install_deps() {
  msg "安装依赖中..."
  ensure_tmp_dir
  if is_alpine; then
    cmd_exists apk || die "未找到 apk，无法安装依赖。"
    apk add --no-cache curl ca-certificates logrotate
    return 0
  fi
  apt-get update -y
  apt-get install -y --no-install-recommends curl ca-certificates logrotate
}

detect_arch_singbox() {
  case "$(uname -m)" in
    x86_64|amd64) echo "linux-amd64" ;;
    i386|i486|i586|i686|x86) echo "linux-386" ;;
    aarch64|arm64) echo "linux-arm64" ;;
    armv7l|armv7|armhf|arm) echo "linux-armv7" ;;
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

get_singbox_version() {
  local ver loc
  ver="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null || true)"
  ver="$(printf '%s' "$ver" | sed -n 's/.*"tag_name": *"v\\([^"]*\\)".*/\\1/p')"
  if [ -z "$ver" ]; then
    loc="$(curl -fsSLI https://github.com/SagerNet/sing-box/releases/latest 2>/dev/null || true)"
    loc="$(printf '%s' "$loc" | awk 'tolower($0) ~ /^location:/ {print $2; exit}' | tr -d '\r')"
    ver="$(echo "$loc" | awk -F'/' '{print $NF}' | sed 's/^v//')"
  fi
  if [ -z "$ver" ]; then
    ui "无法自动获取 sing-box 版本。"
    read -r -p "请手动输入 sing-box 版本(如 1.10.0)，留空取消: " ver
  fi
  echo "$ver"
}

install_singbox() {
  local ver arch file url
  ver="$(get_singbox_version)"
  [ -z "$ver" ] && die "已取消安装。"
  arch="$(detect_arch_singbox)"
  file="sing-box-${ver}-${arch}.tar.gz"
  url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/${file}"

  ensure_tmp_dir
  rm -rf "$SB_UNPACK_DIR"
  mkdir -p "$SB_UNPACK_DIR"

  msg "下载 sing-box 中: ${SB_TGZ}"
  curl -fsSL -o "$SB_TGZ" "$url"
  tar -xzf "$SB_TGZ" -C "$SB_UNPACK_DIR"

  local bin
  bin="$(find "$SB_UNPACK_DIR" -type f -name sing-box | head -n 1)"
  [ -z "$bin" ] && die "未找到 sing-box 二进制。"
  install -m 755 "$bin" "$SB_BIN"
}

write_service() {
  if ! systemd_available; then
    return 0
  fi
  cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=sing-box Service
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
User=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
TasksMax=infinity
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  mkdir -p "$SERVICE_DROPIN_DIR"
  cat > "$SERVICE_DROPIN_FILE" <<'EOF'
[Service]
TasksMax=infinity
LimitNOFILE=1048576
EOF
  systemctl daemon-reload
}

write_openrc_service() {
  if ! openrc_available; then
    return 0
  fi
  cat > "$OPENRC_SERVICE" <<'EOF'
#!/sbin/openrc-run
name="sing-box"
description="sing-box Service"
command="/usr/local/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/sing-box.pid"
output_log="/var/log/sing-box/sing-box.log"
error_log="/var/log/sing-box/sing-box.log"

depend() {
  need net
}
EOF
  chmod +x "$OPENRC_SERVICE"
}

setup_logrotate() {
  mkdir -p "$(dirname "$LOGROTATE_FILE")"
  cat > "$LOGROTATE_FILE" <<'EOF'
/var/log/sing-box/*.log {
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

start_singbox() {
  ensure_dirs
  if systemd_available; then
    write_service
    systemctl enable --now sing-box
  elif openrc_available; then
    write_openrc_service
    rc-update add sing-box default >/dev/null 2>&1 || true
    rc-service sing-box start
  else
    mkdir -p "$(dirname "$PID_FILE")" 2>/dev/null || true
    nohup "$SB_BIN" run -c "${CONFIG_DIR}/config.json" >/var/log/sing-box/sing-box.log 2>&1 &
    echo $! > "$PID_FILE" 2>/dev/null || true
  fi
}

stop_singbox() {
  if systemd_available; then
    systemctl stop sing-box || true
  elif openrc_available; then
    rc-service sing-box stop >/dev/null 2>&1 || true
  else
    if [ -f "$PID_FILE" ]; then
      kill "$(cat "$PID_FILE")" >/dev/null 2>&1 || true
      rm -f "$PID_FILE"
    fi
  fi
}

restart_singbox() {
  if systemd_available; then
    write_service
    systemctl enable sing-box >/dev/null 2>&1 || true
    systemctl restart sing-box
  elif openrc_available; then
    write_openrc_service
    rc-service sing-box restart
  else
    stop_singbox
    start_singbox
  fi
}

restart_singbox_with_check() {
  local port="$1"
  restart_singbox
  if [ -n "$port" ] && ! wait_port_listen "$port"; then
    ui "检测到端口未监听，尝试再次重启 sing-box..."
    restart_singbox
    if ! wait_port_listen "$port"; then
      ui "重启后端口仍未监听，请检查服务状态/日志/防火墙。"
      diagnose_start_failure
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
      cat > /etc/sysctl.d/99-singbox-accel.conf <<'EOF'
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
      apply_sysctl_changes /etc/sysctl.d/99-singbox-accel.conf
      ;;
    lxc|container)
      if [ -r /proc/sys/net/ipv4/tcp_available_congestion_control ] && \
         grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control; then
        cc="bbr"
      else
        cc="cubic"
      fi
      qdisc="fq_codel"
      cat > /etc/sysctl.d/99-singbox-accel.conf <<EOF
net.core.default_qdisc=${qdisc}
net.ipv4.tcp_congestion_control=${cc}
EOF
      apply_sysctl_changes /etc/sysctl.d/99-singbox-accel.conf
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
      rm -f /etc/sysctl.d/99-singbox-accel.conf
      apply_sysctl_changes
      msg "已恢复默认(删除脚本调优)。"
      ;;
    2)
      modprobe tcp_bbr >/dev/null 2>&1 || true
      cat > /etc/sysctl.d/99-singbox-accel.conf <<'EOF'
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
      apply_sysctl_changes /etc/sysctl.d/99-singbox-accel.conf
      msg "已应用保守调优。"
      ;;
    3)
      modprobe tcp_bbr >/dev/null 2>&1 || true
      cat > /etc/sysctl.d/99-singbox-accel.conf <<'EOF'
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
      apply_sysctl_changes /etc/sysctl.d/99-singbox-accel.conf
      msg "已应用激进调优。"
      ;;
    *)
      msg "已取消。"
      ;;
  esac
}
gen_short_id() {
  if cmd_exists od; then
    od -An -N8 -tx1 /dev/urandom | tr -d ' \n'
  elif cmd_exists hexdump; then
    hexdump -n 8 -e '8/1 "%02x"' /dev/urandom
  else
    dd if=/dev/urandom bs=8 count=1 2>/dev/null | xxd -p | tr -d '\n'
  fi
}

gen_uuid() {
  cat /proc/sys/kernel/random/uuid
}

gen_reality_keys() {
  local out
  out="$("$SB_BIN" generate reality-keypair)"
  PRIVATE_KEY="$(echo "$out" | awk -F': *' '/^Private([ ]?key|Key)/ {print $2; exit}')"
  PUBLIC_KEY="$(echo "$out" | awk -F': *' '/^Public([ ]?key|Key)/ {print $2; exit}')"
  if [ -z "${PRIVATE_KEY:-}" ] || [ -z "${PUBLIC_KEY:-}" ]; then
    err "sing-box 输出:"
    err "$out"
    die "生成 Reality 密钥失败。"
  fi
}

gen_hy2_password() {
  if cmd_exists openssl; then
    openssl rand -base64 18 | tr -d '\n'
  else
    dd if=/dev/urandom bs=18 count=1 2>/dev/null | base64 | tr -d '\n'
  fi
}

gen_hy2_obfs_password() {
  if cmd_exists openssl; then
    openssl rand -base64 24 | tr -d '\n'
  else
    dd if=/dev/urandom bs=24 count=1 2>/dev/null | base64 | tr -d '\n'
  fi
}

hy2_cert_pin_sha256() {
  if [ ! -s "$HY2_CERT" ] || ! cmd_exists openssl; then
    return 1
  fi
  openssl x509 -in "$HY2_CERT" -outform der 2>/dev/null \
    | openssl dgst -sha256 -binary 2>/dev/null \
    | openssl base64 -A 2>/dev/null
}

normalize_hy2_masquerade_url() {
  local v
  v="$(printf '%s' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [ -z "$v" ] && v="$DEFAULT_HY2_MASQUERADE"
  if ! echo "$v" | grep -qiE '^(https?|file)://'; then
    v="https://${v}"
  fi
  printf '%s\n' "$v"
}

prompt_hy2_hardening() {
  local __obfs_var="$1" __masq_var="$2"
  local ans obfs_pass masq
  read -r -p "启用 HY2 混淆(obfs salamander，建议开启) [Y/n]: " ans
  case "$ans" in
    n|N)
      obfs_pass=""
      ;;
    *)
      read -r -p "HY2 混淆密码(留空自动生成): " obfs_pass
      if [ -z "$obfs_pass" ]; then
        obfs_pass="$(gen_hy2_obfs_password)"
        msg "已生成 HY2 混淆密码: ${obfs_pass}"
      fi
      ;;
  esac
  read -r -p "HY2 伪装目标(抗探测，留空默认: ${DEFAULT_HY2_MASQUERADE}): " masq
  masq="$(normalize_hy2_masquerade_url "$masq")"
  printf -v "$__obfs_var" '%s' "$obfs_pass"
  printf -v "$__masq_var" '%s' "$masq"
}

prompt_hy2_hardening_self() {
  local __obfs_var="$1" __masq_var="$2"
  local obfs_pass masq
  read -r -p "HY2 混淆密码(自签模式强制 obfs，留空自动生成): " obfs_pass
  if [ -z "$obfs_pass" ]; then
    obfs_pass="$(gen_hy2_obfs_password)"
    msg "已生成 HY2 混淆密码: ${obfs_pass}"
  fi
  masq="$(normalize_hy2_masquerade_url "")"
  printf -v "$__obfs_var" '%s' "$obfs_pass"
  printf -v "$__masq_var" '%s' "$masq"
}

split_host_port() {
  local in="$1" host port
  IFS='|' read -r host port <<< "$(parse_hostport "$in")"
  [ -z "$port" ] && port="443"
  echo "${host}|${port}"
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
HY2_CERT_MODE=${HY2_CERT_MODE:-self}
HY2_DOMAIN=${HY2_DOMAIN:-}
EOF
}

load_manager_conf() {
  if [ ! -f "$MANAGER_CONF" ]; then
    die "未初始化，请先安装。"
  fi
  # shellcheck source=/etc/sing-box/manager.conf
  . "$MANAGER_CONF"
  [ -z "${HY2_CERT_MODE:-}" ] && HY2_CERT_MODE="self"
  [ -z "${SERVER_NAME:-}" ] && SERVER_NAME="${DEFAULT_SNI}"
  [ -z "${DEST:-}" ] && DEST="${SERVER_NAME}:443"
  return 0
}

ensure_reality_material() {
  local changed=0
  [ -n "${UUID:-}" ] || { UUID="$(gen_uuid)"; changed=1; }
  [ -n "${SHORT_ID:-}" ] || { SHORT_ID="$(gen_short_id)"; changed=1; }
  [ -n "${FINGERPRINT:-}" ] || { FINGERPRINT="chrome"; changed=1; }
  [ -n "${SERVER_NAME:-}" ] || { SERVER_NAME="${DEFAULT_SNI}"; changed=1; }
  [ -n "${DEST:-}" ] || { DEST="${SERVER_NAME}:443"; changed=1; }
  if [ -z "${PRIVATE_KEY:-}" ] || [ -z "${PUBLIC_KEY:-}" ]; then
    gen_reality_keys
    changed=1
  fi
  if [ "$changed" -eq 1 ]; then
    save_manager_conf
  fi
}

ensure_direct_outbounds() {
  cat > "${OUTBOUNDS_DIR}/direct4.json" <<'EOF'
{
  "type": "direct",
  "tag": "direct4"
}
EOF
  cat > "${OUTBOUNDS_DIR}/direct6.json" <<'EOF'
{
  "type": "direct",
  "tag": "direct6"
}
EOF
}

ensure_hy2_cert() {
  if [ -s "$HY2_CERT" ] && [ -s "$HY2_KEY" ]; then
    return 0
  fi
  ensure_openssl_dependency || die "未找到 openssl，无法生成/申请 HY2 证书。"
  if [ "${HY2_CERT_MODE:-self}" = "acme" ]; then
    issue_hy2_acme_cert
    return 0
  fi
  msg "生成 Hysteria2 自签证书..."
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/CN=${SERVER_NAME}" \
    -keyout "$HY2_KEY" -out "$HY2_CERT" >/dev/null 2>&1
  chmod 600 "$HY2_KEY"
}

ensure_cron_dependency() {
  if cmd_exists crontab; then
    return 0
  fi
  msg "安装 cron 依赖中..."
  if is_alpine; then
    apk add --no-cache cronie >/dev/null 2>&1 || true
  else
    apt-get update -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cron >/dev/null 2>&1 || true
  fi
  if ! cmd_exists crontab; then
    ui "未检测到 crontab，将继续使用 acme.sh --force 安装模式。"
    return 1
  fi
  if systemd_available; then
    systemctl enable --now cron >/dev/null 2>&1 || systemctl enable --now crond >/dev/null 2>&1 || true
  elif openrc_available; then
    rc-update add crond default >/dev/null 2>&1 || true
    rc-service crond start >/dev/null 2>&1 || true
  fi
  return 0
}

ensure_openssl_dependency() {
  if cmd_exists openssl; then
    return 0
  fi
  msg "安装 openssl 依赖中..."
  if is_alpine; then
    apk add --no-cache openssl >/dev/null 2>&1 || true
  else
    apt-get update -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssl >/dev/null 2>&1 || true
  fi
  cmd_exists openssl
}

ensure_acme_sh() {
  ensure_cron_dependency || true
  if [ -x "$ACME_BIN" ]; then
    return 0
  fi
  msg "安装 acme.sh..."
  curl -fsSL https://get.acme.sh | sh >/dev/null 2>&1 || true
  if [ ! -x "$ACME_BIN" ]; then
    msg "检测到无 crontab 环境，尝试 --force 安装 acme.sh..."
    curl -fsSL https://get.acme.sh | sh -s -- --force >/dev/null 2>&1 || true
  fi
  [ -x "$ACME_BIN" ] || die "acme.sh 安装失败，请检查网络或手动执行: curl -fsSL https://get.acme.sh | sh -s -- --force"
  "$ACME_BIN" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
}

issue_hy2_acme_cert() {
  local domain token ip_choice ip_addr update_dns
  domain="${HY2_DOMAIN:-}"
  if [ -z "$domain" ]; then
    read -r -p "HY2 证书域名(需解析到本机): " domain
  fi
  [ -z "$domain" ] && die "域名不能为空。"
  token="${CF_Token:-}"
  if [ -z "$token" ]; then
    read -r -p "Cloudflare Token (DNS): " token
  fi
  [ -z "$token" ] && die "CF Token 不能为空。"
  read -r -p "是否自动更新 ${domain} 解析到本机? [y/N]: " update_dns
  case "$update_dns" in
    y|Y)
      ui "${C_BOLD}${C_BLUE}解析类型：${C_RESET}"
      ui "  ${C_YELLOW}1)${C_RESET} IPv4 (A 记录，默认)"
      ui "  ${C_YELLOW}2)${C_RESET} IPv6 (AAAA 记录)"
      read -r -p "请选择 [1-2]: " ip_choice
      case "$ip_choice" in
        2)
          ip_addr="$(get_public_ip6)"
          [ -z "$ip_addr" ] && die "未获取到 IPv6 公网地址。"
          cf_upsert_dns_record "$domain" "AAAA" "$ip_addr" "$token"
          ;;
        *)
          ip_addr="$(get_public_ip4)"
          [ -z "$ip_addr" ] && die "未获取到 IPv4 公网地址。"
          cf_upsert_dns_record "$domain" "A" "$ip_addr" "$token"
          ;;
      esac
      ;;
    *)
      msg "跳过 A/AAAA 解析更新，直接使用 Cloudflare DNS API 申请证书。"
      ;;
  esac

  ensure_acme_sh
  export CF_Token="$token"
  "$ACME_BIN" --issue --dns dns_cf --server letsencrypt -d "$domain" --keylength 2048 || die "申请证书失败。"
  unset CF_Token
  "$ACME_BIN" --install-cert -d "$domain" \
    --key-file "$HY2_KEY" \
    --fullchain-file "$HY2_CERT" || die "安装证书失败。"
  chmod 600 "$HY2_KEY"
  HY2_DOMAIN="$domain"
  HY2_CERT_MODE="acme"
  save_manager_conf
  msg "证书已签发并安装: ${domain}"
}

cf_api_error_message() {
  local resp="$1" msg code
  msg="$(echo "$resp" | sed -n 's/.*"message":"\([^"]\+\)".*/\1/p' | head -n1)"
  code="$(echo "$resp" | sed -n 's/.*"code":\([0-9]\+\).*/\1/p' | head -n1)"
  if [ -n "$msg" ] || [ -n "$code" ]; then
    printf '%s\n' "code=${code:-N/A}, message=${msg:-unknown}"
    return 0
  fi
  printf '%s\n' "unknown error"
}

cf_upsert_dns_record() {
  local full_domain="$1" record_type="$2" ip_addr="$3" token="$4" zone_id_in="${5:-}"
  local zone_name zone_id record_id payload resp
  if [ -n "$zone_id_in" ]; then
    zone_id="$zone_id_in"
  else
    zone_name="$(cf_find_zone "$full_domain" "$token")"
    [ -z "$zone_name" ] && die "未找到域名对应的 Zone，请检查域名是否在 Cloudflare。"
    zone_id="$(cf_get_zone_id "$zone_name" "$token")"
    [ -z "$zone_id" ] && die "未获取到 Zone ID，请检查 Token 权限。"
  fi
  record_id="$(cf_get_record_id "$zone_id" "$record_type" "$full_domain" "$token")"
  payload="{\"type\":\"${record_type}\",\"name\":\"${full_domain}\",\"content\":\"${ip_addr}\",\"ttl\":120,\"proxied\":false}"
  if [ -n "$record_id" ]; then
    resp="$(curl -sS -X PUT "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}" \
      -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" \
      --data "$payload" || true)"
  else
    resp="$(curl -sS -X POST "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records" \
      -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" \
      --data "$payload" || true)"
  fi
  if ! echo "$resp" | grep -q '"success":true'; then
    die "Cloudflare DNS 记录设置失败: $(cf_api_error_message "$resp")"
  fi
  msg "DNS 记录已更新: ${full_domain} -> ${ip_addr}"
}

cf_find_zone() {
  local full_domain="$1" token="$2" candidate zone_id
  candidate="$full_domain"
  while [ -n "$candidate" ]; do
    zone_id="$(cf_get_zone_id "$candidate" "$token" || true)"
    if [ -n "$zone_id" ]; then
      echo "$candidate"
      return 0
    fi
    if [ "$candidate" = "${candidate#*.}" ]; then
      break
    fi
    candidate="${candidate#*.}"
  done
  echo ""
}

cf_get_zone_id() {
  local zone_name="$1" token="$2" resp zone_id
  resp="$(curl -sS -G "https://api.cloudflare.com/client/v4/zones" \
    -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" \
    --data-urlencode "name=${zone_name}" --data-urlencode "status=active" || true)"
  zone_id="$(echo "$resp" | sed -n 's/.*"id":"\([a-f0-9]\{32\}\)".*/\1/p' | head -n1)"
  if [ -z "$zone_id" ]; then
    resp="$(curl -sS -G "https://api.cloudflare.com/client/v4/zones" \
      -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" \
      --data-urlencode "name=${zone_name}" || true)"
    zone_id="$(echo "$resp" | sed -n 's/.*"id":"\([a-f0-9]\{32\}\)".*/\1/p' | head -n1)"
  fi
  if [ -n "$zone_id" ]; then
    echo "$zone_id"
    return 0
  fi
  return 1
}

cf_get_record_id() {
  local zone_id="$1" record_type="$2" record_name="$3" token="$4" resp
  resp="$(curl -sS -G "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records" \
    -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" \
    --data-urlencode "type=${record_type}" --data-urlencode "name=${record_name}" || true)"
  echo "$resp" | sed -n 's/.*"id":"\([a-f0-9]\{32\}\)".*/\1/p' | head -n1
}

normalize_inbound_proto() {
  case "${1:-}" in
    hy2) echo "hy2" ;;
    *) echo "vless" ;;
  esac
}

port_usage_with_proto() {
  local port="$1" _wanted_proto="$2" exclude_idx="${3:-0}"
  local i=0 cur_port
  [ -f "$INBOUNDS_FILE" ] || { echo "free"; return 0; }
  while IFS='|' read -r tag cur_port _r1 _r2 _r3 _r4 _r5 _r6 _r7 _r8; do
    [ -z "$tag" ] && continue
    i=$((i+1))
    if [ "$exclude_idx" -gt 0 ] && [ "$i" -eq "$exclude_idx" ]; then
      continue
    fi
    if [ "$cur_port" = "$port" ]; then
      echo "conflict"
      return 0
    fi
  done < "$INBOUNDS_FILE"
  echo "free"
}

port_is_listening() {
  local port="$1"
  if cmd_exists ss; then
    ss -ln "( sport = :${port} )" | tail -n +2 | grep -q .
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
  local outbound_file endpoint_file
  outbound_file="${OUTBOUNDS_DIR}/${tag}.json"
  endpoint_file="${ENDPOINTS_DIR}/${tag}.json"
  if [ ! -f "$outbound_file" ] && [ ! -f "$endpoint_file" ]; then
    ui "跳过出口测试：未找到配置 ${tag}"
    return 0
  fi
  if [ ! -x "$SB_BIN" ]; then
    ui "跳过出口测试：未找到 sing-box"
    return 0
  fi
  if ! cmd_exists curl; then
    ui "跳过出口测试：未安装 curl"
    return 0
  fi
  if [ ! -f "$outbound_file" ] && [ -f "$endpoint_file" ]; then
    ui "出口 ${tag} 为 endpoints 类型，暂不支持自动测试"
    return 0
  fi
  local port cfg logf pid ip
  port="$(pick_free_port)"
  cfg="$(tmp_path outbound-test.json)"
  logf="$(tmp_path outbound-test.log)"
  cat > "$cfg" <<EOF
{
  "log": {"disabled": true},
  "inbounds": [
    {
      "type": "socks",
      "tag": "test-in",
      "listen": "127.0.0.1",
      "listen_port": ${port}
    }
  ],
  "outbounds": [
$(sed 's/^/    /' "$outbound_file")
  ],
  "route": {
    "rules": [
      {
        "inbound": ["test-in"],
        "outbound": "$(json_escape "$tag")"
      }
    ]
  }
}
EOF
  "$SB_BIN" run -c "$cfg" >"$logf" 2>&1 &
  pid=$!
  wait_port_listen "$port" || true
  ip="$(probe_socks_outbound_ip "$port" || true)"
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
  rm -f "$cfg" "$logf"
  if [ -n "$ip" ]; then
    msg "出口 ${tag} 测试成功，出口 IP: ${ip}"
  else
    ui "出口 ${tag} 测试失败（探测源不可达或返回非 IP）"
  fi
}

probe_socks_outbound_ip() {
  local port="$1" tries url raw ip
  for tries in 1 2; do
    for url in \
      "https://api.ip.sb/ip" \
      "https://ip.sb" \
      "https://api.ipify.org" \
      "https://ifconfig.me/ip" \
      "https://ipv4.icanhazip.com"; do
      raw="$(curl -fsSL --connect-timeout 4 --max-time 10 --proxy "socks5h://127.0.0.1:${port}" "$url" 2>/dev/null || \
             curl -fsSL --connect-timeout 4 --max-time 10 --socks5-hostname "127.0.0.1:${port}" "$url" 2>/dev/null || true)"
      ip="$(printf '%s' "$raw" | awk 'NF{gsub(/\r/,"",$0); gsub(/[[:space:]]+/,"",$0); print; exit}')"
      if [ -n "$ip" ] && is_ip_addr "$ip"; then
        echo "$ip"
        return 0
      fi
    done
    sleep 1
  done
  return 1
}

prompt_port() {
  local proto="${1:-vless}" exclude_idx="${2:-0}" port ans usage
  proto="$(normalize_inbound_proto "$proto")"
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
    usage="$(port_usage_with_proto "$port" "$proto" "$exclude_idx")"
    case "$usage" in
      conflict)
        ui "该端口已被其他入口使用，不能重复。"
        ;;
      *) ;;
    esac
    [ "$usage" = "conflict" ] && continue
    if [ "$usage" = "free" ] && port_is_listening "$port"; then
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

resolve_domain_ipv4() {
  local host="$1" ip
  if cmd_exists getent; then
    ip="$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1; exit}')"
    [ -n "$ip" ] && { echo "$ip"; return 0; }
  fi
  if cmd_exists curl; then
    ip="$(curl -fsSL --max-time 6 "https://1.1.1.1/dns-query?name=${host}&type=A" \
      -H 'accept: application/dns-json' 2>/dev/null \
      | sed -n 's/.*"Answer":[[][^]]*"data":"\([0-9.]\+\)".*/\1/p' | head -n1)"
    [ -n "$ip" ] && { echo "$ip"; return 0; }
  fi
  return 1
}

resolve_domain_ipv6() {
  local host="$1" ip
  if cmd_exists getent; then
    ip="$(getent ahostsv6 "$host" 2>/dev/null | awk 'NR==1{print $1; exit}')"
    [ -n "$ip" ] && { echo "$ip"; return 0; }
  fi
  if cmd_exists curl; then
    ip="$(curl -fsSL --max-time 6 "https://1.1.1.1/dns-query?name=${host}&type=AAAA" \
      -H 'accept: application/dns-json' 2>/dev/null \
      | sed -n 's/.*"Answer":[[][^]]*"data":"\([0-9a-fA-F:]\+\)".*/\1/p' | head -n1)"
    [ -n "$ip" ] && { echo "$ip"; return 0; }
  fi
  return 1
}

warp_endpoint_host_for_family() {
  local raw="$1" family="$2" host port ip
  IFS='|' read -r host port <<< "$(parse_hostport "$raw")"
  [ -z "$host" ] && host="$raw"
  if is_ip_addr "$host"; then
    if [ "$family" = "4" ]; then
      echo "$host" | grep -q ":" && return 1
      echo "$host"
      return 0
    fi
    echo "$host" | grep -q ":" || return 1
    echo "$host"
    return 0
  fi
  if [ "$family" = "4" ]; then
    ip="$(resolve_domain_ipv4 "$host" || true)"
    [ -n "$ip" ] || return 1
    echo "$ip"
    return 0
  fi
  ip="$(resolve_domain_ipv6 "$host" || true)"
  [ -n "$ip" ] || return 1
  echo "$ip"
  return 0
}

get_warp_endpoint_field() {
  local file="$1" v
  v="$(sed -n 's/.*"server"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' "$file" | head -n1)"
  if [ -n "$v" ]; then
    echo "server|$v"
    return 0
  fi
  v="$(sed -n 's/.*"address"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' "$file" | head -n1)"
  if [ -n "$v" ]; then
    echo "address|$v"
    return 0
  fi
  echo "|"
}

warp_profile_endpoint_raw() {
  local profile endpoint
  profile="${CONFIG_DIR}/warp/wgcf-profile.conf"
  [ -f "$profile" ] || return 1
  endpoint="$(awk -F' = ' '/^Endpoint/ {print $2; exit}' "$profile" | tr -d '[:space:]')"
  [ -n "$endpoint" ] || return 1
  printf '%s\n' "$endpoint"
}

get_outbound_domains() {
  local tag="$1" f
  if [ -f "${OUTBOUNDS_DIR}/${tag}.json" ]; then
    f="${OUTBOUNDS_DIR}/${tag}.json"
  elif [ -f "${ENDPOINTS_DIR}/${tag}.json" ]; then
    f="${ENDPOINTS_DIR}/${tag}.json"
  else
    f=""
  fi
  if [ -n "$f" ]; then
    for key in server address endpoint server_name serverName sni host Host; do
      sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\\([^\"]\\+\\)\".*/\\1/p" "$f"
    done
  fi
  if [ -f "${OUTBOUNDS_DIR}/${tag}.link" ]; then
    sed -n 's/.*@\([^:/?#]*\).*/\1/p' "${OUTBOUNDS_DIR}/${tag}.link"
    sed -n 's/.*[?&]sni=\([^&]*\).*/\1/p' "${OUTBOUNDS_DIR}/${tag}.link"
    sed -n 's/.*[?&]host=\([^&]*\).*/\1/p' "${OUTBOUNDS_DIR}/${tag}.link"
  fi
}

json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

singbox_check_config() {
  local cfg="$1"
  [ -x "$SB_BIN" ] || return 1
  "$SB_BIN" check -c "$cfg" >/dev/null 2>&1
}

singbox_check_outbound_file() {
  local outbound_file="$1" t check_log
  t="$(tmp_path sb_outbound_probe.json)"
  check_log="$(tmp_path sb_outbound_probe.log)"
  {
    echo '{'
    echo '  "log": {"level": "warn"},'
    echo '  "outbounds": ['
    sed 's/^/    /' "$outbound_file"
    echo '  ]'
    echo '}'
  } > "$t"
  if "$SB_BIN" check -c "$t" >"$check_log" 2>&1; then
    rm -f "$check_log"
    SB_LAST_OUTBOUND_CHECK_LOG=""
    return 0
  fi
  SB_LAST_OUTBOUND_CHECK_LOG="$check_log"
  return 1
}

singbox_check_endpoint_file() {
  local endpoint_file="$1" t check_log
  t="$(tmp_path sb_endpoint_probe.json)"
  check_log="$(tmp_path sb_endpoint_probe.log)"
  {
    echo '{'
    echo '  "log": {"level": "warn"},'
    echo '  "outbounds": [{ "type": "direct", "tag": "direct" }],'
    echo '  "endpoints": ['
    sed 's/^/    /' "$endpoint_file"
    echo '  ]'
    echo '}'
  } > "$t"
  if "$SB_BIN" check -c "$t" >"$check_log" 2>&1; then
    rm -f "$check_log"
    SB_LAST_OUTBOUND_CHECK_LOG=""
    return 0
  fi
  SB_LAST_OUTBOUND_CHECK_LOG="$check_log"
  return 1
}

detect_singbox_features() {
  [ -n "${SB_HAS_DNS_NEW:-}" ] && return 0
  SB_HAS_DNS_NEW=1
  SB_HAS_DOMAIN_RESOLVER=1
  SB_HAS_ROUTE_DEFAULT_DOMAIN_RESOLVER=1
  SB_HAS_WG_NEW=1
  SB_HAS_HY2_MASQ=1
  SB_HAS_HY2_IGNORE_BW=1
  SB_HAS_TLS_PIN=1

  if [ ! -x "$SB_BIN" ]; then
    return 0
  fi

  local t sb_version
  sb_version="$("$SB_BIN" version 2>/dev/null | sed -n 's/^sing-box version \([0-9][0-9.]*\).*/\1/p' | head -n1)"
  if [ -n "$sb_version" ] && ! version_ge "$sb_version" "1.11.0"; then
    SB_HAS_HY2_MASQ=0
    SB_HAS_HY2_IGNORE_BW=0
  fi
  if [ -n "$sb_version" ] && ! version_ge "$sb_version" "1.13.0"; then
    SB_HAS_TLS_PIN=0
  fi

  t="$(tmp_path sb_feature.json)"
  cat > "$t" <<'EOF'
{
  "log": {"level":"warn"},
  "dns": {"servers": [{"tag":"d","type":"https","server":"1.1.1.1"}]},
  "outbounds": [{"type":"direct","tag":"direct"}]
}
EOF
  if ! singbox_check_config "$t"; then
    SB_HAS_DNS_NEW=0
  fi

  if [ "${SB_HAS_DNS_NEW}" -eq 1 ]; then
    cat > "$t" <<'EOF'
{
  "log": {"level":"warn"},
  "dns": {"servers": [{"tag":"dns_probe","type":"https","server":"1.1.1.1"}]},
  "outbounds": [
    {"type":"direct","tag":"direct", "domain_resolver": {"server":"dns_probe","strategy":"prefer_ipv4"}}
  ]
}
EOF
    if ! singbox_check_config "$t"; then
      SB_HAS_DOMAIN_RESOLVER=0
    fi
  else
    SB_HAS_DOMAIN_RESOLVER=0
  fi

  if [ "${SB_HAS_DNS_NEW}" -eq 1 ]; then
    cat > "$t" <<'EOF'
{
  "log": {"level":"warn"},
  "dns": {"servers": [{"tag":"dns_probe","type":"https","server":"1.1.1.1"}]},
  "route": {"default_domain_resolver":"dns_probe"},
  "outbounds": [{"type":"direct","tag":"direct"}]
}
EOF
    if ! singbox_check_config "$t"; then
      SB_HAS_ROUTE_DEFAULT_DOMAIN_RESOLVER=0
    fi
  else
    SB_HAS_ROUTE_DEFAULT_DOMAIN_RESOLVER=0
  fi

  cat > "$t" <<'EOF'
{
  "log": {"level":"warn"},
  "outbounds": [
    {
      "type": "wireguard",
      "tag": "warp",
      "local_address": ["172.16.0.2/32"],
      "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "peers": [
        {"server": "example.com", "server_port": 2408, "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "allowed_ips": ["0.0.0.0/0"]}
      ]
    }
  ]
}
EOF
  if ! singbox_check_config "$t"; then
    SB_HAS_WG_NEW=0
  fi

  if [ "${SB_HAS_TLS_PIN}" -eq 1 ]; then
    cat > "$t" <<'EOF'
{
  "log": {"level":"warn"},
  "outbounds": [
    {
      "type": "hysteria2",
      "tag": "probe",
      "server": "example.com",
      "server_port": 443,
      "password": "p",
      "tls": {
        "enabled": true,
        "server_name": "example.com",
        "certificate_public_key_sha256": ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
      }
    }
  ]
}
EOF
    if ! singbox_check_config "$t"; then
      SB_HAS_TLS_PIN=0
    fi
  fi
}

validate_singbox_config() {
  [ -x "$SB_BIN" ] || return 0
  local check_log
  check_log="$(tmp_path singbox_check.log)"
  if "$SB_BIN" check -c "${CONFIG_DIR}/config.json" >"$check_log" 2>&1; then
    rm -f "$check_log"
    return 0
  fi
  err "sing-box 配置校验失败："
  sed 's/^/  /' "$check_log" >&2 || true
  rm -f "$check_log"
  return 1
}

emit_outbound_with_resolver() {
  local file="$1" resolver="$2" strategy="$3"
  if grep -q '"domain_resolver"' "$file"; then
    sed 's/^/    /' "$file"
    return 0
  fi
  sed -e '$ s/}[[:space:]]*$/,\n  "domain_resolver": { "server": "'"$(json_escape "$resolver")"'", "strategy": "'"$(json_escape "$strategy")"'" }\n}/' "$file" \
    | sed 's/^/    /'
}

get_query_param() {
  local key="$1" qs="$2"
  echo "$qs" | tr '&' '\n' | awk -F= -v k="$key" '$1==k {print $2; exit}'
}

json_array_from_csv() {
  local csv="$1"
  echo "$csv" | tr ',' '\n' | awk 'BEGIN{printf "["} {gsub(/^[ \t]+|[ \t]+$/,""); if($0!=""){if(NR>1)printf ","; printf "\"%s\"", $0}} END{printf "]"}'
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

  local tls_block=""
  if [ "$security" = "tls" ]; then
    local tls_items=""
    local tls_sni="${sni:-$host}"
    tls_items="\"enabled\":true,\"server_name\":\"$(json_escape "$tls_sni")\""
    if [ -n "$alpn" ]; then
      tls_items="${tls_items},\"alpn\":$(json_array_from_csv "$alpn")"
    fi
    if [ "$insecure" = "1" ] || [ "$insecure" = "true" ]; then
      tls_items="${tls_items},\"insecure\":true"
    fi
    tls_block="\"tls\":{${tls_items}}"
  elif [ "$security" = "reality" ]; then
    local r_sni="${sni:-$host}"
    local r_fp="${fp:-chrome}"
    [ -z "$pbk" ] && die "Reality 出口需要 pbk。"
    [ -z "$sid" ] && die "Reality 出口需要 sid。"
    [ -z "$spx" ] && spx="/"
    tls_block="\"tls\":{\"enabled\":true,\"server_name\":\"$(json_escape "$r_sni")\",\"utls\":{\"enabled\":true,\"fingerprint\":\"$(json_escape "$r_fp")\"},\"reality\":{\"enabled\":true,\"public_key\":\"$(json_escape "$pbk")\",\"short_id\":\"$(json_escape "$sid")\",\"spider_x\":\"$(json_escape "$spx")\"}}"
  fi

  local transport_block=""
  if [ "$network" = "ws" ]; then
    [ -z "$path" ] && path="/"
    if [ -n "$param_host" ]; then
      transport_block="\"transport\":{\"type\":\"ws\",\"path\":\"$(json_escape "$path")\",\"headers\":{\"Host\":\"$(json_escape "$param_host")\"}}"
    else
      transport_block="\"transport\":{\"type\":\"ws\",\"path\":\"$(json_escape "$path")\"}"
    fi
  elif [ "$network" = "grpc" ]; then
    [ -z "$service" ] && die "gRPC 需要 serviceName。"
    transport_block="\"transport\":{\"type\":\"grpc\",\"service_name\":\"$(json_escape "$service")\"}"
  fi

  local extra=""
  if [ -n "$tls_block" ]; then
    extra="${extra},${tls_block}"
  fi
  if [ -n "$transport_block" ]; then
    extra="${extra},${transport_block}"
  fi

  cat > "${OUTBOUNDS_DIR}/${tag}.json" <<EOF
{
  "type": "vless",
  "tag": "$(json_escape "$tag")",
  "server": "$(json_escape "$host")",
  "server_port": ${port},
  "uuid": "$(json_escape "$uuid")"$( [ -n "$flow" ] && printf ',\n  "flow": "%s"' "$(json_escape "$flow")" )${extra}
}
EOF
}

build_vmess_outbound() {
  local link="$1" tag="$2"
  local payload json
  local host port uuid aid net tls host_header path scy sni

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

  if [ "$tls" = "true" ]; then
    tls="tls"
  elif [ "$tls" = "false" ]; then
    tls=""
  fi

  [ -z "$host" ] && die "VMess 链接缺少地址。"
  [ -z "$port" ] && die "VMess 链接缺少端口。"
  [ -z "$uuid" ] && die "VMess 链接缺少 UUID。"
  [ -z "$net" ] && net="tcp"
  [ -z "$scy" ] && scy="auto"

  local tls_block=""
  if [ "$tls" = "tls" ]; then
    local tls_sni="${sni:-$host}"
    tls_block="\"tls\":{\"enabled\":true,\"server_name\":\"$(json_escape "$tls_sni")\"}"
  fi

  local transport_block=""
  if [ "$net" = "ws" ]; then
    [ -z "$path" ] && path="/"
    if [ -n "$host_header" ]; then
      transport_block="\"transport\":{\"type\":\"ws\",\"path\":\"$(json_escape "$path")\",\"headers\":{\"Host\":\"$(json_escape "$host_header")\"}}"
    else
      transport_block="\"transport\":{\"type\":\"ws\",\"path\":\"$(json_escape "$path")\"}"
    fi
  elif [ "$net" = "grpc" ]; then
    [ -z "$path" ] && die "VMess gRPC 缺少 serviceName。"
    transport_block="\"transport\":{\"type\":\"grpc\",\"service_name\":\"$(json_escape "$path")\"}"
  fi

  local extra=""
  if [ -n "$tls_block" ]; then
    extra="${extra},${tls_block}"
  fi
  if [ -n "$transport_block" ]; then
    extra="${extra},${transport_block}"
  fi

  local alter=""
  if [ -n "$aid" ] && [ "$aid" != "0" ]; then
    alter=",\n  \"alter_id\": ${aid}"
  fi

  cat > "${OUTBOUNDS_DIR}/${tag}.json" <<EOF
{
  "type": "vmess",
  "tag": "$(json_escape "$tag")",
  "server": "$(json_escape "$host")",
  "server_port": ${port},
  "uuid": "$(json_escape "$uuid")",
  "security": "$(json_escape "$scy")"${alter}${extra}
}
EOF
}

build_trojan_outbound() {
  local link="$1" tag="$2"
  local base qs pass hostport host port
  local network sni alpn insecure path param_host service

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
  [ -z "$pass" ] && die "Trojan 缺少密码。"
  [ -z "$host" ] && die "Trojan 缺少地址。"
  [ -z "$port" ] && die "Trojan 缺少端口。"

  network="$(get_query_param type "$qs")"
  [ -z "$network" ] && network="tcp"
  sni="$(urldecode "$(get_query_param sni "$qs")")"
  alpn="$(urldecode "$(get_query_param alpn "$qs")")"
  insecure="$(get_query_param allowInsecure "$qs")"
  path="$(urldecode "$(get_query_param path "$qs")")"
  param_host="$(urldecode "$(get_query_param host "$qs")")"
  service="$(urldecode "$(get_query_param serviceName "$qs")")"

  local tls_items="\"enabled\":true,\"server_name\":\"$(json_escape "${sni:-$host}")\""
  if [ -n "$alpn" ]; then
    tls_items="${tls_items},\"alpn\":$(json_array_from_csv "$alpn")"
  fi
  if [ "$insecure" = "1" ] || [ "$insecure" = "true" ]; then
    tls_items="${tls_items},\"insecure\":true"
  fi
  local tls_block="\"tls\":{${tls_items}}"

  local transport_block=""
  if [ "$network" = "ws" ]; then
    [ -z "$path" ] && path="/"
    if [ -n "$param_host" ]; then
      transport_block="\"transport\":{\"type\":\"ws\",\"path\":\"$(json_escape "$path")\",\"headers\":{\"Host\":\"$(json_escape "$param_host")\"}}"
    else
      transport_block="\"transport\":{\"type\":\"ws\",\"path\":\"$(json_escape "$path")\"}"
    fi
  elif [ "$network" = "grpc" ]; then
    [ -z "$service" ] && die "Trojan gRPC 需要 serviceName。"
    transport_block="\"transport\":{\"type\":\"grpc\",\"service_name\":\"$(json_escape "$service")\"}"
  fi

  local extra=""
  [ -n "$tls_block" ] && extra="${extra},${tls_block}"
  [ -n "$transport_block" ] && extra="${extra},${transport_block}"

  cat > "${OUTBOUNDS_DIR}/${tag}.json" <<EOF
{
  "type": "trojan",
  "tag": "$(json_escape "$tag")",
  "server": "$(json_escape "$host")",
  "server_port": ${port},
  "password": "$(json_escape "$pass")"${extra}
}
EOF
}

build_ss_outbound() {
  local link="$1" tag="$2"
  local base qs userinfo hostport host port method password decoded

  link="${link#ss://}"
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
    userinfo="$base"
    hostport=""
  fi

  if echo "$userinfo" | grep -q ':'; then
    method="${userinfo%%:*}"
    password="${userinfo#*:}"
  else
    decoded="$(base64_decode "$userinfo")"
    method="${decoded%%:*}"
    password="${decoded#*:}"
  fi

  if [ -z "$hostport" ]; then
    hostport="$qs"
  fi
  IFS='|' read -r host port <<< "$(parse_hostport "$hostport")"

  [ -z "$host" ] && die "SS 缺少地址。"
  [ -z "$port" ] && die "SS 缺少端口。"
  [ -z "$method" ] && die "SS 缺少加密方式。"
  password="$(urldecode "$password")"
  [ -z "$password" ] && die "SS 缺少密码。"

  cat > "${OUTBOUNDS_DIR}/${tag}.json" <<EOF
{
  "type": "shadowsocks",
  "tag": "$(json_escape "$tag")",
  "server": "$(json_escape "$host")",
  "server_port": ${port},
  "method": "$(json_escape "$method")",
  "password": "$(json_escape "$password")"
}
EOF
}

build_hy2_outbound() {
  local link="$1" tag="$2"
  local base qs userinfo hostport host port password
  local sni insecure alpn obfs obfs_pwd up down auth pin_sha

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
  obfs="$(urldecode "$(get_query_param obfs "$qs")")"
  obfs_pwd="$(urldecode "$(get_query_param obfs-password "$qs")")"
  [ -z "$obfs_pwd" ] && obfs_pwd="$(urldecode "$(get_query_param obfs_password "$qs")")"
  pin_sha="$(urldecode "$(get_query_param pinSHA256 "$qs")")"
  [ -z "$pin_sha" ] && pin_sha="$(urldecode "$(get_query_param pinsha256 "$qs")")"
  up="$(get_query_param upmbps "$qs")"
  [ -z "$up" ] && up="$(get_query_param up_mbps "$qs")"
  down="$(get_query_param downmbps "$qs")"
  [ -z "$down" ] && down="$(get_query_param down_mbps "$qs")"

  [ -z "$host" ] && die "HY2 缺少地址。"
  [ -z "$port" ] && die "HY2 缺少端口。"
  password="$(urldecode "$password")"
  [ -z "$password" ] && die "HY2 缺少密码。"

  local tls_items="\"enabled\":true,\"server_name\":\"$(json_escape "${sni:-$host}")\""
  if [ -n "$alpn" ]; then
    tls_items="${tls_items},\"alpn\":$(json_array_from_csv "$alpn")"
  fi
  if [ -n "$pin_sha" ]; then
    detect_singbox_features
    if [ "${SB_HAS_TLS_PIN}" -eq 1 ]; then
      tls_items="${tls_items},\"certificate_public_key_sha256\":[\"$(json_escape "$pin_sha")\"]"
    else
      if [ "$insecure" != "1" ] && [ "$insecure" != "true" ]; then
        ui "提示: 当前 sing-box 版本不支持 pinSHA256，已自动回退 insecure=1。"
      fi
      insecure="1"
    fi
  fi
  if [ "$insecure" = "1" ] || [ "$insecure" = "true" ]; then
    tls_items="${tls_items},\"insecure\":true"
  fi
  local tls_block="\"tls\":{${tls_items}}"

  local obfs_block=""
  if [ -n "$obfs" ] || [ -n "$obfs_pwd" ]; then
    local obfs_type="${obfs:-salamander}"
    obfs_block="\"obfs\":{\"type\":\"$(json_escape "$obfs_type")\""
    if [ -n "$obfs_pwd" ]; then
      obfs_block="${obfs_block},\"password\":\"$(json_escape "$obfs_pwd")\""
    fi
    obfs_block="${obfs_block}}"
  fi

  local extra=""
  [ -n "$tls_block" ] && extra="${extra},${tls_block}"
  [ -n "$obfs_block" ] && extra="${extra},${obfs_block}"
  if [ -n "$up" ]; then
    extra="${extra},\"up_mbps\":${up}"
  fi
  if [ -n "$down" ]; then
    extra="${extra},\"down_mbps\":${down}"
  fi

  cat > "${OUTBOUNDS_DIR}/${tag}.json" <<EOF
{
  "type": "hysteria2",
  "tag": "$(json_escape "$tag")",
  "server": "$(json_escape "$host")",
  "server_port": ${port},
  "password": "$(json_escape "$password")"${extra}
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

  cat > "${OUTBOUNDS_DIR}/${tag}.json" <<EOF
{
  "type": "socks",
  "tag": "$(json_escape "$tag")",
  "server": "$(json_escape "$host")",
  "server_port": ${port},
  "version": "$(json_escape "$version")"$( [ -n "$user" ] && printf ',\n  "username": "%s",\n  "password": "%s"' "$(json_escape "$user")" "$(json_escape "$pass")" )
}
EOF
}

build_http_outbound() {
  local link="$1" tag="$2"
  local scheme base qs userinfo hostport host port user pass sni insecure path

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
  insecure="$(get_query_param insecure "$qs")"
  [ -z "$insecure" ] && insecure="$(get_query_param allowInsecure "$qs")"
  path="$(urldecode "$(get_query_param path "$qs")")"

  local tls_block=""
  if [ "$scheme" = "https" ]; then
    local tls_items="\"enabled\":true,\"server_name\":\"$(json_escape "${sni:-$host}")\""
    if [ "$insecure" = "1" ] || [ "$insecure" = "true" ]; then
      tls_items="${tls_items},\"insecure\":true"
    fi
    tls_block=",\n  \"tls\": {${tls_items}}"
  fi

  cat > "${OUTBOUNDS_DIR}/${tag}.json" <<EOF
{
  "type": "http",
  "tag": "$(json_escape "$tag")",
  "server": "$(json_escape "$host")",
  "server_port": ${port}$( [ -n "$user" ] && printf ',\n  "username": "%s",\n  "password": "%s"' "$(json_escape "$user")" "$(json_escape "$pass")" )$( [ -n "$path" ] && printf ',\n  "path": "%s"' "$(json_escape "$path")" )${tls_block}
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
  local ver arch url priv addr peer_pub endpoint mtu addr4 addr6 allowed allowed_json
  if [ -f "${ENDPOINTS_DIR}/warp.json" ]; then
    if singbox_check_endpoint_file "${ENDPOINTS_DIR}/warp.json"; then
      ensure_warp_variants || true
      return 0
    fi
    rm -f "${ENDPOINTS_DIR}/warp.json"
  fi
  if [ -f "${OUTBOUNDS_DIR}/warp.json" ]; then
    if singbox_check_outbound_file "${OUTBOUNDS_DIR}/warp.json"; then
      ensure_warp_variants || true
      return 0
    fi
    rm -f "${OUTBOUNDS_DIR}/warp.json"
  fi
  ensure_dirs
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
  allowed="$(awk -F' = ' '/^AllowedIPs/ {print $2; exit}' "${WGCF_DIR}/wgcf-profile.conf")"

  IFS=',' read -r addr4 addr6 <<< "$addr"
  [ -z "$mtu" ] && mtu="1280"

  allowed="$(echo "$allowed" | tr -d ' ')"
  if [ -z "$allowed" ]; then
    if [ -n "$addr6" ]; then
      allowed="0.0.0.0/0,::/0"
    else
      allowed="0.0.0.0/0"
    fi
  fi
  allowed_json="$(json_array_from_csv "$allowed")"

  local endpoint_host endpoint_port
  IFS='|' read -r endpoint_host endpoint_port <<< "$(parse_hostport "$endpoint")"
  [ -z "$endpoint_host" ] && endpoint_host="engage.cloudflareclient.com"
  if [ -z "$endpoint_port" ]; then
    endpoint_port="2408"
  fi
  if ! echo "$endpoint_port" | grep -qE '^[0-9]+$'; then
    endpoint_port="2408"
  fi
  if ! is_ip_addr "$endpoint_host"; then
    local endpoint_resolved=""
    if ipv6_only; then
      endpoint_resolved="$(resolve_domain_ipv6 "$endpoint_host" || true)"
      [ -z "$endpoint_resolved" ] && endpoint_resolved="$(resolve_domain_ipv4 "$endpoint_host" || true)"
    else
      endpoint_resolved="$(resolve_domain_ipv4 "$endpoint_host" || true)"
      [ -z "$endpoint_resolved" ] && endpoint_resolved="$(resolve_domain_ipv6 "$endpoint_host" || true)"
    fi
    if [ -n "$endpoint_resolved" ]; then
      endpoint_host="$endpoint_resolved"
    else
      ui "提示: WARP 主出口未解析到固定 IP，继续使用域名端点。"
    fi
  fi

  local warp_endpoint_new_tmp warp_endpoint_legacy_tmp warp_new_tmp warp_old_tmp
  warp_endpoint_new_tmp="$(tmp_path warp.endpoint.new.json)"
  warp_endpoint_legacy_tmp="$(tmp_path warp.endpoint.legacy.json)"
  warp_new_tmp="$(tmp_path warp.new.json)"
  warp_old_tmp="$(tmp_path warp.old.json)"

  cat > "$warp_endpoint_new_tmp" <<EOF
{
  "type": "wireguard",
  "tag": "warp",
  "local_address": ["$(json_escape "$addr4")"$( [ -n "$addr6" ] && printf ', "%s"' "$(json_escape "$addr6")" )],
  "private_key": "$(json_escape "$priv")",
  "server": "$(json_escape "$endpoint_host")",
  "server_port": ${endpoint_port},
  "peer_public_key": "$(json_escape "$peer_pub")",
  "mtu": ${mtu}
}
EOF

  cat > "$warp_endpoint_legacy_tmp" <<EOF
{
  "type": "wireguard",
  "tag": "warp",
  "private_key": "$(json_escape "$priv")",
  "address": ["$(json_escape "$addr4")"$( [ -n "$addr6" ] && printf ', "%s"' "$(json_escape "$addr6")" )],
  "mtu": ${mtu},
  "peers": [
    {
      "public_key": "$(json_escape "$peer_pub")",
      "allowed_ips": ${allowed_json},
      "address": "$(json_escape "$endpoint_host")",
      "port": ${endpoint_port}
    }
  ]
}
EOF

  cat > "$warp_new_tmp" <<EOF
{
  "type": "wireguard",
  "tag": "warp",
  "local_address": ["$(json_escape "$addr4")"$( [ -n "$addr6" ] && printf ', "%s"' "$(json_escape "$addr6")" )],
  "private_key": "$(json_escape "$priv")",
  "mtu": ${mtu},
  "peers": [
    {
      "server": "$(json_escape "$endpoint_host")",
      "server_port": ${endpoint_port},
      "public_key": "$(json_escape "$peer_pub")",
      "allowed_ips": ${allowed_json}
    }
  ]
}
EOF

  cat > "$warp_old_tmp" <<EOF
{
  "type": "wireguard",
  "tag": "warp",
  "private_key": "$(json_escape "$priv")",
  "address": ["$(json_escape "$addr4")"$( [ -n "$addr6" ] && printf ', "%s"' "$(json_escape "$addr6")" )],
  "mtu": ${mtu},
  "peers": [
    {
      "public_key": "$(json_escape "$peer_pub")",
      "allowed_ips": ${allowed_json},
      "address": "$(json_escape "$endpoint_host")",
      "port": ${endpoint_port}
    }
  ]
}
EOF

  local probe_endpoint_new_log="" probe_endpoint_legacy_log="" probe_new_log="" probe_old_log=""
  if singbox_check_endpoint_file "$warp_endpoint_new_tmp"; then
    mv "$warp_endpoint_new_tmp" "${ENDPOINTS_DIR}/warp.json"
    rm -f "$warp_endpoint_legacy_tmp" "$warp_new_tmp" "$warp_old_tmp"
  else
    probe_endpoint_new_log="${SB_LAST_OUTBOUND_CHECK_LOG:-}"
    if singbox_check_endpoint_file "$warp_endpoint_legacy_tmp"; then
      mv "$warp_endpoint_legacy_tmp" "${ENDPOINTS_DIR}/warp.json"
      rm -f "$warp_endpoint_new_tmp" "$warp_new_tmp" "$warp_old_tmp"
      [ -n "$probe_endpoint_new_log" ] && rm -f "$probe_endpoint_new_log" || true
    else
      probe_endpoint_legacy_log="${SB_LAST_OUTBOUND_CHECK_LOG:-}"
      if singbox_check_outbound_file "$warp_new_tmp"; then
        mv "$warp_new_tmp" "${OUTBOUNDS_DIR}/warp.json"
        rm -f "$warp_endpoint_new_tmp" "$warp_endpoint_legacy_tmp" "$warp_old_tmp"
        [ -n "$probe_endpoint_new_log" ] && rm -f "$probe_endpoint_new_log" || true
        [ -n "$probe_endpoint_legacy_log" ] && rm -f "$probe_endpoint_legacy_log" || true
      else
        probe_new_log="${SB_LAST_OUTBOUND_CHECK_LOG:-}"
        if singbox_check_outbound_file "$warp_old_tmp"; then
          mv "$warp_old_tmp" "${OUTBOUNDS_DIR}/warp.json"
          rm -f "$warp_endpoint_new_tmp" "$warp_endpoint_legacy_tmp" "$warp_new_tmp"
          [ -n "$probe_endpoint_new_log" ] && rm -f "$probe_endpoint_new_log" || true
          [ -n "$probe_endpoint_legacy_log" ] && rm -f "$probe_endpoint_legacy_log" || true
          [ -n "$probe_new_log" ] && rm -f "$probe_new_log" || true
        else
          probe_old_log="${SB_LAST_OUTBOUND_CHECK_LOG:-}"
          rm -f "$warp_endpoint_new_tmp" "$warp_endpoint_legacy_tmp" "$warp_new_tmp" "$warp_old_tmp"
          if [ -n "$probe_endpoint_new_log" ] && [ -f "$probe_endpoint_new_log" ]; then
            ui "WARP Endpoint(新) 校验输出："
            sed 's/^/  /' "$probe_endpoint_new_log" >&2 || true
            rm -f "$probe_endpoint_new_log"
          fi
          if [ -n "$probe_endpoint_legacy_log" ] && [ -f "$probe_endpoint_legacy_log" ]; then
            ui "WARP Endpoint(旧) 校验输出："
            sed 's/^/  /' "$probe_endpoint_legacy_log" >&2 || true
            rm -f "$probe_endpoint_legacy_log"
          fi
          if [ -n "$probe_new_log" ] && [ -f "$probe_new_log" ]; then
            ui "WARP Outbound(新) 校验输出："
            sed 's/^/  /' "$probe_new_log" >&2 || true
            rm -f "$probe_new_log"
          fi
          if [ -n "$probe_old_log" ] && [ -f "$probe_old_log" ]; then
            ui "WARP Outbound(旧) 校验输出："
            sed 's/^/  /' "$probe_old_log" >&2 || true
            rm -f "$probe_old_log"
          fi
          die "WARP 配置生成失败：当前 sing-box 版本不兼容生成的 WireGuard 出口格式。"
        fi
      fi
    fi
  fi

  mkdir -p "${CONFIG_DIR}/warp"
  cp "${WGCF_DIR}/wgcf-account.toml" "${CONFIG_DIR}/warp/" || true
  cp "${WGCF_DIR}/wgcf-profile.conf" "${CONFIG_DIR}/warp/" || true
  ensure_warp_variants
}

ensure_warp_variants() {
  local base_file target_dir tmp tag field_mode field_raw resolved family esc profile_raw
  if [ -f "${ENDPOINTS_DIR}/warp.json" ]; then
    base_file="${ENDPOINTS_DIR}/warp.json"
    target_dir="${ENDPOINTS_DIR}"
  elif [ -f "${OUTBOUNDS_DIR}/warp.json" ]; then
    base_file="${OUTBOUNDS_DIR}/warp.json"
    target_dir="${OUTBOUNDS_DIR}"
  else
    return 1
  fi
  IFS='|' read -r field_mode field_raw <<< "$(get_warp_endpoint_field "$base_file")"
  profile_raw="$(warp_profile_endpoint_raw || true)"
  if [ -n "$profile_raw" ]; then
    field_raw="$profile_raw"
  fi
  for tag in warp4 warp6; do
    tmp="$(tmp_path ${tag}.json)"
    sed '/"tag"[[:space:]]*:[[:space:]]*"warp"/s//"tag": "'"${tag}"'"/' "$base_file" > "$tmp"
    if [ -n "$field_mode" ] && [ -n "$field_raw" ]; then
      if [ "$tag" = "warp4" ]; then
        family="4"
      else
        family="6"
      fi
      resolved="$(warp_endpoint_host_for_family "$field_raw" "$family" || true)"
      if [ -n "$resolved" ]; then
        esc="$(printf '%s' "$resolved" | sed 's/[\\/&]/\\&/g')"
        sed -i "/\"${field_mode}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/s//\"${field_mode}\": \"${esc}\"/" "$tmp"
      else
        if [ "$family" = "4" ]; then
          ui "提示: WARP IPv4 未解析到 IPv4 端点，${tag} 将使用自动地址族。"
        else
          ui "提示: WARP IPv6 未解析到 IPv6 端点，${tag} 将使用自动地址族。"
        fi
      fi
    fi
    mv "$tmp" "${target_dir}/${tag}.json"
  done
}

list_custom_outbounds() {
  local f base
  for f in "${OUTBOUNDS_DIR}"/*.json; do
    [ -e "$f" ] || continue
    base="$(basename "$f" .json)"
    case "$base" in
      direct4|direct6|warp|warp4|warp6) continue ;;
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
      direct4|direct6|warp|warp4|warp6) continue ;;
      *) return 0 ;;
    esac
  done
  return 1
}

has_endpoints() {
  local f
  for f in "${ENDPOINTS_DIR}"/*.json; do
    [ -e "$f" ] && return 0
  done
  return 1
}

ensure_feature_routes_file() {
  [ -f "$FEATURE_ROUTES_FILE" ] || : > "$FEATURE_ROUTES_FILE"
}

is_feature_key_valid() {
  case "$1" in
    youtube|streaming|ai|google|telegram|github|tiktok|speedtest) return 0 ;;
    *) return 1 ;;
  esac
}

feature_label() {
  case "$1" in
    youtube) echo "YouTube" ;;
    streaming) echo "流媒体" ;;
    ai) echo "AI" ;;
    google) echo "Google" ;;
    telegram) echo "Telegram" ;;
    github) echo "GitHub" ;;
    tiktok) echo "TikTok" ;;
    speedtest) echo "测速站点" ;;
    *) echo "$1" ;;
  esac
}

feature_domain_suffixes() {
  case "$1" in
    youtube) printf '%s\n' youtube.com youtu.be ytimg.com googlevideo.com ;;
    streaming) printf '%s\n' netflix.com nflxvideo.net nflximg.net disneyplus.com dssott.com bamgrid.com primevideo.com amazonvideo.com hulu.com spotify.com ;;
    ai) printf '%s\n' openai.com chatgpt.com oaistatic.com oaiusercontent.com anthropic.com claude.ai gemini.google.com generativelanguage.googleapis.com ;;
    google) printf '%s\n' google.com gstatic.com googleapis.com googleusercontent.com ggpht.com gvt1.com ;;
    telegram) printf '%s\n' telegram.org t.me tdesktop.com telegram.me ;;
    github) printf '%s\n' github.com githubusercontent.com githubassets.com ghcr.io ;;
    tiktok) printf '%s\n' tiktok.com tiktokcdn.com tiktokv.com byteoversea.com ;;
    speedtest) printf '%s\n' speedtest.net fast.com nperf.com speed.cloudflare.com ;;
    *) ;;
  esac
}

sanitize_feature_routes() {
  local tmp key out
  ensure_feature_routes_file
  tmp="$(tmp_path feature-routes.list)"
  : > "$tmp"
  while IFS='|' read -r key out; do
    [ -z "$key" ] && continue
    if ! is_feature_key_valid "$key"; then
      continue
    fi
    if [ -z "$out" ] || ! echo "$out" | grep -qE '^[A-Za-z0-9_]+$'; then
      continue
    fi
    echo "${key}|${out}" >> "$tmp"
  done < "$FEATURE_ROUTES_FILE"
  awk -F'|' '!seen[$1]++' "$tmp" > "${tmp}.uniq"
  mv "${tmp}.uniq" "$FEATURE_ROUTES_FILE"
  rm -f "$tmp"
}

list_feature_routes() {
  sanitize_feature_routes
  [ -s "$FEATURE_ROUTES_FILE" ] || return 1
  cat "$FEATURE_ROUTES_FILE"
}

feature_route_uses_outbound() {
  local tag="$1"
  sanitize_feature_routes
  if [ -s "$FEATURE_ROUTES_FILE" ] && awk -F'|' -v t="$tag" '$2==t {found=1} END{exit !found}' "$FEATURE_ROUTES_FILE"; then
    return 0
  fi
  return 1
}

outbound_in_use() {
  local tag="$1"
  if [ -f "$INBOUNDS_FILE" ] && awk -F'|' -v t="$tag" '$3==t {found=1} END{exit !found}' "$INBOUNDS_FILE"; then
    return 0
  fi
  if feature_route_uses_outbound "$tag"; then
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
    case "$tag" in
      direct4|direct6|warp|warp4|warp6)
        ui "该标签为系统保留，请换一个。"
        continue
        ;;
    esac
    if [ -f "${OUTBOUNDS_DIR}/${tag}.json" ] || [ -f "${ENDPOINTS_DIR}/${tag}.json" ]; then
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
    restart_singbox
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
    restart_singbox
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
    msg "该出口仍被入口/功能分流使用，请先解除引用。"
    return 0
  fi
  rm -f "${OUTBOUNDS_DIR}/${tag}.json"
  rm -f "${OUTBOUNDS_DIR}/${tag}.link"
  if [ -s "$INBOUNDS_FILE" ]; then
    build_config
    restart_singbox
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

feature_domain_suffix_json() {
  local key="$1" first=1 d
  printf '['
  while IFS= read -r d; do
    [ -z "$d" ] && continue
    if [ "$first" -eq 0 ]; then
      printf ','
    fi
    first=0
    printf '"%s"' "$(json_escape "$d")"
  done < <(feature_domain_suffixes "$key")
  printf ']'
}

choose_feature_key() {
  local choice
  ui "${C_BOLD}${C_BLUE}功能分类：${C_RESET}"
  ui "  ${C_YELLOW}1)${C_RESET} YouTube"
  ui "  ${C_YELLOW}2)${C_RESET} 流媒体"
  ui "  ${C_YELLOW}3)${C_RESET} AI"
  ui "  ${C_YELLOW}4)${C_RESET} Google"
  ui "  ${C_YELLOW}5)${C_RESET} Telegram"
  ui "  ${C_YELLOW}6)${C_RESET} GitHub"
  ui "  ${C_YELLOW}7)${C_RESET} TikTok"
  ui "  ${C_YELLOW}8)${C_RESET} 测速站点"
  while true; do
    read -r -p "请选择: " choice
    case "$choice" in
      1) echo "youtube"; return 0 ;;
      2) echo "streaming"; return 0 ;;
      3) echo "ai"; return 0 ;;
      4) echo "google"; return 0 ;;
      5) echo "telegram"; return 0 ;;
      6) echo "github"; return 0 ;;
      7) echo "tiktok"; return 0 ;;
      8) echo "speedtest"; return 0 ;;
    esac
  done
}

set_feature_route() {
  local key="$1" out="$2" tmp found=0 cur_key cur_out
  ensure_feature_routes_file
  sanitize_feature_routes
  tmp="$(tmp_path feature-routes.list)"
  : > "$tmp"
  while IFS='|' read -r cur_key cur_out; do
    [ -z "$cur_key" ] && continue
    if [ "$cur_key" = "$key" ]; then
      echo "${key}|${out}" >> "$tmp"
      found=1
    else
      echo "${cur_key}|${cur_out}" >> "$tmp"
    fi
  done < "$FEATURE_ROUTES_FILE"
  if [ "$found" -eq 0 ]; then
    echo "${key}|${out}" >> "$tmp"
  fi
  mv "$tmp" "$FEATURE_ROUTES_FILE"
}

delete_feature_route() {
  local key="$1" tmp cur_key cur_out
  ensure_feature_routes_file
  sanitize_feature_routes
  tmp="$(tmp_path feature-routes.list)"
  : > "$tmp"
  while IFS='|' read -r cur_key cur_out; do
    [ -z "$cur_key" ] && continue
    [ "$cur_key" = "$key" ] && continue
    echo "${cur_key}|${cur_out}" >> "$tmp"
  done < "$FEATURE_ROUTES_FILE"
  mv "$tmp" "$FEATURE_ROUTES_FILE"
}

pick_feature_route_key() {
  local keys=() i=0 choice key out
  sanitize_feature_routes
  while IFS='|' read -r key out; do
    [ -z "$key" ] && continue
    keys+=("$key")
  done < "$FEATURE_ROUTES_FILE"
  [ "${#keys[@]}" -gt 0 ] || return 1
  ui "现有功能分流："
  for key in "${keys[@]}"; do
    i=$((i+1))
    ui "  ${i}) $(feature_label "$key")"
  done
  while true; do
    read -r -p "请选择: " choice
    if echo "$choice" | grep -qE '^[0-9]+$' && [ "$choice" -ge 1 ] && [ "$choice" -le "${#keys[@]}" ]; then
      echo "${keys[$((choice-1))]}"
      return 0
    fi
  done
}

show_feature_routes() {
  local key out
  if ! list_feature_routes >/dev/null 2>&1; then
    msg "暂无功能分流规则。"
    return 0
  fi
  msg "功能分流规则："
  while IFS='|' read -r key out; do
    [ -z "$key" ] && continue
    msg "  $(feature_label "$key") -> ${out}"
  done < "$FEATURE_ROUTES_FILE"
}

manage_feature_routes() {
  local choice key route_out
  ensure_feature_routes_file
  while true; do
    ui "${C_BOLD}${C_BLUE}功能分流管理：${C_RESET}"
    ui "  ${C_YELLOW}1)${C_RESET} 新增/更新功能分流"
    ui "  ${C_YELLOW}2)${C_RESET} 删除功能分流"
    ui "  ${C_YELLOW}3)${C_RESET} 查看功能分流"
    ui "  ${C_YELLOW}4)${C_RESET} 清空功能分流"
    ui "  ${C_YELLOW}0)${C_RESET} 返回"
    read -r -p "请选择: " choice
    case "$choice" in
      1)
        key="$(choose_feature_key)"
        route_out="$(choose_outbound)"
        set_feature_route "$key" "$route_out"
        if [ -s "$INBOUNDS_FILE" ]; then
          build_config
          restart_singbox
        fi
        msg "功能分流已设置: $(feature_label "$key") -> ${route_out}"
        ;;
      2)
        if ! list_feature_routes >/dev/null 2>&1; then
          msg "暂无功能分流规则。"
          continue
        fi
        key="$(pick_feature_route_key)" || continue
        delete_feature_route "$key"
        if [ -s "$INBOUNDS_FILE" ]; then
          build_config
          restart_singbox
        fi
        msg "功能分流已删除: $(feature_label "$key")"
        ;;
      3) show_feature_routes ;;
      4)
        : > "$FEATURE_ROUTES_FILE"
        if [ -s "$INBOUNDS_FILE" ]; then
          build_config
          restart_singbox
        fi
        msg "功能分流规则已清空。"
        ;;
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
  ui "  ${C_YELLOW}3)${C_RESET} WARP(自动)"
  ui "  ${C_YELLOW}4)${C_RESET} WARP IPv4"
  ui "  ${C_YELLOW}5)${C_RESET} WARP IPv6"
  ui "  ${C_YELLOW}6)${C_RESET} 新增出口链接"
  ui "  ${C_YELLOW}7)${C_RESET} 使用已有自定义出口"
  while true; do
    read -r -p "请选择: " choice
    case "$choice" in
      1) echo "direct4"; return 0 ;;
      2) echo "direct6"; return 0 ;;
      3) setup_warp 1>&2; echo "warp"; return 0 ;;
      4) setup_warp 1>&2; echo "warp4"; return 0 ;;
      5) setup_warp 1>&2; echo "warp6"; return 0 ;;
      6) tag="$(add_custom_outbound)"; echo "$tag"; return 0 ;;
      7)
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
  local port out_tag tag remark proto hy2_pass up down choice hy2_obfs hy2_masq
  hy2_pass=""
  up=""
  down=""
  hy2_obfs=""
  hy2_masq=""
  if [ -n "${AUTO_PROTO:-}" ]; then
    proto="$AUTO_PROTO"
    AUTO_PROTO=""
  else
    ui "${C_BOLD}${C_BLUE}入口协议：${C_RESET}"
    ui "  ${C_YELLOW}1)${C_RESET} VLESS Reality (TCP)"
    ui "  ${C_YELLOW}2)${C_RESET} Hysteria2 (HY2)"
    read -r -p "请选择 [1-2]: " proto
    case "$proto" in
      2) proto="hy2" ;;
      *) proto="vless" ;;
    esac
  fi
  if [ "$proto" = "vless" ]; then
    if [ ! -f "$MANAGER_CONF" ]; then
      init_base_config
    fi
    load_manager_conf
    ensure_reality_material
  fi
  if [ "$proto" = "hy2" ] && [ ! -f "$MANAGER_CONF" ]; then
    init_base_config_silent
  fi
  port="$(prompt_port "$proto")"
  out_tag="$(choose_outbound)"
  if ! echo "$out_tag" | grep -qE '^[A-Za-z0-9_]+$'; then
    die "出口选择异常，请重试。"
  fi
  if [ "$proto" = "hy2" ]; then
    [ -z "${HY2_CERT_MODE:-}" ] && HY2_CERT_MODE="self"
    [ -z "${HY2_DOMAIN:-}" ] && HY2_DOMAIN=""
    ui "${C_BOLD}${C_BLUE}HY2 证书类型：${C_RESET}"
    ui "  ${C_YELLOW}1)${C_RESET} 自签证书(推荐 pin 验证，强制 obfs)"
    ui "  ${C_YELLOW}2)${C_RESET} 自动申请证书(Cloudflare DNS API)"
    read -r -p "请选择 [1-2]: " choice
    case "$choice" in
      2)
        HY2_CERT_MODE="acme"
        read -r -p "HY2 域名(需解析到本机): " HY2_DOMAIN
        ;;
      *)
        HY2_CERT_MODE="self"
        HY2_DOMAIN=""
        ;;
    esac
    save_manager_conf
    read -r -p "HY2 密码(留空自动生成): " hy2_pass
    if [ -z "$hy2_pass" ]; then
      hy2_pass="$(gen_hy2_password)"
      msg "已生成 HY2 密码: ${hy2_pass}"
    fi
    read -r -p "HY2 上行带宽(Mbps，可留空): " up
    read -r -p "HY2 下行带宽(Mbps，可留空): " down
    if [ "${HY2_CERT_MODE:-self}" = "self" ]; then
      prompt_hy2_hardening_self hy2_obfs hy2_masq
    else
      prompt_hy2_hardening hy2_obfs hy2_masq
    fi
  fi
  if [ "$proto" = "hy2" ]; then
    read -r -p "别名(用于分享链接，留空默认 hy2-${port}): " remark
  else
    read -r -p "别名(用于分享链接，留空默认 sing-${port}): " remark
  fi
  if [ -z "$remark" ]; then
    if [ "$proto" = "hy2" ]; then
      remark="hy2-${port}"
    else
      remark="sing-${port}"
    fi
  fi
  tag="$(next_inbound_tag)"
  echo "${tag}|${port}|${out_tag}|${remark}|${proto}|${hy2_pass}|${up}|${down}|${hy2_obfs}|${hy2_masq}" >> "$INBOUNDS_FILE"
  msg "入口配置完成，正在生成配置并重启..."
  if ! build_config; then
    err "生成配置失败，请检查配置输入。"
    diagnose_start_failure
    return 1
  fi
  restart_singbox_with_check "$port"
  test_outbound "$out_tag"
  msg "入口已添加。"
}

sanitize_inbounds() {
  local tmp
  [ -f "$INBOUNDS_FILE" ] || return 0
  tmp="$(tmp_path inbounds.list)"
  > "$tmp"
  while IFS='|' read -r tag port out remark proto hy2_pass up down hy2_obfs hy2_masq; do
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
    [ -z "$proto" ] && proto="vless"
    if [ "$proto" = "hy2" ]; then
      [ -z "$hy2_masq" ] && hy2_masq="$(normalize_hy2_masquerade_url "")"
    else
      hy2_pass=""
      up=""
      down=""
      hy2_obfs=""
      hy2_masq=""
    fi
    echo "${tag}|${port}|${out}|${remark}|${proto}|${hy2_pass}|${up}|${down}|${hy2_obfs}|${hy2_masq}" >> "$tmp"
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
  while IFS='|' read -r tag port out remark proto hy2_pass up down hy2_obfs hy2_masq; do
    [ -z "$tag" ] && continue
    i=$((i+1))
    [ -z "$proto" ] && proto="vless"
    ui "  ${i}) ${tag}  端口=${port}  出口=${out}  协议=${proto}"
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

get_inbound_proto_by_index() {
  local idx="$1" i=0 proto
  while IFS='|' read -r tag port out remark proto _r1 _r2 _r3 _r4 _r5; do
    [ -z "$tag" ] && continue
    i=$((i+1))
    if [ "$i" -eq "$idx" ]; then
      normalize_inbound_proto "$proto"
      return 0
    fi
  done < "$INBOUNDS_FILE"
  echo "vless"
}

update_inbound_line() {
  local idx="$1" new_port="$2" new_out="$3"
  local tmp
  tmp="$(tmp_path inbounds.list)"
  : > "$tmp"
  local i=0
  while IFS='|' read -r tag port out remark proto hy2_pass up down hy2_obfs hy2_masq; do
    [ -z "$tag" ] && continue
    i=$((i+1))
    if [ "$i" -eq "$idx" ]; then
      echo "${tag}|${new_port:-$port}|${new_out:-$out}|${remark}|${proto}|${hy2_pass}|${up}|${down}|${hy2_obfs}|${hy2_masq}" >> "$tmp"
    else
      echo "${tag}|${port}|${out}|${remark}|${proto}|${hy2_pass}|${up}|${down}|${hy2_obfs}|${hy2_masq}" >> "$tmp"
    fi
  done < "$INBOUNDS_FILE"
  mv "$tmp" "$INBOUNDS_FILE"
}

update_inbound_proto_line() {
  local idx="$1" new_proto="$2" new_pass="$3" new_up="$4" new_down="$5" new_obfs="$6" new_masq="$7"
  local tmp
  tmp="$(tmp_path inbounds.list)"
  : > "$tmp"
  local i=0
  while IFS='|' read -r tag port out remark proto hy2_pass up down hy2_obfs hy2_masq; do
    [ -z "$tag" ] && continue
    i=$((i+1))
    if [ "$i" -eq "$idx" ]; then
      echo "${tag}|${port}|${out}|${remark}|${new_proto:-$proto}|${new_pass}|${new_up}|${new_down}|${new_obfs}|${new_masq}" >> "$tmp"
    else
      echo "${tag}|${port}|${out}|${remark}|${proto}|${hy2_pass}|${up}|${down}|${hy2_obfs}|${hy2_masq}" >> "$tmp"
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
  while IFS='|' read -r tag port out remark proto hy2_pass up down hy2_obfs hy2_masq; do
    [ -z "$tag" ] && continue
    i=$((i+1))
    if [ "$i" -ne "$idx" ]; then
      echo "${tag}|${port}|${out}|${remark}|${proto}|${hy2_pass}|${up}|${down}|${hy2_obfs}|${hy2_masq}" >> "$tmp"
    fi
  done < "$INBOUNDS_FILE"
  mv "$tmp" "$INBOUNDS_FILE"
}

change_port() {
  local idx new_port proto
  idx="$(select_inbound_index)" || return 0
  proto="$(get_inbound_proto_by_index "$idx")"
  new_port="$(prompt_port "$proto" "$idx")"
  update_inbound_line "$idx" "$new_port" ""
  build_config
  restart_singbox_with_check "$new_port"
  msg "端口已更新。"
}

change_outbound() {
  local idx new_out
  idx="$(select_inbound_index)" || return 0
  new_out="$(choose_outbound)"
  update_inbound_line "$idx" "" "$new_out"
  build_config
  restart_singbox
  test_outbound "$new_out"
  msg "出口已更新。"
}

change_protocol() {
  local idx proto choice hy2_pass up down hy2_obfs hy2_masq
  idx="$(select_inbound_index)" || return 0
  ui "${C_BOLD}${C_BLUE}入口协议：${C_RESET}"
  ui "  ${C_YELLOW}1)${C_RESET} VLESS Reality (TCP)"
  ui "  ${C_YELLOW}2)${C_RESET} Hysteria2 (HY2)"
  read -r -p "请选择 [1-2]: " proto
  case "$proto" in
    2) proto="hy2" ;;
    *) proto="vless" ;;
  esac
  hy2_pass=""
  up=""
  down=""
  hy2_obfs=""
  hy2_masq=""
  if [ "$proto" = "hy2" ]; then
    load_manager_conf
    ui "${C_BOLD}${C_BLUE}HY2 证书类型：${C_RESET}"
    ui "  ${C_YELLOW}1)${C_RESET} 自签证书(推荐 pin 验证，强制 obfs)"
    ui "  ${C_YELLOW}2)${C_RESET} 自动申请证书(Cloudflare DNS API)"
    read -r -p "请选择 [1-2]: " choice
    case "$choice" in
      2)
        HY2_CERT_MODE="acme"
        read -r -p "HY2 域名(需解析到本机): " HY2_DOMAIN
        ;;
      *)
        HY2_CERT_MODE="self"
        HY2_DOMAIN=""
        ;;
    esac
    save_manager_conf
    read -r -p "HY2 密码(留空自动生成): " hy2_pass
    if [ -z "$hy2_pass" ]; then
      hy2_pass="$(gen_hy2_password)"
      msg "已生成 HY2 密码: ${hy2_pass}"
    fi
    read -r -p "HY2 上行带宽(Mbps，可留空): " up
    read -r -p "HY2 下行带宽(Mbps，可留空): " down
    if [ "${HY2_CERT_MODE:-self}" = "self" ]; then
      prompt_hy2_hardening_self hy2_obfs hy2_masq
    else
      prompt_hy2_hardening hy2_obfs hy2_masq
    fi
  else
    load_manager_conf
    ensure_reality_material
  fi
  update_inbound_proto_line "$idx" "$proto" "$hy2_pass" "$up" "$down" "$hy2_obfs" "$hy2_masq"
  build_config
  restart_singbox
  msg "协议已更新。"
}

remove_inbound() {
  local idx
  idx="$(select_inbound_index)" || return 0
  remove_inbound_line "$idx"
  if [ ! -s "$INBOUNDS_FILE" ]; then
    stop_singbox
    msg "已无入口，sing-box 已停止。"
    return 0
  fi
  build_config
  restart_singbox
  msg "入口已删除。"
}

build_config() {
  load_manager_conf
  ensure_direct_outbounds
  sanitize_inbounds
  sanitize_feature_routes
  detect_singbox_features

  if [ ! -s "$INBOUNDS_FILE" ]; then
    die "未配置任何入口。"
  fi

  local tmp dest_host dest_port dns_strategy dns_final
  dns_strategy="prefer_ipv4"
  dns_final="dns_direct4_1"
  if ipv6_only; then
    dns_strategy="prefer_ipv6"
    dns_final="dns_direct6_1"
  fi
  tmp="$(tmp_path config.json)"
  IFS='|' read -r dest_host dest_port <<< "$(split_host_port "$DEST")"

  local hy2_needed=0 vless_needed=0
  while IFS='|' read -r tag port out remark proto hy2_pass up down hy2_obfs hy2_masq; do
    [ -z "$tag" ] && continue
    [ -z "$proto" ] && proto="vless"
    if [ "$proto" = "hy2" ]; then
      hy2_needed=1
    else
      vless_needed=1
    fi
  done < "$INBOUNDS_FILE"
  if [ "$hy2_needed" -eq 1 ]; then
    ensure_hy2_cert
  fi
  if [ "$vless_needed" -eq 1 ]; then
    ensure_reality_material
  fi

  local used_outbounds inbound_used_outbounds feature_used_outbounds
  inbound_used_outbounds="$(awk -F'|' 'NF>=3{print $3}' "$INBOUNDS_FILE")"
  feature_used_outbounds="$(awk -F'|' 'NF>=2{print $2}' "$FEATURE_ROUTES_FILE" 2>/dev/null || true)"
  used_outbounds="$(printf "%s\n%s\n" "$inbound_used_outbounds" "$feature_used_outbounds" | awk 'NF>0 && !seen[$0]++')"
  local dns_bootstrap_domains=""
  if [ -n "$used_outbounds" ]; then
    while IFS= read -r out_tag; do
      [ -z "$out_tag" ] && continue
      case "$out_tag" in
        warp|warp4|warp6) dns_bootstrap_domains="${dns_bootstrap_domains}engage.cloudflareclient.com\n" ;;
      esac
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

  local inbound_count=0 outbound_count=0 endpoint_count=0 rule_count=0
  local inbound_tags_json
  inbound_tags_json="$(awk -F'|' 'BEGIN{printf "["} NF>=1 && $1!="" {if(n++) printf ","; printf "\"%s\"", $1} END{printf "]"}' "$INBOUNDS_FILE")"
  {
    echo '{'
    echo '  "log": {'
    echo '    "level": "warn",'
    echo '    "output": "/var/log/sing-box/sing-box.log"'
    echo '  },'
    echo '  "dns": {'
    echo '    "servers": ['
    if [ "${SB_HAS_DNS_NEW}" -eq 1 ]; then
      echo '      { "tag": "dns_local", "type": "local" },'
      echo '      { "tag": "dns_direct4_1", "type": "https", "server": "1.1.1.1" },'
      echo '      { "tag": "dns_direct4_2", "type": "https", "server": "8.8.8.8" },'
      echo '      { "tag": "dns_direct4_3", "type": "https", "server": "223.5.5.5" },'
      echo '      { "tag": "dns_direct6_1", "type": "https", "server": "2606:4700:4700::1111" },'
      echo '      { "tag": "dns_direct6_2", "type": "https", "server": "2001:4860:4860::8888" }'
    else
      echo '      { "tag": "dns_local", "address": "local" },'
      echo '      { "tag": "dns_direct4_1", "address": "https://1.1.1.1/dns-query" },'
      echo '      { "tag": "dns_direct4_2", "address": "https://8.8.8.8/dns-query" },'
      echo '      { "tag": "dns_direct4_3", "address": "https://223.5.5.5/dns-query" },'
      echo '      { "tag": "dns_direct6_1", "address": "https://[2606:4700:4700::1111]/dns-query" },'
      echo '      { "tag": "dns_direct6_2", "address": "https://[2001:4860:4860::8888]/dns-query" }'
    fi
    echo '    ],'
    echo '    "rules": ['
    local dns_rule_count=0
    if [ -n "$dns_bootstrap_domains" ]; then
      while IFS= read -r domain; do
        [ -z "$domain" ] && continue
        if [ "$dns_rule_count" -gt 0 ]; then
          echo '      ,'
        fi
        dns_rule_count=$((dns_rule_count+1))
        echo "      { \"domain\": [\"$(json_escape "$domain")\"], \"server\": \"dns_local\" }"
      done <<< "$dns_bootstrap_domains"
    fi
    echo '    ],'
    echo "    \"final\": \"${dns_final}\","
    echo "    \"strategy\": \"${dns_strategy}\""
    echo '  },'
    echo '  "inbounds": ['
    while IFS='|' read -r tag port out remark proto hy2_pass up down hy2_obfs hy2_masq; do
      [ -z "$tag" ] && continue
      [ -z "$proto" ] && proto="vless"
      inbound_count=$((inbound_count+1))
      if [ "$inbound_count" -gt 1 ]; then
        echo '    ,'
      fi
      if [ "$proto" = "hy2" ]; then
        cat <<EOF
    {
      "type": "hysteria2",
      "tag": "$(json_escape "$tag")",
      "listen": "0.0.0.0",
      "listen_port": ${port},
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "password": "$(json_escape "$hy2_pass")"
        }
      ],
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "$(json_escape "$HY2_CERT")",
        "key_path": "$(json_escape "$HY2_KEY")"
      }$( [ -n "$up" ] && printf ',\n      "up_mbps": %s' "$up" )$( [ -n "$down" ] && printf ',\n      "down_mbps": %s' "$down" )$( [ -z "$up" ] && [ -z "$down" ] && [ "${SB_HAS_HY2_IGNORE_BW}" -eq 1 ] && printf ',\n      "ignore_client_bandwidth": true' )$( [ -n "$hy2_obfs" ] && printf ',\n      "obfs": {"type":"salamander","password":"%s"}' "$(json_escape "$hy2_obfs")" )$( [ -n "$hy2_masq" ] && [ "${SB_HAS_HY2_MASQ}" -eq 1 ] && printf ',\n      "masquerade": "%s"' "$(json_escape "$hy2_masq")" )
    }
EOF
      else
        cat <<EOF
    {
      "type": "vless",
      "tag": "$(json_escape "$tag")",
      "listen": "0.0.0.0",
      "listen_port": ${port},
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "uuid": "$(json_escape "$UUID")",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$(json_escape "$SERVER_NAME")",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$(json_escape "$dest_host")",
            "server_port": ${dest_port}
          },
          "private_key": "$(json_escape "$PRIVATE_KEY")",
          "short_id": ["$(json_escape "$SHORT_ID")"]
        }
      }
    }
EOF
      fi
    done < "$INBOUNDS_FILE"
    echo '  ],'
    echo '  "outbounds": ['
    local used_outbounds_set
    used_outbounds_set="$(printf "%s\n" "$used_outbounds")"
    for f in "${OUTBOUNDS_DIR}"/*.json; do
      [ -e "$f" ] || continue
      local base resolver_tag resolver_strategy
      base="$(basename "$f" .json)"
      resolver_tag=""
      resolver_strategy="$dns_strategy"
      if [ "${SB_HAS_DOMAIN_RESOLVER}" -eq 1 ] && echo "$used_outbounds_set" | grep -qx "$base"; then
        case "$base" in
          direct4)
            resolver_tag="dns_direct4_1"
            resolver_strategy="prefer_ipv4"
            ;;
          direct6)
            resolver_tag="dns_direct6_1"
            resolver_strategy="prefer_ipv6"
            ;;
          *) resolver_tag="dns_local" ;;
        esac
      fi
      outbound_count=$((outbound_count+1))
      if [ "$outbound_count" -gt 1 ]; then
        echo '    ,'
      fi
      if [ -n "$resolver_tag" ]; then
        emit_outbound_with_resolver "$f" "$resolver_tag" "$resolver_strategy"
      else
        sed 's/^/    /' "$f"
      fi
    done
    echo '  ],'
    if has_endpoints; then
      echo '  "endpoints": ['
      for f in "${ENDPOINTS_DIR}"/*.json; do
        [ -e "$f" ] || continue
        local base resolver_tag resolver_strategy
        base="$(basename "$f" .json)"
        resolver_tag=""
        resolver_strategy="$dns_strategy"
        if [ "${SB_HAS_DOMAIN_RESOLVER}" -eq 1 ] && echo "$used_outbounds_set" | grep -qx "$base"; then
          case "$base" in
            direct4)
              resolver_tag="dns_direct4_1"
              resolver_strategy="prefer_ipv4"
              ;;
            direct6)
              resolver_tag="dns_direct6_1"
              resolver_strategy="prefer_ipv6"
              ;;
            *) resolver_tag="dns_local" ;;
          esac
        fi
        endpoint_count=$((endpoint_count+1))
        if [ "$endpoint_count" -gt 1 ]; then
          echo '    ,'
        fi
        if [ -n "$resolver_tag" ]; then
          emit_outbound_with_resolver "$f" "$resolver_tag" "$resolver_strategy"
        else
          sed 's/^/    /' "$f"
        fi
      done
      echo '  ],'
    fi
    echo '  "route": {'
    echo '    "auto_detect_interface": true,'
    if [ "${SB_HAS_ROUTE_DEFAULT_DOMAIN_RESOLVER}" -eq 1 ]; then
      echo '    "default_domain_resolver": "dns_local",'
    fi
    echo '    "rules": ['
    if [ -s "$FEATURE_ROUTES_FILE" ]; then
      while IFS='|' read -r fkey fout; do
        [ -z "$fkey" ] && continue
        [ -z "$fout" ] && continue
        if [ ! -f "${OUTBOUNDS_DIR}/${fout}.json" ] && [ ! -f "${ENDPOINTS_DIR}/${fout}.json" ]; then
          continue
        fi
        local suffix_json
        suffix_json="$(feature_domain_suffix_json "$fkey")"
        [ -z "$suffix_json" ] && continue
        rule_count=$((rule_count+1))
        if [ "$rule_count" -gt 1 ]; then
          echo '      ,'
        fi
        cat <<EOF
      {
        "inbound": ${inbound_tags_json},
        "domain_suffix": ${suffix_json},
        "outbound": "$(json_escape "$fout")"
      }
EOF
      done < "$FEATURE_ROUTES_FILE"
    fi
    while IFS='|' read -r tag port out remark proto hy2_pass up down hy2_obfs hy2_masq; do
      [ -z "$tag" ] && continue
      if [ ! -f "${OUTBOUNDS_DIR}/${out}.json" ] && [ ! -f "${ENDPOINTS_DIR}/${out}.json" ]; then
        die "未找到出口: ${out}"
      fi
      rule_count=$((rule_count+1))
      if [ "$rule_count" -gt 1 ]; then
        echo '      ,'
      fi
      cat <<EOF
      {
        "inbound": ["$(json_escape "$tag")"],
        "outbound": "$(json_escape "$out")"
      }
EOF
    done < "$INBOUNDS_FILE"
    echo '    ]'
    echo '  }'
    echo '}'
  } > "$tmp"

  mv "$tmp" "${CONFIG_DIR}/config.json"
  validate_singbox_config
}

get_public_ip4() {
  if ! cmd_exists curl; then
    return 0
  fi
  curl -4 -fsSL --max-time 6 https://api.ipify.org 2>/dev/null || true
}

get_public_ip6() {
  if ! cmd_exists curl; then
    return 0
  fi
  curl -6 -fsSL --max-time 6 https://api64.ipify.org 2>/dev/null || true
}

show_info() {
  if [ ! -f "$MANAGER_CONF" ]; then
    msg "未初始化，请先新增入口或更新基础配置。"
    return 0
  fi
  load_manager_conf
  HY2_CERT_MODE="${HY2_CERT_MODE:-self}"
  HY2_DOMAIN="${HY2_DOMAIN:-}"
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
  while IFS='|' read -r tag port out remark proto hy2_pass up down hy2_obfs hy2_masq; do
    [ -z "$tag" ] && continue
    local alias frag
    alias="${remark:-$tag}"
    frag="$(urlencode "$alias")"
    msg "  ${tag}  端口=${port}  出口=${out}"
    [ -z "${proto:-}" ] && proto="vless"
    hy2_pass="${hy2_pass:-}"
    if [ "$proto" = "hy2" ]; then
      local insecure_q="" pin_q="" obfs_q="" sni_name
      local hy2_pass_enc cert_pin
      sni_name="${SERVER_NAME}"
      if [ "${HY2_CERT_MODE:-self}" = "acme" ] && [ -n "${HY2_DOMAIN:-}" ]; then
        sni_name="${HY2_DOMAIN}"
      fi
      if [ "${HY2_CERT_MODE:-self}" = "self" ]; then
        cert_pin="$(hy2_cert_pin_sha256 || true)"
        if [ -n "$cert_pin" ]; then
          pin_q="&pinSHA256=$(urlencode "$cert_pin")"
        else
          insecure_q="&insecure=1"
          msg "  (未计算到证书 pin，已回退 insecure=1)"
        fi
      fi
      if [ -z "$hy2_pass" ]; then
        msg "  (HY2 密码为空，无法生成分享链接)"
        continue
      fi
      hy2_pass_enc="$(urlencode "$hy2_pass")"
      if [ -n "$hy2_obfs" ]; then
        obfs_q="&obfs=salamander&obfs-password=$(urlencode "$hy2_obfs")"
      fi
      if [ "$have_share" -eq 1 ]; then
        msg "  hysteria2://${hy2_pass_enc}@${host}:${port}?sni=${sni_name}&alpn=h3${pin_q}${insecure_q}${obfs_q}#${frag}"
      else
        if [ -n "$host4" ]; then
          msg "  hysteria2://${hy2_pass_enc}@${host4}:${port}?sni=${sni_name}&alpn=h3${pin_q}${insecure_q}${obfs_q}#${frag}"
        fi
        if [ -n "$host6" ]; then
          msg "  hysteria2://${hy2_pass_enc}@[${host6}]:${port}?sni=${sni_name}&alpn=h3${pin_q}${insecure_q}${obfs_q}#${frag}"
        fi
        if [ -z "$host4" ] && [ -z "$host6" ]; then
          msg "  hysteria2://${hy2_pass_enc}@SERVER_IP:${port}?sni=${sni_name}&alpn=h3${pin_q}${insecure_q}${obfs_q}#${frag}"
        fi
      fi
    else
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
    fi
  done < "$INBOUNDS_FILE"
}

update_base_config() {
  load_manager_conf
  local ans
  read -r -p "Reality SNI(建议常见 TLS 域名，默认: ${DEFAULT_SNI}): " SERVER_NAME_NEW
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
  restart_singbox
  msg "基础配置已更新。"
}

install_flow() {
  need_root
  install_deps
  install_singbox
  ensure_dirs
  enable_accel
  write_service
  write_openrc_service
  setup_logrotate

  msg "安装完成。"
  msg "请在菜单中新增入口并选择协议(VLESS/HY2)。"
}

init_base_config() {
  need_root
  ensure_dirs
  UUID="$(gen_uuid)"
  SHORT_ID="$(gen_short_id)"
  FINGERPRINT="chrome"
  gen_reality_keys
  HY2_CERT_MODE="self"
  HY2_DOMAIN=""

  read -r -p "Reality SNI(建议常见 TLS 域名，默认: ${DEFAULT_SNI}): " SERVER_NAME
  SERVER_NAME="${SERVER_NAME:-${DEFAULT_SNI}}"
  read -r -p "Reality 目标(默认: ${SERVER_NAME}:443): " DEST
  DEST="${DEST:-${SERVER_NAME}:443}"
  read -r -p "分享地址(域名或IP，留空自动获取): " SHARE_HOST

  save_manager_conf
  > "$INBOUNDS_FILE"
}

init_base_config_silent() {
  need_root
  ensure_dirs
  UUID="$(gen_uuid)"
  SHORT_ID="$(gen_short_id)"
  gen_reality_keys
  FINGERPRINT="chrome"
  HY2_CERT_MODE="self"
  HY2_DOMAIN=""
  SERVER_NAME="${DEFAULT_SNI}"
  DEST="${SERVER_NAME}:443"
  SHARE_HOST=""
  save_manager_conf
  > "$INBOUNDS_FILE"
}

uninstall_all() {
  need_root
  stop_singbox
  if systemd_available; then
    systemctl disable sing-box >/dev/null 2>&1 || true
    rm -f "$SERVICE_FILE"
    rm -f "$SERVICE_DROPIN_FILE"
    rmdir "$SERVICE_DROPIN_DIR" >/dev/null 2>&1 || true
    systemctl daemon-reload || true
  elif openrc_available; then
    rc-service sing-box stop >/dev/null 2>&1 || true
    rc-update del sing-box default >/dev/null 2>&1 || true
    rm -f "$OPENRC_SERVICE"
  fi
  rm -rf "$CONFIG_DIR"
  rm -f /etc/sysctl.d/99-singbox-accel.conf
  sysctl --system >/dev/null 2>&1 || true
  rm -f "$SB_BIN"
  rm -f "$LOGROTATE_FILE"
  rm -f "$PID_FILE"
  rm -f "$WGCF_DST"
  rm -rf /var/log/sing-box
  rm -rf "$TMP_DIR"
  msg "已卸载。"
}

show_status() {
  local active enabled pid
  if systemd_available; then
    if systemctl is-active --quiet sing-box; then
      active="运行中"
    else
      active="未运行"
    fi
    if systemctl is-enabled --quiet sing-box; then
      enabled="已设置开机自启"
    else
      enabled="未设置开机自启"
    fi
    pid="$(systemctl show -p MainPID --value sing-box 2>/dev/null || true)"
    [ -z "$pid" ] && pid="0"
    msg "服务状态: ${active}"
    msg "自启状态: ${enabled}"
    msg "主进程 PID: ${pid}"
  elif openrc_available; then
    if rc-service sing-box status >/dev/null 2>&1; then
      active="运行中"
    else
      active="未运行"
    fi
    if rc-update show default 2>/dev/null | awk '{print $1}' | grep -qx "sing-box"; then
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
      local p
      p="$(pgrep -f "sing-box run -c ${CONFIG_DIR}/config.json" 2>/dev/null | head -n1 || true)"
      if [ -n "$p" ]; then
        msg "服务状态: 运行中 (PID ${p})"
      else
        msg "服务状态: 未运行"
      fi
    fi
  fi
  if [ -f /var/log/sing-box/sing-box.log ]; then
    msg "日志路径: /var/log/sing-box/sing-box.log"
    msg "日志大小: $(stat -c %s /var/log/sing-box/sing-box.log 2>/dev/null || echo 0) 字节"
  fi
}

restart_service() {
  restart_singbox
  msg "服务已重启。"
  show_status
}

diagnose_start_failure() {
  if [ -x "$SB_BIN" ] && [ -f "${CONFIG_DIR}/config.json" ]; then
    ui "sing-box 配置校验："
    "$SB_BIN" check -c "${CONFIG_DIR}/config.json" 2>&1 | head -n 50 >&2 || true
  fi
  if [ -f /var/log/sing-box/sing-box.log ]; then
    ui "sing-box 最近日志："
    tail -n 50 /var/log/sing-box/sing-box.log >&2 || true
  fi
}

main_menu() {
  local choice
  while true; do
    msg ""
    menu_title "sing-box 一键脚本"
    msg "${C_DIM}(${OS_NAME} ${OS_VERSION} / ${ARCH_LABEL})${C_RESET}"
    menu_sep
    if [ -x "$SB_BIN" ]; then
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
      menu_item 13 "功能分流管理"
      menu_item 0 "退出"
      read -r -p "请选择: " choice
      if [ ! -f "$MANAGER_CONF" ] && [ "$choice" != "1" ] && [ "$choice" != "0" ] && [ "$choice" != "11" ] && [ "$choice" != "12" ] && [ "$choice" != "13" ]; then
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
        13) manage_feature_routes ;;
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
