#!/usr/bin/env bash
# OpenConnect Server (ocserv) 安装/管理脚本
# 适用系统: Debian 12/13, Ubuntu 22.04/24.04
# 登录方式: 证书 / 密码
#
# 使用说明:
# 1) 安装（交互式）
#    bash ocserv.sh install
#    - 选择 TCP/UDP 端口（默认 443）
#    - 选择登录方式（密码/证书）
#    - 密码方式：会提示输入账号和密码并创建用户
#    - 证书方式：自动生成 CA/服务器证书/客户端证书
#      客户端证书输出: /etc/ocserv/pki/<客户端名>.p12（默认 client.p12）
#
# 2) 用户管理（密码登录）
#    bash ocserv.sh adduser 用户名 密码
#    bash ocserv.sh deluser 用户名
#
# 3) 切换认证方式（不自动生成客户端证书）
#    bash ocserv.sh auth cert
#    bash ocserv.sh auth password
#
# 4) 关键文件路径
#    配置文件: /etc/ocserv/ocserv.conf
#    账号文件: /etc/ocserv/ocpasswd
#    证书目录: /etc/ocserv/pki
#
# 5) 防火墙/转发说明
#    - 自动开启 IPv4 转发（/etc/sysctl.d/99-ocserv.conf）
#    - 自动添加 iptables NAT 与端口放行规则
#
# 注意:
# - 仅支持 systemd 系统（默认 Debian 12/13、Ubuntu 22/24）
# - 如果是证书登录，客户端需导入 .p12 文件
set -euo pipefail

CONFIG_FILE="/etc/ocserv/ocserv.conf"
OC_PASSWD="/etc/ocserv/ocpasswd"
PKI_DIR="/etc/ocserv/pki"
SYSCTL_FILE="/etc/sysctl.d/99-ocserv.conf"
TCP_PORT_DEFAULT=443
UDP_PORT_DEFAULT=443
VPN_NET="192.168.8.0"
VPN_NETMASK="255.255.255.0"
VPN_CIDR="24"

APT_UPDATED=0
OS_ID=""
OS_VERSION=""

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "请用 root 运行。" >&2
    exit 1
  fi
}

check_os() {
  if [ ! -r /etc/os-release ]; then
    echo "无法识别系统版本，仅支持 Debian 12/13 与 Ubuntu 22.04/24.04。" >&2
    exit 1
  fi
  # shellcheck source=/etc/os-release
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_VERSION="${VERSION_ID:-}"
  case "$OS_ID" in
    debian)
      case "$OS_VERSION" in
        12|13) ;;
        *) echo "仅支持 Debian 12/13 (当前: ${OS_VERSION:-unknown})." >&2; exit 1 ;;
      esac
      ;;
    ubuntu)
      case "$OS_VERSION" in
        22.04|24.04) ;;
        *) echo "仅支持 Ubuntu 22.04/24.04 (当前: ${OS_VERSION:-unknown})." >&2; exit 1 ;;
      esac
      ;;
    *)
      echo "仅支持 Debian 12/13 与 Ubuntu 22.04/24.04。" >&2
      exit 1
      ;;
  esac
}

apt_update() {
  if [ "$APT_UPDATED" -eq 0 ]; then
    DEBIAN_FRONTEND=noninteractive apt-get update -y
    APT_UPDATED=1
  fi
}

apt_install() {
  apt_update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

detect_iface() {
  local iface
  iface="$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  if [ -z "$iface" ]; then
    iface="$(ip -o link show 2>/dev/null | awk -F': ' '$2!="lo" {print $2; exit}')"
  fi
  echo "$iface"
}

get_public_ip() {
  local ip
  ip="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"
  if [ -z "$ip" ]; then
    ip="$(curl -fsSL https://ifconfig.me 2>/dev/null || true)"
  fi
  echo "$ip"
}

prompt_port() {
  local prompt="$1" default="$2" value
  while true; do
    read -r -p "$prompt" value
    value="${value:-$default}"
    if echo "$value" | grep -qE '^[0-9]+$' && [ "$value" -ge 1 ] && [ "$value" -le 65535 ]; then
      echo "$value"
      return 0
    fi
    echo "端口无效，请输入 1-65535。" >&2
  done
}

prompt_auth() {
  local choice
  echo "选择登录方式:"
  echo "1) 密码登录"
  echo "2) 证书登录"
  read -r -p "请选择 [1-2] (默认 1): " choice
  case "${choice:-1}" in
    1) echo "password" ;;
    2) echo "certificate" ;;
    *) echo "password" ;;
  esac
}

write_sysctl() {
  cat > "$SYSCTL_FILE" <<'EOF'
net.ipv4.ip_forward = 1
EOF
  sysctl --system >/dev/null 2>&1 || true
}

setup_firewall() {
  local iface="$1" tcp_port="$2" udp_port="$3"
  if [ -z "$iface" ]; then
    echo "未检测到网卡，跳过防火墙配置。" >&2
    return 0
  fi
  if ! command -v iptables >/dev/null 2>&1; then
    apt_install iptables
  fi

  iptables -t nat -C POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$iface" -j MASQUERADE

  iptables -C INPUT -p tcp --dport "$tcp_port" -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p tcp --dport "$tcp_port" -j ACCEPT
  iptables -C INPUT -p udp --dport "$udp_port" -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p udp --dport "$udp_port" -j ACCEPT

  iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -C FORWARD -s "$VPN_NET/$VPN_CIDR" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -s "$VPN_NET/$VPN_CIDR" -j ACCEPT

  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  elif [ -d /etc/iptables ] && command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
  fi
}

write_config() {
  local auth_type="$1" tcp_port="$2" udp_port="$3"
  local auth_line
  if [ "$auth_type" = "certificate" ]; then
    auth_line='auth = "certificate"'
  else
    auth_line='auth = "plain[passwd=/etc/ocserv/ocpasswd]"'
  fi

  cat > "$CONFIG_FILE" <<EOF
${auth_line}

tcp-port = ${tcp_port}
udp-port = ${udp_port}

run-as-user = ocserv
run-as-group = ocserv
socket-file = /run/ocserv.sock
pid-file = /run/ocserv.pid
isolate-workers = true
max-clients = 128
max-same-clients = 2
keepalive = 32400
dpd = 90
mobile-dpd = 1800
try-mtu-discovery = true
compression = false

server-cert = ${PKI_DIR}/server.cert.pem
server-key = ${PKI_DIR}/server.key.pem
ca-cert = ${PKI_DIR}/ca.cert.pem
cert-user-oid = 2.5.4.3

tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-ARCFOUR-128"

ipv4-network = ${VPN_NET}
ipv4-netmask = ${VPN_NETMASK}

# 全局代理
route = default
# 常见内网不走 VPN
no-route = 10.0.0.0/255.0.0.0
no-route = 172.16.0.0/255.240.0.0
no-route = 192.168.0.0/255.255.0.0

# DNS
_dns = 1.1.1.1
_dns = 8.8.8.8
EOF

  # 修正 DNS 行（避免被 ocserv 认为是注释）
  sed -i 's/^_dns /dns = /g' "$CONFIG_FILE"
}

is_ip() {
  echo "$1" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
}

gen_pki() {
  local server_name="$1"
  mkdir -p "$PKI_DIR"

  # CA
  cat > "$PKI_DIR/ca.tmpl" <<EOF
cn = "OCSERV CA"
organization = "OCSERV"
serial = 1
expiration_days = 3650
ca
signing_key
cert_signing_key
crl_signing_key
EOF
  certtool --generate-privkey --outfile "$PKI_DIR/ca.key.pem"
  certtool --generate-self-signed \
    --load-privkey "$PKI_DIR/ca.key.pem" \
    --template "$PKI_DIR/ca.tmpl" \
    --outfile "$PKI_DIR/ca.cert.pem"

  # DH params
  certtool --generate-dh-params --outfile "$PKI_DIR/dh.pem" >/dev/null 2>&1 || true

  # Server
  cat > "$PKI_DIR/server.tmpl" <<EOF
cn = "${server_name}"
organization = "OCSERV"
serial = 2
expiration_days = 825
signing_key
encryption_key
tls_www_server
EOF
  if is_ip "$server_name"; then
    echo "ip_address = ${server_name}" >> "$PKI_DIR/server.tmpl"
  else
    echo "dns_name = ${server_name}" >> "$PKI_DIR/server.tmpl"
  fi

  certtool --generate-privkey --outfile "$PKI_DIR/server.key.pem"
  certtool --generate-certificate \
    --load-privkey "$PKI_DIR/server.key.pem" \
    --load-ca-certificate "$PKI_DIR/ca.cert.pem" \
    --load-ca-privkey "$PKI_DIR/ca.key.pem" \
    --template "$PKI_DIR/server.tmpl" \
    --outfile "$PKI_DIR/server.cert.pem"
}

gen_client_cert() {
  local client_name="$1"
  cat > "$PKI_DIR/client.tmpl" <<EOF
cn = "${client_name}"
organization = "OCSERV"
serial = 3
expiration_days = 825
signing_key
tls_www_client
EOF
  certtool --generate-privkey --outfile "$PKI_DIR/client.key.pem"
  certtool --generate-certificate \
    --load-privkey "$PKI_DIR/client.key.pem" \
    --load-ca-certificate "$PKI_DIR/ca.cert.pem" \
    --load-ca-privkey "$PKI_DIR/ca.key.pem" \
    --template "$PKI_DIR/client.tmpl" \
    --outfile "$PKI_DIR/client.cert.pem"

  cat "$PKI_DIR/ca.cert.pem" >> "$PKI_DIR/client.cert.pem"
  openssl pkcs12 -export \
    -inkey "$PKI_DIR/client.key.pem" \
    -in "$PKI_DIR/client.cert.pem" \
    -name "$client_name" \
    -certfile "$PKI_DIR/ca.cert.pem" \
    -out "$PKI_DIR/${client_name}.p12" \
    -passout pass:
}

set_auth_type() {
  local auth_type="$1"
  if [ ! -f "$CONFIG_FILE" ]; then
    echo "未找到配置文件: $CONFIG_FILE" >&2
    exit 1
  fi
  if [ "$auth_type" = "certificate" ]; then
    sed -i 's/^auth =.*/auth = "certificate"/' "$CONFIG_FILE"
  else
    sed -i 's/^auth =.*/auth = "plain[passwd=\/etc\/ocserv\/ocpasswd]"/' "$CONFIG_FILE"
  fi
  systemctl restart ocserv >/dev/null 2>&1 || true
}

add_user() {
  local user="$1" pass="$2"
  if [ -z "$user" ] || [ -z "$pass" ]; then
    echo "用法: $0 adduser USER PASS" >&2
    exit 1
  fi
  printf '%s\n%s\n' "$pass" "$pass" | ocpasswd -c "$OC_PASSWD" "$user"
  systemctl restart ocserv >/dev/null 2>&1 || true
}

del_user() {
  local user="$1"
  if [ -z "$user" ]; then
    echo "用法: $0 deluser USER" >&2
    exit 1
  fi
  ocpasswd -d -c "$OC_PASSWD" "$user"
  systemctl restart ocserv >/dev/null 2>&1 || true
}

install_flow() {
  need_root
  check_os

  apt_install ocserv gnutls-bin openssl curl iproute2 ca-certificates

  local tcp_port udp_port auth_type
  local public_ip server_name iface

  tcp_port="$(prompt_port "AnyConnect TCP 端口 [默认 ${TCP_PORT_DEFAULT}]: " "$TCP_PORT_DEFAULT")"
  udp_port="$(prompt_port "AnyConnect UDP 端口 [默认 ${UDP_PORT_DEFAULT}]: " "$UDP_PORT_DEFAULT")"
  auth_type="$(prompt_auth)"

  public_ip="$(get_public_ip)"
  server_name="$public_ip"
  read -r -p "服务器域名或IP (默认: ${public_ip:-空}): " server_name_input
  if [ -n "${server_name_input:-}" ]; then
    server_name="$server_name_input"
  fi
  if [ -z "${server_name:-}" ]; then
    echo "未能获取服务器 IP，请手动输入域名或 IP。" >&2
    exit 1
  fi

  write_sysctl
  gen_pki "$server_name"
  write_config "$auth_type" "$tcp_port" "$udp_port"

  if [ "$auth_type" = "password" ]; then
    local user pass
    read -r -p "设置账号用户名: " user
    read -r -s -p "设置账号密码: " pass
    echo
    add_user "$user" "$pass"
  else
    local client_name
    read -r -p "客户端证书名称 (默认: client): " client_name
    client_name="${client_name:-client}"
    gen_client_cert "$client_name"
    echo "客户端证书已生成: ${PKI_DIR}/${client_name}.p12"
  fi

  iface="$(detect_iface)"
  setup_firewall "$iface" "$tcp_port" "$udp_port"

  systemctl enable --now ocserv
  systemctl restart ocserv

  echo "安装完成。"
  echo "服务状态: $(systemctl is-active ocserv 2>/dev/null || true)"
  echo "配置文件: $CONFIG_FILE"
}

usage() {
  cat <<EOF
用法:
  $0 install              安装 ocserv
  $0 adduser USER PASS    添加账号
  $0 deluser USER         删除账号
  $0 auth cert|password   切换认证方式
EOF
}

main() {
  case "${1:-install}" in
    install) shift; install_flow ;;
    adduser) shift; add_user "${1:-}" "${2:-}" ;;
    deluser) shift; del_user "${1:-}" ;;
    auth) shift; set_auth_type "${1:-}" ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
