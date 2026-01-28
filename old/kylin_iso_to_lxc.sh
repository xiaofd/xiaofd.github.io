#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  kylin_iso_to_lxc.sh /path/to.iso [name] [options]
  kylin_iso_to_lxc.sh --iso /path/to.iso [options]
  kylin_iso_to_lxc.sh --menu

Options:
  --iso PATH           Path to Kylin ISO (required unless positional ISO is used)
  --workdir DIR        Working directory (default: /tmp/kylin-lxc-work)
  --rootfs DIR         Extracted rootfs output (default: /root/kylin)
  --tar PATH           LXC template tarball (default: /root/kylin-lxc-template.tar.gz)
  --name NAME          Target container name (create/start/forward)
  --create             Create LXC container from tar (use with --name)
  --lxc-path DIR       LXC container base path (default: /var/lib/lxc)
  --bridge NAME        LXC bridge name (default: lxcbr0)
  --set-kylin-sources  Overwrite /etc/apt/sources.list with Kylin V10 SP1 repo
  --set-dns            Overwrite /etc/resolv.conf with 1.1.1.1
  --set-root-pass      Randomize root password and update /etc/shadow
  --set-dhcp           Force DHCP inside rootfs (systemd-networkd)
  --fix-net            Configure host forwarding/NAT for LXC (Docker friendly)
  --start              Start container after creation
  --forward SPEC       Port forward spec (repeatable), e.g. 2222:22 or 8080:80/tcp
  --fix-conf           Apply recommended LXC config fixes for systemd containers
  --no-desktop-conf    Disable desktop-oriented device/mount config (default: enabled)
  --start-foreground   Start container in foreground (implies --fix-conf)
  --force              Remove existing rootfs/container if present
  --menu               Interactive menu
  -h, --help           Show this help

Notes:
  - The ISO is ARM64; run the container on an ARM host.
  - Port forwarding uses iptables and enables ip_forward.
EOF
}

ISO=""
WORKDIR="/tmp/kylin-lxc-work"
ROOTFS="/root/kylin"
TAR_OUT="/root/kylin-lxc-template.tar.gz"
NAME=""
LXC_PATH="/var/lib/lxc"
BRIDGE="lxcbr0"
START="0"
START_FOREGROUND="0"
FIX_CONF="0"
DESKTOP_CONF="1"
SET_SOURCES="1"
SET_DNS="1"
SET_ROOT_PASS="1"
SET_DHCP="1"
FORCE="0"
FORWARDS=()
FIX_NET="0"
MENU="0"
CREATE="0"
DO_BUILD="0"
DO_CREATE="0"
DO_START="0"
DO_START_FG="0"
DO_FIX_NET="0"

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --iso) ISO="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --rootfs) ROOTFS="$2"; shift 2 ;;
    --tar) TAR_OUT="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --create) CREATE="1"; shift ;;
    --lxc-path) LXC_PATH="$2"; shift 2 ;;
    --bridge) BRIDGE="$2"; shift 2 ;;
    --start) START="1"; shift ;;
    --start-foreground) START_FOREGROUND="1"; FIX_CONF="1"; shift ;;
    --forward) FORWARDS+=("$2"); shift 2 ;;
    --fix-conf) FIX_CONF="1"; shift ;;
    --no-desktop-conf) DESKTOP_CONF="0"; shift ;;
    --set-kylin-sources) SET_SOURCES="1"; shift ;;
    --set-dns) SET_DNS="1"; shift ;;
    --set-root-pass) SET_ROOT_PASS="1"; shift ;;
    --set-dhcp) SET_DHCP="1"; shift ;;
    --fix-net) FIX_NET="1"; shift ;;
    --menu) MENU="1"; shift ;;
    --force) FORCE="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ ${#POSITIONAL[@]} -ge 1 && -z "$ISO" ]]; then
  ISO="${POSITIONAL[0]}"
fi
if [[ ${#POSITIONAL[@]} -ge 2 && -z "$NAME" ]]; then
  NAME="${POSITIONAL[1]}"
fi

prompt() {
  local var="$1"
  local text="$2"
  local default="${3:-}"
  local val=""
  if [[ -n "$default" ]]; then
    if [[ -t 0 ]]; then
      read -e -p "$text [$default]: " -i "$default" val
    else
      read -r -p "$text [$default]: " val
    fi
    val="${val:-$default}"
  else
    if [[ -t 0 ]]; then
      read -e -p "$text: " val
    else
      read -r -p "$text: " val
    fi
  fi
  printf -v "$var" "%s" "$val"
}

apply_forward() {
  local name="$1"
  local spec="$2"
  local proto="tcp"
  if [[ "$spec" == */* ]]; then
    proto="${spec##*/}"
    spec="${spec%/*}"
  fi
  local host_port="${spec%%:*}"
  local cont_port="${spec##*:}"
  if [[ -z "$host_port" || -z "$cont_port" ]]; then
    echo "Invalid forward spec: $spec"
    return 1
  fi
  local ip=""
  for _ in {1..30}; do
    ip=$(lxc-info -n "$name" -iH | head -n1 || true)
    [[ -n "$ip" ]] && break
    sleep 1
  done
  if [[ -z "$ip" ]]; then
    echo "Error: container IP not found."
    return 1
  fi
  iptables -t nat -A PREROUTING -p "$proto" --dport "$host_port" -j DNAT --to-destination "$ip:$cont_port"
  iptables -A FORWARD -p "$proto" -d "$ip" --dport "$cont_port" -j ACCEPT
  echo "Forwarded $host_port->$ip:$cont_port/$proto"
}

ensure_config_line() {
  local file="$1"
  local line="$2"
  grep -qF -- "$line" "$file" || echo "$line" >> "$file"
}

apply_fix_conf() {
  local cfg="$1"
  if ! grep -q "common.conf" "$cfg"; then
    sed -i '1i lxc.include = /usr/share/lxc/config/common.conf' "$cfg"
  fi
  ensure_config_line "$cfg" "lxc.include = /usr/share/lxc/config/nesting.conf"
  ensure_config_line "$cfg" "lxc.apparmor.profile = unconfined"
  ensure_config_line "$cfg" "lxc.apparmor.allow_nesting = 1"
  ensure_config_line "$cfg" "lxc.mount.auto = proc:mixed cgroup:mixed"
}

apply_desktop_conf() {
  local cfg="$1"
  ensure_config_line "$cfg" "lxc.pty.max = 1024"
  ensure_config_line "$cfg" "lxc.cgroup.devices.allow = a"
  ensure_config_line "$cfg" "lxc.mount.entry = /dev/dri dev/dri none bind,optional,create=dir"
  ensure_config_line "$cfg" "lxc.mount.entry = /dev/snd dev/snd none bind,optional,create=dir"
  ensure_config_line "$cfg" "lxc.mount.entry = /dev/input dev/input none bind,optional,create=dir"
  ensure_config_line "$cfg" "lxc.mount.entry = /tmp/.X11-unix tmp/.X11-unix none bind,optional,create=dir"
  ensure_config_line "$cfg" "lxc.mount.entry = tmpfs dev/shm tmpfs rw,create=dir,optional 0 0"
}

check_space_kb() {
  local path="$1"
  local need_kb="$2"
  local label="$3"
  local avail_kb
  avail_kb=$(df -Pk "$path" 2>/dev/null | awk 'NR==2 {print $4}')
  if [[ -z "$avail_kb" ]]; then
    echo "Warning: could not check free space for $label ($path)."
    return 0
  fi
  if (( avail_kb < need_kb )); then
    echo "Error: insufficient space for $label at $path (need ~${need_kb}KB, have ${avail_kb}KB)."
    exit 1
  fi
}

run_menu() {
  while true; do
    echo ""
    echo "Select action:"
    echo "  1) Build rootfs + tar from ISO"
    echo "  2) Create LXC container from tar"
    echo "  3) Start container (bg)"
    echo "  4) Start container (fg) + fix conf"
    echo "  5) Fix host networking (NAT/forward)"
    echo "  6) Add port forward rule"
    echo "  7) Exit"
    read -r -p "Choice: " choice
    case "$choice" in
      1)
        prompt ISO "ISO path"
        prompt ROOTFS "Rootfs output dir" "$ROOTFS"
        prompt TAR_OUT "Tar output path" "$TAR_OUT"
        prompt WORKDIR "Workdir (squashfs temp)" "$WORKDIR"
        FORCE="1"
        DO_BUILD="1"
        ;;
      2)
        prompt NAME "Container name"
        prompt LXC_PATH "LXC base path" "$LXC_PATH"
        prompt BRIDGE "Bridge name" "$BRIDGE"
        prompt TAR_OUT "Tar input path" "$TAR_OUT"
        DO_CREATE="1"
        DO_BUILD="0"
        ;;
      3)
        prompt NAME "Container name"
        DO_START="1"
        DO_BUILD="0"
        ;;
      4)
        prompt NAME "Container name"
        DO_START_FG="1"
        FIX_CONF="1"
        DO_BUILD="0"
        ;;
      5)
        DO_FIX_NET="1"
        DO_BUILD="0"
        ;;
      6)
        prompt NAME "Container name"
        prompt spec "Forward spec (e.g. 2222:22 or 8080:80/tcp)"
        if ! command -v iptables >/dev/null 2>&1; then
          echo "iptables not found."
        else
          apply_forward "$NAME" "$spec" || true
        fi
        continue
        ;;
      7) exit 0 ;;
      *) echo "Invalid choice"; continue ;;
    esac
    break
  done
}

if [[ "$MENU" == "1" || $# -eq 0 ]]; then
  run_menu
fi

if [[ "$MENU" == "0" ]]; then
  [[ -n "$ISO" ]] && DO_BUILD="1"
  if [[ "$CREATE" == "1" ]] || [[ -n "$ISO" && -n "$NAME" ]]; then
    DO_CREATE="1"
  fi
  [[ "$START" == "1" ]] && DO_START="1"
  [[ "$START_FOREGROUND" == "1" ]] && DO_START_FG="1"
  [[ "$FIX_NET" == "1" ]] && DO_FIX_NET="1"
fi

if [[ -z "$ISO" && "$DO_BUILD" == "1" ]]; then
  echo "Error: --iso is required."
  usage
  exit 1
fi

if [[ -n "$ISO" && "$DO_BUILD" == "1" ]]; then
  if [[ ! -f "$ISO" ]]; then
    echo "Error: ISO not found: $ISO"
    exit 1
  fi
  if ! command -v bsdtar >/dev/null 2>&1 || ! command -v unsquashfs >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y
      apt-get install -y libarchive-tools squashfs-tools tar
    else
      echo "Missing dependencies and apt-get not found."
      exit 1
    fi
  fi
fi

if [[ -n "$ISO" && "$DO_BUILD" == "1" ]]; then
  mkdir -p "$WORKDIR"
fi

if [[ -n "$ISO" && "$DO_BUILD" == "1" ]]; then
  if ! bsdtar -tf "$ISO" | grep -q '^casper/filesystem.squashfs$'; then
    echo "Error: casper/filesystem.squashfs not found in ISO."
    exit 1
  fi
fi

if [[ -n "$ISO" && "$DO_BUILD" == "1" ]]; then
  if [[ -d "$ROOTFS" ]]; then
    if [[ "$FORCE" == "1" ]]; then
      rm -rf "$ROOTFS"
    else
      echo "Error: $ROOTFS exists. Use --force to overwrite."
      exit 1
    fi
  fi
fi

if [[ -n "$ISO" && "$DO_BUILD" == "1" ]]; then
  echo "Build inputs:"
  echo "  ISO: $ISO"
  echo "  WORKDIR: $WORKDIR"
  echo "  ROOTFS: $ROOTFS"
  echo "  TAR_OUT: $TAR_OUT"

  echo "Extracting squashfs from ISO..."
  if ! bsdtar -xOf "$ISO" casper/filesystem.squashfs > "$WORKDIR/filesystem.squashfs"; then
    echo "Error: failed to extract casper/filesystem.squashfs"
    exit 1
  fi
  if [[ ! -s "$WORKDIR/filesystem.squashfs" ]]; then
    echo "Error: extracted squashfs is empty: $WORKDIR/filesystem.squashfs"
    exit 1
  fi

  echo "Unsquashing to $ROOTFS..."
  SQUASH_KB=$(du -sk "$WORKDIR/filesystem.squashfs" | awk '{print $1}')
  ROOT_PARENT="$(dirname "$ROOTFS")"
  check_space_kb "$ROOT_PARENT" "$((SQUASH_KB * 4))" "rootfs extract"
  if ! unsquashfs -d "$ROOTFS" "$WORKDIR/filesystem.squashfs"; then
    echo "Error: unsquashfs failed (check disk space)."
    exit 1
  fi
  if [[ ! -f "$ROOTFS/etc/os-release" ]]; then
    echo "Error: rootfs extract failed (missing /etc/os-release)."
    exit 1
  fi
fi

ROOT_PASSWORD=""
if [[ -n "$ISO" && "$DO_BUILD" == "1" ]]; then
  if [[ "$SET_SOURCES" == "1" ]]; then
    if [[ -f "$ROOTFS/etc/apt/sources.list" ]]; then
      cp -f "$ROOTFS/etc/apt/sources.list" "$ROOTFS/etc/apt/sources.list.bak"
    fi
    mkdir -p "$ROOTFS/etc/apt"
    cat > "$ROOTFS/etc/apt/sources.list" <<'EOF'
deb http://archive.kylinos.cn/kylin/KYLIN-ALL 10.1 main restricted universe multiverse
EOF
  fi

  if [[ "$SET_DNS" == "1" ]]; then
    rm -f "$ROOTFS/etc/resolv.conf"
    echo "nameserver 1.1.1.1" > "$ROOTFS/etc/resolv.conf"
  fi

  if [[ "$SET_ROOT_PASS" == "1" ]]; then
    if ! command -v openssl >/dev/null 2>&1; then
      if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y openssl
      else
        echo "Missing openssl and apt-get not found."
        exit 1
      fi
    fi
    ROOT_PASSWORD="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)"
    ROOT_HASH="$(openssl passwd -6 "$ROOT_PASSWORD")"
    if [[ -f "$ROOTFS/etc/shadow" ]]; then
      sed -i "s#^root:[^:]*:#root:${ROOT_HASH}:#" "$ROOTFS/etc/shadow"
    fi
  fi

  if [[ "$SET_DHCP" == "1" ]]; then
    mkdir -p "$ROOTFS/etc/systemd/network"
    cat > "$ROOTFS/etc/systemd/network/10-eth0.network" <<'EOF'
[Match]
Name=eth0

[Network]
DHCP=yes
EOF
    mkdir -p "$ROOTFS/etc/systemd/system/multi-user.target.wants"
    mkdir -p "$ROOTFS/etc/systemd/system/sockets.target.wants"
    if [[ -f "$ROOTFS/lib/systemd/system/systemd-networkd.service" ]]; then
      ln -sf /lib/systemd/system/systemd-networkd.service \
        "$ROOTFS/etc/systemd/system/multi-user.target.wants/systemd-networkd.service"
      ln -sf /lib/systemd/system/systemd-networkd.socket \
        "$ROOTFS/etc/systemd/system/sockets.target.wants/systemd-networkd.socket"
    elif [[ -f "$ROOTFS/usr/lib/systemd/system/systemd-networkd.service" ]]; then
      ln -sf /usr/lib/systemd/system/systemd-networkd.service \
        "$ROOTFS/etc/systemd/system/multi-user.target.wants/systemd-networkd.service"
      ln -sf /usr/lib/systemd/system/systemd-networkd.socket \
        "$ROOTFS/etc/systemd/system/sockets.target.wants/systemd-networkd.socket"
    fi
    mkdir -p "$ROOTFS/etc/systemd/system"
    if [[ -f "$ROOTFS/lib/systemd/system/systemd-networkd.service" ]]; then
      ln -sf /lib/systemd/system/systemd-networkd.service \
        "$ROOTFS/etc/systemd/system/dbus-org.freedesktop.network1.service"
    elif [[ -f "$ROOTFS/usr/lib/systemd/system/systemd-networkd.service" ]]; then
      ln -sf /usr/lib/systemd/system/systemd-networkd.service \
        "$ROOTFS/etc/systemd/system/dbus-org.freedesktop.network1.service"
    fi
  fi
fi

if [[ -n "$ISO" && "$DO_BUILD" == "1" ]]; then
  echo "Packing LXC template to $TAR_OUT..."
  TAR_PARENT="$(dirname "$TAR_OUT")"
  check_space_kb "$TAR_PARENT" "$((SQUASH_KB * 3))" "tar output"
  if ! tar --numeric-owner -czf "$TAR_OUT" -C "$ROOTFS" .; then
    echo "Error: tar failed (check disk space)."
    exit 1
  fi
  if [[ ! -s "$TAR_OUT" ]]; then
    echo "Error: tar output not created: $TAR_OUT"
    exit 1
  fi
fi

if [[ -n "$NAME" && "$DO_CREATE" == "1" ]]; then
  if [[ ! -s "$TAR_OUT" ]]; then
    echo "Error: LXC template tar not found: $TAR_OUT"
    exit 1
  fi
  if ! command -v lxc-start >/dev/null 2>&1 || ! command -v lxc-info >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y
      apt-get install -y lxc lxc-templates debootstrap bridge-utils
    else
      echo "Missing lxc and apt-get not found."
      exit 1
    fi
  fi

  LXC_DIR="$LXC_PATH/$NAME"
  if [[ -e "$LXC_DIR" ]]; then
    if [[ "$FORCE" == "1" ]]; then
      rm -rf "$LXC_DIR"
    else
      echo "Error: $LXC_DIR exists. Use --force to overwrite."
      exit 1
    fi
  fi

  mkdir -p "$LXC_DIR/rootfs"
  tar --numeric-owner -xzf "$TAR_OUT" -C "$LXC_DIR/rootfs"

  cat > "$LXC_DIR/config" <<EOF
lxc.arch = aarch64
lxc.rootfs.path = $LXC_DIR/rootfs
lxc.uts.name = $NAME
lxc.init.cmd = /sbin/init
lxc.net.0.type = veth
lxc.net.0.link = $BRIDGE
lxc.net.0.flags = up
lxc.net.0.name = eth0
EOF

  if [[ "$FIX_CONF" == "1" ]]; then
    apply_fix_conf "$LXC_DIR/config"
  fi
  if [[ "$DESKTOP_CONF" == "1" ]]; then
    apply_desktop_conf "$LXC_DIR/config"
  fi

fi

if [[ -n "$NAME" && "$FIX_CONF" == "1" && "$DO_CREATE" == "0" ]]; then
  LXC_CFG="$LXC_PATH/$NAME/config"
  if [[ ! -f "$LXC_CFG" ]]; then
    echo "Error: LXC config not found: $LXC_CFG"
    exit 1
  fi
  apply_fix_conf "$LXC_CFG"
fi

if [[ -n "$NAME" && ( "$DO_START" == "1" || "$DO_START_FG" == "1" ) ]]; then
  if ! command -v lxc-start >/dev/null 2>&1 || ! command -v lxc-info >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y
      apt-get install -y lxc lxc-templates debootstrap bridge-utils
    else
      echo "Missing lxc and apt-get not found."
      exit 1
    fi
  fi
  LXC_DIR="$LXC_PATH/$NAME"
  if [[ ! -d "$LXC_DIR" ]]; then
    echo "Error: container not found at $LXC_DIR"
    exit 1
  fi
  if lxc-info -n "$NAME" -sH 2>/dev/null | grep -qi RUNNING; then
    echo "Container already running: $NAME"
  else
    if [[ "$DO_START_FG" == "1" ]]; then
      lxc-start -n "$NAME" -F
    else
      lxc-start -n "$NAME"
    fi
  fi
fi

if [[ -n "$NAME" && "${#FORWARDS[@]}" -gt 0 ]]; then
  if ! command -v iptables >/dev/null 2>&1 || ! command -v lxc-info >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y
      apt-get install -y iptables lxc lxc-templates debootstrap bridge-utils iproute2 procps dnsmasq-base
    else
      echo "Missing iptables/lxc and apt-get not found."
      exit 1
    fi
  fi
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  for spec in "${FORWARDS[@]}"; do
    apply_forward "$NAME" "$spec"
  done
fi

if [[ "$DO_FIX_NET" == "1" ]]; then
  if ! command -v iptables >/dev/null 2>&1 || ! command -v ip >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y
      apt-get install -y iptables lxc lxc-templates debootstrap bridge-utils iproute2 procps dnsmasq-base
    else
      echo "Missing iptables and apt-get not found."
      exit 1
    fi
  fi
  if [[ -f /etc/default/lxc-net ]]; then
    if ! grep -q 'USE_LXC_BRIDGE="true"' /etc/default/lxc-net; then
      sed -i 's/^#\\?USE_LXC_BRIDGE=.*/USE_LXC_BRIDGE="true"/' /etc/default/lxc-net
    fi
    systemctl restart lxc-net >/dev/null 2>&1 || service lxc-net restart >/dev/null 2>&1 || true
  fi
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  OUT_IF="$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {print $5; exit}')"
  if [[ -z "$OUT_IF" ]]; then
    OUT_IF="$(ip route show default | awk '/default/ {print $5; exit}')"
  fi
  if [[ -z "$OUT_IF" ]]; then
    echo "Error: could not detect default interface."
    exit 1
  fi
  if [[ "$(iptables -S FORWARD 2>/dev/null | head -n1)" == "-P FORWARD DROP" ]]; then
    iptables -P FORWARD ACCEPT
  fi
  LXC_NET="10.0.3.0/24"
  if [[ -f /etc/lxc/default.conf ]]; then
    CFG_NET="$(grep -E '^lxc\.net\.0\.ipv4\.address' /etc/lxc/default.conf | awk '{print $3}' | head -n1)"
    if [[ -n "$CFG_NET" ]]; then
      if [[ "$CFG_NET" == *"/"* ]]; then
        LXC_NET="$CFG_NET"
      else
        LXC_NET="$CFG_NET/24"
      fi
    fi
  fi
  iptables -C FORWARD -i "$BRIDGE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$BRIDGE" -j ACCEPT
  iptables -C FORWARD -o "$BRIDGE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "$BRIDGE" -j ACCEPT
  iptables -t nat -C POSTROUTING -s "$LXC_NET" -o "$OUT_IF" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "$LXC_NET" -o "$OUT_IF" -j MASQUERADE
  if iptables -L DOCKER-USER >/dev/null 2>&1; then
    iptables -C DOCKER-USER -i "$BRIDGE" -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER -i "$BRIDGE" -j ACCEPT
  fi
  echo "Host NAT/forwarding configured: $BRIDGE -> $OUT_IF ($LXC_NET)"
fi

echo "Done."
if [[ -n "$ROOT_PASSWORD" ]]; then
  echo "Root password: $ROOT_PASSWORD"
fi
