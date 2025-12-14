#!/usr/bin/env bash
# =================================================================
# Rclone Mount Ultimate (Production Final)
# - 小硬盘防爆：自动算 vfs-cache-max-size + min-free-space 兜底
# - 多网盘/多路径/多挂载点：service/log/cache 三者全部唯一化
# - 穿透 crypt/alias：识别底层类型（如 drive）做专项优化
# - 目录更新策略：按 remote 是否支持 polling(ChangeNotify) 自动调优
# - 僵尸挂载处理：检测 + 强制卸载 + 必要时重启服务
# - 选项9：安装/更新 rclone 最新版 + 安装脚本依赖（默认无交互）
#
# 用法：
#   sudo bash rclone-mount-ultimate.sh          # 进入菜单
#   sudo bash rclone-mount-ultimate.sh 9        # 直接无交互安装/更新 rclone + 依赖
#   sudo bash rclone-mount-ultimate.sh 1        # 直接进入新增挂载（仍需交互输入）
#   sudo bash rclone-mount-ultimate.sh 2        # 直接进入卸载（选择卸载）
#   sudo bash rclone-mount-ultimate.sh 3        # 直接进入修复僵尸
# =================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

log_i(){ echo -e "${BLUE}[INFO]${PLAIN} $*"; }
log_w(){ echo -e "${YELLOW}[WARN]${PLAIN} $*"; }
log_e(){ echo -e "${RED}[ERR ]${PLAIN} $*"; }
log_ok(){ echo -e "${GREEN}[ OK ]${PLAIN} $*"; }
die(){ log_e "$*"; exit 1; }

need_cmd(){ command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"; }

trim(){ echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

normalize_remote_name(){
  local r; r="$(trim "$1")"; r="${r%:}"; echo "$r"
}

quote_args_for_systemd(){
  local out=() a esc
  for a in "$@"; do
    esc="${a//\\/\\\\}"
    esc="${esc//\"/\\\"}"
    out+=("\"${esc}\"")
  done
  (IFS=' '; echo "${out[*]}")
}

is_mounted(){ local mp="$1"; findmnt -rn --target "$mp" >/dev/null 2>&1; }
mount_fstype(){ local mp="$1"; findmnt -rn --target "$mp" -o FSTYPE 2>/dev/null || true; }

is_stale_mount(){
  local mp="$1" tmp err
  tmp="$(mktemp)"
  if timeout 2 ls "$mp" >/dev/null 2>"$tmp"; then rm -f "$tmp"; return 1; fi
  err="$(cat "$tmp" || true)"; rm -f "$tmp"
  echo "$err" | grep -qi "Transport endpoint is not connected"
}

# 全局变量（按需初始化）
RCLONE_BIN=""
RCLONE_CONF=""
FUSERMOUNT_PATH=""

force_unmount(){
  local mp="$1"

  if ! is_mounted "$mp"; then
    return 0
  fi

  log_w "检测到挂载存在: $mp (fstype=$(mount_fstype "$mp"))，尝试强制卸载..."
  if [[ -n "${FUSERMOUNT_PATH:-}" && -x "$FUSERMOUNT_PATH" ]]; then
    timeout 10 "$FUSERMOUNT_PATH" -uz "$mp" >/dev/null 2>&1 || true
    sleep 0.2
  fi

  if is_mounted "$mp"; then
    timeout 10 /bin/umount -l "$mp" >/dev/null 2>&1 || true
  fi

  if is_mounted "$mp" && command -v fuser >/dev/null 2>&1; then
    log_w "卸载仍失败，尝试 fuser -km（可能会中断正在访问该挂载的程序）..."
    timeout 10 fuser -km "$mp" >/dev/null 2>&1 || true
    timeout 10 /bin/umount -l "$mp" >/dev/null 2>&1 || true
  fi

  if is_mounted "$mp"; then
    log_e "仍无法卸载: $mp（可能 busy 或内核/FUSE 异常）。"
    return 1
  fi

  log_ok "已卸载: $mp"
  return 0
}

ensure_fuse_allow_other(){
  local f="/etc/fuse.conf"
  if [[ ! -f "$f" ]]; then
    log_w "/etc/fuse.conf 不存在，将创建并写入 user_allow_other"
    echo "user_allow_other" > "$f"
    return 0
  fi

  if ! grep -Eq '^[[:space:]]*#?[[:space:]]*user_allow_other[[:space:]]*$' "$f"; then
    echo "user_allow_other" >> "$f"
    log_ok "已追加 user_allow_other 到 /etc/fuse.conf"
    return 0
  fi

  sed -i 's/^[[:space:]]*#*[[:space:]]*user_allow_other[[:space:]]*$/user_allow_other/g' "$f"
}

get_rclone_conf(){
  local p
  p="$("$RCLONE_BIN" config file 2>/dev/null | awk 'END{print $NF}')"
  [[ -n "${p:-}" ]] || die "无法获取 rclone 配置路径（rclone config file 失败）"
  mkdir -p "$(dirname "$p")"
  if [[ ! -f "$p" ]]; then
    (umask 077; : > "$p")
    chmod 600 "$p" >/dev/null 2>&1 || true
    log_w "rclone 配置文件不存在，已创建空文件：$p（请运行 rclone config 添加 remote）"
  fi
  echo "$p"
}

remote_exists(){
  local r="$1"
  "$RCLONE_BIN" listremotes --config "$RCLONE_CONF" | grep -qx "${r}:"
}

get_remote_type(){
  local r="$1"
  "$RCLONE_BIN" config show "$r" --config "$RCLONE_CONF" 2>/dev/null \
    | awk -F' *= *' '$1=="type"{print $2; exit}'
}

get_remote_wrapped_remote(){
  local r="$1"
  "$RCLONE_BIN" config show "$r" --config "$RCLONE_CONF" 2>/dev/null \
    | awk -F' *= *' '$1=="remote"{print $2; exit}'
}

get_physical_remote(){
  local current="$1" depth=0 type next_full next_name
  while [[ $depth -lt 5 ]]; do
    type="$(get_remote_type "$current")"
    if [[ "$type" == "crypt" || "$type" == "alias" ]]; then
      next_full="$(get_remote_wrapped_remote "$current")"
      next_name="$(echo "$next_full" | awk -F':' '{print $1}')"
      [[ -n "${next_name:-}" ]] || { echo "$current"; return 0; }
      current="$next_name"
      ((depth++))
    else
      echo "$current"
      return 0
    fi
  done
  echo "$current"
}

calc_cache_max_size(){
  local cache_root="$1" avail_kb max
  avail_kb="$(df -k "$cache_root" | awk 'NR==2 {print $4}')"
  max="$(awk -v kb="$avail_kb" 'BEGIN{
    gb = kb/1024/1024*0.40;
    if (gb < 1.0) print "1G";
    else printf "%.1fG", gb;
  }')"
  echo "$avail_kb|$max"
}

hash_id(){
  local s="$1"
  if command -v sha1sum >/dev/null 2>&1; then
    echo -n "$s" | sha1sum | awk '{print $1}'
  elif command -v md5sum >/dev/null 2>&1; then
    echo -n "$s" | md5sum | awk '{print $1}'
  else
    echo -n "$s" | od -An -tx1 | tr -d ' \n' | cut -c1-40
  fi
}

backend_features(){
  local r="$1"
  "$RCLONE_BIN" backend features "${r}:" --config "$RCLONE_CONF" 2>/dev/null || true
}

json_has_true(){
  local json="$1" key="$2"
  echo "$json" | grep -Eq "\"${key}\"[[:space:]]*:[[:space:]]*true"
}

json_has_false(){
  local json="$1" key="$2"
  echo "$json" | grep -Eq "\"${key}\"[[:space:]]*:[[:space:]]*false"
}

json_hashes_empty(){
  local json="$1"
  echo "$json" | grep -Eq '"Hashes"[[:space:]]*:[[:space:]]*\[[[:space:]]*\]'
}

unit_files(){
  ls /etc/systemd/system/rclone-mount-*.service 2>/dev/null || true
}

service_active(){
  local s="$1"
  systemctl is-active --quiet "$s"
}

heal_mount_by_service(){
  local svc="$1" mp="$2"
  local stale="no" mounted="no" active="no"

  if service_active "$svc"; then active="yes"; fi
  if is_mounted "$mp"; then mounted="yes"; fi
  if [[ "$mounted" == "yes" ]] && is_stale_mount "$mp"; then stale="yes"; fi

  if [[ "$active" == "no" && "$mounted" == "yes" ]]; then
    log_w "发现遗留挂载（服务不活跃但仍挂载）: $mp -> 强制卸载"
    force_unmount "$mp" || true
  fi

  if [[ "$active" == "yes" && ( "$mounted" == "no" || "$stale" == "yes" ) ]]; then
    log_w "发现异常挂载（active=$active mounted=$mounted stale=$stale），重启服务: $svc"
    systemctl restart "$svc" || true
    sleep 0.5
  fi

  if is_mounted "$mp" && is_stale_mount "$mp"; then
    log_w "重启后仍检测到僵尸挂载，先强制卸载再启动: $svc"
    force_unmount "$mp" || true
    systemctl restart "$svc" || true
  fi
}

init_runtime_basic(){
  need_cmd systemctl
  need_cmd findmnt
  need_cmd df
  need_cmd awk
  need_cmd grep
  need_cmd sed
  need_cmd timeout
  need_cmd ls

  FUSERMOUNT_PATH="$(command -v fusermount3 2>/dev/null || command -v fusermount 2>/dev/null || true)"
}

init_runtime_mount(){
  init_runtime_basic
  need_cmd rclone
  RCLONE_BIN="$(command -v rclone)"
  RCLONE_CONF="$(get_rclone_conf)"
  ensure_fuse_allow_other
  [[ -n "${FUSERMOUNT_PATH:-}" ]] || die "缺少 fusermount/fusermount3（请先用选项9安装依赖或安装 fuse3）"
}

install_mount(){
  init_runtime_mount

  echo -e "${BLUE}=== 新增挂载 (Ultimate) ===${PLAIN}"

  read -p "请输入 Rclone 配置名称 (如 sgd 或 sgd:): " input_remote_raw
  local REMOTE_NAME; REMOTE_NAME="$(normalize_remote_name "$input_remote_raw")"
  [[ -n "${REMOTE_NAME:-}" ]] || { log_e "Remote 名不能为空"; return; }

  if ! remote_exists "$REMOTE_NAME"; then
    log_e "配置不存在: ${REMOTE_NAME}（如果还没配置，请先运行：rclone config）"
    return
  fi

  read -p "请输入远端路径 (留空=根目录, 例 /Video 或 Video): " REMOTE_PATH_RAW
  local REMOTE_PATH; REMOTE_PATH="$(trim "${REMOTE_PATH_RAW:-}")"

  read -p "请输入本地挂载路径: " LOCAL_MOUNT_POINT_RAW
  local LOCAL_MOUNT_POINT; LOCAL_MOUNT_POINT="$(trim "${LOCAL_MOUNT_POINT_RAW:-}")"
  [[ -n "${LOCAL_MOUNT_POINT:-}" ]] || { log_e "挂载路径必填"; return; }

  mkdir -p "$LOCAL_MOUNT_POINT"

  local ALLOW_NON_EMPTY="no"
  if [[ -n "$(ls -A "$LOCAL_MOUNT_POINT" 2>/dev/null || true)" ]]; then
    log_w "挂载目录非空: $LOCAL_MOUNT_POINT（rclone mount 默认要求空目录）"
    read -p "是否继续并允许挂载到非空目录? (y/n): " c
    [[ "${c:-n}" == "y" ]] || { log_i "已取消"; return; }
    ALLOW_NON_EMPTY="yes"
  fi

  local PHYSICAL_REMOTE PHYSICAL_TYPE
  PHYSICAL_REMOTE="$(get_physical_remote "$REMOTE_NAME")"
  PHYSICAL_TYPE="$(get_remote_type "$PHYSICAL_REMOTE")"

  local CACHE_ROOT="/var/cache/rclone"
  mkdir -p "$CACHE_ROOT"
  local calc out_avail_kb MAX_SIZE
  calc="$(calc_cache_max_size "$CACHE_ROOT")"
  out_avail_kb="${calc%%|*}"
  MAX_SIZE="${calc##*|}"

  local SPEC_STR CACHE_ID SUFFIX
  SPEC_STR="${REMOTE_NAME}:${REMOTE_PATH}:${LOCAL_MOUNT_POINT}"
  CACHE_ID="$(hash_id "$SPEC_STR")"
  SUFFIX="${CACHE_ID:0:8}"

  local SERVICE_NAME="rclone-mount-${REMOTE_NAME}-${SUFFIX}"
  local SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
  local LOG_FILE="/var/log/${SERVICE_NAME}.log"
  local CACHE_DIR="${CACHE_ROOT}/${REMOTE_NAME}-${SUFFIX}"

  mkdir -p "$CACHE_DIR"
  touch "$LOG_FILE" || true

  # 特性探测：以“实际挂载的 remote”判断 polling(ChangeNotify)
  local FEAT_TOP; FEAT_TOP="$(backend_features "$REMOTE_NAME")"

  local SUPPORT_POLL="no"
  if json_has_true "$FEAT_TOP" "ChangeNotify"; then SUPPORT_POLL="yes"; fi

  local READ_ONLY="no"
  if json_has_false "$FEAT_TOP" "CanWrite"; then READ_ONLY="yes"; fi

  local NO_CHECKSUM="no"
  if json_hashes_empty "$FEAT_TOP"; then NO_CHECKSUM="yes"; fi

  local -a OPTS
  OPTS+=( "--config" "$RCLONE_CONF" )
  OPTS+=( "--allow-other" )
  OPTS+=( "--umask" "000" )
  OPTS+=( "--log-level" "INFO" )

  OPTS+=( "--vfs-cache-mode" "full" )
  OPTS+=( "--cache-dir" "$CACHE_DIR" )
  OPTS+=( "--vfs-cache-max-size" "$MAX_SIZE" )
  OPTS+=( "--vfs-cache-min-free-space" "1G" )
  OPTS+=( "--vfs-cache-poll-interval" "30s" )
  OPTS+=( "--vfs-read-chunk-size" "32M" )
  OPTS+=( "--vfs-read-chunk-size-limit" "off" )
  OPTS+=( "--vfs-read-chunk-streams" "1" )
  OPTS+=( "--buffer-size" "32M" )
  OPTS+=( "--tpslimit" "10" "--tpslimit-burst" "10" )

  if [[ "$ALLOW_NON_EMPTY" == "yes" ]]; then
    OPTS+=( "--allow-non-empty" )
  fi

  # 目录更新策略（严格口径：polling(ChangeNotify) 支持与否）
  if [[ "$SUPPORT_POLL" == "yes" ]]; then
    OPTS+=( "--dir-cache-time" "24h" )
    OPTS+=( "--poll-interval" "15s" )
  else
    OPTS+=( "--dir-cache-time" "60s" )
    OPTS+=( "--vfs-fast-fingerprint" )
  fi

  if [[ "$READ_ONLY" == "yes" ]]; then OPTS+=( "--read-only" ); fi
  if [[ "$NO_CHECKSUM" == "yes" ]]; then OPTS+=( "--no-checksum" ); fi
  if [[ "$PHYSICAL_TYPE" == "drive" ]]; then OPTS+=( "--drive-pacer-min-sleep" "10ms" ); fi

  local REMOTE_SPEC
  if [[ -n "$REMOTE_PATH" ]]; then REMOTE_SPEC="${REMOTE_NAME}:${REMOTE_PATH}"; else REMOTE_SPEC="${REMOTE_NAME}:"; fi

  if is_mounted "$LOCAL_MOUNT_POINT"; then
    log_w "挂载点已被占用: $LOCAL_MOUNT_POINT (fstype=$(mount_fstype "$LOCAL_MOUNT_POINT"))"
    if is_stale_mount "$LOCAL_MOUNT_POINT"; then
      log_w "检测到僵尸挂载（Transport endpoint...），将强制卸载后继续"
      force_unmount "$LOCAL_MOUNT_POINT" || return
    else
      log_e "挂载点正在被正常使用，请先卸载或换挂载点。"
      return
    fi
  fi

  echo -e "\n${GREEN}================ [ 决策逻辑公示 ] ================${PLAIN}"
  echo -e "🔗 挂载链路: ${REMOTE_NAME} (mount) -> ${PHYSICAL_REMOTE} (physical: ${PHYSICAL_TYPE})"
  echo -e "📌 RemoteSpec: ${REMOTE_SPEC}"
  echo -e "📍 MountPoint: ${LOCAL_MOUNT_POINT}"
  echo -e "💾 磁盘保护: cache-dir=${CACHE_DIR} | 可用KB=${out_avail_kb} | max-size=${MAX_SIZE} | min-free=1G"
  if [[ "$SUPPORT_POLL" == "yes" ]]; then
    echo -e "🛰️ 目录更新: 支持 polling(ChangeNotify) -> poll=15s, dir-cache=24h"
  else
    echo -e "🛰️ 目录更新: 不支持 polling(ChangeNotify) -> dir-cache=60s（更实时但更耗API）"
  fi
  echo -e "🧾 Service: ${SERVICE_NAME}"
  echo -e "📜 LogFile: ${LOG_FILE}"
  echo -e "${GREEN}===================================================${PLAIN}\n"

  read -p "确认写入 systemd 并启动该挂载吗? (y/n): " CONFIRM
  [[ "${CONFIRM:-n}" == "y" ]] || { log_i "已取消"; return; }

  local CMD_STR
  CMD_STR="$(quote_args_for_systemd "$RCLONE_BIN" "mount" "$REMOTE_SPEC" "$LOCAL_MOUNT_POINT" "${OPTS[@]}" "--log-file" "$LOG_FILE")"

  cat > "$SERVICE_FILE" <<EOF
# ManagedBy=rclone-mount-ultimate
# ServiceName=${SERVICE_NAME}
# Remote=${REMOTE_NAME}
# RemotePath=${REMOTE_PATH}
# MountPoint=${LOCAL_MOUNT_POINT}
# CacheDir=${CACHE_DIR}
# LogFile=${LOG_FILE}
# PhysicalRemote=${PHYSICAL_REMOTE}
# PhysicalType=${PHYSICAL_TYPE}

[Unit]
Description=Rclone mount ${REMOTE_SPEC} -> ${LOCAL_MOUNT_POINT}
Wants=network-online.target
After=network-online.target
AssertPathIsDirectory=${LOCAL_MOUNT_POINT}
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=notify
User=root
Group=root
Restart=on-failure
RestartSec=10
TimeoutStopSec=30
KillMode=mixed

ExecStartPre=-${FUSERMOUNT_PATH} -uz "${LOCAL_MOUNT_POINT}"
ExecStartPre=-/bin/umount -l "${LOCAL_MOUNT_POINT}"

ExecStart=${CMD_STR}

ExecStop=-${FUSERMOUNT_PATH} -uz "${LOCAL_MOUNT_POINT}"
ExecStopPost=-/bin/umount -l "${LOCAL_MOUNT_POINT}"

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null
  systemctl start "$SERVICE_NAME"

  heal_mount_by_service "$SERVICE_NAME" "$LOCAL_MOUNT_POINT"

  if service_active "$SERVICE_NAME" && is_mounted "$LOCAL_MOUNT_POINT" && ! is_stale_mount "$LOCAL_MOUNT_POINT"; then
    log_ok "挂载成功: ${LOCAL_MOUNT_POINT}"
    log_i "查看日志: tail -f \"$LOG_FILE\""
  else
    log_e "挂载未达到健康状态（可能网络/认证/API/权限）。"
    systemctl status "$SERVICE_NAME" --no-pager || true
    log_i "日志: tail -n 120 \"$LOG_FILE\""
  fi
}

uninstall_mount(){
  init_runtime_basic

  echo -e "${BLUE}=== 卸载挂载 ===${PLAIN}"
  local files; files="$(unit_files)"
  [[ -n "${files:-}" ]] || { log_w "未找到 rclone-mount-*.service"; return; }

  local -a arr
  local f
  while IFS= read -r f; do [[ -n "$f" ]] && arr+=("$f"); done <<< "$files"

  echo -e "${GREEN}请选择要卸载的挂载（会显示状态/僵尸检测）:${PLAIN}"
  local i svc mp remote rpath active mounted stale
  for i in "${!arr[@]}"; do
    f="${arr[$i]}"
    svc="$(basename "$f" .service)"
    remote="$(grep -E '^# Remote=' "$f" | cut -d= -f2- || true)"
    rpath="$(grep -E '^# RemotePath=' "$f" | cut -d= -f2- || true)"
    mp="$(grep -E '^# MountPoint=' "$f" | cut -d= -f2- || true)"
    active="no"; mounted="no"; stale="no"
    service_active "$svc" && active="yes" || true
    is_mounted "$mp" && mounted="yes" || true
    ( [[ "$mounted" == "yes" ]] && is_stale_mount "$mp" ) && stale="yes" || true
    printf "[%d] svc=%s | remote=%s:%s | mp=%s | active=%s mounted=%s stale=%s\n" \
      "$((i+1))" "$svc" "$remote" "$rpath" "$mp" "$active" "$mounted" "$stale"
  done

  read -p "输入序号(或 0 取消): " idx
  idx="${idx:-0}"
  [[ "$idx" =~ ^[0-9]+$ ]] || { log_e "输入非法"; return; }
  [[ "$idx" -ne 0 ]] || { log_i "已取消"; return; }
  ((idx--))
  [[ "$idx" -ge 0 && "$idx" -lt "${#arr[@]}" ]] || { log_e "序号超出范围"; return; }

  f="${arr[$idx]}"
  svc="$(basename "$f" .service)"
  mp="$(grep -E '^# MountPoint=' "$f" | cut -d= -f2- || true)"
  local cache_dir; cache_dir="$(grep -E '^# CacheDir=' "$f" | cut -d= -f2- || true)"

  log_i "停止服务: $svc"
  systemctl stop "$svc" >/dev/null 2>&1 || true
  systemctl disable "$svc" >/dev/null 2>&1 || true

  if is_mounted "$mp"; then
    force_unmount "$mp" || true
  fi

  rm -f "$f"
  systemctl daemon-reload
  log_ok "已卸载并移除 unit: $svc"

  if [[ -n "${cache_dir:-}" && -d "$cache_dir" ]]; then
    read -p "是否删除缓存目录以释放空间? ${cache_dir} (y/n): " dc
    if [[ "${dc:-n}" == "y" ]]; then
      rm -rf "$cache_dir" || true
      log_ok "已删除缓存目录: $cache_dir"
    else
      log_i "保留缓存目录: $cache_dir"
    fi
  fi
}

repair_all(){
  init_runtime_basic

  echo -e "${BLUE}=== 检测并修复僵尸/异常挂载 ===${PLAIN}"
  local files; files="$(unit_files)"
  [[ -n "${files:-}" ]] || { log_w "未找到 rclone-mount-*.service"; return; }

  local f svc mp
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    svc="$(basename "$f" .service)"
    mp="$(grep -E '^# MountPoint=' "$f" | cut -d= -f2- || true)"
    [[ -n "${mp:-}" ]] || continue
    log_i "检查: $svc -> $mp"
    heal_mount_by_service "$svc" "$mp"
  done <<< "$files"

  log_ok "修复流程结束。"
}

# -------------------- 选项 9：安装/更新 rclone & 依赖（默认无交互） --------------------

detect_pkg_mgr(){
  if command -v apt-get >/dev/null 2>&1; then echo "apt"
  elif command -v dnf >/dev/null 2>&1; then echo "dnf"
  elif command -v yum >/dev/null 2>&1; then echo "yum"
  elif command -v pacman >/dev/null 2>&1; then echo "pacman"
  elif command -v apk >/dev/null 2>&1; then echo "apk"
  elif command -v zypper >/dev/null 2>&1; then echo "zypper"
  else echo "none"
  fi
}

install_pkgs(){
  local pm="$1"
  local pkgs=(curl ca-certificates unzip util-linux psmisc)
  case "$pm" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y "${pkgs[@]}"
      apt-get install -y fuse3 || apt-get install -y fuse
      ;;
    dnf)
      dnf -y install "${pkgs[@]}"
      dnf -y install fuse3 || dnf -y install fuse
      ;;
    yum)
      yum -y install "${pkgs[@]}"
      yum -y install fuse3 || yum -y install fuse
      ;;
    pacman)
      pacman -Sy --noconfirm "${pkgs[@]}"
      pacman -Sy --noconfirm fuse3 || pacman -Sy --noconfirm fuse2
      ;;
    apk)
      apk add --no-cache "${pkgs[@]}"
      apk add --no-cache fuse3
      ;;
    zypper)
      zypper --non-interactive refresh
      zypper --non-interactive install -y "${pkgs[@]}"
      zypper --non-interactive install -y fuse3 || zypper --non-interactive install -y fuse
      ;;
    *)
      return 1
      ;;
  esac
}

install_or_update_rclone(){
  need_cmd curl
  log_i "使用官方 install.sh 安装/更新 rclone 最新版（无交互）..."
  curl -fsSL https://rclone.org/install.sh | bash
  command -v rclone >/dev/null 2>&1 || die "rclone 安装失败（未在 PATH 中找到）"
  rclone version || true
}

install_update_rclone_and_deps(){
  [[ $EUID -eq 0 ]] || die "必须 root 执行（安装依赖与写入 /usr/bin）"

  local pm; pm="$(detect_pkg_mgr)"
  [[ "$pm" != "none" ]] || die "无法识别包管理器（apt/dnf/yum/pacman/apk/zypper 均未找到）"

  log_i "检测到包管理器: $pm"
  log_i "安装/更新依赖（无交互）..."
  install_pkgs "$pm"

  # 依赖验证（关键命令）
  need_cmd curl
  need_cmd unzip
  need_cmd findmnt
  need_cmd timeout
  command -v fusermount3 >/dev/null 2>&1 || command -v fusermount >/dev/null 2>&1 || \
    log_w "未检测到 fusermount/fusermount3：请确认 fuse3 安装是否成功"

  ensure_fuse_allow_other
  install_or_update_rclone

  log_ok "选项9完成（无交互）。"
  log_i "下一步：如果还没配置 remote，请运行：rclone config"
}

# --- 入口（支持 bash xx.sh 9 直达分支） ---
[[ $EUID -eq 0 ]] || die "必须使用 root 权限运行（请用 sudo）"

ARG="${1:-}"

if [[ -n "${ARG}" ]]; then
  case "${ARG}" in
    1|mount|add) install_mount ;;
    2|unmount|uninstall|remove) uninstall_mount ;;
    3|repair|heal|fix) repair_all ;;
    9|install|update|deps) install_update_rclone_and_deps ;;
    0|exit|quit) exit 0 ;;
    *)
      die "未知参数: ${ARG}
用法示例:
  sudo bash $0 9        # 无交互安装/更新 rclone + 依赖
  sudo bash $0 1        # 新增挂载（交互输入）
  sudo bash $0 2        # 卸载挂载（选择卸载）
  sudo bash $0 3        # 修复僵尸/异常挂载
"
      ;;
  esac
  exit 0
fi

# 进入菜单（交互）
clear
echo "----------------------------------------"
echo " Rclone Mount Ultimate (Production Final)"
echo "----------------------------------------"
echo "1. 新增挂载 (多网盘/多路径/多挂载点)"
echo "2. 卸载挂载 (选择指定卸载)"
echo "3. 检测并修复僵尸/异常挂载"
echo "9. 安装/更新 rclone 最新版 + 安装脚本依赖（无交互）"
echo "0. 退出"
echo "----------------------------------------"
read -p "选择: " OPT

case "${OPT:-0}" in
  1) install_mount ;;
  2) uninstall_mount ;;
  3) repair_all ;;
  9) install_update_rclone_and_deps ;;
  0) exit 0 ;;
  *) echo "退出" ;;
esac
