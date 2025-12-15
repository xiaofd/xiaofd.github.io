#!/usr/bin/env bash
# ==============================================================================
# Rclone Mount Ultimate (磁盘保护上限 + 日志回滚 + 美化中文 + 多挂载隔离 + 僵尸自愈)
#
# 目标：
# - 小硬盘防爆：vfs-cache-max-size 自动计算，但【上限不超过 4G】；并保留 1G 空间
# - 多网盘/多路径/多挂载点：service/log/cache 独立隔离，不冲突
# - 穿透 crypt/alias：识别物理底层类型（drive 等）做专项优化
# - “实时”自动调优：按 remote 是否支持 polling(ChangeNotify) 决定策略
# - 僵尸挂载自愈：检测 "Transport endpoint is not connected" → 强制卸载/重启
# - 日志回滚：logrotate 自动配置，所有脚本相关日志（/var/log/rclone-mount-*.log）单文件不超过 10MB
# - 选项9：安装/更新依赖 + rclone 最新版（默认无交互）
# - 选项4：Dry-Run（仅展示决策与最终命令，不写 systemd，不挂载）
#
# 用法：
#   sudo bash rclone-mount-ultimate.sh              # 菜单
#   sudo bash rclone-mount-ultimate.sh 9            # 直接：安装/更新（无交互）
#   sudo bash rclone-mount-ultimate.sh 4            # 直接：Dry-Run 预览
#   sudo bash rclone-mount-ultimate.sh 1            # 直接：新增挂载（交互）
#   sudo bash rclone-mount-ultimate.sh 2            # 直接：卸载（选择）
#   sudo bash rclone-mount-ultimate.sh 3            # 直接：修复僵尸/异常挂载
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ---------------- 配置区（你可以按需改） ----------------
CACHE_ROOT_DEFAULT="/var/cache/rclone"
# 自动算出来的 vfs-cache-max-size 上限（强制 <= 4G）
CACHE_MAX_UPPER_GB="4.0"
# 单个日志文件最大 10MB
LOG_MAX_BYTES=$((10 * 1024 * 1024))
# logrotate：保留份数（10MB * 5 份 = 最多 ~50MB/挂载）
LOGROTATE_ROTATE=5
# -------------------------------------------------------

# --------- 颜色/输出 ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'
BOLD='\033[1m'

say()   { echo -e "$*"; }
info()  { echo -e "${BLUE}ℹ️  ${PLAIN}$*"; }
ok()    { echo -e "${GREEN}✅ ${PLAIN}$*"; }
warn()  { echo -e "${YELLOW}⚠️  ${PLAIN}$*"; }
err()   { echo -e "${RED}❌ ${PLAIN}$*"; }
die()   { err "$*"; exit 1; }

hr() { echo -e "${GREEN}------------------------------------------------------------${PLAIN}"; }

need_cmd(){ command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1（建议先运行：sudo bash $0 9）"; }

trim(){ echo "${1:-}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

normalize_remote_name(){
  local r; r="$(trim "${1:-}")"
  r="${r%:}"
  echo "$r"
}

# systemd ExecStart 安全引用：逐参数 quote（systemd 支持引号）
quote_args_for_systemd(){
  local out=() a esc
  for a in "$@"; do
    esc="${a//\\/\\\\}"
    esc="${esc//\"/\\\"}"
    out+=("\"${esc}\"")
  done
  (IFS=' '; echo "${out[*]}")
}

# --------- 全局运行时变量 ----------
RCLONE_BIN=""
RCLONE_CONF=""
FUSERMOUNT_PATH=""
UMOUNT_PATH=""

# --------- mount/僵尸检测（关键修复：只在“目录本身就是挂载点”时才算已挂载） ----------
is_mountpoint_exact(){
  local mp="$1"
  local target
  target="$(findmnt -rn -T "$mp" -o TARGET 2>/dev/null || true)"
  [[ -n "$target" && "$target" == "$mp" ]]
}

mount_fstype(){
  local mp="$1"
  findmnt -rn -T "$mp" -o FSTYPE 2>/dev/null || true
}

mount_source(){
  local mp="$1"
  findmnt -rn -T "$mp" -o SOURCE 2>/dev/null || true
}

is_stale_mount(){
  local mp="$1" tmp errtxt
  tmp="$(mktemp)"
  if timeout 2 ls "$mp" >/dev/null 2>"$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  errtxt="$(cat "$tmp" 2>/dev/null || true)"
  rm -f "$tmp"
  echo "$errtxt" | grep -qi "Transport endpoint is not connected"
}

force_unmount(){
  local mp="$1"

  if ! is_mountpoint_exact "$mp"; then
    return 0
  fi

  warn "准备强制卸载：$mp (fstype=$(mount_fstype "$mp"), source=$(mount_source "$mp"))"

  # 1) 首选 fusermount(3) -uz
  if [[ -n "${FUSERMOUNT_PATH:-}" && -x "$FUSERMOUNT_PATH" ]]; then
    timeout 10 "$FUSERMOUNT_PATH" -uz "$mp" >/dev/null 2>&1 || true
    sleep 0.2
  fi

  # 2) 再尝试 umount -l
  if is_mountpoint_exact "$mp"; then
    timeout 10 "$UMOUNT_PATH" -l "$mp" >/dev/null 2>&1 || true
  fi

  # 3) 最后手段：fuser -km 杀占用者
  if is_mountpoint_exact "$mp" && command -v fuser >/dev/null 2>&1; then
    warn "卸载仍失败，尝试 fuser -km 释放占用（⚠️ 可能中断程序）..."
    timeout 10 fuser -km "$mp" >/dev/null 2>&1 || true
    timeout 10 "$UMOUNT_PATH" -l "$mp" >/dev/null 2>&1 || true
  fi

  if is_mountpoint_exact "$mp"; then
    err "仍无法卸载：$mp（可能 busy 或内核/FUSE 异常）。建议检查占用或重启。"
    return 1
  fi

  ok "已卸载：$mp"
  return 0
}

# --------- FUSE allow_other ----------
ensure_fuse_allow_other(){
  local f="/etc/fuse.conf"
  if [[ ! -f "$f" ]]; then
    warn "/etc/fuse.conf 不存在，将创建并写入 user_allow_other"
    echo "user_allow_other" > "$f"
    return 0
  fi

  if grep -Eq '^[[:space:]]*#?[[:space:]]*user_allow_other[[:space:]]*$' "$f"; then
    sed -i 's/^[[:space:]]*#*[[:space:]]*user_allow_other[[:space:]]*$/user_allow_other/g' "$f"
    return 0
  fi

  echo "user_allow_other" >> "$f"
  ok "已追加 user_allow_other 到 /etc/fuse.conf"
}

# --------- rclone 配置/remote ----------
get_rclone_conf(){
  local p
  p="$("$RCLONE_BIN" config file 2>/dev/null | awk 'END{print $NF}')"
  [[ -n "${p:-}" ]] || die "无法获取 rclone 配置路径（rclone config file 失败）"
  mkdir -p "$(dirname "$p")"
  if [[ ! -f "$p" ]]; then
    (umask 077; : > "$p")
    chmod 600 "$p" >/dev/null 2>&1 || true
    warn "rclone 配置文件不存在，已创建空文件：$p（请运行：rclone config 添加 remote）"
  fi
  echo "$p"
}

remote_exists(){
  local r="$1"
  "$RCLONE_BIN" listremotes --config "$RCLONE_CONF" \
    | awk -v want="${r}:" '$0==want{found=1} END{exit !found}'
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

# --------- 计算缓存上限：自动算 *0.40，但强制 <= 4G 且 >= 1G ----------
calc_cache_max_size(){
  local cache_root="$1"
  local avail_kb gb calc_gb max

  avail_kb="$(df -k "$cache_root" | awk 'NR==2 {print $4}')"
  # 计算：avail_gb * 0.4
  calc_gb="$(awk -v kb="$avail_kb" 'BEGIN{ printf "%.2f", kb/1024/1024*0.40 }')"

  # clamp： [1.00, CACHE_MAX_UPPER_GB]
  max="$(awk -v g="$calc_gb" -v upper="$CACHE_MAX_UPPER_GB" 'BEGIN{
    if (g < 1.00) g = 1.00;
    if (g > upper) g = upper;
    printf "%.1fG", g;
  }')"

  echo "$avail_kb|$calc_gb|$max"
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

  service_active "$svc" && active="yes" || true
  is_mountpoint_exact "$mp" && mounted="yes" || true
  [[ "$mounted" == "yes" ]] && is_stale_mount "$mp" && stale="yes" || true

  if [[ "$active" == "no" && "$mounted" == "yes" ]]; then
    warn "发现遗留挂载：服务不活跃但仍挂载：$mp → 强制卸载"
    force_unmount "$mp" || true
  fi

  if [[ "$active" == "yes" && ( "$mounted" == "no" || "$stale" == "yes" ) ]]; then
    warn "发现异常挂载：active=$active mounted=$mounted stale=$stale → 重启服务：$svc"
    systemctl restart "$svc" >/dev/null 2>&1 || true
    sleep 0.6
  fi

  if is_mountpoint_exact "$mp" && is_stale_mount "$mp"; then
    warn "重启后仍僵尸：先强制卸载再启动：$svc"
    force_unmount "$mp" || true
    systemctl restart "$svc" >/dev/null 2>&1 || true
  fi
}

# --------- 日志回滚：logrotate 配置（所有 /var/log/rclone-mount-*.log 单文件 <= 10MB） ----------
ensure_logrotate(){
  # 若系统无 logrotate，跳过但提示
  if ! command -v logrotate >/dev/null 2>&1; then
    warn "未检测到 logrotate：将无法自动回滚日志（建议：sudo bash $0 9 安装依赖）"
    return 0
  fi

  local cfg="/etc/logrotate.d/rclone-mount-ultimate"
  cat > "$cfg" <<EOF
/var/log/rclone-mount-*.log {
  size 10M
  rotate ${LOGROTATE_ROTATE}
  copytruncate
  missingok
  notifempty
  compress
  delaycompress
  su root root
}
EOF
  ok "已确保日志回滚策略：$cfg（单文件≤10MB，保留${LOGROTATE_ROTATE}份）"
}

# 限制单个日志文件不超过 10MB：超了就立刻滚动一次（不依赖 cron）
# 说明：logrotate 通常按天跑；这里是“即时保护”
maybe_roll_log_now(){
  local logfile="$1"
  [[ -f "$logfile" ]] || return 0

  local sz
  sz="$(stat -c%s "$logfile" 2>/dev/null || echo 0)"
  if [[ "$sz" -le "$LOG_MAX_BYTES" ]]; then
    return 0
  fi

  # 立刻滚动：log -> log.1 -> log.2 ...
  warn "日志已超过 10MB，执行即时回滚：$logfile"
  local i
  for ((i=LOGROTATE_ROTATE-1; i>=1; i--)); do
    [[ -f "${logfile}.${i}.gz" ]] && mv -f "${logfile}.${i}.gz" "${logfile}.$((i+1)).gz" || true
    [[ -f "${logfile}.${i}" ]] && mv -f "${logfile}.${i}" "${logfile}.$((i+1))" || true
  done
  mv -f "$logfile" "${logfile}.1" || true
  : > "$logfile" || true
  ok "已回滚：${logfile}.1"
}

# --------- 运行时初始化 ----------
init_runtime_basic(){
  need_cmd systemctl
  need_cmd findmnt
  need_cmd df
  need_cmd awk
  need_cmd grep
  need_cmd sed
  need_cmd timeout
  need_cmd ls
  need_cmd stat

  FUSERMOUNT_PATH="$(command -v fusermount3 2>/dev/null || command -v fusermount 2>/dev/null || true)"
  UMOUNT_PATH="$(command -v umount 2>/dev/null || echo /bin/umount)"
  [[ -n "${UMOUNT_PATH:-}" ]] || die "找不到 umount"

  ensure_logrotate
}

init_runtime_mount(){
  init_runtime_basic
  need_cmd rclone
  RCLONE_BIN="$(command -v rclone)"
  RCLONE_CONF="$(get_rclone_conf)"
  ensure_fuse_allow_other
  [[ -n "${FUSERMOUNT_PATH:-}" ]] || die "缺少 fusermount/fusermount3（建议先运行：sudo bash $0 9）"
}

# --------- 生成一次“决策+命令”（新增挂载 & dry-run 共用） ----------
prepare_mount_plan(){
  init_runtime_mount

  hr
  say "${BOLD}🧩 新增挂载：参数输入${PLAIN}"
  hr
  info "使用的 rclone 配置文件：${RCLONE_CONF}"
  say

  local input_remote_raw
  read -p "① 输入 Rclone 配置名称（如 sgd 或 sgd:）： " input_remote_raw
  REMOTE_NAME="$(normalize_remote_name "$input_remote_raw")"
  REMOTE_NAME="$(trim "$REMOTE_NAME")"
  [[ -n "${REMOTE_NAME:-}" ]] || die "Remote 名不能为空"

  if ! remote_exists "$REMOTE_NAME"; then
    err "找不到 remote：${REMOTE_NAME}"
    info "当前配置文件中的 remotes："
    "$RCLONE_BIN" listremotes --config "$RCLONE_CONF" | sed 's/^/   - /'
    die "请检查：remote 名是否拼写一致 / 是否使用了正确的配置文件 / 是否需要先运行 rclone config"
  fi

  local REMOTE_PATH_RAW
  read -p "② 输入远端路径（留空=根目录；例 /Video 或 Video）： " REMOTE_PATH_RAW
  REMOTE_PATH="$(trim "${REMOTE_PATH_RAW:-}")"

  local LOCAL_MP_RAW
  read -p "③ 输入本地挂载路径（例 /mnt/sgd_video）： " LOCAL_MP_RAW
  LOCAL_MOUNT_POINT="$(trim "${LOCAL_MP_RAW:-}")"
  [[ -n "${LOCAL_MOUNT_POINT:-}" ]] || die "挂载路径必填"

  mkdir -p "$LOCAL_MOUNT_POINT"

  local ALLOW_NON_EMPTY="no"
  if [[ -n "$(ls -A "$LOCAL_MOUNT_POINT" 2>/dev/null || true)" ]]; then
    warn "挂载目录非空：$LOCAL_MOUNT_POINT（默认不建议，必要时可允许）"
    read -p "   是否继续并允许挂载到非空目录？(y/n): " ans
    [[ "${ans:-n}" == "y" ]] || die "用户取消"
    ALLOW_NON_EMPTY="yes"
  fi

  PHYSICAL_REMOTE="$(get_physical_remote "$REMOTE_NAME")"
  PHYSICAL_TYPE="$(get_remote_type "$PHYSICAL_REMOTE")"

  local CACHE_ROOT="$CACHE_ROOT_DEFAULT"
  mkdir -p "$CACHE_ROOT"

  local calc out_avail_kb calc_gb MAX_SIZE
  calc="$(calc_cache_max_size "$CACHE_ROOT")"
  out_avail_kb="${calc%%|*}"
  calc_gb="$(echo "$calc" | awk -F'|' '{print $2}')"
  MAX_SIZE="$(echo "$calc" | awk -F'|' '{print $3}')"

  local SPEC_STR CACHE_ID SUFFIX
  SPEC_STR="${REMOTE_NAME}:${REMOTE_PATH}:${LOCAL_MOUNT_POINT}"
  CACHE_ID="$(hash_id "$SPEC_STR")"
  SUFFIX="${CACHE_ID:0:8}"

  SERVICE_NAME="rclone-mount-${REMOTE_NAME}-${SUFFIX}"
  SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
  LOG_FILE="/var/log/${SERVICE_NAME}.log"
  CACHE_DIR="${CACHE_ROOT}/${REMOTE_NAME}-${SUFFIX}"

  mkdir -p "$CACHE_DIR"
  touch "$LOG_FILE" >/dev/null 2>&1 || true
  maybe_roll_log_now "$LOG_FILE"

  local FEAT_TOP
  FEAT_TOP="$(backend_features "$REMOTE_NAME")"

  SUPPORT_POLL="no"
  json_has_true "$FEAT_TOP" "ChangeNotify" && SUPPORT_POLL="yes" || true

  READ_ONLY="no"
  json_has_false "$FEAT_TOP" "CanWrite" && READ_ONLY="yes" || true

  NO_CHECKSUM="no"
  json_hashes_empty "$FEAT_TOP" && NO_CHECKSUM="yes" || true

  if [[ -n "${REMOTE_PATH:-}" ]]; then
    REMOTE_SPEC="${REMOTE_NAME}:${REMOTE_PATH}"
  else
    REMOTE_SPEC="${REMOTE_NAME}:"
  fi

  if is_mountpoint_exact "$LOCAL_MOUNT_POINT"; then
    warn "挂载点已被占用：$LOCAL_MOUNT_POINT (fstype=$(mount_fstype "$LOCAL_MOUNT_POINT"), source=$(mount_source "$LOCAL_MOUNT_POINT"))"
    if is_stale_mount "$LOCAL_MOUNT_POINT"; then
      warn "检测到僵尸挂载（Transport endpoint...），将先强制卸载再继续"
      force_unmount "$LOCAL_MOUNT_POINT" || die "僵尸卸载失败，停止"
    else
      die "该路径本身就是一个挂载点且正常使用中。请更换挂载点或先卸载。"
    fi
  fi

  # 组装参数
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

  [[ "$ALLOW_NON_EMPTY" == "yes" ]] && OPTS+=( "--allow-non-empty" ) || true

  if [[ "$SUPPORT_POLL" == "yes" ]]; then
    OPTS+=( "--dir-cache-time" "24h" )
    OPTS+=( "--poll-interval" "15s" )
  else
    OPTS+=( "--dir-cache-time" "60s" )
    OPTS+=( "--vfs-fast-fingerprint" )
  fi

  [[ "$READ_ONLY" == "yes" ]] && OPTS+=( "--read-only" ) || true
  [[ "$NO_CHECKSUM" == "yes" ]] && OPTS+=( "--no-checksum" ) || true
  [[ "$PHYSICAL_TYPE" == "drive" ]] && OPTS+=( "--drive-pacer-min-sleep" "10ms" ) || true

  CMD_STR="$(quote_args_for_systemd "$RCLONE_BIN" "mount" "$REMOTE_SPEC" "$LOCAL_MOUNT_POINT" "${OPTS[@]}" "--log-file" "$LOG_FILE")"

  PLAN_MAX_SIZE="$MAX_SIZE"
  PLAN_AVAIL_KB="$out_avail_kb"
  PLAN_CALC_GB="$calc_gb"
}

# --------- 选项1：新增挂载 ----------
install_mount(){
  prepare_mount_plan

  hr
  say "${BOLD}📣 决策逻辑公示（请确认无误）${PLAIN}"
  hr
  say "🔗 挂载链路： ${BOLD}${REMOTE_NAME}${PLAIN} (mount) → ${BOLD}${PHYSICAL_REMOTE}${PLAIN} (physical: ${PHYSICAL_TYPE})"
  say "📌 RemoteSpec： ${BOLD}${REMOTE_SPEC}${PLAIN}"
  say "📍 MountPoint： ${BOLD}${LOCAL_MOUNT_POINT}${PLAIN}"
  say "💾 磁盘保护： cache-dir=${CACHE_DIR}"
  say "             可用KB=${PLAN_AVAIL_KB} | 估算值=${PLAN_CALC_GB}GB× | 最终上限=${BOLD}${PLAN_MAX_SIZE}${PLAIN}（强制≤${CACHE_MAX_UPPER_GB}G）"
  if [[ "$SUPPORT_POLL" == "yes" ]]; then
    say "🛰️ 目录更新： 支持 polling(ChangeNotify) → poll=15s, dir-cache=24h（更省 API）"
  else
    say "🛰️ 目录更新： 不支持 polling(ChangeNotify) → dir-cache=60s（更实时但更耗 API）"
  fi
  [[ "$READ_ONLY" == "yes" ]] && say "🔒 只读：     是（--read-only）" || say "🔒 只读：     否"
  [[ "$NO_CHECKSUM" == "yes" ]] && say "🧾 校验：     关闭 checksum（无 Hashes 支持）" || say "🧾 校验：     默认"
  say "🧩 Service：  ${BOLD}${SERVICE_NAME}${PLAIN}"
  say "📜 LogFile：  ${BOLD}${LOG_FILE}${PLAIN}（自动回滚，单文件≤10MB）"
  hr
  say
  read -p "确认写入 systemd 并启动该挂载？(y/n): " CONFIRM
  [[ "${CONFIRM:-n}" == "y" ]] || { warn "已取消"; return; }

  ensure_logrotate
  maybe_roll_log_now "$LOG_FILE"

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

# 启动前清理遗留/僵尸挂载（忽略失败）
ExecStartPre=-${FUSERMOUNT_PATH} -uz "${LOCAL_MOUNT_POINT}"
ExecStartPre=-${UMOUNT_PATH} -l "${LOCAL_MOUNT_POINT}"
# 启动前若日志过大，先回滚（不依赖 cron）
ExecStartPre=-/bin/bash -lc '[[ -f "${LOG_FILE}" ]] && [[ \$(stat -c%s "${LOG_FILE}" 2>/dev/null || echo 0) -gt ${LOG_MAX_BYTES} ]] && mv -f "${LOG_FILE}" "${LOG_FILE}.1" && : > "${LOG_FILE}" || true'

ExecStart=${CMD_STR}

ExecStop=-${FUSERMOUNT_PATH} -uz "${LOCAL_MOUNT_POINT}"
ExecStopPost=-${UMOUNT_PATH} -l "${LOCAL_MOUNT_POINT}"

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null
  systemctl start "$SERVICE_NAME"

  heal_mount_by_service "$SERVICE_NAME" "$LOCAL_MOUNT_POINT"

  if service_active "$SERVICE_NAME" && is_mountpoint_exact "$LOCAL_MOUNT_POINT" && ! is_stale_mount "$LOCAL_MOUNT_POINT"; then
    ok "挂载成功：$LOCAL_MOUNT_POINT"
    info "查看日志：tail -f \"$LOG_FILE\""
  else
    err "挂载未达到健康状态（可能网络/认证/API/权限）。"
    systemctl status "$SERVICE_NAME" --no-pager || true
    info "日志：tail -n 120 \"$LOG_FILE\""
  fi
}

# --------- 选项4：Dry-Run ----------
dry_run(){
  prepare_mount_plan

  hr
  say "${BOLD}🧪 Dry-Run 预览（不会写 systemd，不会启动挂载）${PLAIN}"
  hr
  say "🔗 挂载链路： ${BOLD}${REMOTE_NAME}${PLAIN} (mount) → ${BOLD}${PHYSICAL_REMOTE}${PLAIN} (physical: ${PHYSICAL_TYPE})"
  say "📌 RemoteSpec： ${BOLD}${REMOTE_SPEC}${PLAIN}"
  say "📍 MountPoint： ${BOLD}${LOCAL_MOUNT_POINT}${PLAIN}"
  say "💾 cache-dir：  ${BOLD}${CACHE_DIR}${PLAIN}"
  say "📜 log-file：   ${BOLD}${LOG_FILE}${PLAIN}（自动回滚，单文件≤10MB）"
  say "💽 cache 上限： ${BOLD}${PLAN_MAX_SIZE}${PLAIN}（自动计算后强制≤${CACHE_MAX_UPPER_GB}G）"
  if [[ "$SUPPORT_POLL" == "yes" ]]; then
    say "🛰️ 目录更新： 支持 polling(ChangeNotify) → poll=15s, dir-cache=24h"
  else
    say "🛰️ 目录更新： 不支持 polling(ChangeNotify) → dir-cache=60s（更耗 API）"
  fi
  hr
  say "${BOLD}将写入 systemd 的 ExecStart：${PLAIN}"
  say "${CMD_STR}"
  hr
  ok "Dry-Run 完成（未执行任何挂载/写入操作）"
}

# --------- 选项2：卸载 ----------
uninstall_mount(){
  init_runtime_basic

  hr
  say "${BOLD}🧹 卸载挂载（请选择要卸载的条目）${PLAIN}"
  hr

  local files; files="$(unit_files)"
  [[ -n "${files:-}" ]] || { warn "未找到 rclone-mount-*.service"; return; }

  local -a arr=()
  local f
  while IFS= read -r f; do [[ -n "$f" ]] && arr+=("$f"); done <<< "$files"

  local i svc mp remote rpath active mounted stale fstype src
  for i in "${!arr[@]}"; do
    f="${arr[$i]}"
    svc="$(basename "$f" .service)"
    remote="$(grep -E '^# Remote=' "$f" | cut -d= -f2- || true)"
    rpath="$(grep -E '^# RemotePath=' "$f" | cut -d= -f2- || true)"
    mp="$(grep -E '^# MountPoint=' "$f" | cut -d= -f2- || true)"

    active="no"; mounted="no"; stale="no"
    service_active "$svc" && active="yes" || true
    is_mountpoint_exact "$mp" && mounted="yes" || true
    [[ "$mounted" == "yes" ]] && is_stale_mount "$mp" && stale="yes" || true
    fstype="$(mount_fstype "$mp")"
    src="$(mount_source "$mp")"

    printf "[%d] %s\n" "$((i+1))" "$svc"
    printf "    - Remote : %s:%s\n" "$remote" "$rpath"
    printf "    - Mount  : %s\n" "$mp"
    printf "    - State  : active=%s mounted=%s stale=%s fstype=%s source=%s\n" "$active" "$mounted" "$stale" "${fstype:-NA}" "${src:-NA}"
  done

  say
  read -p "输入序号（或 0 取消）： " idx
  idx="${idx:-0}"
  [[ "$idx" =~ ^[0-9]+$ ]] || { err "输入非法"; return; }
  [[ "$idx" -ne 0 ]] || { warn "已取消"; return; }
  ((idx--))
  [[ "$idx" -ge 0 && "$idx" -lt "${#arr[@]}" ]] || { err "序号超出范围"; return; }

  f="${arr[$idx]}"
  svc="$(basename "$f" .service)"
  mp="$(grep -E '^# MountPoint=' "$f" | cut -d= -f2- || true)"
  local cache_dir; cache_dir="$(grep -E '^# CacheDir=' "$f" | cut -d= -f2- || true)"
  local log_file; log_file="$(grep -E '^# LogFile=' "$f" | cut -d= -f2- || true)"

  hr
  info "停止并禁用服务：$svc"
  systemctl stop "$svc" >/dev/null 2>&1 || true
  systemctl disable "$svc" >/dev/null 2>&1 || true

  if is_mountpoint_exact "$mp"; then
    warn "卸载后仍检测到挂载点存在，进行强制卸载：$mp"
    force_unmount "$mp" || true
  fi

  rm -f "$f"
  systemctl daemon-reload
  ok "已卸载并移除 unit：$svc"

  if [[ -n "${cache_dir:-}" && -d "$cache_dir" ]]; then
    read -p "是否删除缓存目录以释放空间？${cache_dir} (y/n): " dc
    if [[ "${dc:-n}" == "y" ]]; then
      rm -rf "$cache_dir" || true
      ok "已删除缓存目录：$cache_dir"
    else
      info "保留缓存目录：$cache_dir"
    fi
  fi

  if [[ -n "${log_file:-}" && -f "$log_file" ]]; then
    maybe_roll_log_now "$log_file"
  fi
}

# --------- 选项3：修复所有僵尸/异常挂载 ----------
repair_all(){
  init_runtime_basic

  hr
  say "${BOLD}🧰 检测并修复僵尸/异常挂载（批量自愈）${PLAIN}"
  hr

  local files; files="$(unit_files)"
  [[ -n "${files:-}" ]] || { warn "未找到 rclone-mount-*.service"; return; }

  local f svc mp log_file
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    svc="$(basename "$f" .service)"
    mp="$(grep -E '^# MountPoint=' "$f" | cut -d= -f2- || true)"
    log_file="$(grep -E '^# LogFile=' "$f" | cut -d= -f2- || true)"
    [[ -n "${mp:-}" ]] || continue
    info "检查：$svc → $mp"
    heal_mount_by_service "$svc" "$mp"
    [[ -n "${log_file:-}" ]] && maybe_roll_log_now "$log_file" || true
  done <<< "$files"

  ok "修复流程结束（如仍异常，请查看对应日志）。"
}

# --------- 选项9：安装/更新 rclone & 依赖（默认无交互） ----------
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
  local pkgs=(curl ca-certificates unzip util-linux psmisc logrotate)
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
      apk add --no-cache fuse3 || true
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
  info "开始安装/更新 rclone 最新版（官方 install.sh，无交互）..."
  curl -fsSL https://rclone.org/install.sh | bash
  command -v rclone >/dev/null 2>&1 || die "rclone 安装失败（未在 PATH 中找到）"
  ok "rclone 已安装：$(command -v rclone)"
  rclone version || true
}

install_update_rclone_and_deps(){
  [[ $EUID -eq 0 ]] || die "必须 root 执行（请用 sudo）"

  hr
  say "${BOLD}🧱 选项9：安装/更新依赖 + rclone 最新版（默认无交互）${PLAIN}"
  hr

  local pm; pm="$(detect_pkg_mgr)"
  [[ "$pm" != "none" ]] || die "无法识别包管理器（apt/dnf/yum/pacman/apk/zypper 均未找到）"

  info "检测到包管理器：$pm"
  info "安装/更新依赖：curl / ca-certificates / unzip / util-linux / psmisc / fuse3 / logrotate ..."
  install_pkgs "$pm"

  # 基础校验
  need_cmd findmnt
  need_cmd timeout
  need_cmd stat
  command -v fusermount3 >/dev/null 2>&1 || command -v fusermount >/dev/null 2>&1 || \
    warn "未检测到 fusermount/fusermount3：请确认 fuse3 安装是否成功（挂载/卸载会受限）"

  ensure_fuse_allow_other
  ensure_logrotate
  install_or_update_rclone

  ok "选项9完成。"
  info "下一步：如果还没配置 remote，请运行：rclone config"
}

# --------- 入口：支持 bash xx.sh 9 直达（9 默认免交互） ----------
[[ $EUID -eq 0 ]] || die "必须使用 root 权限运行（请用 sudo）"

ARG="${1:-}"
if [[ -n "${ARG}" ]]; then
  case "$ARG" in
    1|mount|add) install_mount ;;
    2|unmount|uninstall|remove) uninstall_mount ;;
    3|repair|heal|fix) repair_all ;;
    4|dry|dryrun|preview|show) dry_run ;;
    9|install|update|deps) install_update_rclone_and_deps ;;
    0|exit|quit) exit 0 ;;
    *)
      die "未知参数：$ARG
示例：
  sudo bash $0 9      # 免交互安装/更新依赖+rclone
  sudo bash $0 4      # Dry-Run 预览（不执行）
  sudo bash $0 1      # 新增挂载
  sudo bash $0 2      # 卸载挂载
  sudo bash $0 3      # 修复僵尸/异常挂载
"
      ;;
  esac
  exit 0
fi

# --------- 菜单 ----------
clear
hr
say "${BOLD}Rclone Mount Ultimate (Production Final)${PLAIN}"
hr
say "1. 新增挂载（多网盘/多路径/多挂载点）"
say "2. 卸载挂载（可选择指定卸载）"
say "3. 检测并修复僵尸/异常挂载（批量自愈）"
say "4. Dry-Run 预览（不执行，仅展示最终命令/决策）"
say "9. 安装/更新 rclone 最新版 + 安装脚本依赖（默认无交互）"
say "0. 退出"
hr
read -p "请选择： " OPT

case "${OPT:-0}" in
  1) install_mount ;;
  2) uninstall_mount ;;
  3) repair_all ;;
  4) dry_run ;;
  9) install_update_rclone_and_deps ;;
  0) exit 0 ;;
  *) warn "退出" ;;
esac
