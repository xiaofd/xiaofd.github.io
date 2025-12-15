#!/usr/bin/env bash
# ==============================================================================
# Rclone Mount Ultimate (最终版)
# - 缓存上限：自动算，但强制 <= 4G；并保留 1G 空间
# - 日志回滚：logrotate + systemd timer（尽量保证单文件 <= 10MB）
# - 多挂载隔离：service/log/cache 唯一化，不冲突
# - 穿透 crypt/alias：识别物理底层类型（drive 等）
# - “实时”调优：按 polling(ChangeNotify) 支持与否自动调优
# - 僵尸/半健康自愈：
#     * 僵尸：Transport endpoint is not connected → 强制卸载+重启
#     * 半健康：挂载正常但目录空，且远端非空 → 自动重启一次刷新
# - 选项9：安装/更新依赖 + rclone 最新版（默认无交互）
# - 选项4：Dry-Run（仅展示最终命令/决策）
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

# ---------------- 配置区 ----------------
CACHE_ROOT_DEFAULT="/var/cache/rclone"
CACHE_MAX_UPPER_GB="4.0"                 # vfs-cache-max-size 上限
LOG_MAX_BYTES=$((10 * 1024 * 1024))      # 单日志文件最大 10MB
LOGROTATE_ROTATE=5                       # 保留份数
LOGROTATE_CFG="/etc/logrotate.d/rclone-mount-ultimate"
LOGROTATE_STATE="/var/lib/logrotate/rclone-mount-ultimate.status"
LOGROTATE_TIMER_NAME="rclone-mount-logrotate"
LOGROTATE_INTERVAL_SEC=300               # 5分钟跑一次 logrotate（更贴近“单文件不超 10MB”）
# -------------------------------------------------------

# --------- 颜色/输出 ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'
PLAIN='\033[0m'; BOLD='\033[1m'
say()   { echo -e "$*"; }
info()  { echo -e "${BLUE}ℹ️  ${PLAIN}$*"; }
ok()    { echo -e "${GREEN}✅ ${PLAIN}$*"; }
warn()  { echo -e "${YELLOW}⚠️  ${PLAIN}$*"; }
err()   { echo -e "${RED}❌ ${PLAIN}$*"; }
die()   { err "$*"; exit 1; }
hr() { echo -e "${GREEN}------------------------------------------------------------${PLAIN}"; }

need_cmd(){ command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1（建议先运行：sudo bash $0 9）"; }
trim(){ echo "${1:-}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }
normalize_remote_name(){ local r; r="$(trim "${1:-}")"; r="${r%:}"; echo "$r"; }

# systemd ExecStart 安全引用：逐参数 quote
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
RCLONE_BIN=""; RCLONE_CONF=""; FUSERMOUNT_PATH=""; UMOUNT_PATH=""; LOGROTATE_BIN=""

# 挂载计划（prepare_mount_plan 会填）
REMOTE_NAME=""; REMOTE_PATH=""; LOCAL_MOUNT_POINT=""
PHYSICAL_REMOTE=""; PHYSICAL_TYPE=""
SERVICE_NAME=""; SERVICE_FILE=""; LOG_FILE=""; CACHE_DIR=""
SUPPORT_POLL="no"; READ_ONLY="no"; NO_CHECKSUM="no"
REMOTE_SPEC=""; CMD_STR=""
PLAN_MAX_SIZE=""; PLAN_AVAIL_KB=""; PLAN_CALC_GB=""

# --------- mount/僵尸检测 ----------
# 只在“目录本身是挂载点”时才算已挂载
is_mountpoint_exact(){
  local mp="$1"
  local target
  target="$(findmnt -rn -T "$mp" -o TARGET 2>/dev/null || true)"
  [[ -n "$target" && "$target" == "$mp" ]]
}
mount_fstype(){ findmnt -rn -T "$1" -o FSTYPE 2>/dev/null || true; }
mount_source(){ findmnt -rn -T "$1" -o SOURCE 2>/dev/null || true; }

is_stale_mount(){
  local mp="$1" tmp errtxt
  tmp="$(mktemp)"
  if timeout 2 ls "$mp" >/dev/null 2>"$tmp"; then rm -f "$tmp"; return 1; fi
  errtxt="$(cat "$tmp" 2>/dev/null || true)"; rm -f "$tmp"
  echo "$errtxt" | grep -qi "Transport endpoint is not connected"
}

force_unmount(){
  local mp="$1"
  if ! is_mountpoint_exact "$mp"; then return 0; fi
  warn "准备强制卸载：$mp (fstype=$(mount_fstype "$mp"), source=$(mount_source "$mp"))"

  if [[ -n "${FUSERMOUNT_PATH:-}" && -x "$FUSERMOUNT_PATH" ]]; then
    timeout 10 "$FUSERMOUNT_PATH" -uz "$mp" >/dev/null 2>&1 || true
    sleep 0.2
  fi
  if is_mountpoint_exact "$mp"; then
    timeout 10 "$UMOUNT_PATH" -l "$mp" >/dev/null 2>&1 || true
  fi
  if is_mountpoint_exact "$mp" && command -v fuser >/dev/null 2>&1; then
    warn "卸载仍失败，尝试 fuser -km（⚠️ 可能中断程序）..."
    timeout 10 fuser -km "$mp" >/dev/null 2>&1 || true
    timeout 10 "$UMOUNT_PATH" -l "$mp" >/dev/null 2>&1 || true
  fi

  if is_mountpoint_exact "$mp"; then
    err "仍无法卸载：$mp（可能 busy 或内核/FUSE 异常）。"
    return 1
  fi
  ok "已卸载：$mp"
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
  "$RCLONE_BIN" config show "$1" --config "$RCLONE_CONF" 2>/dev/null \
    | awk -F' *= *' '$1=="type"{print $2; exit}'
}
get_remote_wrapped_remote(){
  "$RCLONE_BIN" config show "$1" --config "$RCLONE_CONF" 2>/dev/null \
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
      echo "$current"; return 0
    fi
  done
  echo "$current"
}

backend_features(){
  "$RCLONE_BIN" backend features "${1}:" --config "$RCLONE_CONF" 2>/dev/null || true
}
json_has_true(){  echo "$1" | grep -Eq "\"${2}\"[[:space:]]*:[[:space:]]*true"; }
json_has_false(){ echo "$1" | grep -Eq "\"${2}\"[[:space:]]*:[[:space:]]*false"; }
json_hashes_empty(){ echo "$1" | grep -Eq '"Hashes"[[:space:]]*:[[:space:]]*\[[[:space:]]*\]'; }

hash_id(){
  local s="$1"
  if command -v sha1sum >/dev/null 2>&1; then echo -n "$s" | sha1sum | awk '{print $1}'
  elif command -v md5sum >/dev/null 2>&1; then echo -n "$s" | md5sum | awk '{print $1}'
  else echo -n "$s" | od -An -tx1 | tr -d ' \n' | cut -c1-40
  fi
}

unit_files(){ ls /etc/systemd/system/rclone-mount-*.service 2>/dev/null || true; }
service_active(){ systemctl is-active --quiet "$1"; }

# --------- 缓存上限：自动算 *0.40，但 clamp 到 [1G, 4G] ----------
calc_cache_max_size(){
  local cache_root="$1" avail_kb calc_gb max
  avail_kb="$(df -k "$cache_root" | awk 'NR==2 {print $4}')"
  calc_gb="$(awk -v kb="$avail_kb" 'BEGIN{ printf "%.2f", kb/1024/1024*0.40 }')"
  max="$(awk -v g="$calc_gb" -v upper="$CACHE_MAX_UPPER_GB" 'BEGIN{
    if (g < 1.00) g = 1.00;
    if (g > upper) g = upper;
    printf "%.1fG", g;
  }')"
  echo "$avail_kb|$calc_gb|$max"
}

# --------- 日志回滚：logrotate + timer ----------
ensure_logrotate(){
  LOGROTATE_BIN="$(command -v logrotate 2>/dev/null || true)"
  if [[ -z "${LOGROTATE_BIN:-}" ]]; then
    warn "未检测到 logrotate：无法自动回滚日志（建议：sudo bash $0 9 安装依赖）"
    return 0
  fi

  cat > "$LOGROTATE_CFG" <<EOF
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
  ok "已写入 logrotate 配置：$LOGROTATE_CFG（单文件≤10MB，保留${LOGROTATE_ROTATE}份）"

  # systemd timer：每 5 分钟跑一次（更贴近“单文件不超10MB”的诉求）
  local svc="/etc/systemd/system/${LOGROTATE_TIMER_NAME}.service"
  local tmr="/etc/systemd/system/${LOGROTATE_TIMER_NAME}.timer"

  cat > "$svc" <<EOF
[Unit]
Description=Rotate rclone-mount logs (<=10MB)

[Service]
Type=oneshot
ExecStart=${LOGROTATE_BIN} -s ${LOGROTATE_STATE} ${LOGROTATE_CFG}
EOF

  cat > "$tmr" <<EOF
[Unit]
Description=Run logrotate for rclone-mount logs periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=${LOGROTATE_INTERVAL_SEC}
Unit=${LOGROTATE_TIMER_NAME}.service
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${LOGROTATE_TIMER_NAME}.timer" >/dev/null 2>&1 || true
}

# 启动/修复时做一次“即时截断保护”（避免启动瞬间就超 10MB）
maybe_roll_log_now(){
  local logfile="$1"
  [[ -f "$logfile" ]] || return 0
  local sz
  sz="$(stat -c%s "$logfile" 2>/dev/null || echo 0)"
  if [[ "$sz" -le "$LOG_MAX_BYTES" ]]; then return 0; fi
  warn "日志超过 10MB，先回滚：$logfile"
  mv -f "$logfile" "${logfile}.1" || true
  : > "$logfile" || true
  ok "已回滚：${logfile}.1"
}

# --------- 半健康检测：挂载正常但目录空（且远端非空）→ 自动重启一次 ----------
mountpoint_has_any_entry(){
  local mp="$1" out
  out="$(timeout 5 ls -A "$mp" 2>/dev/null | head -n 1 || true)"
  [[ -n "${out:-}" ]]
}

remote_has_any_entry(){
  local out
  # 只取一条：max-depth=1 + head -n 1（最小化 API）
  out="$(timeout 20 "$RCLONE_BIN" lsf "$REMOTE_SPEC" --config "$RCLONE_CONF" --max-depth 1 2>/dev/null | head -n 1 || true)"
  [[ -n "${out:-}" ]]
}

post_mount_verify_and_fix(){
  local svc="$1" mp="$2"
  # 已经僵尸的交给僵尸逻辑；这里处理“非僵尸但看不到文件”
  if ! service_active "$svc"; then return 0; fi
  if ! is_mountpoint_exact "$mp"; then return 0; fi
  if is_stale_mount "$mp"; then return 0; fi

  # 给第一次列目录一点时间
  sleep 1

  if mountpoint_has_any_entry "$mp"; then
    ok "目录可见性检查：挂载点已有内容（正常）"
    return 0
  fi

  # 挂载点为空：探测远端是否非空
  warn "目录可见性检查：挂载点暂为空，正在轻量探测远端是否非空..."
  if remote_has_any_entry; then
    warn "探测结果：远端非空但挂载点为空 → 自动重启一次刷新目录缓存"
    systemctl restart "$svc" >/dev/null 2>&1 || true
    sleep 2
    if mountpoint_has_any_entry "$mp"; then
      ok "刷新成功：重启后已可见目录内容"
    else
      warn "重启后仍为空：可能远端目录确实为空、或后端仍不稳定。建议查看日志。"
    fi
  else
    info "探测结果：远端也可能为空（或探测超时/受限）。若确定远端有内容，请查看日志排查。"
  fi
}

# --------- 健康自愈（含僵尸） ----------
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
    sleep 1
  fi

  if is_mountpoint_exact "$mp" && is_stale_mount "$mp"; then
    warn "重启后仍僵尸：先强制卸载再启动：$svc"
    force_unmount "$mp" || true
    systemctl restart "$svc" >/dev/null 2>&1 || true
  fi
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

# --------- 生成挂载计划（新增挂载 & dry-run 共用） ----------
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
    die "请检查 remote 名或配置文件是否正确（必要时运行：rclone config）"
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

  local cache_root="$CACHE_ROOT_DEFAULT"
  mkdir -p "$cache_root"

  local calc out_avail_kb calc_gb MAX_SIZE
  calc="$(calc_cache_max_size "$cache_root")"
  out_avail_kb="${calc%%|*}"
  calc_gb="$(echo "$calc" | awk -F'|' '{print $2}')"
  MAX_SIZE="$(echo "$calc" | awk -F'|' '{print $3}')"

  local spec cache_id suffix
  spec="${REMOTE_NAME}:${REMOTE_PATH}:${LOCAL_MOUNT_POINT}"
  cache_id="$(hash_id "$spec")"
  suffix="${cache_id:0:8}"

  SERVICE_NAME="rclone-mount-${REMOTE_NAME}-${suffix}"
  SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
  LOG_FILE="/var/log/${SERVICE_NAME}.log"
  CACHE_DIR="${cache_root}/${REMOTE_NAME}-${suffix}"

  mkdir -p "$CACHE_DIR"
  touch "$LOG_FILE" >/dev/null 2>&1 || true
  maybe_roll_log_now "$LOG_FILE"

  local feat
  feat="$(backend_features "$REMOTE_NAME")"
  SUPPORT_POLL="no"; json_has_true "$feat" "ChangeNotify" && SUPPORT_POLL="yes" || true
  READ_ONLY="no";   json_has_false "$feat" "CanWrite"    && READ_ONLY="yes"   || true
  NO_CHECKSUM="no"; json_hashes_empty "$feat"            && NO_CHECKSUM="yes" || true

  if [[ -n "${REMOTE_PATH:-}" ]]; then REMOTE_SPEC="${REMOTE_NAME}:${REMOTE_PATH}"; else REMOTE_SPEC="${REMOTE_NAME}:"; fi

  # 只在“目录本身是挂载点”才算被占用
  if is_mountpoint_exact "$LOCAL_MOUNT_POINT"; then
    warn "挂载点已被占用：$LOCAL_MOUNT_POINT (fstype=$(mount_fstype "$LOCAL_MOUNT_POINT"), source=$(mount_source "$LOCAL_MOUNT_POINT"))"
    if is_stale_mount "$LOCAL_MOUNT_POINT"; then
      warn "检测到僵尸挂载，将先强制卸载"
      force_unmount "$LOCAL_MOUNT_POINT" || die "僵尸卸载失败，停止"
    else
      die "该路径本身就是挂载点且正常使用中。请更换挂载点或先卸载。"
    fi
  fi

  # 组装 rclone mount 参数（尽量稳 + 小内存 + 少 API）
  local -a opts
  opts+=( "--config" "$RCLONE_CONF" "--allow-other" "--umask" "000" "--log-level" "INFO" )
  opts+=( "--vfs-cache-mode" "full" "--cache-dir" "$CACHE_DIR" "--vfs-cache-max-size" "$MAX_SIZE" "--vfs-cache-min-free-space" "1G" "--vfs-cache-poll-interval" "30s" )
  opts+=( "--vfs-read-chunk-size" "32M" "--vfs-read-chunk-size-limit" "off" "--vfs-read-chunk-streams" "1" "--buffer-size" "32M" )
  opts+=( "--tpslimit" "10" "--tpslimit-burst" "10" )

  [[ "$ALLOW_NON_EMPTY" == "yes" ]] && opts+=( "--allow-non-empty" ) || true

  if [[ "$SUPPORT_POLL" == "yes" ]]; then
    opts+=( "--dir-cache-time" "24h" "--poll-interval" "15s" )
  else
    opts+=( "--dir-cache-time" "60s" "--vfs-fast-fingerprint" )
  fi

  [[ "$READ_ONLY" == "yes" ]] && opts+=( "--read-only" ) || true
  [[ "$NO_CHECKSUM" == "yes" ]] && opts+=( "--no-checksum" ) || true
  [[ "$PHYSICAL_TYPE" == "drive" ]] && opts+=( "--drive-pacer-min-sleep" "10ms" ) || true

  CMD_STR="$(quote_args_for_systemd "$RCLONE_BIN" "mount" "$REMOTE_SPEC" "$LOCAL_MOUNT_POINT" "${opts[@]}" "--log-file" "$LOG_FILE")"

  PLAN_MAX_SIZE="$MAX_SIZE"; PLAN_AVAIL_KB="$out_avail_kb"; PLAN_CALC_GB="$calc_gb"
}

# --------- 选项1：新增挂载 ----------
install_mount(){
  prepare_mount_plan

  hr
  say "${BOLD}📣 决策逻辑公示${PLAIN}"
  hr
  say "🔗 挂载链路： ${BOLD}${REMOTE_NAME}${PLAIN} → ${BOLD}${PHYSICAL_REMOTE}${PLAIN} (type: ${PHYSICAL_TYPE})"
  say "📌 RemoteSpec： ${BOLD}${REMOTE_SPEC}${PLAIN}"
  say "📍 MountPoint： ${BOLD}${LOCAL_MOUNT_POINT}${PLAIN}"
  say "💾 CacheDir：  ${BOLD}${CACHE_DIR}${PLAIN}"
  say "💽 Cache 上限：可用KB=${PLAN_AVAIL_KB} | 估算=${PLAN_CALC_GB}GB× | 最终=${BOLD}${PLAN_MAX_SIZE}${PLAIN}（强制≤${CACHE_MAX_UPPER_GB}G）"
  if [[ "$SUPPORT_POLL" == "yes" ]]; then
    say "🛰️ 目录更新：支持 polling(ChangeNotify) → poll=15s, dir-cache=24h"
  else
    say "🛰️ 目录更新：不支持 polling(ChangeNotify) → dir-cache=60s（更耗 API）"
  fi
  say "📜 LogFile：  ${BOLD}${LOG_FILE}${PLAIN}（logrotate+timer，尽量单文件≤10MB）"
  hr
  read -p "确认写入 systemd 并启动？(y/n): " CONFIRM
  [[ "${CONFIRM:-n}" == "y" ]] || { warn "已取消"; return; }

  ensure_logrotate
  maybe_roll_log_now "$LOG_FILE"

  cat > "$SERVICE_FILE" <<EOF
# ManagedBy=rclone-mount-ultimate
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
ExecStartPre=-${UMOUNT_PATH} -l "${LOCAL_MOUNT_POINT}"
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

  # 先做僵尸自愈
  heal_mount_by_service "$SERVICE_NAME" "$LOCAL_MOUNT_POINT"

  # 再做“半健康可见性检查”（你这次遇到的就是这个）
  post_mount_verify_and_fix "$SERVICE_NAME" "$LOCAL_MOUNT_POINT"

  if service_active "$SERVICE_NAME" && is_mountpoint_exact "$LOCAL_MOUNT_POINT" && ! is_stale_mount "$LOCAL_MOUNT_POINT"; then
    ok "挂载完成：$LOCAL_MOUNT_POINT"
    info "查看日志：tail -f \"$LOG_FILE\""
  else
    err "挂载未达到健康状态。"
    systemctl status "$SERVICE_NAME" --no-pager || true
    info "日志：tail -n 160 \"$LOG_FILE\""
  fi
}

# --------- 选项4：Dry-Run ----------
dry_run(){
  prepare_mount_plan
  hr
  say "${BOLD}🧪 Dry-Run 预览（不写 systemd，不挂载）${PLAIN}"
  hr
  say "🔗 ${REMOTE_NAME} → ${PHYSICAL_REMOTE} (type: ${PHYSICAL_TYPE})"
  say "📌 ${REMOTE_SPEC}"
  say "📍 ${LOCAL_MOUNT_POINT}"
  say "💾 ${CACHE_DIR}"
  say "💽 max-size=${PLAN_MAX_SIZE}（强制≤${CACHE_MAX_UPPER_GB}G）"
  say "📜 ${LOG_FILE}"
  hr
  say "${BOLD}ExecStart：${PLAIN}"
  say "$CMD_STR"
  hr
  ok "Dry-Run 完成"
}

# --------- 选项2：卸载 ----------
uninstall_mount(){
  init_runtime_basic

  hr
  say "${BOLD}🧹 卸载挂载（请选择要卸载的条目）${PLAIN}"
  hr

  local files; files="$(unit_files)"
  [[ -n "${files:-}" ]] || { warn "未找到 rclone-mount-*.service"; return; }

  local -a arr=(); local f
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
  local log_file;  log_file="$(grep -E '^# LogFile=' "$f" | cut -d= -f2- || true)"

  hr
  info "停止并禁用：$svc"
  systemctl stop "$svc" >/dev/null 2>&1 || true
  systemctl disable "$svc" >/dev/null 2>&1 || true

  if is_mountpoint_exact "$mp"; then
    warn "确保不留挂载：$mp"
    force_unmount "$mp" || true
  fi

  rm -f "$f"
  systemctl daemon-reload
  ok "已移除：$svc"

  if [[ -n "${cache_dir:-}" && -d "$cache_dir" ]]; then
    read -p "是否删除缓存目录？${cache_dir} (y/n): " dc
    [[ "${dc:-n}" == "y" ]] && rm -rf "$cache_dir" && ok "已删除缓存目录" || info "保留缓存目录"
  fi

  [[ -n "${log_file:-}" ]] && maybe_roll_log_now "$log_file" || true
}

# --------- 选项3：修复所有僵尸/异常挂载 ----------
repair_all(){
  init_runtime_basic

  hr
  say "${BOLD}🧰 修复僵尸/异常挂载（批量）${PLAIN}"
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

  ok "修复完成"
}

# --------- 选项9：安装/更新 rclone & 依赖（默认无交互） ----------
detect_pkg_mgr(){
  if command -v apt-get >/dev/null 2>&1; then echo "apt"
  elif command -v dnf >/dev/null 2>&1; then echo "dnf"
  elif command -v yum >/dev/null 2>&1; then echo "yum"
  elif command -v pacman >/dev/null 2>&1; then echo "pacman"
  elif command -v apk >/dev/null 2>&1; then echo "apk"
  elif command -v zypper >/dev/null 2>&1; then echo "zypper"
  else echo "none"; fi
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
    *) return 1 ;;
  esac
}

install_or_update_rclone(){
  need_cmd curl
  info "安装/更新 rclone 最新版（官方 install.sh，无交互）..."
  curl -fsSL https://rclone.org/install.sh | bash
  command -v rclone >/dev/null 2>&1 || die "rclone 安装失败（未在 PATH 中找到）"
  ok "rclone：$(rclone version | head -n 1)"
}

install_update_rclone_and_deps(){
  [[ $EUID -eq 0 ]] || die "必须 root 执行（请用 sudo）"
  hr
  say "${BOLD}🧱 选项9：安装/更新依赖 + rclone 最新版（无交互）${PLAIN}"
  hr

  local pm; pm="$(detect_pkg_mgr)"
  [[ "$pm" != "none" ]] || die "无法识别包管理器"

  info "包管理器：$pm"
  info "安装依赖：curl/ca-certificates/unzip/util-linux/psmisc/logrotate/fuse3 ..."
  install_pkgs "$pm"

  ensure_fuse_allow_other
  ensure_logrotate
  install_or_update_rclone

  ok "选项9完成"
  info "下一步：如未配置 remote，请运行：rclone config"
}

# --------- 入口 ----------
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
    *) die "未知参数：$ARG（用法：sudo bash $0 1|2|3|4|9）" ;;
  esac
  exit 0
fi

clear
hr
say "${BOLD}Rclone Mount Ultimate (最终版)${PLAIN}"
hr
say "1. 新增挂载（多网盘/多路径/多挂载点）"
say "2. 卸载挂载（可选择指定卸载）"
say "3. 修复僵尸/异常挂载（批量自愈）"
say "4. Dry-Run 预览（不执行，仅展示命令/决策）"
say "9. 安装/更新 rclone 最新版 + 依赖（默认无交互）"
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
