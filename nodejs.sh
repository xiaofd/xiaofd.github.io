#!/bin/bash
# ==============================================================================
# Node.js 安装与 NPM 镜像测速脚本（加强版）
# Ubuntu / Debian
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PLAIN='\033[0m'

# 图标
ICON_OK="✅"
ICON_ERR="❌"
ICON_INFO="ℹ️"
ICON_WAIT="⏳"
ICON_ROCKET="🚀"

log_info()    { echo -e "${BLUE}${ICON_INFO} $1${PLAIN}"; }
log_success() { echo -e "${GREEN}${ICON_OK} $1${PLAIN}"; }
log_wait()    { echo -e "${YELLOW}${ICON_WAIT} $1${PLAIN}"; }
log_error()   { echo -e "${RED}${ICON_ERR} $1${PLAIN}"; }

section_title() {
  echo -e "\n${CYAN}==============================================================${PLAIN}"
  echo -e "${CYAN}   $1${PLAIN}"
  echo -e "${CYAN}==============================================================${PLAIN}"
}

trap 'log_error "脚本在第 $LINENO 行失败，退出码=$?"' ERR

# Root 检查
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  log_error "必须使用 Root 权限运行（建议 sudo -i）"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

check_dependencies() {
  section_title "检查依赖"
  log_wait "检查基础依赖..."
  local pkgs=()

  command -v curl >/dev/null 2>&1 || pkgs+=("curl")
  command -v bc   >/dev/null 2>&1 || pkgs+=("bc")
  command -v gpg  >/dev/null 2>&1 || pkgs+=("gnupg")
  dpkg -s ca-certificates >/dev/null 2>&1 || pkgs+=("ca-certificates")

  if (( ${#pkgs[@]} > 0 )); then
    log_info "安装缺失工具: ${pkgs[*]}"
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends "${pkgs[@]}"
  fi
  log_success "依赖检查通过"
}

select_version() {
  section_title "Node.js 版本选择"

  # 允许通过环境变量或第一个参数指定：NODE_VER=20 ./script.sh
  if [[ -n "${NODE_VER:-}" ]]; then
    log_info "检测到环境变量 NODE_VER=${NODE_VER}"
    return
  fi

  # 非交互环境：直接默认 22
  if [[ ! -t 0 ]]; then
    NODE_VER="22"
    log_info "非交互环境，默认安装 Node.js v${NODE_VER}.x"
    return
  fi

  echo -e "请选择要安装的版本:"
  echo -e " ${GREEN}1.${PLAIN} Node.js v22"
  echo -e " ${GREEN}2.${PLAIN} Node.js v20"
  echo -e " ${GREEN}3.${PLAIN} Node.js v18"
  echo ""
  read -r -p "请输入选项 [1-3] (默认: 1): " choice

  case "${choice:-1}" in
    2) NODE_VER="20" ;;
    3) NODE_VER="18" ;;
    *) NODE_VER="22" ;;
  esac

  log_info "已选择安装: Node.js v${NODE_VER}.x"
}

install_node() {
  section_title "开始安装 Node.js"

  # 清理旧版本（可选：你也可以改成检测版本满足就跳过）
  if command -v node >/dev/null 2>&1; then
    log_wait "检测到旧版本 Node.js，正在清理..."
    apt-get remove -y -qq nodejs npm >/dev/null 2>&1 || true
    apt-get autoremove -y -qq >/dev/null 2>&1 || true
  fi

  log_wait "配置 NodeSource 源 (v${NODE_VER})..."
  # 注意：curl|bash 有供应链风险；此处保留你原逻辑，但用 pipefail 确保失败会中断
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_VER}.x" | bash -

  log_wait "安装 Node.js..."
  apt-get install -y -qq nodejs

  command -v node >/dev/null 2>&1 || { log_error "安装失败：node 命令不存在"; exit 1; }

  local v_node v_npm
  v_node="$(node -v)"
  v_npm="$(npm -v)"
  log_success "安装成功!"
  echo -e "   - Node: ${GREEN}${v_node}${PLAIN}"
  echo -e "   - NPM : ${GREEN}${v_npm}${PLAIN}"
}

configure_mirror() {
  section_title "NPM 镜像源智能测速"

  # 源列表（保持输出顺序稳定）
  local names=("官方源" "淘宝源(npmmirror)" "腾讯云")
  local urls=("https://registry.npmjs.org" "https://registry.npmmirror.com" "https://mirrors.cloud.tencent.com/npm")

  local best=""
  local min_time="999999"

  log_wait "正在测试各源响应速度（/-/ping，connect 3s，total 5s）..."

  for i in "${!names[@]}"; do
    local name="${names[$i]}"
    local base="${urls[$i]}"
    local test_url="${base}/-/ping"

    local time_taken=""
    if time_taken="$(curl -L --silent --show-error \
        --connect-timeout 3 --max-time 5 \
        -o /dev/null -w '%{time_total}' "$test_url" 2>/dev/null)"; then
      echo -e "   - ${name}: ${GREEN}${time_taken}s${PLAIN}"

      # 浮点比较：time_taken < min_time ?
      if awk "BEGIN{exit !(${time_taken} < ${min_time})}"; then
        min_time="$time_taken"
        best="$base/"
      fi
    else
      echo -e "   - ${name}: ${RED}超时/失败${PLAIN}"
    fi
  done

  echo ""
  if [[ -n "$best" ]]; then
    log_success "${ICON_ROCKET} 最快源: ${best} (${min_time}s)"
    log_wait "应用 registry..."
    npm config set registry "$best" >/dev/null
  else
    log_error "所有源测速失败，保持默认 registry。"
  fi
}

install_tools() {
  section_title "安装常用包管理器"

  log_wait "安装 pnpm 和 yarn..."
  npm install -g pnpm yarn >/dev/null 2>&1 || { log_error "全局安装 pnpm/yarn 失败"; exit 1; }

  local reg
  reg="$(npm config get registry 2>/dev/null || true)"
  [[ -n "$reg" ]] || reg="https://registry.npmjs.org/"

  if command -v pnpm >/dev/null 2>&1; then
    pnpm config set registry "$reg" >/dev/null 2>&1 || true
    log_success "pnpm 安装成功 ($(pnpm -v))"
  fi

  if command -v yarn >/dev/null 2>&1; then
    yarn config set registry "$reg" >/dev/null 2>&1 || true
    log_success "yarn 安装成功 ($(yarn -v))"
  fi
}

# Main
clear || true
check_dependencies
select_version
install_node
configure_mirror
install_tools

section_title "安装完成"
echo -e " ${GREEN}所有步骤已完成！${PLAIN}"
echo -e " 当前 Node 版本: $(node -v)"
echo -e " 当前 NPM 源   : $(npm config get registry)"
echo -e " ${YELLOW}提示: 新开终端一般即可使用 pnpm/yarn。${PLAIN}"
echo ""

