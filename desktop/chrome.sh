#!/usr/bin/env bash
# 支持: Ubuntu 22.04/24.04, Debian 12/13
# 架构: amd64 安装 Google Chrome；其他架构安装 Chromium（同源最新稳定版）
set -euo pipefail

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "请用 root 运行。" >&2
    exit 1
  fi
}

check_os() {
  if [ ! -r /etc/os-release ]; then
    echo "无法识别系统版本，仅支持 Ubuntu 22.04/24.04 与 Debian 12/13。" >&2
    exit 1
  fi
  # shellcheck source=/etc/os-release
  . /etc/os-release
  case "${ID:-}" in
    ubuntu)
      case "${VERSION_ID:-}" in
        22.04|24.04) ;;
        *) echo "仅支持 Ubuntu 22.04/24.04 (当前: ${VERSION_ID:-unknown})." >&2; exit 1 ;;
      esac
      ;;
    debian)
      case "${VERSION_ID:-}" in
        12|13) ;;
        *) echo "仅支持 Debian 12/13 (当前: ${VERSION_ID:-unknown})." >&2; exit 1 ;;
      esac
      ;;
    *)
      echo "仅支持 Ubuntu 22.04/24.04 与 Debian 12/13。" >&2
      exit 1
      ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7|armhf) echo "armhf" ;;
    i386|i486|i586|i686|x86) echo "i386" ;;
    *) echo "unknown" ;;
  esac
}

install_chrome_amd64() {
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg

  install -m 0755 -d /usr/share/keyrings
  if [ ! -f /usr/share/keyrings/google-chrome.gpg ]; then
    curl -fsSL https://dl.google.com/linux/linux_signing_key.pub \
      | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg
  fi

  cat > /etc/apt/sources.list.d/google-chrome.list <<'EOF'
deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main
EOF

  apt-get update -y
  apt-get install -y google-chrome-stable
}

install_chromium_debian() {
  apt-get update -y
  apt-get install -y chromium
}

install_chromium_ubuntu() {
  apt-get update -y
  apt-get install -y snapd
  if ! command -v snap >/dev/null 2>&1; then
    echo "snap 未就绪，无法安装 Chromium。" >&2
    exit 1
  fi
  snap install chromium
}

need_root
check_os
ARCH="$(detect_arch)"
case "$ARCH" in
  amd64)
    install_chrome_amd64
    echo "安装完成。命令: google-chrome-stable"
    ;;
  arm64|armhf|i386)
    case "${ID:-}" in
      debian) install_chromium_debian ;;
      ubuntu) install_chromium_ubuntu ;;
    esac
    echo "安装完成。命令: chromium 或 chromium-browser"
    ;;
  *)
    echo "不支持的架构: $(uname -m)" >&2
    exit 1
    ;;
esac
