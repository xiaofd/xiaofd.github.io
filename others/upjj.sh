#!/usr/bin/env bash
# upjj 上传脚本
# 用法: upjj 文件1 [文件2 ...]
#       bash upjj.sh -i|--install
# 默认上传地址: https://casic.win/re/ud
# 可通过环境变量 UPJJ_URL 覆盖
set -euo pipefail

UPLOAD_URL="${UPJJ_URL:-https://casic.win/re/ud}"

usage() {
  echo "用法: upjj 文件1 [文件2 ...]" >&2
  echo "示例: upjj /path/to/file" >&2
  if [ "$(basename "${BASH_SOURCE[0]}")" = "upjj.sh" ]; then
    echo "安装: bash upjj.sh -i|--install (部署到 /usr/local/bin/upjj)" >&2
  fi
}

install_self() {
  local target="/usr/local/bin/upjj"
  local src
  src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  if [ ! -r "$src" ]; then
    echo "错误: 无法读取脚本源文件: $src" >&2
    exit 1
  fi
  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
      sudo install -m 0755 "$src" "$target"
    else
      echo "错误: 需要 root 权限安装到 $target，且未找到 sudo" >&2
      exit 1
    fi
  else
    install -m 0755 "$src" "$target"
  fi
  echo "已安装: $target"
}

if [ "$(basename "${BASH_SOURCE[0]}")" = "upjj.sh" ] && \
  [ "$#" -eq 1 ] && { [ "$1" = "-i" ] || [ "$1" = "--install" ]; }; then
  install_self
  exit 0
fi

if [ "$#" -lt 1 ]; then
  usage
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "错误: 未找到 curl" >&2
  exit 1
fi

for file in "$@"; do
  if [ ! -e "$file" ]; then
    echo "跳过: 文件不存在 -> $file" >&2
    continue
  fi
  if [ -d "$file" ]; then
    echo "跳过: 目录不支持 -> $file" >&2
    continue
  fi

  fname="$(basename "$file")"
  echo "上传: $file"
  resp="$(curl -fsS --retry 3 --retry-delay 2 --connect-timeout 10 \
    -F "file=@${file};filename=${fname}" "${UPLOAD_URL}")" || {
      echo "上传失败: $file" >&2
      exit 1
    }
  echo "${resp}"
  echo
 done
