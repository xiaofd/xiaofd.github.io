#!/usr/bin/env bash
# upjj 上传脚本
# 用法: upjj 文件1 [文件2 ...]
# 默认上传地址: https://casic.win/re/ud
# 可通过环境变量 UPJJ_URL 覆盖
set -euo pipefail

UPLOAD_URL="${UPJJ_URL:-https://casic.win/re/ud}"

usage() {
  echo "用法: upjj 文件1 [文件2 ...]" >&2
  echo "示例: upjj /path/to/file" >&2
}

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
