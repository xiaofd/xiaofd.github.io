#!/usr/bin/env bash
set -euo pipefail

APP_NAME="gofile"
MANIFEST_DEFAULT="$HOME/.gofile/manifest.jsonl"
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"

if { [ -t 1 ] || [ -t 2 ]; } && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_CYAN=$'\033[36m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_RED=$'\033[31m'
else
  C_RESET=""
  C_BOLD=""
  C_CYAN=""
  C_GREEN=""
  C_YELLOW=""
  C_BLUE=""
  C_RED=""
fi

usage() {
  cat <<'USAGE'
Gofile 管理脚本

用法:
  gofile.sh <命令> [选项]

命令:
  upload   上传文件并记录清单
  direct   获取“网页下载链接”或 Premium 直链
  download 下载指定文件或全部文件
  delete   按链接/Code/ID/清单序号删除
  list     查看清单
  prune    删除超过 N 天的清单文件并同步删除远端
  speedtest 测试不同区域上传速度并设置默认值

提示: gofile.sh <命令> --help 查看详细参数
USAGE
}

msg_info() { echo -e "${C_BLUE}${C_BOLD}$*${C_RESET}"; }
msg_ok() { echo -e "${C_GREEN}${C_BOLD}$*${C_RESET}"; }
msg_warn() { echo -e "${C_YELLOW}${C_BOLD}$*${C_RESET}" >&2; }
msg_err() { echo -e "${C_RED}${C_BOLD}$*${C_RESET}" >&2; }

fatal() {
  msg_err "错误: $*"
  exit 1
}

need_tool() {
  command -v "$1" >/dev/null 2>&1 || fatal "缺少必需工具: $1"
}

need_jq() {
  command -v jq >/dev/null 2>&1 || return 1
  return 0
}

install_dep() {
  local dep="$1"
  local sudo_cmd=""
  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
      sudo_cmd="sudo"
    else
      fatal "缺少依赖 $dep，且未检测到 sudo"
    fi
  fi
  if command -v apt-get >/dev/null 2>&1; then
    $sudo_cmd apt-get update -qq
    $sudo_cmd apt-get install -y "$dep"
  elif command -v dnf >/dev/null 2>&1; then
    $sudo_cmd dnf install -y "$dep"
  elif command -v yum >/dev/null 2>&1; then
    $sudo_cmd yum install -y "$dep"
  elif command -v apk >/dev/null 2>&1; then
    $sudo_cmd apk add --no-cache "$dep"
  elif command -v pacman >/dev/null 2>&1; then
    $sudo_cmd pacman -Sy --noconfirm "$dep"
  elif command -v zypper >/dev/null 2>&1; then
    $sudo_cmd zypper --non-interactive in "$dep"
  else
    fatal "缺少依赖 $dep，且无法自动安装（未检测到包管理器）"
  fi
}

install_xxd() {
  local sudo_cmd=""
  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
      sudo_cmd="sudo"
    else
      fatal "缺少依赖 xxd，且未检测到 sudo"
    fi
  fi
  if command -v apt-get >/dev/null 2>&1; then
    $sudo_cmd apt-get update -qq
    if ! $sudo_cmd apt-get install -y xxd; then
      $sudo_cmd apt-get install -y vim-common
    fi
  elif command -v dnf >/dev/null 2>&1; then
    $sudo_cmd dnf install -y vim-common
  elif command -v yum >/dev/null 2>&1; then
    $sudo_cmd yum install -y vim-common
  elif command -v apk >/dev/null 2>&1; then
    if ! $sudo_cmd apk add --no-cache xxd; then
      $sudo_cmd apk add --no-cache vim
    fi
  elif command -v pacman >/dev/null 2>&1; then
    if ! $sudo_cmd pacman -Sy --noconfirm xxd; then
      $sudo_cmd pacman -Sy --noconfirm vim
    fi
  elif command -v zypper >/dev/null 2>&1; then
    $sudo_cmd zypper --non-interactive in vim
  else
    fatal "缺少依赖 xxd，且无法自动安装（未检测到包管理器）"
  fi
}

ensure_deps() {
  local dep
  for dep in "$@"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      msg_warn "缺少依赖: $dep，正在安装..."
      if [ "$dep" = "xxd" ]; then
        install_xxd
      else
        install_dep "$dep"
      fi
    fi
  done
}

region_list() {
  cat <<'EOF'
auto
eu-par
na-phx
na-nyc
ap-sgp
ap-hkg
ap-tyo
ap-syd
sa-sao
EOF
}

region_endpoint() {
  local region="$1" host
  case "${region:-auto}" in
    auto|"") host="upload.gofile.io" ;;
    eu|eu-par|par|paris) host="upload-eu-par.gofile.io" ;;
    na|na-phx|phx|phoenix) host="upload-na-phx.gofile.io" ;;
    na-nyc|nyc|newyork|new-york|new-york-city) host="upload-na-nyc.gofile.io" ;;
    ap-sgp|sgp|singapore) host="upload-ap-sgp.gofile.io" ;;
    ap-hkg|hkg|hongkong|hong-kong) host="upload-ap-hkg.gofile.io" ;;
    ap-tyo|tyo|tokyo) host="upload-ap-tyo.gofile.io" ;;
    ap-syd|syd|sydney) host="upload-ap-syd.gofile.io" ;;
    sa|sa-sao|sao|sao-paulo|saopaulo) host="upload-sa-sao.gofile.io" ;;
    *) echo ""; return 1 ;;
  esac
  echo "https://${host}/uploadfile"
}

fmt_speed() {
  local bps="${1:-0}"
  awk -v b="$bps" 'BEGIN{
    s=b+0; u="B/s";
    if (s>=1024){s/=1024;u="KB/s"}
    if (s>=1024){s/=1024;u="MB/s"}
    if (s>=1024){s/=1024;u="GB/s"}
    printf "%.2f %s", s, u
  }'
}

gen_password() {
  openssl rand -base64 32
}

derive_hmac_key() {
  local pass="$1"
  printf '%s' "${pass}:hmac:v1"
}

openssl_cipher_supported() {
  local c="$1"
  openssl enc -ciphers 2>/dev/null | tr ' ' '\n' | grep -qi "^-${c}$"
}

default_cipher() {
  echo "aes-256-cbc"
}

manifest_path() {
  echo "${GOFILE_MANIFEST:-$MANIFEST_DEFAULT}"
}

ensure_manifest_dir() {
  local m
  m="$(manifest_path)"
  mkdir -p "$(dirname "$m")"
}

config_path() {
  echo "${GOFILE_CONFIG:-$HOME/.gofile/config}"
}

ensure_config_dir() {
  mkdir -p "$(dirname "$(config_path)")"
}

config_get() {
  local key="$1" cfg
  cfg="$(config_path)"
  [ -f "$cfg" ] || return 0
  grep -E "^${key}=" "$cfg" | head -n1 | cut -d= -f2-
}

config_set() {
  local key="$1" val="$2" cfg tmp
  cfg="$(config_path)"
  ensure_config_dir
  if [ -f "$cfg" ]; then
    tmp="$(mktemp)"
    awk -v k="$key" -v v="$val" 'BEGIN{found=0}
      $0 ~ "^"k"=" {print k"="v; found=1; next}
      {print}
      END{if(found==0) print k"="v}' "$cfg" > "$tmp"
    mv -f "$tmp" "$cfg"
  else
    printf "%s=%s\n" "$key" "$val" > "$cfg"
  fi
}

get_config() {
  local config_js wt api_server
  config_js="$(curl -sS https://gofile.io/dist/js/config.js || true)"
  wt="$(printf '%s' "$config_js" | sed -nE 's/.*appdata\.wt[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"
  api_server="$(printf '%s' "$config_js" | sed -nE 's/.*appdata\.apiServer[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"
  api_server="${api_server:-api}"
  [ -n "$wt" ] || fatal "无法获取网站令牌 (wt)"
  echo "$wt" "$api_server"
}

create_guest_token() {
  local api_server="$1"
  local resp
  resp="$(curl -sS -A "$USER_AGENT" -H "Origin: https://gofile.io" -H "Referer: https://gofile.io/" -X POST "https://${api_server}.gofile.io/accounts" || true)"
  printf '%s' "$resp" | jq -r 'try (.data.token // .data.accessToken // "") catch ""' || true
}

extract_code() {
  local input="$1"
  if [[ "$input" =~ gofile\.io/d/([^/?#]+) ]]; then
    echo "${BASH_REMATCH[1]}"
    return
  fi
  if [[ "$input" == *"/"* ]]; then
    input="${input##*/}"
    input="${input%%\?*}"
    input="${input%%#*}"
  fi
  echo "$input"
}

content_fetch() {
  local api_server="$1" wt="$2" token="$3" code="$4" password="$5"
  local query
  query="contentFilter=&page=1&pageSize=1000&sortField=createTime&sortDirection=-1&wt=${wt}"
  if [ -n "$password" ]; then
    query="${query}&password=${password}"
  fi
  curl -sS -H "Authorization: Bearer ${token}" -H "X-Website-Token: ${wt}" \
    "https://${api_server}.gofile.io/contents/${code}?${query}"
}

content_parse() {
  printf '%s' "$1" | jq -r '
    def items:
      (.data.children // .data.contents // []) |
      (if type=="object" then to_entries|map(.value) else . end) |
      map(select(.type != "folder"));
    .data as $d
    | (items | map(select(.link != null)) | .[0]) as $f
    | ($d.id // ""),
      ($f.name // ""),
      ($f.link // "")
  ' || true
}

content_list_files() {
  printf '%s' "$1" | jq -r '
    def items:
      (.data.children // .data.contents // []) |
      (if type=="object" then to_entries|map(.value) else . end) |
      map(select(.type != "folder"));
    items[] | [(.id // ""), (.name // ""), (.link // ""), (.size // 0)] | @tsv
  ' || true
}

directlink_create() {
  local api_server="$1" token="$2" content_id="$3"
  curl -sS -X POST "https://${api_server}.gofile.io/contents/${content_id}/directlinks" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -d "{}"
}

directlink_extract() {
  printf '%s' "$1" | jq -r 'try (.data.directLink // "") catch ""' || true
}

content_select_files() {
  local json="$1" name="$2" fid="$3" all_flag="$4"
  printf '%s' "$json" | jq -r --arg name "$name" --arg fid "$fid" --arg all "$all_flag" '
    def items:
      (.data.children // .data.contents // []) |
      (if type=="object" then to_entries|map(.value) else . end) |
      map(select(.type != "folder"));
    def emit($list):
      $list[] | [(.id // ""), (.name // ""), (.link // ""), (.size // 0)] | @tsv;
    (items) as $files
    | if $all == "1" then emit($files)
      elif $fid != "" then emit($files | map(select(.id == $fid)))
      elif $name != "" then
        ($files | map(select(.name == $name))) as $exact
        | if ($exact | length) > 0 then emit($exact)
          else emit($files | map(select(.name != null and (.name | contains($name)))))
          end
      elif ($files | length) == 1 then emit($files)
      else empty
      end
  ' || true
}

manifest_add() {
  local file_path="$1" size="$2" download="$3" direct="$4" token="$5" code="$6" file_id="$7" content_id="$8"
  ensure_manifest_dir
  local m
  m="$(manifest_path)"
  size="${size:-0}"
  jq -cn \
    --arg file "$file_path" \
    --arg download "$download" \
    --arg direct "$direct" \
    --arg token "$token" \
    --arg code "$code" \
    --arg file_id "$file_id" \
    --arg content_id "$content_id" \
    --argjson size "$size" \
    --argjson created_at "$(date +%s)" \
    '{created_at:$created_at, file:$file, size:$size, download:$download, direct:$direct, token:$token, code:$code, file_id:$file_id, content_id:$content_id}' >> "$m"
}

manifest_list() {
  local m
  m="$(manifest_path)"
  [ -f "$m" ] || { msg_warn "清单不存在: $m"; return 0; }
  local out
  out="$(jq -s -r '
    if length == 0 then
      "(空)"
    else
      "序号\t日期\tCODE\t文件\t下载页\tToken",
      (to_entries[] | [
        (.key + 1),
        ((.value.created_at // 0) | tonumber | strflocaltime("%Y-%m-%d %H:%M:%S")),
        (.value.code // ""),
        (.value.file // ""),
        (.value.download // ""),
        (.value.token // "")
      ] | @tsv)
    end
  ' "$m")"
  printf '%s\n' "$out"
}

manifest_find_by_code_or_download() {
  local needle="$1" m
  m="$(manifest_path)"
  [ -f "$m" ] || return 1
  jq -c -s --arg needle "$needle" 'map(select(.code == $needle or .download == $needle)) | .[0] // empty' "$m"
}

manifest_find_by_index() {
  local idx="$1" m
  m="$(manifest_path)"
  [ -f "$m" ] || return 1
  jq -c -s --argjson idx "$idx" 'if ($idx>=1 and $idx<=length) then .[$idx-1] else empty end' "$m"
}

manifest_remove_by_codes() {
  local codes_csv="$1" m
  m="$(manifest_path)"
  [ -f "$m" ] || return 0
  local tmp
  tmp="$(mktemp)"
  jq -c -s --arg codes "$codes_csv" '
    ($codes | split(",") | map(select(length>0))) as $c
    | map(select(.code as $k | ($c | index($k) | not)))
    | .[]' "$m" > "$tmp"
  mv -f "$tmp" "$m"
}

cmd_upload() {
  local file="" token="${GOFILE_TOKEN:-}" folder_id="${GOFILE_FOLDER_ID:-}" region="" endpoint="${GOFILE_ENDPOINT:-}"
  local no_progress=0 simple=0 print_json=0 no_manifest=0 want_direct=0 recursive=0
  local encrypt=0 enc_pass="" enc_show=1 enc_cipher="" enc_cipher_user=0 enc_hmac=0 tmp_hmac=""

  while [ $# -gt 0 ]; do
    case "$1" in
      -t|--token) token="$2"; shift 2;;
      -f|--folder-id) folder_id="$2"; shift 2;;
      --region) region="$2"; shift 2;;
      -r|--recursive) recursive=1; shift;;
      -e|--endpoint) endpoint="$2"; shift 2;;
      --no-progress) no_progress=1; shift;;
      --encrypt) encrypt=1; shift;;
      --enc-pass|--password) enc_pass="$2"; shift 2;;
      --enc-cipher) enc_cipher="$2"; enc_cipher_user=1; shift 2;;
      --enc-hmac) enc_hmac=1; shift;;
      --enc-no-show) enc_show=0; shift;;
      --simple) simple=1; shift;;
      --json) print_json=1; shift;;
      --direct) want_direct=1; shift;;
      --no-manifest) no_manifest=1; shift;;
      -h|--help)
        cat <<'USAGE'
用法: gofile.sh upload [选项] <文件>

选项:
  -t, --token TOKEN       API Token (或环境变量 GOFILE_TOKEN)
  -f, --folder-id ID      目标 folderId (可选)
  --region REGION         auto|eu-par|na-phx|na-nyc|ap-sgp|ap-hkg|ap-tyo|ap-syd|sa-sao
  -r, --recursive         递归上传目录下所有文件
  -e, --endpoint URL      指定上传地址 (默认按 region/auto)
  --json                  输出完整 JSON
  --simple                仅输出下载页链接
  --no-progress           关闭进度条
  --encrypt               上传前加密文件（默认 AES-256-CBC + PBKDF2）
  --enc-pass PASS         指定加密密码（不指定则自动生成）
  --enc-cipher CIPHER     指定加密算法（默认自动选择）
  --enc-hmac              生成 HMAC 完整性校验（强烈建议）
  --direct                生成 Premium 直链 (需要 Premium token)
  --no-manifest           不写入清单
USAGE
        return 0;;
      --) shift; break;;
      -*) fatal "未知参数: $1";;
      *) if [ -z "$file" ]; then file="$1"; shift; else fatal "多余参数: $1"; fi;;
    esac
  done

  [ -n "$file" ] || fatal "请提供文件路径"
  ensure_deps curl jq
  if [ -z "$region" ]; then
    region="${GOFILE_REGION:-}"
  fi
  if [ -z "$region" ]; then
    region="$(config_get REGION)"
  fi
  if [ "$encrypt" -eq 1 ]; then
    ensure_deps openssl
    [ -n "$enc_pass" ] || enc_pass="$(gen_password)"
    if [ -z "$enc_cipher" ]; then
      enc_cipher="$(default_cipher)"
    fi
    if ! openssl_cipher_supported "$enc_cipher"; then
      if [ "$enc_cipher_user" -eq 1 ]; then
        msg_warn "不支持算法 $enc_cipher，已改用 aes-256-cbc"
      fi
      enc_cipher="aes-256-cbc"
    fi
    if [ "$enc_hmac" -eq 1 ]; then
      ensure_deps xxd
    fi
  fi

  if [ -d "$file" ]; then
    if [ "$recursive" -ne 1 ]; then
      fatal "传入的是目录，请使用 -r/--recursive 递归上传"
    fi
    local files=()
    while IFS= read -r -d '' f; do
      files+=("$f")
    done < <(find "$file" -type f -print0 | LC_ALL=C sort -z)
    [ "${#files[@]}" -gt 0 ] || fatal "目录为空: $file"
    msg_info "共发现 ${#files[@]} 个文件，开始上传..."
    local args=()
    [ -n "$token" ] && args+=(--token "$token")
    [ -n "$folder_id" ] && args+=(--folder-id "$folder_id")
    [ -n "$region" ] && args+=(--region "$region")
    [ -n "$endpoint" ] && args+=(--endpoint "$endpoint")
    [ "$no_progress" -eq 1 ] && args+=(--no-progress)
    [ "$encrypt" -eq 1 ] && args+=(--encrypt --enc-no-show --enc-pass "$enc_pass" --enc-cipher "$enc_cipher")
    [ "$simple" -eq 1 ] && args+=(--simple)
    [ "$print_json" -eq 1 ] && args+=(--json)
    [ "$want_direct" -eq 1 ] && args+=(--direct)
    [ "$no_manifest" -eq 1 ] && args+=(--no-manifest)
    local idx=1
    for f in "${files[@]}"; do
      msg_info "[$idx/${#files[@]}] 上传: $f"
      cmd_upload "${args[@]}" -- "$f"
      idx=$((idx+1))
    done
    if [ "$encrypt" -eq 1 ] && [ "$enc_show" -eq 1 ]; then
      echo -e "${C_CYAN}加密密码:${C_RESET} $enc_pass"
    fi
    return 0
  fi
  [ -f "$file" ] || fatal "文件不存在: $file"

  if [ -z "$endpoint" ]; then
    case "${region:-auto}" in
      auto|"") host="upload.gofile.io" ;;
      eu|eu-par|par|paris) host="upload-eu-par.gofile.io" ;;
      na|na-phx|phx|phoenix) host="upload-na-phx.gofile.io" ;;
      na-nyc|nyc|newyork|new-york|new-york-city) host="upload-na-nyc.gofile.io" ;;
      ap-sgp|sgp|singapore) host="upload-ap-sgp.gofile.io" ;;
      ap-hkg|hkg|hongkong|hong-kong) host="upload-ap-hkg.gofile.io" ;;
      ap-tyo|tyo|tokyo) host="upload-ap-tyo.gofile.io" ;;
      ap-syd|syd|sydney) host="upload-ap-syd.gofile.io" ;;
      sa|sa-sao|sao|sao-paulo|saopaulo) host="upload-sa-sao.gofile.io" ;;
      *) fatal "未知 region: $region" ;;
    esac
    endpoint="https://${host}/uploadfile"
  fi

  local tmp_resp
  tmp_resp="$(mktemp)"
  trap 'rm -f "$tmp_resp" "${tmp_hmac:-}"' RETURN
  local file_size=""
  file_size="$(stat -c%s "$file" 2>/dev/null || wc -c <"$file")"

  local curl_args=( -X POST "$endpoint" )
  if [ -n "$token" ]; then curl_args+=( -H "Authorization: Bearer $token" ); fi
  if [ -n "$folder_id" ]; then curl_args+=( -F "folderId=$folder_id" ); fi

  if [ "$no_progress" -eq 1 ]; then
    curl_args+=( -sS )
  else
    curl_args+=( --progress-bar -S )
  fi

  if [ "$encrypt" -eq 1 ]; then
    local enc_name
    enc_name="$(basename "$file").enc"
    curl_args+=( -F "file=@-;filename=${enc_name}" )
    if [ "$enc_hmac" -eq 1 ]; then
      tmp_hmac="$(mktemp)"
      HMAC_KEY="$(derive_hmac_key "$enc_pass")" \
        openssl dgst -sha256 -hmac "$HMAC_KEY" -binary "$file" | xxd -p -c 256 > "$tmp_hmac"
      OPENSSL_PASS="$enc_pass" openssl enc -"${enc_cipher}" -salt -pbkdf2 -iter 200000 -md sha256 \
        -pass env:OPENSSL_PASS -in "$file" | curl "${curl_args[@]}" -o "$tmp_resp"
    else
      OPENSSL_PASS="$enc_pass" openssl enc -"${enc_cipher}" -salt -pbkdf2 -iter 200000 -md sha256 \
        -pass env:OPENSSL_PASS -in "$file" | curl "${curl_args[@]}" -o "$tmp_resp"
    fi
  else
    curl_args+=( -F "file=@$file" )
    curl "${curl_args[@]}" -o "$tmp_resp"
  fi

  local response
  response="$(cat "$tmp_resp")"

  local parsed_lines status download file_id code guest_token parent_folder
  mapfile -t parsed_lines < <(printf '%s' "$response" | jq -r '
    .status//"",
    .data.downloadPage//"",
    (.data.fileId // .data.id // ""),
    .data.code//"",
    .data.guestToken//"",
    .data.parentFolder//""
  ' || true)
  status="${parsed_lines[0]:-}"
  download="${parsed_lines[1]:-}"
  file_id="${parsed_lines[2]:-}"
  code="${parsed_lines[3]:-}"
  guest_token="${parsed_lines[4]:-}"
  parent_folder="${parsed_lines[5]:-}"

  [ "$status" = "ok" ] || fatal "上传失败"
  [ -n "$download" ] || fatal "上传成功但缺少下载页链接"

  local token_out="$token"
  [ -n "$token_out" ] || token_out="$guest_token"

  if [ -z "$code" ]; then
    code="$(extract_code "$download")"
  fi

  if [ "$encrypt" -eq 1 ] && [ "$enc_hmac" -eq 1 ]; then
    if [ -n "$tmp_hmac" ] && [ -f "$tmp_hmac" ]; then
      local enc_hmac_name
      enc_hmac_name="$(basename "$file").enc.hmac"
      if [ -z "$token_out" ] || [ -z "$parent_folder" ]; then
        msg_warn "HMAC 文件未能写入同一分享（缺少 Token 或 parentFolder）"
      else
        curl -sS -X POST "$endpoint" \
          -H "Authorization: Bearer $token_out" \
          -F "folderId=$parent_folder" \
          -F "file=@${tmp_hmac};filename=${enc_hmac_name}" \
          -o /dev/null >/dev/null || msg_warn "HMAC 文件上传失败"
      fi
      rm -f "$tmp_hmac"
    fi
  fi

  if [ "$print_json" -eq 1 ]; then
    echo "$response"
    return 0
  fi

  local web_link="" direct_link="" content_id="" name="" file_entry_id=""
  if [ -n "$code" ] && [ -n "$token_out" ]; then
    read -r wt api_server < <(get_config)
    local content_resp _cp
    content_resp="$(content_fetch "$api_server" "$wt" "$token_out" "$code" "")"
    mapfile -t _cp < <(content_parse "$content_resp")
    content_id="${_cp[0]:-}"
    name="${_cp[1]:-}"
    web_link="${_cp[2]:-}"
    if [ -n "$content_resp" ]; then
      file_entry_id="$(printf '%s' "$(content_list_files "$content_resp" | head -n1)" | cut -f1)"
    fi
  fi

  if [ "$want_direct" -eq 1 ]; then
    if [ -z "$token_out" ]; then
      msg_warn "生成直链需要 Token"
    else
      read -r wt api_server < <(get_config)
      target_id="${file_id:-$file_entry_id}"
      if [ -n "$target_id" ]; then
        dl_resp="$(directlink_create "$api_server" "$token_out" "$target_id")"
        direct_link="$(directlink_extract "$dl_resp")"
        if [ -z "$direct_link" ]; then
          msg_warn "直链不可用（需要 Premium Token）"
        fi
      fi
    fi
  fi

  echo -e "${C_GREEN}下载页:${C_RESET} $download"
  [ -n "$web_link" ] && echo -e "${C_GREEN}网页链接:${C_RESET} $web_link"
  [ -n "$direct_link" ] && echo -e "${C_GREEN}直链:${C_RESET} $direct_link"
  [ -n "$token_out" ] && echo -e "${C_CYAN}Token:${C_RESET} $token_out"
  [ -n "$file_id" ] && echo -e "${C_CYAN}文件ID:${C_RESET} $file_id"
  [ -n "$code" ] && echo -e "${C_CYAN}Code:${C_RESET} $code"
  if [ "$encrypt" -eq 1 ] && [ "$enc_show" -eq 1 ]; then
    echo -e "${C_CYAN}加密密码:${C_RESET} $enc_pass"
    echo -e "${C_CYAN}加密算法:${C_RESET} $enc_cipher"
    if [ "$enc_hmac" -eq 1 ]; then
      echo -e "${C_CYAN}完整性校验:${C_RESET} HMAC-SHA256 (文件名后缀 .hmac)"
    fi
    if [ -n "$code" ]; then
      local dl_cmd
      dl_cmd="./gofile.sh download --all --dec-pass '$enc_pass' --dec-cipher $enc_cipher"
      [ "$enc_hmac" -eq 1 ] && dl_cmd="$dl_cmd --dec-hmac"
      dl_cmd="$dl_cmd https://gofile.io/d/${code}"
      echo -e "${C_CYAN}下载解密命令:${C_RESET} $dl_cmd"
    fi
  fi

  if [ "$no_manifest" -eq 0 ]; then
    manifest_add "$file" "$file_size" "$download" "$direct_link" "$token_out" "$code" "$file_id" "$content_id"
  fi
}

cmd_direct() {
  local input="" token="${GOFILE_TOKEN:-}" wt="${GOFILE_WT:-}" api_server="${GOFILE_API_SERVER:-}" password="${GOFILE_PASSWORD:-}"
  local print_json=0 first_only=0 want_direct=0

  while [ $# -gt 0 ]; do
    case "$1" in
      -t|--token) token="$2"; shift 2;;
      -w|--wt) wt="$2"; shift 2;;
      -a|--api-server) api_server="$2"; shift 2;;
      -p|--password) password="$2"; shift 2;;
      --direct) want_direct=1; shift;;
      --json) print_json=1; shift;;
      --first) first_only=1; shift;;
      -h|--help)
        cat <<'USAGE'
用法: gofile.sh direct [选项] <分享链接或Code>

选项:
  -t, --token TOKEN       账号/访客 Token (可选)
  -w, --wt WT             网站令牌 (可选)
  -a, --api-server HOST   API 服务器 (默认自动识别，或 "api")
  -p, --password PASS     受保护链接密码
  --direct                生成 Premium 直链 (需要 Premium Token)
  --json                  输出原始 JSON
  --first                 仅输出第一个文件
USAGE
        return 0;;
      --) shift; break;;
      -*) fatal "未知参数: $1";;
      *) if [ -z "$input" ]; then input="$1"; shift; else fatal "多余参数: $1"; fi;;
    esac
  done

  [ -n "$input" ] || fatal "请提供分享链接或 Code"
  ensure_deps curl jq

  local code
  code="$(extract_code "$input")"
  [ -n "$code" ] || fatal "无法解析 Code"

  api_server="${api_server:-api}"
  if [ -z "$wt" ]; then
    read -r wt api_server < <(get_config)
  fi

  if [ -z "$token" ]; then
    if [ "$want_direct" -eq 1 ]; then
      fatal "直链需要 Premium Token"
    fi
    token="$(create_guest_token "$api_server")"
  fi
  [ -n "$token" ] || fatal "获取 Token 失败"

  local content_resp
  content_resp="$(content_fetch "$api_server" "$wt" "$token" "$code" "$password")"

  if [ "$print_json" -eq 1 ]; then
    echo "$content_resp"
    return 0
  fi
  if [ "$want_direct" -eq 1 ]; then
    files="$(content_list_files "$content_resp")"
    if [ -z "$files" ]; then
      fatal "未找到文件"
    fi
    while IFS=$'\t' read -r fid name link size; do
      [ -n "$fid" ] || continue
      dl_resp="$(directlink_create "$api_server" "$token" "$fid")"
      dl_link="$(directlink_extract "$dl_resp")"
      if [ -n "$dl_link" ]; then
        echo -e "${name}\t${dl_link}"
      else
        msg_warn "直链不可用（需要 Premium Token）"
      fi
      if [ "$first_only" -eq 1 ]; then
        break
      fi
    done
    return 0
  fi

  msg_warn "提示: 网页链接可能会跳转；要真正直链请使用 --direct 且提供 Premium Token。"
  local lines
  lines="$(content_list_files "$content_resp")"
  if [ -z "$lines" ]; then
    msg_err "未找到链接"
    return 1
  fi
  while IFS=$'\t' read -r fid name link size; do
    [ -n "$link" ] || continue
    echo -e "${name}\t${link}"
    if [ "$first_only" -eq 1 ]; then
      break
    fi
  done <<< "$lines"
}

cmd_download() {
  local input="" token="${GOFILE_TOKEN:-}" wt="${GOFILE_WT:-}" api_server="${GOFILE_API_SERVER:-}" password="${GOFILE_PASSWORD:-}"
  local outdir="." outdir_set=0 name="" fid="" all=0 direct=0 resume=1 no_progress=0
  local decrypt=0 dec_pass="" dec_cipher="" dec_cipher_user=0 dec_hmac=0

  while [ $# -gt 0 ]; do
    case "$1" in
      -t|--token) token="$2"; shift 2;;
      -w|--wt) wt="$2"; shift 2;;
      -a|--api-server) api_server="$2"; shift 2;;
      -p|--password) password="$2"; shift 2;;
      -o|--out) outdir="$2"; outdir_set=1; shift 2;;
      --name) name="$2"; shift 2;;
      --id) fid="$2"; shift 2;;
      --all) all=1; shift;;
      --direct) direct=1; shift;;
      --resume) resume=1; shift;;
      --no-resume) resume=0; shift;;
      --no-progress) no_progress=1; shift;;
      --decrypt) decrypt=1; shift;;
      --dec-pass) dec_pass="$2"; shift 2;;
      --dec-cipher) dec_cipher="$2"; dec_cipher_user=1; shift 2;;
      --dec-hmac) dec_hmac=1; shift;;
      -h|--help)
        cat <<'USAGE'
用法: gofile.sh download [选项] <分享链接或Code>

选项:
  -t, --token TOKEN       账号/访客 Token (可选；直链需要 Premium Token)
  -w, --wt WT             网站令牌 (可选)
  -a, --api-server HOST   API 服务器 (默认自动识别，或 "api")
  -p, --password PASS     受保护链接密码
  -o, --out DIR           输出目录 (默认当前目录)
  --name 文件名           指定下载文件名（可选；不指定则交互选择）
  --id 文件ID             指定文件ID（可选；不指定则交互选择）
  --all                   下载全部文件
  --direct                使用 Premium 直链下载（推荐）
  --resume                断点续传（默认开启）
  --no-resume             关闭断点续传
  --no-progress           关闭进度显示
  --decrypt               下载后解密（默认 AES-256-CBC + PBKDF2）
  --dec-pass PASS         解密密码（设置后自动解密）
  --dec-cipher CIPHER     指定解密算法（默认自动选择）
  --dec-hmac              校验 HMAC 完整性（需先下载 .hmac 文件）
USAGE
        return 0;;
      --) shift; break;;
      -*) fatal "未知参数: $1";;
      *) if [ -z "$input" ]; then input="$1"; shift; else fatal "多余参数: $1"; fi;;
    esac
  done

  [ -n "$input" ] || fatal "请提供分享链接或 Code"
  ensure_deps curl jq

  local code
  code="$(extract_code "$input")"
  [ -n "$code" ] || fatal "无法解析 Code"

  api_server="${api_server:-api}"
  if [ -z "$wt" ]; then
    read -r wt api_server < <(get_config)
  fi

  if [ -z "$token" ]; then
    if [ "$direct" -eq 1 ]; then
      fatal "使用 --direct 需要 Premium Token"
    fi
    token="$(create_guest_token "$api_server")"
  fi
  [ -n "$token" ] || fatal "获取 Token 失败"

  if [ -n "$dec_pass" ]; then
    decrypt=1
  fi

  if [ "$decrypt" -eq 1 ]; then
    ensure_deps openssl
    if [ -z "$dec_pass" ]; then
      printf "%s请输入解密密码:%s " "$C_BLUE" "$C_RESET" >&2
      read -r -s dec_pass
      echo >&2
    fi
    [ -n "$dec_pass" ] || fatal "解密密码不能为空"
    if [ -z "$dec_cipher" ]; then
      dec_cipher="$(default_cipher)"
    fi
    if ! openssl_cipher_supported "$dec_cipher"; then
      if [ "$dec_cipher_user" -eq 1 ]; then
        msg_warn "不支持算法 $dec_cipher，已改用 aes-256-cbc"
      fi
      dec_cipher="aes-256-cbc"
    fi
    if [ "$dec_hmac" -eq 1 ]; then
      ensure_deps xxd
    fi
    resume=0
  fi

  local content_resp
  content_resp="$(content_fetch "$api_server" "$wt" "$token" "$code" "$password")"

  local files all_files
  all_files="$(content_list_files "$content_resp")"
  files=""
  if [ "$all" -eq 1 ] || [ -n "$name" ] || [ -n "$fid" ]; then
    files="$(content_select_files "$content_resp" "$name" "$fid" "$all")"
  else
    if [ -z "$all_files" ]; then
      fatal "未匹配到任何文件"
    fi
    mapfile -t lines <<< "$all_files"
    echo -e "${C_BOLD}可下载文件列表（共 ${#lines[@]} 个）:${C_RESET}" >&2
    idx=1
    for line in "${lines[@]}"; do
      IFS=$'\t' read -r fid_line name_line link_line size_line <<< "$line"
      size_show="$(awk -v b="${size_line:-0}" 'BEGIN{
        s=b+0; u="B";
        if (s>=1024){s/=1024;u="KB"}
        if (s>=1024){s/=1024;u="MB"}
        if (s>=1024){s/=1024;u="GB"}
        printf "%.2f %s", s, u
      }')"
      printf "  %s%2d)%s %s%s%s  %s(%s)%s\n" \
        "$C_CYAN" "$idx" "$C_RESET" \
        "$C_GREEN" "$name_line" "$C_RESET" \
        "$C_YELLOW" "$size_show" "$C_RESET" >&2
      idx=$((idx+1))
    done

    echo -e "${C_BOLD}选择文件:${C_RESET} 输入序号（可逗号分隔，如 1,3,5）；" >&2
    echo -e "          输入 ${C_YELLOW}a${C_RESET} 下载全部，${C_YELLOW}q${C_RESET} 取消。" >&2
    printf "%s> %s" "$C_BLUE" "$C_RESET" >&2
    read -r selection
    selection="$(printf '%s' "$selection" | tr ' ' '\n' | tr -d '\n')"
    if [ -z "$selection" ]; then
      fatal "未选择任何文件"
    fi
    if [ "$selection" = "q" ] || [ "$selection" = "Q" ]; then
      msg_warn "已取消"
      return 0
    fi
    if [ "$selection" = "a" ] || [ "$selection" = "A" ] || [ "$selection" = "all" ]; then
      files="$all_files"
    else
      IFS=',' read -r -a picks <<< "$selection"
      mapfile -t lines <<< "$all_files"
      for p in "${picks[@]}"; do
        p="$(printf '%s' "$p" | tr -d ' ')"
        if ! printf '%s' "$p" | grep -Eq '^[0-9]+$'; then
          fatal "无效序号: $p"
        fi
        if [ "$p" -le 0 ] || [ "$p" -gt "${#lines[@]}" ]; then
          fatal "序号超出范围: $p"
        fi
        files+="${lines[$((p-1))]}\n"
      done
      files="$(printf '%b' "$files")"
    fi
  fi

  if [ -z "$files" ]; then
    msg_warn "未匹配到文件。可用文件列表："
    content_list_files "$content_resp" | awk -F'\t' '{printf "ID: %s  名称: %s  大小: %s\\n",$1,$2,$4}'
    return 1
  fi

  local file_count
  file_count="$(printf '%s\n' "$files" | awk 'NF{c++} END{print c+0}')"
  if [ "$file_count" -gt 1 ] && [ "$outdir_set" -eq 0 ]; then
    outdir="./gofile-${code}"
  fi
  mkdir -p "$outdir"

  download_raw() {
    local name="$1" url="$2" out="$3"
    local tmp="${out}.part"
    local info http_code content_type
    local curl_args=( -L -A "$USER_AGENT" -e "https://gofile.io/d/$code"
      -H "Authorization: Bearer ${token}" -b "accountToken=${token}" "$url" )
    [ "$no_progress" -eq 1 ] && curl_args+=( -sS )
    info="$(curl "${curl_args[@]}" -o "$tmp" -w '%{http_code} %{content_type}' || true)"
    http_code="$(printf '%s' "$info" | awk '{print $1}')"
    content_type="$(printf '%s' "$info" | awk '{print $2}')"
    if [ -z "$http_code" ] || [ "$http_code" -ge 400 ] || [[ "$content_type" == text/html* ]]; then
      rm -f "$tmp"
      return 1
    fi
    mv -f "$tmp" "$out"
    return 0
  }

  local cleanup_hmac_files=()
  if [ "$dec_hmac" -eq 1 ]; then
    while IFS=$'\t' read -r file_id file_name file_link file_size; do
      [[ "$file_name" == *.hmac ]] || continue
      local hmac_path="${outdir%/}/$file_name"
      if [ -f "$hmac_path" ]; then
        continue
      fi
      msg_info "预下载 HMAC: $file_name"
      if download_raw "$file_name" "$file_link" "$hmac_path"; then
        cleanup_hmac_files+=("$hmac_path")
      else
        msg_warn "HMAC 下载失败: $file_name"
      fi
    done <<< "$all_files"
  fi

  while IFS=$'\t' read -r file_id file_name file_link file_size; do
    [ -n "$file_id" ] || continue
    local url="$file_link"
    if [ "$direct" -eq 1 ]; then
      dl_resp="$(directlink_create "$api_server" "$token" "$file_id")"
      url="$(directlink_extract "$dl_resp")"
      if [ -z "$url" ]; then
        msg_warn "直链不可用（需要 Premium Token）: $file_name"
        continue
      fi
    else
      msg_warn "提示: 网页链接可能会跳转为下载页；如需稳定下载请使用 --direct。"
    fi

    local out_path="${outdir%/}/$file_name"
    local tmp_path="${out_path}.part"

    if [ -f "$out_path" ] && [ -n "$file_size" ] && [ "$file_size" -gt 0 ]; then
      local exist_size
      exist_size="$(stat -c%s "$out_path" 2>/dev/null || wc -c <"$out_path")"
      if [ "$exist_size" -eq "$file_size" ]; then
        msg_warn "已存在，跳过: $out_path"
        continue
      fi
    fi

    local is_hmac=0
    if [[ "$file_name" == *.hmac ]]; then
      is_hmac=1
    fi

    if [ "$decrypt" -eq 1 ] && [ "$is_hmac" -eq 0 ]; then
      local out_dec="$out_path"
      if [[ "$file_name" == *.enc ]]; then
        out_dec="${outdir%/}/${file_name%.enc}"
      else
        out_dec="${outdir%/}/${file_name}.dec"
      fi
      local tmp_dec="${out_dec}.part"
    if [ -f "$out_dec" ]; then
      msg_warn "已存在，跳过: $out_dec"
      continue
    fi
    local curl_args=( -L -A "$USER_AGENT" -e "https://gofile.io/d/$code"
      -H "Authorization: Bearer ${token}" -b "accountToken=${token}" "$url" )
    [ "$no_progress" -eq 1 ] && curl_args+=( -sS )
      if [ "$dec_hmac" -eq 1 ]; then
        local hmac_file expected_hmac actual_hmac
        hmac_file="${outdir%/}/${file_name}.hmac"
        if [ ! -f "$hmac_file" ]; then
          msg_err "缺少 HMAC 文件: $hmac_file"
          continue
        fi
        OPENSSL_PASS="$dec_pass" curl "${curl_args[@]}" | \
          env OPENSSL_PASS="$dec_pass" openssl enc -d -"${dec_cipher}" -salt -pbkdf2 -iter 200000 -md sha256 \
          -pass env:OPENSSL_PASS -out "$tmp_dec"
        if [ $? -ne 0 ]; then
          rm -f "$tmp_dec"
          msg_err "解密失败（可能直链失效或密码错误）: $file_name"
          continue
        fi
        expected_hmac="$(cat "$hmac_file" | tr -d '\r\n')"
        HMAC_KEY="$(derive_hmac_key "$dec_pass")" \
          actual_hmac="$(openssl dgst -sha256 -hmac "$HMAC_KEY" -binary "$tmp_dec" | xxd -p -c 256)"
        if [ -z "$expected_hmac" ] || [ "$expected_hmac" != "$actual_hmac" ]; then
          rm -f "$tmp_dec"
          msg_err "HMAC 校验失败: $file_name"
          continue
        fi
      else
        OPENSSL_PASS="$dec_pass" curl "${curl_args[@]}" | \
          env OPENSSL_PASS="$dec_pass" openssl enc -d -"${dec_cipher}" -salt -pbkdf2 -iter 200000 -md sha256 \
          -pass env:OPENSSL_PASS -out "$tmp_dec"
      fi
      if [ $? -ne 0 ]; then
        rm -f "$tmp_dec"
        msg_err "解密失败（可能直链失效或密码错误）: $file_name"
        continue
      fi
      mv -f "$tmp_dec" "$out_dec"
      msg_ok "已解密下载: $out_dec"
      continue
    fi

    if [ "$decrypt" -eq 1 ] && [ "$is_hmac" -eq 1 ]; then
      msg_warn "检测到 .hmac 文件，跳过解密: $file_name"
    fi

    local curl_resume=()
    if [ "$resume" -eq 1 ]; then
      curl_resume+=( -C - )
    fi

    local info
    if [ "$no_progress" -eq 1 ]; then
      info="$(curl -L -sS -A "$USER_AGENT" -e "https://gofile.io/d/$code" \
        -H "Authorization: Bearer ${token}" -b "accountToken=${token}" \
        "${curl_resume[@]}" -o "$tmp_path" -w '%{http_code} %{content_type}' "$url")"
    else
      info="$(curl -L -A "$USER_AGENT" -e "https://gofile.io/d/$code" \
        -H "Authorization: Bearer ${token}" -b "accountToken=${token}" \
        "${curl_resume[@]}" -o "$tmp_path" -w '%{http_code} %{content_type}' "$url")"
    fi
    local http_code content_type
    http_code="$(printf '%s' "$info" | awk '{print $1}')"
    content_type="$(printf '%s' "$info" | awk '{print $2}')"

    if [ "$http_code" -ge 400 ]; then
      msg_err "下载失败($http_code): $file_name"
      rm -f "$tmp_path"
      continue
    fi
    local actual_size
    actual_size="$(stat -c%s "$tmp_path" 2>/dev/null || wc -c <"$tmp_path")"
    local bad=0
    if [[ "$content_type" == text/html* ]]; then
      bad=1
    fi
    if [ -n "$file_size" ] && [ "$file_size" -gt 0 ] && [ "$actual_size" -ne "$file_size" ]; then
      bad=1
    fi
    if [ "$bad" -eq 1 ]; then
      local html_path="${out_path}.html"
      mv -f "$tmp_path" "$html_path"
      msg_err "下载失败（可能被跳转到网页）: $file_name 已保存为 $html_path"
      continue
    fi
    mv -f "$tmp_path" "$out_path"
    msg_ok "已下载: $out_path"
  done <<< "$files"

  if [ "$dec_hmac" -eq 1 ] && [ "${#cleanup_hmac_files[@]}" -gt 0 ]; then
    for hf in "${cleanup_hmac_files[@]}"; do
      rm -f "$hf"
    done
    msg_info "已清理本地 HMAC 文件"
  fi
}

cmd_delete() {
  local input="" token="${GOFILE_TOKEN:-}" wt="${GOFILE_WT:-}" api_server="${GOFILE_API_SERVER:-}"
  local no_resolve=0 print_json=0

  while [ $# -gt 0 ]; do
    case "$1" in
      -t|--token) token="$2"; shift 2;;
      -w|--wt) wt="$2"; shift 2;;
      -a|--api-server) api_server="$2"; shift 2;;
      --no-resolve) no_resolve=1; shift;;
      --json) print_json=1; shift;;
      -h|--help)
        cat <<'USAGE'
用法: gofile.sh delete [选项] <code|链接|content_id|清单序号>

选项:
  -t, --token TOKEN       API Token (可选；若不传将尝试从清单读取)
  -w, --wt WT             网站令牌 (可选)
  -a, --api-server HOST   API 服务器 (默认自动识别，或 "api")
  --no-resolve            不解析分享 Code 到内部 UUID
  --json                  输出完整 JSON
  (不传参数将进入交互式选择)
USAGE
        return 0;;
      --) shift; break;;
      -*) fatal "未知参数: $1";;
      *) if [ -z "$input" ]; then input="$1"; shift; else fatal "多余参数: $1"; fi;;
    esac
  done

  ensure_deps curl jq

  if [ -z "$input" ]; then
    local m
    m="$(manifest_path)"
    [ -f "$m" ] || { msg_warn "清单不存在: $m"; return 0; }
    mapfile -t entries < <(jq -c -s '.[]' "$m")
    if [ "${#entries[@]}" -eq 0 ]; then
      msg_warn "清单为空"
      return 0
    fi
    echo -e "${C_BOLD}可删除列表（共 ${#entries[@]} 条）:${C_RESET}" >&2
    idx=1
    for entry in "${entries[@]}"; do
      code="$(printf '%s' "$entry" | jq -r '.code // ""')"
      file="$(printf '%s' "$entry" | jq -r '.file // ""')"
      ts="$(printf '%s' "$entry" | jq -r '.created_at // 0')"
      date="$(date -d "@${ts}" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "-")"
      printf "  %s%2d)%s %s%s%s  %s(%s)%s\n" \
        "$C_CYAN" "$idx" "$C_RESET" \
        "$C_GREEN" "${file:-}" "$C_RESET" \
        "$C_YELLOW" "${code:-}" "$C_RESET" >&2
      idx=$((idx+1))
    done
    echo -e "${C_BOLD}选择删除:${C_RESET} 输入序号（可逗号分隔，如 1,3,5）；" >&2
    echo -e "          输入 ${C_YELLOW}a${C_RESET} 删除全部，${C_YELLOW}q${C_RESET} 取消。" >&2
    printf "%s> %s" "$C_BLUE" "$C_RESET" >&2
    read -r selection
    selection="$(printf '%s' "$selection" | tr ' ' '\n' | tr -d '\n')"
    if [ -z "$selection" ]; then
      msg_warn "已取消"
      return 0
    fi
    if [ "$selection" = "q" ] || [ "$selection" = "Q" ]; then
      msg_warn "已取消"
      return 0
    fi
    local picks=()
    if [ "$selection" = "a" ] || [ "$selection" = "A" ] || [ "$selection" = "all" ]; then
      for i in $(seq 1 "${#entries[@]}"); do picks+=("$i"); done
    else
      IFS=',' read -r -a picks <<< "$selection"
    fi
    local args=()
    [ -n "$token" ] && args+=(--token "$token")
    [ -n "$wt" ] && args+=(--wt "$wt")
    [ -n "$api_server" ] && args+=(--api-server "$api_server")
    [ "$no_resolve" -eq 1 ] && args+=(--no-resolve)
    [ "$print_json" -eq 1 ] && args+=(--json)
    for p in "${picks[@]}"; do
      p="$(printf '%s' "$p" | tr -d ' ')"
      if ! printf '%s' "$p" | grep -Eq '^[0-9]+$'; then
        msg_warn "无效序号: $p"
        continue
      fi
      if [ "$p" -le 0 ] || [ "$p" -gt "${#entries[@]}" ]; then
        msg_warn "序号超出范围: $p"
        continue
      fi
      cmd_delete "${args[@]}" "$p"
    done
    return 0
  fi

  local entry_json=""
  if [[ "$input" =~ ^[0-9]+$ ]]; then
    entry_json="$(manifest_find_by_index "$input" || true)"
  fi
  if [ -z "$entry_json" ]; then
    entry_json="$(manifest_find_by_code_or_download "$input" || true)"
  fi

  local code="" content_id="" token_from_manifest="" file_id_from_manifest=""
  if [ -n "$entry_json" ]; then
    mapfile -t _fields < <(printf '%s' "$entry_json" | jq -r '.code//"", .content_id//"", .token//"", .file_id//""' || true)
    code="${_fields[0]:-}"
    content_id="${_fields[1]:-}"
    token_from_manifest="${_fields[2]:-}"
    file_id_from_manifest="${_fields[3]:-}"
    if [ -z "$token_from_manifest" ] && printf '%s' "$file_id_from_manifest" | grep -Eq '^[A-Za-z0-9]{32}$'; then
      token_from_manifest="$file_id_from_manifest"
      msg_warn "清单未记录 Token，已尝试从 file_id 读取 Token"
    fi
  fi

  if [ -z "$code" ]; then
    code="$(extract_code "$input")"
  fi

  if [ -z "$token" ]; then
    token="$token_from_manifest"
  fi
  [ -n "$token" ] || fatal "需要 Token（请传 --token 或确保清单中有记录）"

  api_server="${api_server:-api}"
  if [ -z "$wt" ] && [ "$no_resolve" -eq 0 ]; then
    read -r wt api_server < <(get_config)
  fi

  if [ -z "$content_id" ] && [ "$no_resolve" -eq 0 ]; then
    local resolve_resp
    resolve_resp="$(content_fetch "$api_server" "$wt" "$token" "$code" "")"
    content_id="$(printf '%s' "$resolve_resp" | jq -r 'try (.data.id // "") catch ""' || true)"
  fi

  local delete_id="$content_id"
  if [ -z "$delete_id" ]; then
    delete_id="$code"
  fi

  local payload response
  payload="{\"contentsId\":\"${delete_id}\"}"
  response="$(curl -sS -X DELETE "https://${api_server}.gofile.io/contents" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -d "$payload")"

  if [ "$print_json" -eq 1 ]; then
    echo "$response"
    return 0
  fi

  local status
  status="$(printf '%s' "$response" | jq -r 'try (.status // "") catch ""' || true)"

  [ "$status" = "ok" ] || { echo "$response" >&2; fatal "删除失败"; }
  msg_ok "已删除: $delete_id"

  if [ -n "$code" ]; then
    manifest_remove_by_codes "$code"
  fi
}

cmd_list() {
  ensure_deps jq
  manifest_list
}

cmd_prune() {
  local days=1 dry_run=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --days) days="$2"; shift 2;;
      --dry-run) dry_run=1; shift;;
      -h|--help)
        cat <<'USAGE'
用法: gofile.sh prune [选项]

选项:
  --days N        删除超过 N 天的记录 (默认 1)
  --dry-run       仅显示将要删除的内容
USAGE
        return 0;;
      --) shift; break;;
      -*) fatal "未知参数: $1";;
      *) fatal "多余参数: $1";;
    esac
  done

  ensure_deps curl jq
  local m
  m="$(manifest_path)"
  [ -f "$m" ] || { msg_warn "清单不存在: $m"; return 0; }

  local list api_server wt cutoff
  api_server="${GOFILE_API_SERVER:-api}"
  wt="${GOFILE_WT:-}"
  cutoff=$(( $(date +%s) - days*86400 ))
  list="$(jq -r --argjson cutoff "$cutoff" '
    select((.created_at // 0) <= $cutoff)
    | [(.code // ""), (.content_id // ""), (.token // ""), (.download // ""), (.file // "")] | @tsv
  ' "$m" || true)"

  if [ -z "$list" ]; then
    msg_info "没有超过 ${days} 天的记录"
    return 0
  fi

  local deleted_codes=()
  while IFS=$'\t' read -r code content_id token download file_path; do
    [ -n "$code" ] || continue
    if [ "$dry_run" -eq 1 ]; then
      msg_warn "将删除: $code ($file_path)"
      continue
    fi
    if [ -z "$token" ]; then
      msg_warn "跳过（无 Token）: $code"
      continue
    fi
    if [ -z "$content_id" ]; then
      if [ -z "$wt" ]; then
        read -r wt api_server < <(get_config)
      fi
      resolve_resp="$(content_fetch "$api_server" "$wt" "$token" "$code" "")"
      content_id="$(printf '%s' "$resolve_resp" | jq -r 'try (.data.id // "") catch ""' || true)"
    fi
    delete_id="$content_id"
    [ -n "$delete_id" ] || delete_id="$code"
    resp="$(curl -sS -X DELETE "https://${api_server}.gofile.io/contents" -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" -d "{\"contentsId\":\"${delete_id}\"}")"
    status="$(printf '%s' "$resp" | jq -r 'try (.status // "") catch ""' || true)"
    if [ "$status" = "ok" ]; then
      msg_ok "已删除: $code"
      deleted_codes+=("$code")
    else
      msg_err "删除失败: $code"
    fi
  done <<< "$list"

  if [ "$dry_run" -eq 0 ] && [ ${#deleted_codes[@]} -gt 0 ]; then
    local csv
    csv="$(IFS=,; echo "${deleted_codes[*]}")"
    manifest_remove_by_codes "$csv"
  fi
}

cmd_speedtest() {
  local size_mb=10 sort_by_speed=0 ask=1 mode="both"
  while [ $# -gt 0 ]; do
    case "$1" in
      --size) size_mb="$2"; shift 2;;
      --sort) sort_by_speed=1; shift;;
      --upload) mode="upload"; shift;;
      --download) mode="download"; shift;;
      --both) mode="both"; shift;;
      --no-ask) ask=0; shift;;
      -h|--help)
        cat <<'USAGE'
用法: gofile.sh speedtest [选项]

选项:
  --size MB       上传测试文件大小 (默认 10MB)
  --sort          按速度排序
  --upload        仅测速上传
  --download      仅测速下载
  --both          同时测速上传与下载 (默认)
  --no-ask        不询问是否设置默认区域
USAGE
        return 0;;
      --) shift; break;;
      -*) fatal "未知参数: $1";;
      *) fatal "多余参数: $1";;
    esac
  done

  ensure_deps curl jq
  [ "$size_mb" -gt 0 ] 2>/dev/null || fatal "无效 --size: $size_mb"
  local tmp_file
  tmp_file="$(mktemp)"
  dd if=/dev/zero of="$tmp_file" bs=1M count="$size_mb" status=none

  local default_region="${GOFILE_REGION:-}"
  [ -n "$default_region" ] || default_region="$(config_get REGION)"

  local wt api_server
  read -r wt api_server < <(get_config)
  if [ "$mode" = "download" ]; then
    msg_info "开始测速 (${size_mb}MB 下载，需先上传测试文件)，当前默认 region: ${default_region:-auto}"
  elif [ "$mode" = "both" ]; then
    msg_info "开始测速 (${size_mb}MB 上传+下载)，当前默认 region: ${default_region:-auto}"
  else
    msg_info "开始测速 (${size_mb}MB 上传)，当前默认 region: ${default_region:-auto}"
  fi
  local results=()
  while IFS= read -r region; do
    [ -n "$region" ] || continue
    endpoint="$(region_endpoint "$region")" || { msg_warn "未知 region: $region"; continue; }
    printf "%s%-8s%s " "$C_CYAN" "$region" "$C_RESET"
    local resp speed_up json status download code parent_code guest_token token auth_token
    local file_id server name parent_folder link speed_down
    token=""
    if [ "$mode" != "upload" ]; then
      token="$(create_guest_token "$api_server" || true)"
    fi
    local upload_args=(-sS -w '\n%{speed_upload}' -X POST "$endpoint" -F "file=@$tmp_file")
    [ -n "$token" ] && upload_args+=( -H "Authorization: Bearer $token" )
    resp="$(curl "${upload_args[@]}" || true)"
    speed_up="$(printf '%s' "$resp" | tail -n1 | tr -d '\r')"
    json="$(printf '%s' "$resp" | sed '$d')"
    speed_up="${speed_up:-0}"
    if [ "$mode" = "upload" ]; then
      speed_fmt="$(fmt_speed "$speed_up")"
      printf "%s\n" "$speed_fmt"
      results+=("${region}"$'\t'"${speed_up}"$'\t'"0")
      continue
    fi

    status="$(printf '%s' "$json" | jq -r 'try (.status // "") catch ""' || true)"
    download="$(printf '%s' "$json" | jq -r 'try (.data.downloadPage // "") catch ""' || true)"
    code="$(printf '%s' "$json" | jq -r 'try (.data.code // "") catch ""' || true)"
    parent_code="$(printf '%s' "$json" | jq -r 'try (.data.parentFolderCode // "") catch ""' || true)"
    guest_token="$(printf '%s' "$json" | jq -r 'try (.data.guestToken // "") catch ""' || true)"
    file_id="$(printf '%s' "$json" | jq -r 'try (.data.id // "") catch ""' || true)"
    server="$(printf '%s' "$json" | jq -r 'try (.data.servers[0] // "") catch ""' || true)"
    name="$(printf '%s' "$json" | jq -r 'try (.data.name // "") catch ""' || true)"
    parent_folder="$(printf '%s' "$json" | jq -r 'try (.data.parentFolder // "") catch ""' || true)"
    if [ -z "$code" ]; then
      code="$parent_code"
    fi
    if [ -z "$code" ] && [ -n "$download" ]; then
      code="$(extract_code "$download")"
    fi
    if [ -n "$guest_token" ]; then
      auth_token="$guest_token"
    else
      auth_token="$token"
    fi
    if [ "$status" != "ok" ] || [ -z "$auth_token" ]; then
      if [ "$mode" = "download" ]; then
        printf "%s\n" "N/A"
      else
        printf "%s | %s\n" "$(fmt_speed "$speed_up")" "N/A"
      fi
      results+=("${region}"$'\t'"${speed_up}"$'\t'"0")
      continue
    fi

    link=""
    content_id=""
    if [ -n "$code" ]; then
      local content_resp _cp
      for _ in 1 2 3 4 5; do
        content_resp="$(content_fetch "$api_server" "$wt" "$auth_token" "$code" "")"
        mapfile -t _cp < <(content_parse "$content_resp")
        content_id="${_cp[0]:-}"
        name="${_cp[1]:-}"
        link="${_cp[2]:-}"
        [ -n "$link" ] && break
        sleep 0.3
      done
    fi

    if [ -z "$link" ] && [ -n "$server" ] && [ -n "$file_id" ] && [ -n "$name" ]; then
      link="https://${server}.gofile.io/download/web/${file_id}/${name}"
      [ -n "$content_id" ] || content_id="$parent_folder"
    fi
    if [ -n "$link" ]; then
      local referer
      referer="${download:-}"
      [ -n "$referer" ] || referer="https://gofile.io/d/${code}"
      speed_down="$(curl -L -sS -o /dev/null -w '%{speed_download}' \
        -A "$USER_AGENT" -e "$referer" \
        -H "Authorization: Bearer ${auth_token}" -b "accountToken=${auth_token}" \
        "$link" || true)"
    else
      speed_down="0"
    fi

    if [ "$mode" = "download" ]; then
      if [ -n "$link" ]; then
        printf "%s\n" "$(fmt_speed "$speed_down")"
      else
        printf "%s\n" "N/A"
      fi
    else
      if [ -n "$link" ]; then
        printf "%s | %s\n" "$(fmt_speed "$speed_up")" "$(fmt_speed "$speed_down")"
      else
        printf "%s | %s\n" "$(fmt_speed "$speed_up")" "N/A"
      fi
    fi
    results+=("${region}"$'\t'"${speed_up}"$'\t'"${speed_down}")

    if [ -n "$content_id" ]; then
      curl -sS -X DELETE "https://${api_server}.gofile.io/contents" \
        -H "Authorization: Bearer ${auth_token}" \
        -H "Content-Type: application/json" \
        -d "{\"contentsId\":\"${content_id}\"}" >/dev/null || true
    fi
  done < <(region_list)

  rm -f "$tmp_file"

  local lines
  if [ "$sort_by_speed" -eq 1 ]; then
    if [ "$mode" = "download" ]; then
      lines="$(printf '%s\n' "${results[@]}" | sort -t$'\t' -k3,3nr)"
    else
      lines="$(printf '%s\n' "${results[@]}" | sort -t$'\t' -k2,2nr)"
    fi
  else
    lines="$(printf '%s\n' "${results[@]}")"
  fi

  echo -e "${C_BOLD}测速结果:${C_RESET}"
  while IFS=$'\t' read -r region speed_up speed_down; do
    [ -n "$region" ] || continue
    if [ "$mode" = "download" ]; then
      if [ "${speed_down:-0}" -gt 0 ] 2>/dev/null; then
        printf "  %s%-8s%s %s\n" "$C_GREEN" "$region" "$C_RESET" "$(fmt_speed "$speed_down")"
      else
        printf "  %s%-8s%s %s\n" "$C_GREEN" "$region" "$C_RESET" "N/A"
      fi
    elif [ "$mode" = "both" ]; then
      local down_show
      if [ "${speed_down:-0}" -gt 0 ] 2>/dev/null; then
        down_show="$(fmt_speed "$speed_down")"
      else
        down_show="N/A"
      fi
      printf "  %s%-8s%s 上:%s  下:%s\n" "$C_GREEN" "$region" "$C_RESET" "$(fmt_speed "$speed_up")" "$down_show"
    else
      printf "  %s%-8s%s %s\n" "$C_GREEN" "$region" "$C_RESET" "$(fmt_speed "$speed_up")"
    fi
  done <<< "$lines"

  if [ "$ask" -eq 1 ]; then
    local best_region best_non_auto sort_key
    if [ "$mode" = "download" ]; then
      sort_key="3"
    else
      sort_key="2"
    fi
    best_region="$(printf '%s\n' "${results[@]}" | sort -t$'\t' -k"${sort_key}","${sort_key}"nr | head -n1 | cut -f1)"
    best_non_auto="$(printf '%s\n' "${results[@]}" | sort -t$'\t' -k"${sort_key}","${sort_key}"nr | awk -F'\t' '$1!="auto"{print $1; exit}')"
    [ -n "$best_region" ] || return 0
    if [ -z "$best_non_auto" ]; then
      echo -e "${C_BOLD}可设置默认 region: ${C_YELLOW}${best_region}${C_RESET}"
    else
      echo -e "${C_BOLD}可设置默认 region: ${C_YELLOW}${best_non_auto}${C_RESET} 或 ${C_YELLOW}auto${C_RESET}"
    fi
    printf "%s输入 region (回车跳过): %s" "$C_BLUE" "$C_RESET"
    read -r choice
    choice="${choice// /}"
    if [ -z "$choice" ]; then
      return 0
    fi
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
      choice="$best_region"
    fi
    if [ "$choice" = "auto" ] || grep -qx "$choice" < <(region_list); then
      config_set REGION "$choice"
      msg_ok "已设置默认 region: $choice (配置: $(config_path))"
    else
      msg_warn "无效 region: $choice"
    fi
  fi
}

cmd="${1:-}"
case "${cmd:-}" in
  upload) shift; cmd_upload "$@";;
  direct) shift; cmd_direct "$@";;
  download) shift; cmd_download "$@";;
  delete) shift; cmd_delete "$@";;
  list) shift; cmd_list "$@";;
  prune) shift; cmd_prune "$@";;
  speedtest) shift; cmd_speedtest "$@";;
  -h|--help|help|"") usage;;
  *) fatal "未知命令: $cmd";;
esac
