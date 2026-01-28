#!/bin/bash
# ==============================================================================
# 自动化初始化脚本 v2.4 (Fix: Restore fuse3 to prevent system removal)
# ==============================================================================

# ------------------------------------------------------------------------------
# 0. 全局设置 & 提前配置中文环境
# ------------------------------------------------------------------------------
set -Eeuo pipefail
trap 'echo "❌ [ERROR] 脚本执行失败，错误行号: $LINENO" >&2' ERR

if [[ $EUID -ne 0 ]]; then
   echo "🛑 必须使用 Root 权限运行此脚本 (sudo -i)" 
   exit 1
fi

# 彻底的非交互设置 (防止 dpkg 弹窗)
export DEBIAN_FRONTEND=noninteractive
export APT_OPTS="-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"

# >>> [Step 0] 优先配置中文环境 <<<
echo ">> [Step 0] 正在优先配置中文环境..."
apt-get update -qq

if [ -f /etc/os-release ]; then
    . /etc/os-release
else
    ID=$(uname -s)
fi

if [[ "$ID" == "ubuntu" ]]; then
    apt-get install -y -qq $APT_OPTS language-pack-zh-hans
    locale-gen zh_CN.UTF-8
elif [[ "$ID" == "debian" ]]; then
    apt-get install -y -qq $APT_OPTS locales fonts-wqy-zenhei
    sed -i 's/^# zh_CN.UTF-8/zh_CN.UTF-8/' /etc/locale.gen
    sed -i 's/^# en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen
    locale-gen
fi

export LANG=zh_CN.UTF-8
export LC_ALL=zh_CN.UTF-8
update-locale LANG=zh_CN.UTF-8

sed -i '/export LANG=/d' "$HOME/.bashrc"
echo "export LANG=zh_CN.UTF-8" >> "$HOME/.bashrc"
echo "export LC_ALL=zh_CN.UTF-8" >> "$HOME/.bashrc"

echo "✅ 中文环境配置完成。"

# ------------------------------------------------------------------------------
# 1. 用户配置 (SSH/Keys)
# ------------------------------------------------------------------------------
SSH_PORT=3927

# ⚠️⚠️⚠️ 请在此替换你的公钥 ⚠️⚠️⚠️
MY_SSH_KEYS="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCfuo9/cfgAHy8HYEGVxY+wklHlnrAQ0bPsz6FcAahXQXqw7OdrBzFpkh4U0a7f/Ir0BVgzeYIdDIOL8Ow9Ko1UHldJRCFyy/9W8ji2MGF2YgOUMxmxrCOD1DeOOh04Xrjqx5kPxiscHDZIZEuUF6eM20h3HR+D4xN/3H0OYRkMAaUrSoR8QZVg5P5QSni+HOT6JPHfk7rocKnk/0aQbLPMhSCLjAP4iyM9Fhotn6ofjw9aJnxp/agjwvJPkYSCmC5LJY8Mrv3Xpl4/cjknN0NbxMLUEhXXPDvGnPdS+KSAfpoHDTpm2Zi/WuVtf7AUP0ao0OnWbiPpQcvlEzxXhAm88ipzlY8n4mUnkyR7wIn6nf8y3HeOo8RVwjXWxsc6hNh6gPmNMlJeJo9FGMDxmriX/dRaAqsoYMRtxW3TNxMkfLXKTGs3ykEb/H/WXirwAPpHnSxbCY9/JVvfQMYDctZO+bZ3NV6Nvv5d2ATjq+1FWWaIq6vNkgMQKqs4mxw5CZUGnx4Zd6DMM1VkfA4W3hiNedoFyhSaQWVucza2gdHT7MPDJxNV6TNJErjo6wiobHOXyWghop4UjO32MMhRWyKAhdn3iCIPUglLloEEpvYI0b/TTd5ZdobHAjh+smX9mlIJe3yaQSPlA4sp6MPOjGhC/r08u+6hkmjE1Ycmgw7W7Q== JuiceSSH"

# ------------------------------------------------------------------------------
# 2. Tmux 挂载
# ------------------------------------------------------------------------------
function command_exists() { command -v "$1" >/dev/null 2>&1; }

function append_if_missing() {
    local file="$1"
    local content="$2"
    if [ ! -f "$file" ]; then touch "$file"; fi
    if ! grep -qF "$content" "$file"; then
        echo "$content" >> "$file"
    fi
    return 0
}

if [[ -z "${TMUX:-}" ]]; then
    echo ">> [Step 1] 检测 Tmux..."
    if ! command_exists tmux; then
        apt-get install -y -qq $APT_OPTS tmux
    fi

    SESSION_NAME="init_session"
    if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
        echo "✅ 会话已存在，正在接入..."
        exec tmux attach -t "$SESSION_NAME"
    fi

    CURRENT_SCRIPT="$0"
    if [[ "$0" == "bash" ]] || [[ "$0" == "-bash" ]] || [[ ! -f "$0" ]]; then
        cat > /tmp/init_script.sh <<EOF
$(cat)
EOF
        CURRENT_SCRIPT="/tmp/init_script.sh"
        chmod +x "$CURRENT_SCRIPT"
    else
        CURRENT_SCRIPT=$(realpath "$0")
    fi

    echo ">> 进入 Tmux 后台运行..."
    exec tmux new-session -s "$SESSION_NAME" "/bin/bash '$CURRENT_SCRIPT'; exec /bin/bash"
fi

# ==============================================================================
# Tmux 会话内逻辑
# ==============================================================================

# ------------------------------------------------------------------------------
# 3. 基础组件
# ------------------------------------------------------------------------------
echo ">> [Step 2] 安装基础组件..."
append_if_missing "/etc/gai.conf" "precedence ::ffff:0:0/96 100"

# 修正：
# 1. 使用 fuse3 (现代系统标准) 防止卸载 ubuntu-server-minimal
# 2. 额外安装 libfuse2 (用于兼容 AppImage 等旧软件)
PKGS="net-tools dnsutils curl wget tmux vim git iperf3 fuse3 libfuse2 p7zip-full openssl ca-certificates gnupg lsb-release procps"

# 使用 $APT_OPTS 强制不弹窗
apt-get install -y -qq --no-install-recommends $APT_OPTS $PKGS

# ------------------------------------------------------------------------------
# 4. SSH 核心安全配置
# ------------------------------------------------------------------------------
echo ">> [Step 3] 配置 SSH 安全 (目标端口: $SSH_PORT)..."

SSHD_CONFIG="/etc/ssh/sshd_config"
SSH_DIR="/root/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"

mkdir -p "$SSH_DIR" && chmod 700 "$SSH_DIR" && touch "$AUTH_KEYS"
while IFS= read -r key; do
    [[ -z "$key" || "$key" =~ ^# ]] && continue
    if ! grep -qF "${key:0:20}" "$AUTH_KEYS"; then
        echo "$key" >> "$AUTH_KEYS"
        echo "  + 添加密钥: ${key:0:20}..."
    fi
done <<< "$MY_SSH_KEYS"
chmod 600 "$AUTH_KEYS"

[ ! -f "${SSHD_CONFIG}.bak.init" ] && cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.init"

function set_ssh_config() {
    local key="$1"
    local value="$2"
    if grep -q "^[#]*\s*${key}\b" "$SSHD_CONFIG"; then
        sed -i "s|^[#]*\s*${key}\b.*|${key} ${value}|" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}

set_ssh_config "Port" "$SSH_PORT"
set_ssh_config "PermitRootLogin" "prohibit-password"
set_ssh_config "PubkeyAuthentication" "yes"
set_ssh_config "PasswordAuthentication" "no"
set_ssh_config "PermitEmptyPasswords" "no"
set_ssh_config "KbdInteractiveAuthentication" "no"
set_ssh_config "ChallengeResponseAuthentication" "no"

echo "  - 校验配置文件语法..."
if sshd -t; then
    SVC_NAME="sshd"
    systemctl list-units --all --type=service | grep -q "ssh.service" && SVC_NAME="ssh"
    
    if systemctl reload "$SVC_NAME"; then
        echo "✅ SSH 服务已重载 (端口: $SSH_PORT)"
    else
        systemctl restart "$SVC_NAME"
        echo "⚠️ SSH 服务已重启 (端口: $SSH_PORT)"
    fi
else
    echo "🛑 SSH 配置语法错误！已还原，请检查！"
    cp "${SSHD_CONFIG}.bak.init" "$SSHD_CONFIG"
    exit 1
fi

# ------------------------------------------------------------------------------
# 5. Git & 工具 & 内核
# ------------------------------------------------------------------------------
echo ">> [Step 4] 配置 Git & Docker & BBR..."

RAND_ID=$(openssl rand -hex 4)
git config --global user.email "${RAND_ID}@private.local"
git config --global user.name "User_${RAND_ID}"

sed -i '/function gitpush/,/^}/d' "$HOME/.bashrc"
cat << 'EOF' >> "$HOME/.bashrc"
function gitpush() {
    local msg="${1:-Auto-commit: $(date +'%Y-%m-%d %H:%M:%S')}"
    git add .
    if git commit -m "$msg"; then
        git push && echo "✅ Success!"
    else
        echo "⚠️  Nothing to commit."
    fi
}
EOF

if ! command_exists docker; then
    curl -fsSL https://get.docker.com | bash
    append_if_missing "$HOME/.bashrc" "alias drestart='docker compose down && docker compose build && docker compose up'"
fi

if ! command_exists rclone; then
    curl https://rclone.org/install.sh | bash
fi

timedatectl set-timezone Asia/Shanghai || ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

SYS_CONF="/etc/sysctl.conf"
append_if_missing "$SYS_CONF" "net.core.default_qdisc=fq"
append_if_missing "$SYS_CONF" "net.ipv4.tcp_congestion_control=bbr"
sysctl -p >/dev/null 2>&1 || true

# ------------------------------------------------------------------------------
# 6. 最终验证
# ------------------------------------------------------------------------------
echo ""
echo "=========================================================="
echo "✅ 初始化全部完成！状态确认："
echo "----------------------------------------------------------"
echo "1. 中文环境: $(echo $LANG)"
echo "2. SSH配置 (grep /etc/ssh/sshd_config):"
grep -E "^Port|^PasswordAuthentication|^PermitRootLogin" /etc/ssh/sshd_config
echo "----------------------------------------------------------"
echo "🔑 请新开窗口测试： ssh root@<IP> -p $SSH_PORT"
echo "=========================================================="

exec /bin/bash
