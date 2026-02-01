#!/bin/bash
set -u

# ==============================================================================
# 脚本名称: Docker 高级策略路由与双栈网络配置工具 (Universe Edition - Formatted)
# 功能描述:
#   1. 创建双栈 Docker 网络 (NetOut/NetIn)，配置 ULA IPv6 地址。
#   2. 配置 Docker Daemon (daemon.json)，支持原子写入，防止配置损坏。
#   3. 生成 Systemd 服务 (apply-routes)，实现开机自动配置策略路由。
#   4. 修复非对称路由问题 (通过 Connmark 双栈回程修正)，支持端口映射正常访问。
#   5. 优化内核参数，确保宿主机 IPv6 在开启转发后不掉线 (RA Fix)。
#   6. 引入自定义 iptables 链与锁机制，防止规则冲突与启动竞争。
#
# 适用环境: Debian/Ubuntu, Docker 环境
# 运行权限: Root
# ==============================================================================

# ==============================================================================
# [0] 权限与环境预检
# ==============================================================================
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo -e "\033[31m[ERROR] 请使用 root 权限运行此脚本 (sudo bash ...)\033[0m"
    exit 1
fi

# 注册清理钩子 (Trap): 脚本退出时自动删除临时文件
tmp_file=""
cleanup() {
    [ -n "$tmp_file" ] && [ -f "$tmp_file" ] && rm -f "$tmp_file"
}
trap cleanup EXIT

echo -e "\n\033[34m[INFO] 初始化环境检测...\033[0m"

# 1. 检查并安装工具
if ! command -v docker >/dev/null 2>&1; then 
    echo "  > 未找到 Docker，正在安装..."
    curl -fsSL get.docker.com | bash
fi

if ! command -v jq >/dev/null 2>&1 || \
   ! command -v iptables >/dev/null 2>&1 || \
   ! command -v ip6tables >/dev/null 2>&1; then
    echo "  > 未找到必要工具 (jq/iptables/net-tools)，正在安装..."
    apt-get update -qq && apt-get install -y jq iptables net-tools
fi

# 2. 打印版本信息 (便于排障)
echo "  > Iptables Version:  $(iptables -V)"
echo "  > Ip6tables Version: $(ip6tables -V 2>/dev/null || echo 'N/A')"

# ==============================================================================
# [用户配置区] (请根据实际情况修改)
# ==============================================================================
DEFAULT_TRAFFIC_MODE="netout"

# 物理接口 (尝试自动获取，获取失败回退到 eth0)
AUTO_PHY_DEV=$(ip route show default | awk '/default/ {print $5}' | head -n1)
PHY_DEV=${AUTO_PHY_DEV:-"eth0"}

# --- 线路定义 ---
# 线路 1: 旁路由 (NetOut) -> 对应表 101
GW_OUT="192.168.0.11"
GW_V6_OUT="fdf7:a100:557::1"
BR_OUT="br-netout"

# 线路 2: 主路由 (NetIn) -> 对应表 102
GW_DEF="192.168.0.1"
GW_V6_DEF="fe80::1"  # [🔴必须修改] 请填入主路由真实的 Link-Local (fe80) 地址
BR_IN="br-netin"

# --- 优先级定义 (使用固定ID防止规则残留) ---
PRIO_MARK=5000     # 回程标记规则 (最高优)
PRIO_OUT=11000     # NetOut 规则
PRIO_IN=12000      # NetIn 规则
PRIO_DEF=13000     # 默认网桥规则

# --- 标记定义 (使用掩码模式，占用1个bit) ---
MARK_ID="0x200"
MARK_MASK="0x200"

# --- 自定义 iptables 链名称 ---
CHAIN_NAME="DOCKER_SPLIT"

# --- 网段规划 (IPv4私有段 + IPv6 ULA) ---
SUBNET_OUT_V4="10.11.0.0/24"; SUBNET_OUT_V6="fd00:11::/64"
SUBNET_IN_V4="10.10.0.0/24";  SUBNET_IN_V6="fd00:10::/64"
DEFAULT_BRIDGE_IP="10.99.0.1/24"; DEFAULT_BRIDGE_NET="10.99.0.0/24"; DEFAULT_BRIDGE_V6="fd00:99::/64"

# 获取物理 LAN 网段 (用于添加直连路由)
LAN_SUBNET=$(ip -4 route show dev "$PHY_DEV" proto kernel scope link | awk 'NR==1{print $1}')
echo "  > 物理网卡: $PHY_DEV"
echo "  > LAN网段:  ${LAN_SUBNET:-"未检测到"}"

# ==============================================================================
# [1] 内核优化 (双栈转发 + RA 修复 + RP_Filter)
# ==============================================================================
echo -e "\n\033[34m[INFO] 正在优化内核参数...\033[0m"

cat >/etc/sysctl.d/99-docker-routing.conf<<EOF
# 开启 IPv4/IPv6 转发
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1

# [关键] 允许在转发模式下接收 RA 广播 (防止宿主机 IPv6 掉线)
net.ipv6.conf.all.accept_ra=2
net.ipv6.conf.default.accept_ra=2
net.ipv6.conf.$PHY_DEV.accept_ra=2

# [关键] 宽松的反向路径过滤 (允许非对称路由)
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.conf.$PHY_DEV.rp_filter=2
EOF

# 应用配置 (忽略部分非关键报错)
if ! sysctl -p /etc/sysctl.d/99-docker-routing.conf >/dev/null 2>&1; then
    echo -e "\033[33m[WARN] sysctl 部分参数应用失败 (可能因内核模块差异)，继续执行...\033[0m"
fi

# 强制刷新关键参数 (双重保险)
sysctl -w net.ipv6.conf.all.accept_ra=2 >/dev/null 2>&1
sysctl -w "net.ipv6.conf.$PHY_DEV.accept_ra=2" >/dev/null 2>&1
sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null 2>&1
echo "  > 内核参数优化完成。"

# ==============================================================================
# [2] 配置 Docker Daemon (原子写入)
# ==============================================================================
echo -e "\n\033[34m[INFO] 配置 Docker Daemon (daemon.json)...\033[0m"
DAEMON_FILE="/etc/docker/daemon.json"
DIR_NAME=$(dirname "$DAEMON_FILE")
[ ! -d "$DIR_NAME" ] && mkdir -p "$DIR_NAME"
[ ! -f "$DAEMON_FILE" ] && echo "{}" > "$DAEMON_FILE"

# 在同级目录创建临时文件 (确保 mv 是原子操作)
tmp_file=$(mktemp "$DIR_NAME/daemon.json.tmp.XXXXXX")

# 使用 jq 生成新配置
jq --arg bip "$DEFAULT_BRIDGE_IP" \
   --arg fixedv6 "$DEFAULT_BRIDGE_V6" \
   '.ipv6 = true | .ip6tables = true | ."fixed-cidr-v6" = $fixedv6 | .bip = $bip' \
   "$DAEMON_FILE" > "$tmp_file" && \
   mv -f "$tmp_file" "$DAEMON_FILE" && \
   tmp_file="" # 清空变量防止 trap 误删

echo "  > 重启 Docker 服务..."
systemctl restart docker

# ==============================================================================
# [3] 创建 Docker 网络
# ==============================================================================
echo -e "\n\033[34m[INFO] 重建 Docker 网络...\033[0m"

recreate_net() {
    local net_name="$1"
    local subnet_v4="$2"
    local subnet_v6="$3"
    local br_name="$4"

    # 检查并删除旧网络
    if docker network inspect "$net_name" >/dev/null 2>&1; then
        if ! docker network rm "$net_name" >/dev/null 2>&1; then
            echo -e "\033[31m[ERROR] 无法删除网络 $net_name，可能有容器正在运行。\033[0m"
            exit 1
        fi
    fi

    # 创建新网络
    if ! docker network create \
        --driver=bridge \
        --subnet="$subnet_v4" \
        --ipv6 --subnet="$subnet_v6" \
        --opt com.docker.network.bridge.name="$br_name" \
        "$net_name" >/dev/null; then
        echo -e "\033[31m[ERROR] 创建网络 $net_name 失败。\033[0m"
        exit 1
    fi
    echo "  > 网络已创建: $net_name ($subnet_v4)"
}

recreate_net "netout" "$SUBNET_OUT_V4" "$SUBNET_OUT_V6" "$BR_OUT"
recreate_net "netin"  "$SUBNET_IN_V4"  "$SUBNET_IN_V6"  "$BR_IN"

# ==============================================================================
# [4] 生成 Systemd 路由服务 (核心逻辑)
# ==============================================================================
echo -e "\n\033[34m[INFO] 生成 Systemd 路由服务 (apply-routes.service)...\033[0m"

# 确定默认路由表
if [ "$DEFAULT_TRAFFIC_MODE" == "netout" ]; then DEF_TABLE="101"; else DEF_TABLE="102"; fi

# 构建 LAN 直连命令 (防止内网流量走网关)
LAN_CMD_101=""; LAN_CMD_102=""
if [ -n "$LAN_SUBNET" ]; then
    LAN_CMD_101="ExecStart=/bin/bash -c 'ip route replace $LAN_SUBNET dev $PHY_DEV scope link table 101'"
    LAN_CMD_102="ExecStart=/bin/bash -c 'ip route replace $LAN_SUBNET dev $PHY_DEV scope link table 102'"
fi

# 写入 Service 文件
cat >/etc/systemd/system/apply-routes.service<<EOF
[Unit]
Description=Apply Custom Routing Rules for Docker
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=oneshot
RemainAfterExit=yes

# ------------------------------------------------------------------------------
# [Phase 1: 等待 & 参数保险]
# ------------------------------------------------------------------------------
# 循环检查网桥是否存在 (超时 30s)
ExecStartPre=/bin/bash -c 'count=0; \
    while ! ip link show $BR_OUT >/dev/null 2>&1 || ! ip link show $BR_IN >/dev/null 2>&1; do \
        sleep 1; \
        count=\$((count+1)); \
        if [ \$count -ge 30 ]; then echo "[ERROR] Bridge Wait Timeout"; exit 1; fi; \
    done'

# 确保网桥 rp_filter 为 Loose 模式
ExecStartPre=/bin/bash -c 'sysctl -w net.ipv4.conf.$BR_OUT.rp_filter=2 >/dev/null 2>&1 || true'
ExecStartPre=/bin/bash -c 'sysctl -w net.ipv4.conf.$BR_IN.rp_filter=2 >/dev/null 2>&1 || true'
ExecStartPre=/bin/bash -c 'sysctl -w net.ipv4.conf.docker0.rp_filter=2 >/dev/null 2>&1 || true'

# ------------------------------------------------------------------------------
# [Phase 2: 环境清理 (Rule & Iptables)]
# ------------------------------------------------------------------------------
# 循环清理 IP Rule (直到没有残留)
ExecStartPre=-/bin/bash -c 'while ip rule del pref $PRIO_MARK 2>/dev/null; do :; done'
ExecStartPre=-/bin/bash -c 'while ip rule del pref $PRIO_OUT 2>/dev/null; do :; done'
ExecStartPre=-/bin/bash -c 'while ip rule del pref $PRIO_IN 2>/dev/null; do :; done'
ExecStartPre=-/bin/bash -c 'while ip rule del pref $PRIO_DEF 2>/dev/null; do :; done'
ExecStartPre=-/bin/bash -c 'while ip -6 rule del pref $PRIO_MARK 2>/dev/null; do :; done'
ExecStartPre=-/bin/bash -c 'while ip -6 rule del pref $PRIO_OUT 2>/dev/null; do :; done'
ExecStartPre=-/bin/bash -c 'while ip -6 rule del pref $PRIO_IN 2>/dev/null; do :; done'
ExecStartPre=-/bin/bash -c 'while ip -6 rule del pref $PRIO_DEF 2>/dev/null; do :; done'

# ------------------------------------------------------------------------------
# [Phase 3: IPTABLES 架构初始化]
# ------------------------------------------------------------------------------
# 1. 初始化自定义链 (IPv4 & IPv6), 使用 -w 5 防止锁竞争
ExecStartPre=/bin/bash -c 'iptables  -w 5 -t mangle -N $CHAIN_NAME 2>/dev/null || true'
ExecStartPre=/bin/bash -c 'ip6tables -w 5 -t mangle -N $CHAIN_NAME 2>/dev/null || true'

# 2. 清空链内规则
ExecStartPre=/bin/bash -c 'iptables  -w 5 -t mangle -F $CHAIN_NAME'
ExecStartPre=/bin/bash -c 'ip6tables -w 5 -t mangle -F $CHAIN_NAME'

# 3. 清洗 PREROUTING 中的跳转规则 (防止重复)
ExecStartPre=/bin/bash -c 'while iptables  -w 5 -t mangle -D PREROUTING -j $CHAIN_NAME 2>/dev/null; do :; done'
ExecStartPre=/bin/bash -c 'while ip6tables -w 5 -t mangle -D PREROUTING -j $CHAIN_NAME 2>/dev/null; do :; done'

# 4. 插入跳转规则到最前
ExecStartPre=/bin/bash -c 'iptables  -w 5 -t mangle -I PREROUTING -j $CHAIN_NAME -m comment --comment "docker split routing"'
ExecStartPre=/bin/bash -c 'ip6tables -w 5 -t mangle -I PREROUTING -j $CHAIN_NAME -m comment --comment "docker split routing"'

# ------------------------------------------------------------------------------
# [Phase 4: 路由表构建]
# ------------------------------------------------------------------------------
# >>> Table 101 (NetOut/旁路由)
ExecStart=/bin/bash -c 'ip route flush table 101 || true'
$LAN_CMD_101
ExecStart=/bin/bash -c 'ip route replace default via $GW_OUT dev $PHY_DEV table 101'
ExecStart=/bin/bash -c 'ip -6 route flush table 101 || true'
ExecStart=/bin/bash -c 'ip -6 route replace default via $GW_V6_OUT dev $PHY_DEV table 101 || true'

# >>> Table 102 (NetIn/主路由)
ExecStart=/bin/bash -c 'ip route flush table 102 || true'
$LAN_CMD_102
ExecStart=/bin/bash -c 'ip route replace default via $GW_DEF dev $PHY_DEV table 102'
ExecStart=/bin/bash -c 'ip -6 route flush table 102 || true'
ExecStart=/bin/bash -c 'ip -6 route replace default via $GW_V6_DEF dev $PHY_DEV table 102 || true'

# ------------------------------------------------------------------------------
# [Phase 5: MANGLE 规则注入 - 全栈回程修正]
# ------------------------------------------------------------------------------
# 目的: 解决端口映射的非对称路由问题。
# 逻辑: 只有目标是本机的连接才打标，回复时恢复标记，强制走主路由返回。

# >>> IPv4 打标
ExecStart=/bin/bash -c 'iptables -w 5 -t mangle -A $CHAIN_NAME \
    -i $PHY_DEV -m conntrack --ctstate NEW -m addrtype --dst-type LOCAL \
    -j CONNMARK --set-mark $MARK_ID/$MARK_MASK'
# >>> IPv4 恢复
ExecStart=/bin/bash -c 'iptables -w 5 -t mangle -A $CHAIN_NAME \
    -i $BR_OUT -m connmark --mark $MARK_ID/$MARK_MASK -j CONNMARK --restore-mark'
ExecStart=/bin/bash -c 'iptables -w 5 -t mangle -A $CHAIN_NAME \
    -i $BR_IN  -m connmark --mark $MARK_ID/$MARK_MASK -j CONNMARK --restore-mark'
ExecStart=/bin/bash -c 'iptables -w 5 -t mangle -A $CHAIN_NAME \
    -i docker0 -m connmark --mark $MARK_ID/$MARK_MASK -j CONNMARK --restore-mark'

# >>> IPv6 打标
ExecStart=/bin/bash -c 'ip6tables -w 5 -t mangle -A $CHAIN_NAME \
    -i $PHY_DEV -m conntrack --ctstate NEW -m addrtype --dst-type LOCAL \
    -j CONNMARK --set-mark $MARK_ID/$MARK_MASK'
# >>> IPv6 恢复
ExecStart=/bin/bash -c 'ip6tables -w 5 -t mangle -A $CHAIN_NAME \
    -i $BR_OUT -m connmark --mark $MARK_ID/$MARK_MASK -j CONNMARK --restore-mark'
ExecStart=/bin/bash -c 'ip6tables -w 5 -t mangle -A $CHAIN_NAME \
    -i $BR_IN  -m connmark --mark $MARK_ID/$MARK_MASK -j CONNMARK --restore-mark'
ExecStart=/bin/bash -c 'ip6tables -w 5 -t mangle -A $CHAIN_NAME \
    -i docker0 -m connmark --mark $MARK_ID/$MARK_MASK -j CONNMARK --restore-mark'

# ------------------------------------------------------------------------------
# [Phase 6: 策略路由规则 (IP Rule)]
# ------------------------------------------------------------------------------
# 1. 回程优先 (命中标记则强制走表 102)
ExecStart=/bin/bash -c 'ip rule add pref $PRIO_MARK fwmark $MARK_ID/$MARK_MASK lookup 102'
ExecStart=/bin/bash -c 'ip -6 rule add pref $PRIO_MARK fwmark $MARK_ID/$MARK_MASK lookup 102'

# 2. 出站分流 (NetOut -> 101)
ExecStart=/bin/bash -c 'ip rule add pref $PRIO_OUT from $SUBNET_OUT_V4 iif $BR_OUT lookup 101'
ExecStart=/bin/bash -c 'ip -6 rule add pref $PRIO_OUT from $SUBNET_OUT_V6 iif $BR_OUT lookup 101'

# 3. 出站分流 (NetIn -> 102)
ExecStart=/bin/bash -c 'ip rule add pref $PRIO_IN from $SUBNET_IN_V4 iif $BR_IN lookup 102'
ExecStart=/bin/bash -c 'ip -6 rule add pref $PRIO_IN from $SUBNET_IN_V6 iif $BR_IN lookup 102'

# 4. 默认网桥分流
ExecStart=/bin/bash -c 'ip rule add pref $PRIO_DEF from $DEFAULT_BRIDGE_NET iif docker0 lookup $DEF_TABLE'
ExecStart=/bin/bash -c 'ip -6 rule add pref $PRIO_DEF from $DEFAULT_BRIDGE_V6 iif docker0 lookup $DEF_TABLE'

# ------------------------------------------------------------------------------
# [Phase 7: 停止清理逻辑]
# ------------------------------------------------------------------------------
# 清理 Rule
ExecStop=/bin/bash -c 'while ip rule del pref $PRIO_MARK 2>/dev/null; do :; done'
ExecStop=/bin/bash -c 'while ip rule del pref $PRIO_OUT 2>/dev/null; do :; done'
ExecStop=/bin/bash -c 'while ip rule del pref $PRIO_IN 2>/dev/null; do :; done'
ExecStop=/bin/bash -c 'while ip rule del pref $PRIO_DEF 2>/dev/null; do :; done'
ExecStop=/bin/bash -c 'while ip -6 rule del pref $PRIO_MARK 2>/dev/null; do :; done'
ExecStop=/bin/bash -c 'while ip -6 rule del pref $PRIO_OUT 2>/dev/null; do :; done'
ExecStop=/bin/bash -c 'while ip -6 rule del pref $PRIO_IN 2>/dev/null; do :; done'
ExecStop=/bin/bash -c 'while ip -6 rule del pref $PRIO_DEF 2>/dev/null; do :; done'

# 清空路由表
ExecStop=/bin/bash -c 'ip route flush table 101 || true'
ExecStop=/bin/bash -c 'ip route flush table 102 || true'

# 清理 IPTABLES (删除跳转 -> 清空链 -> 删除链)
ExecStop=/bin/bash -c 'while iptables -w 5 -t mangle -D PREROUTING -j $CHAIN_NAME 2>/dev/null; do :; done'
ExecStop=/bin/bash -c 'iptables  -w 5 -t mangle -F $CHAIN_NAME 2>/dev/null || true'
ExecStop=/bin/bash -c 'iptables  -w 5 -t mangle -X $CHAIN_NAME 2>/dev/null || true'

# 清理 IP6TABLES
ExecStop=/bin/bash -c 'while ip6tables -w 5 -t mangle -D PREROUTING -j $CHAIN_NAME 2>/dev/null; do :; done'
ExecStop=/bin/bash -c 'ip6tables -w 5 -t mangle -F $CHAIN_NAME 2>/dev/null || true'
ExecStop=/bin/bash -c 'ip6tables -w 5 -t mangle -X $CHAIN_NAME 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF

# ==============================================================================
# [5] 启动与验证
# ==============================================================================
echo -e "\n\033[34m[INFO] 正在启动路由服务...\033[0m"
systemctl daemon-reload
systemctl enable apply-routes.service >/dev/null 2>&1
systemctl restart apply-routes.service

if systemctl is-active --quiet apply-routes.service; then
    echo -e "\033[32m[SUCCESS] 配置成功！服务状态: Active\033[0m"
    echo "  > 双栈入站回程修正: 已启用 (IPv4 & IPv6)"
    echo "  > 自定义链: $CHAIN_NAME (Mangle Table)"
else
    echo -e "\033[31m[ERROR] 服务启动失败！\033[0m"
    echo "  请检查日志: journalctl -xeu apply-routes.service"
    exit 1
fi

echo -e "\n\033[33m[验证指南] 请运行以下命令检查生效情况：\033[0m"
echo "1. 检查路由规则:"
echo "   ip rule | head -n 30"
echo "2. 检查 NetOut 路由 (应指向 .0.11):"
echo "   ip route show table 101"
echo "3. 模拟测试 (NetOut 网桥 -> 8.8.8.8):"
echo "   ip route get 8.8.8.8 from 10.11.0.2 iif $BR_OUT"
