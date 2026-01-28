#!/usr/bin/env bash
#
# 启用 TCP BBR + fq（优先不更换内核）
#
# 适用系统: Debian 8+, Ubuntu 16+, CentOS 7+
#
# Copyright (C) 2016-2026 Teddysun <i@teddysun.com>
#
# URL: https://teddysun.com/489.html
#

cur_dir="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"

_red() {
    printf '\033[1;31;31m%b\033[0m' "$1"
}

_green() {
    printf '\033[1;31;32m%b\033[0m' "$1"
}

_yellow() {
    printf '\033[1;31;33m%b\033[0m' "$1"
}

_info() {
    _green "[信息] "
    printf -- "%s" "$1"
    printf "\n"
}

_warn() {
    _yellow "[警告] "
    printf -- "%s" "$1"
    printf "\n"
}

_error() {
    _red "[错误] "
    printf -- "%s" "$1"
    printf "\n"
    exit 1
}

_exists() {
    local cmd="$1"
    if eval type type > /dev/null 2>&1; then
        eval type "$cmd" > /dev/null 2>&1
    elif command > /dev/null 2>&1; then
        command -v "$cmd" > /dev/null 2>&1
    else
        which "$cmd" > /dev/null 2>&1
    fi
    local rt=$?
    return ${rt}
}

_os() {
    local os=""
    [ -f "/etc/debian_version" ] && source /etc/os-release && os="${ID}" && printf -- "%s" "${os}" && return
    [ -f "/etc/redhat-release" ] && os="centos" && printf -- "%s" "${os}" && return
}

_os_full() {
    [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
    [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

_os_ver() {
    local main_ver="$( echo $(_os_full) | grep -oE  "[0-9.]+")"
    printf -- "%s" "${main_ver%%.*}"
}

_is_digit(){
    local input=${1}
    if [[ "$input" =~ ^[0-9]+$ ]]; then
        return 0
    else
        return 1
    fi
}

_version_ge(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

check_bbr_status() {
    local param
    param=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    if [[ x"${param}" == x"bbr" ]]; then
        return 0
    else
        return 1
    fi
}

check_qdisc_status() {
    local param
    param=$(sysctl net.core.default_qdisc 2>/dev/null | awk '{print $3}')
    if [[ x"${param}" == x"fq" ]]; then
        return 0
    else
        return 1
    fi
}

print_current_status() {
    local kver
    kver="$(uname -r 2>/dev/null || echo unknown)"
    _info "当前内核版本: ${kver}"
    if check_bbr_status; then
        _info "拥塞控制算法: bbr (已开启)"
    else
        _warn "拥塞控制算法: $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')"
    fi
    if check_qdisc_status; then
        _info "默认队列调度: fq (已开启)"
    else
        _warn "默认队列调度: $(sysctl net.core.default_qdisc 2>/dev/null | awk '{print $3}')"
    fi
}

check_kernel_version() {
    local kernel_version
    kernel_version=$(uname -r | cut -d- -f1)
    if _version_ge ${kernel_version} 4.9; then
        return 0
    else
        return 1
    fi
}

# 检查系统
check_os() {
    if _exists "virt-what"; then
        virt="$(virt-what)"
    elif _exists "systemd-detect-virt"; then
        virt="$(systemd-detect-virt)"
    fi
    if [ -n "${virt}" -a "${virt}" = "lxc" ]; then
        _error "虚拟化类型为 LXC，不支持。"
    fi
    if [ -n "${virt}" -a "${virt}" = "openvz" ] || [ -d "/proc/vz" ]; then
        _error "虚拟化类型为 OpenVZ，不支持。"
    fi
    [ -z "$(_os)" ] && _error "不支持的系统。"
    case "$(_os)" in
        centos)
            [ -n "$(_os_ver)" -a "$(_os_ver)" -lt 7 ] &&  _error "系统版本过低，请使用 CentOS 7+。"
            ;;
        ubuntu|debian)
            ;;
        *)
            _error "不支持的系统。"
            ;;
    esac
}

sysctl_config() {
    local sysctl_file="/etc/sysctl.d/99-bbr.conf"
    echo "net.core.default_qdisc = fq" > "$sysctl_file"
    echo "net.ipv4.tcp_congestion_control = bbr" >> "$sysctl_file"
    if _exists "sysctl"; then
        sysctl --system >/dev/null 2>&1 || sysctl -p "$sysctl_file" >/dev/null 2>&1
    fi
}

print_upgrade_hint() {
    _warn "当前内核不支持 BBR（需要 >= 4.9）。"
    _warn "请通过系统官方仓库升级内核后再运行本脚本。"
    _warn "示例 (Debian/Ubuntu)：apt-get install linux-image-amd64 或 linux-generic"
    _warn "示例 (CentOS/RHEL)：yum/dnf install kernel"
}

install_bbr() {
    if check_bbr_status; then
        echo
        _info "已开启 TCP BBR，无需重复设置。"
        exit 0
    fi
    if ! check_kernel_version; then
        print_upgrade_hint
        exit 1
    fi
    sysctl_config
    if check_bbr_status; then
        _info "TCP BBR 启用成功。"
    else
        _error "TCP BBR 启用失败。"
    fi
}

# 必须 root
if [[ $(id -u) != 0 ]]; then
    _error "必须使用 root 运行。"
fi

check_os
print_current_status
install_bbr 2>&1 | tee ${cur_dir}/install_bbr.log

