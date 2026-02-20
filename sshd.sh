#!/usr/bin/env bash
set -euo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "Please run this script as root." >&2
  exit 1
fi

SSHD_CONFIG="/etc/ssh/sshd_config"
if [ ! -f "$SSHD_CONFIG" ]; then
  echo "Cannot find $SSHD_CONFIG" >&2
  exit 1
fi

# Allow override via env var; defaults to the existing key used by this repo script.
PUBLIC_KEY="${SSH_PUBLIC_KEY:-ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCfuo9/cfgAHy8HYEGVxY+wklHlnrAQ0bPsz6FcAahXQXqw7OdrBzFpkh4U0a7f/Ir0BVgzeYIdDIOL8Ow9Ko1UHldJRCFyy/9W8ji2MGF2YgOUMxmxrCOD1DeOOh04Xrjqx5kPxiscHDZIZEuUF6eM20h3HR+D4xN/3H0OYRkMAaUrSoR8QZVg5P5QSni+HOT6JPHfk7rocKnk/0aQbLPMhSCLjAP4iyM9Fhotn6ofjw9aJnxp/agjwvJPkYSCmC5LJY8Mrv3Xpl4/cjknN0NbxMLUEhXXPDvGnPdS+KSAfpoHDTpm2Zi/WuVtf7AUP0ao0OnWbiPpQcvlEzxXhAm88ipzlY8n4mUnkyR7wIn6nf8y3HeOo8RVwjXWxsc6hNh6gPmNMlJeJo9FGMDxmriX/dRaAqsoYMRtxW3TNxMkfLXKTGs3ykEb/H/WXirwAPpHnSxbCY9/JVvfQMYDctZO+bZ3NV6Nvv5d2ATjq+1FWWaIq6vNkgMQKqs4mxw5CZUGnx4Zd6DMM1VkfA4W3hiNedoFyhSaQWVucza2gdHT7MPDJxNV6TNJErjo6wiobHOXyWghop4UjO32MMhRWyKAhdn3iCIPUglLloEEpvYI0b/TTd5ZdobHAjh+smX9mlIJe3yaQSPlA4sp6MPOjGhC/r08u+6hkmjE1Ycmgw7W7Q== JuiceSSH}"

backup_file="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
cp -a "$SSHD_CONFIG" "$backup_file"
echo "Backup created: $backup_file"

set_sshd_option() {
  local key="$1"
  local value="$2"
  if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+" "$SSHD_CONFIG"; then
    sed -i "s|^[[:space:]]*#\\{0,1\\}[[:space:]]*${key}[[:space:]].*|${key} ${value}|g" "$SSHD_CONFIG"
  else
    printf '%s %s\n' "$key" "$value" >> "$SSHD_CONFIG"
  fi
}

root_home="$(awk -F: '$1=="root"{print $6}' /etc/passwd)"
if [ -z "$root_home" ]; then
  root_home="/root"
fi

install -d -m 700 "$root_home/.ssh"
touch "$root_home/.ssh/authorized_keys"
chmod 600 "$root_home/.ssh/authorized_keys"

if ! grep -Fqx "$PUBLIC_KEY" "$root_home/.ssh/authorized_keys"; then
  printf '%s\n' "$PUBLIC_KEY" >> "$root_home/.ssh/authorized_keys"
  echo "Root public key appended to $root_home/.ssh/authorized_keys"
else
  echo "Root public key already exists in $root_home/.ssh/authorized_keys"
fi

set_sshd_option "Port" "3927"
set_sshd_option "PermitRootLogin" "prohibit-password"
set_sshd_option "PubkeyAuthentication" "yes"
set_sshd_option "PasswordAuthentication" "no"
set_sshd_option "KbdInteractiveAuthentication" "no"
set_sshd_option "ChallengeResponseAuthentication" "no"
set_sshd_option "AuthenticationMethods" "publickey"

if command -v sshd >/dev/null 2>&1; then
  sshd -t -f "$SSHD_CONFIG"
  echo "sshd config test passed"
else
  echo "Warning: sshd command not found, skipped config test" >&2
fi

restart_ssh_service() {
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    if systemctl restart ssh >/dev/null 2>&1; then
      systemctl enable ssh >/dev/null 2>&1 || true
      echo "Restarted service: ssh (systemd)"
      return 0
    fi
    if systemctl restart sshd >/dev/null 2>&1; then
      systemctl enable sshd >/dev/null 2>&1 || true
      echo "Restarted service: sshd (systemd)"
      return 0
    fi
  fi

  if command -v rc-service >/dev/null 2>&1; then
    if rc-service sshd restart >/dev/null 2>&1; then
      rc-update add sshd default >/dev/null 2>&1 || true
      echo "Restarted service: sshd (openrc)"
      return 0
    fi
    if rc-service ssh restart >/dev/null 2>&1; then
      rc-update add ssh default >/dev/null 2>&1 || true
      echo "Restarted service: ssh (openrc)"
      return 0
    fi
  fi

  if command -v service >/dev/null 2>&1; then
    if service ssh restart >/dev/null 2>&1; then
      echo "Restarted service: ssh (service)"
      return 0
    fi
    if service sshd restart >/dev/null 2>&1; then
      echo "Restarted service: sshd (service)"
      return 0
    fi
  fi

  echo "Unable to restart SSH service automatically. Please restart ssh/sshd manually." >&2
  return 1
}

restart_ssh_service

echo "sshd config completed: root key-only login, port 3927"
