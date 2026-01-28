# upjj 文件名补齐
# cp to /etc/profile.d/upjj.sh
if [ -n "${BASH_VERSION:-}" ]; then
  complete -o default -o bashdefault upjj 2>/dev/null || true
fi
