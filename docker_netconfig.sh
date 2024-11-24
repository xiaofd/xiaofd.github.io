#!/bin/bash
# Netout Gateway
NetoutGateway='192.168.0.11'
NetdefGateway='192.168.0.1'
NetoutGateway6='fdf7:a100:557::1'

[[ -z $(which docker) ]] && echo "Install Docker......" && wget -qO- get.docker.com | bash
[[ -z $(which iptables) ]] && echo "Install Iptables......" && apt update && apt install -y iptables net-tools

# config docker network
docker network create \
  --driver=bridge \
  --subnet=192.168.1.0/24 \
  --ipv6 \
  --subnet=2001:db8:1::/64 \
  netout

docker network create \
  --driver=bridge \
  --subnet=192.168.2.0/24 \
  --ipv6 \
  --subnet=2001:db8:2::/64 \
  netin

NetDevice=$(ip link show | grep -E '^[0-9]+: (en|eth|ens)' | awk -F': ' '{print $2}' | awk '{print $1}')
NetinDevice=$(ip route | grep 192.168.2.0 | awk "{print \$3}")
NetoutDevice=$(ip route | grep 192.168.1.0 | awk "{print \$3}")
# add route rule
[[ -z $(cat /etc/iproute2/rt_tables | grep "100 table_1") ]] && echo "100 table_1" | sudo tee -a /etc/iproute2/rt_tables
[[ -z $(cat /etc/iproute2/rt_tables | grep "200 table_2") ]] && echo "200 table_2" | sudo tee -a /etc/iproute2/rt_tables

# add route-apply.service
cat >/etc/systemd/system/apply-routes.service<<EOF
[Unit]
Description=Apply Custom Routing Rules
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'sleep 5; ip route add default via ${NetoutGateway} dev ${NetDevice} table table_1; ip -6 route add default via ${NetoutGateway6} dev ${NetDevice} table table_1; ip route add default via ${NetdefGateway} dev ${NetDevice} table table_2; ip rule add from 192.168.1.0/24 iif $(ip route | grep 192.168.1.0 | awk "{print \$3}") lookup table_1; ip rule add from 192.168.2.0/24 iif $(ip route | grep 192.168.2.0 | awk "{print \$3}") lookup table_2;sudo ip -6 rule add from 2001:db8:1::/64 iif $(ip -6 route | grep 2001:db8:1:: | awk '{print $3}') lookup table_1;sudo ip -6 rule add from 2001:db8:2::/64 iif $(ip -6 route | grep 2001:db8:2:: | awk '{print $3}') lookup table_2; sudo ip -6 route del default; sudo ip -6 route del default; sudo ip -6 route add default via ${NetoutGateway6}'
RemainAfterExit=true
ExecStop=/bin/bash -c 'ip rule del from 192.168.1.0/24 iif $(ip route | grep 192.168.1.0 | awk "{print \$3}") lookup table_1; ip rule del from 192.168.2.0/24 iif $(ip route | grep 192.168.2.0 | awk "{print \$3}") lookup table_2; sudo ip -6 rule del from 2001:db8:1::/64 iif $(ip -6 route | grep 2001:db8:1:: | awk '{print $3}') lookup table_1; sudo ip -6 rule del from 2001:db8:2::/64 iif $(ip -6 route | grep 2001:db8:2:: | awk '{print $3}') lookup table_2'

Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl enable apply-routes.service
systemctl daemon-reload
systemctl restart apply-routes.service
systemctl status apply-routes.service

# 为网段 192.168.1.0/24 指定使用路由表 100
# sudo ip route add default via 192.168.0.11 dev ens18 table table_1
# 为网段 192.168.2.0/24 指定使用路由表 200
# sudo ip route add default via 192.168.0.1 dev ens18 table table_2
# 为源地址在 192.168.1.0/24 网段的数据包添加规则，使用路由表 100
# sudo ip rule add from 192.168.1.0/24 iif $(ip route | grep 192.168.1.0 | awk '{print $3}') lookup table_1
# 为源地址在 192.168.2.0/24 网段的数据包添加规则，使用路由表 200
# sudo ip rule add from 192.168.2.0/24 iif $(ip route | grep 192.168.2.0 | awk '{print $3}') lookup table_2
# 为源地址在 2001:db8:1::/64 网段的数据包添加规则，使用路由表 table_1
# sudo ip -6 rule add from 2001:db8:1::/64 iif $(ip -6 route | grep 2001:db8:1:: | awk '{print $3}') lookup table_1
# 为源地址在 2001:db8:2::/64 网段的数据包添加规则，使用路由表 table_2
# sudo ip -6 rule add from 2001:db8:2::/64 iif $(ip -6 route | grep 2001:db8:2:: | awk '{print $3}') lookup table_2
