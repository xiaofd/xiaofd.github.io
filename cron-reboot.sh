#!/bin/bash
#every 2 hours
apt-get update && apt-get install -y sudo
sudo chmod 0777 /etc/cron.d
sudo cat > /etc/cron.d/zz-cron-reboot << EOF
0 */2 * * * root /sbin/shutdown -r now
EOF
sudo chmod 0644 /etc/cron.d/zz-cron-reboot
sudo chown root:root /etc/cron.d/zz-cron-reboot
