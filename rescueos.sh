#!/bin/bash
# base: ubuntu rescue
# usage: stardust ipv6
# Run Before NetInstall.sh

chroot_dir="/mnt"
diskdev=$(fdisk -l | grep -oP "Disk /.*?:" | grep -oP "/\\w*?/\\w*")
diskefi=${diskdev}"1"
diskname=${diskdev}"2"
filegz="https://cdimage.ubuntu.com/ubuntu-base/releases/focal/release/ubuntu-base-20.04.5-base-amd64.tar.gz"
nameserver="2a00:1098:2c::1" #DNS64
ipaddr="2001:bc8:630:282::1/64"
ipgate="2001:bc8:630:282::"
ipmask="255.255.255.254"

(
echo g # Create a new empty GPT partition table
echo n # Add a new partition
echo 1 # Partition number
echo   # First sector(default)
echo +512M # Last sector
echo   # Last sector (Accept default: varies)
echo y # try remove partition signature
sleep 1
echo n # Add a new partition
echo 2 # Partition number
echo   # First sector(default)
echo   # Last sector(default)
echo y # try remove partition signature
sleep 1
echo t # change EFI partition type
echo 1
echo C12A7328-F81F-11D2-BA4B-00A0C93EC93B
sleep 1
echo w # Write changes
sleep 1
echo q 
) | fdisk ${diskdev}
partprobe
sleep 2
mkfs.ext4 -F ${diskname}
sleep 1
mount ${diskname} ${chroot_dir}
cd ${chroot_dir}

# for ipv6 only
echo "nameserver ${nameserver}" >/etc/resolv.conf

wget ${filegz}  && tar xpvf ubuntu-*.tar.gz && rm ubuntu-*.tar.gz

# for ipv6 only
echo "nameserver ${nameserver}" >${chroot_dir}/etc/resolv.conf

mount -o bind /dev ${chroot_dir}/dev
mount -t proc none ${chroot_dir}/proc
mount -o bind /sys ${chroot_dir}/sys
mount -o bind /run ${chroot_dir}/run
mount -o bind /dev/pts ${chroot_dir}/dev/pts

# linux64 chroot ${chroot_dir}
cat >${chroot_dir}/no.sh<<REND
diskdev=$(fdisk -l | grep -oP "Disk /.*?:" | grep -oP "/\\w*?/\\w*")
diskefi=${diskdev}"1"
nameserver="2a00:1098:2c::1" #DNS64
ipaddr="2001:bc8:630:282::1/64"
ipgate="2001:bc8:630:282::"
ipmask="255.255.255.254"

apt update && DEBIAN_FRONTEND=noninteractive apt install -y initramfs-tools dosfstools wget iproute2 net-tools arch-install-scripts grub-efi efibootmgr netplan.io vim openssh-server inetutils-ping  

mkdosfs -F 32 ${diskefi}
sleep 1
install -d -m 000 /boot/efi
mount ${diskefi} /boot/efi
genfstab -U / >> /etc/fstab
echo -e "xiaofd\nxiaofd" | passwd

apt-get install -y --no-install-recommends linux-generic linux-image-generic linux-headers-generic initramfs-tools linux-firmware 

cp /etc/default/grub /etc/default/grub.orig

cat <<EOF | tee /etc/default/grub
GRUB_DEFAULT=0
GRUB_TIMEOUT=10
GRUB_RECORDFAIL_TIMEOUT=\${GRUB_TIMEOUT}
GRUB_DISTRIBUTOR=\`lsb_release -i -s 2> /dev/null || echo Debian\`
GRUB_CMDLINE_LINUX_DEFAULT=""
GRUB_CMDLINE_LINUX="console=tty1 console=ttyS0,115200"
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no \
--stop=1"
EOF

grub-install --force --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=GRUB --boot-directory=/boot ${diskdev} 
update-grub 
grub-mkconfig -o /boot/grub/grub.cfg
grub-install --target=x86_64-efi --efi-directory=/boot/efi --recheck ${diskdev}  ## important

wget xiaofd.github.io/os.sh
bash os.sh -u focal -v 64 -a --ip-addr ${ipaddr} --ip-gate ${ipgate} --ip-mask ${ipmask} --ip-dns ${nameserver}
REND

wget -qO- https://raw.githubusercontent.com/xiaofd/xiaofd.github.io/master/rescueos.sh | sed -n "62,100p" >${chroot_dir}/run.sh 

linux64 chroot ${chroot_dir} bash ./run.sh
