# iptables -j icmp_frag

Add missing ICMP FRAG_NEEDED reply to iptables. Intended for CentOS 8


## Build

### Build & install kernel module
```
cd ./data/kernel-module
make -C /lib/modules/$(uname -r)/build/ M=$(pwd) modules
sudo insmod ./ipt_icmp_frag.ko
```

### Build & install modified iptables

Only `extensions/xt_icmp_frag.c` is new.

```
cd ./data/iptables-modified/iptables-1.8.4
./configure --disable-nftables --prefix=$HOME/.local
make -j4
make install
```

## Test and usage example

```
vagrant up --provision # this brings up a CentOS 8 VM
vagrant ssh # The following command happens in vagrant box

# Build and install kernel modules / modified iptables as above
# ./data/ is synced to /vagrant_data

~/.local/sbin/iptables -A INPUT -p tcp --dport 6789 -j icmp_frag --mtu 13

sudo tcpdump -i lo -vvvvv &
mtr -tTP 6789 -4 localhost >/dev/null
# Expect to see tcpdump outputs ICMP frag needed reply
```
