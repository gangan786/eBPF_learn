防火墙命令
 iptables -I OUTPUT -d 39.106.233.176/32 -p tcp -m tcp --dport 80 -j DROP
 iptables -D OUTPUT -d 39.106.233.176/32 -p tcp -m tcp --dport 80 -j DROP
 iptables -nvL OUTPUT

 faddr2line /usr/lib/debug/boot/vmlinux-5.15.0-113-generic __ip_local_out+219