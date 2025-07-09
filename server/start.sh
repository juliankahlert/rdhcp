#!/bin/sh

echo "Clearing all existing IPs on eth0..."
ip addr flush dev eth0
sleep 1

echo "Setting IP address 172.20.0.10/24 on eth0..."
ip addr add 172.20.0.10/24 dev eth0
ip route add 255.255.255.255 dev eth0
sleep 1

echo "Bringing interface eth0 up..."
ip link set eth0 up
sleep 1

echo "Current IP address configuration:"
ip a
sleep 1

echo "Starting the DHCP server..."
tcpdump -i eth0 -n -s 0 -vvv -e -l port 68 and port 67 &
#dhcpd -f -d -lf dhcpd.leases
which server
ls -la $(which server)
stat $(which server)

chmod +x $(which server)
server
kill $!
