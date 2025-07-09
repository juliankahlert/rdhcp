#!/bin/sh

echo "Flushing all existing IPs on eth0..."
ip addr flush dev eth0
ip route add 255.255.255.255 dev eth0
sleep 1

echo "Bringing up the eth0 interface..."
ip link set eth0 up
sleep 1

echo "Current interface addresses:"
ip a
sleep 1

echo "Starting the DHCP client..."
tcpdump -i eth0 -n -s 0 -vvv -e -XX -l port 68 and port 67 &
dhclient -v eth0
kill $!
