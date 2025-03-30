#!/bin/sh

# Set the IP address for eth0 based on the dhcpd.conf network (192.168.1.1/24)
ip addr add 192.168.1.1/24 dev eth0

# Bring up the interface
ip link set eth0 up

ip a

# Start the server
dhcpd -f -d -lf dhcpd.leases
