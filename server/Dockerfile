FROM ubuntu:latest

RUN apt-get update && apt-get install -y isc-dhcp-server iproute2
RUN touch dhcpd.leases

COPY dhcpd.conf /etc/dhcp/dhcpd.conf
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

CMD ["start.sh"]
