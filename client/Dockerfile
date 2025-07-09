FROM ubuntu:latest

RUN apt-get update && apt-get install -y isc-dhcp-server iproute2 isc-dhcp-client tcpdump

COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

CMD ["start.sh"]
