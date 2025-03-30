FROM ubuntu:latest

RUN apt-get update && apt-get install -y isc-dhcp-client

CMD ["dhclient", "-v", "eth0"]

