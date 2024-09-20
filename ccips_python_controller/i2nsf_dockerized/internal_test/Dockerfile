FROM ubuntu
RUN apt update && apt install -y tcpdump iputils-ping iproute2
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]