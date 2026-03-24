FROM alpine:3.20

RUN apk add --no-cache \
  iproute2 \
  iptables \
  iputils \
  openssh-server \
  shadow \
  sudo

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
