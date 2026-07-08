FROM alpine:3.19 AS builder

RUN apk add --no-cache curl tar

RUN curl -Lo /tmp/sliver-server \
    https://github.com/BishopFox/sliver/releases/download/v1.7.3/sliver-server_linux-amd64 \
    && chmod +x /tmp/sliver-server \
    && mv /tmp/sliver-server /usr/local/bin/sliver-server

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata git

COPY --from=builder /usr/local/bin/sliver-server /usr/local/bin/sliver-server

RUN mkdir -p /config /data

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 31337 31334

VOLUME ["/config", "/data"]

ENTRYPOINT ["/entrypoint.sh"]
