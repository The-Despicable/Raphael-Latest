FROM alpine:3.19 AS builder

RUN apk add --no-cache curl tar

RUN curl -Lo /tmp/sliver-server.tar.gz \
    https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux.tar.gz \
    && tar xzf /tmp/sliver-server.tar.gz -C /tmp/ \
    && mv /tmp/sliver-server /usr/local/bin/sliver-server \
    && rm /tmp/sliver-server.tar.gz

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /usr/local/bin/sliver-server /usr/local/bin/sliver-server

RUN mkdir -p /config /data

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 31337 31334

VOLUME ["/config", "/data"]

ENTRYPOINT ["/entrypoint.sh"]
