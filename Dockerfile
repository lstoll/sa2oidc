FROM debian:bookworm
ARG TARGETARCH

WORKDIR /app

RUN apt-get update && \
    apt-get install -y ca-certificates

COPY sa2oidc-$TARGETARCH /usr/bin/tsproxy

CMD ["/usr/bin/sa2oidc"]
