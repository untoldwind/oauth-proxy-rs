FROM alpine

RUN apk add -U --no-cache ca-certificates

FROM scratch

COPY target/x86_64-unknown-linux-musl/release/oauth-proxy-rs /oauth-proxy-rs
COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT [ "/oauth-proxy-rs" ]