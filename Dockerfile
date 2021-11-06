FROM scratch

COPY target/x86_64-unknown-linux-musl/release/oauth-proxy-rs /oauth-proxy-rs

ENTRYPOINT [ "/oauth-proxy-rs" ]