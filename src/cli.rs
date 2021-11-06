use clap::Parser;

#[derive(Parser, Debug)]
#[clap(name = "oauth-proxy-rs")]
pub struct Opts {
    #[clap(long)]
    pub debug: bool,

    #[clap(long)]
    pub json_log: bool,

    #[clap(long)]
    pub permit_login: bool,

    #[clap(long, env = "OAUTH_PROXY_CLIENT_ID")]
    pub client_id: String,

    #[clap(long, env = "OAUTH_PROXY_CLIENT_SECRET")]
    pub client_secret: String,

    #[clap(long, env = "OAUTH_PROXY_ISSUER")]
    pub issuer: String,

    #[clap(long, default_value = "0.0.0.0:8080", env = "OAUTH_PROXY_BIND_ADDRESS")]
    pub bind_address: String,

    #[clap(long, default_value = "http://localhost:8080", env = "OAUTH_PROXY_EXTERNAL_URL")]
    pub external_url: String,

    #[clap(long, env = "OAUTH_PROXY_BACKEND")]
    pub backend: String,

    #[clap(long, default_value = "12345678", env = "OAUTH_PROXY_COOKIE_SECRET")]
    pub cookie_secret: String,

    #[clap(
        long,
        default_value = "OAUTH_PROXY_LOGIN",
        env = "OAUTH_PROXY_LOGIN_COOKIE"
    )]
    pub login_cookie: String,

    #[clap(
        long,
        default_value = "OAUTH_PROXY_AUTH",
        env = "OAUTH_PROXY_AUTH_COOKIE"
    )]
    pub auth_cookie: String,

    #[clap(
        long,
        default_value = "OAUTH_PROXY_REFRESH",
        env = "OAUTH_PROXY_AUTH_REFRESH"
    )]
    pub refresh_cookie: String,
}
