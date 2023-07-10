use clap::Parser;

// Collection of all command-line/environment variables.
#[derive(Parser, Debug)]
#[clap(name = "oauth-proxy-rs", version = clap::crate_version!())]
pub struct Opts {
    #[clap(long, env = "OAUTH_PROXY_DEBUG", help = "Enable debug messages in log")]
    pub debug: bool,

    #[clap(
        long,
        env = "OAUTH_PROXY_JSON_LOG",
        help = "Log in json-format (ELK stack friendly)"
    )]
    pub json_log: bool,

    #[clap(
        long,
        env = "OAUTH_PROXY_PERMIT_LOGIN",
        help = "Permit login flow. If disabled the login has to be implemented elsewhere, oauth-proxy just assumes that the cookies or bearer auth are present."
    )]
    pub permit_login: bool,

    #[clap(
        long,
        env = "OAUTH_PROXY_CLIENT_ID",
        help = "The client id to communicate with the openid provider"
    )]
    pub client_id: String,

    #[clap(
        long,
        env = "OAUTH_PROXY_CLIENT_SECRET",
        help = "The client secret to communicate with the openid provider"
    )]
    pub client_secret: String,

    #[clap(
        long,
        env = "OAUTH_PROXY_ISSUER",
        help = "The issuer url of the openid provider (see openid discovery for details)"
    )]
    pub issuer: String,

    #[clap(
        long,
        env = "OAUTH_PROXY_SCOPES",
        default_value = "openid email profile",
        help = "Scopes to request on login"
    )]
    pub scopes: String,

    #[clap(
        long,
        default_value = "0.0.0.0:8080",
        env = "OAUTH_PROXY_BIND_ADDRESS",
        help = "Socket address to bind to"
    )]
    pub bind_address: String,

    #[clap(
        long,
        env = "OAUTH_PROXY_BACKEND",
        help = "Url of the backend service that should be proxies/protected"
    )]
    pub backend: String,

    #[clap(
        long,
        default_value = "12345678",
        env = "OAUTH_PROXY_COOKIE_SECRET",
        help = "Shared secret for cookie hmac-signing (only relevant for the login flow)"
    )]
    pub cookie_secret: String,

    #[clap(
        long,
        default_value = "OAUTH_PROXY_LOGIN",
        env = "OAUTH_PROXY_LOGIN_COOKIE",
        help = "Name of the temporary cookie to use during the login flow"
    )]
    pub login_cookie: String,

    #[clap(
        long,
        default_value = "OAUTH_PROXY_AUTH",
        env = "OAUTH_PROXY_AUTH_COOKIE",
        help = "Name of the cookie to store the id token (or access token if id token is not available)"
    )]
    pub auth_cookie: String,

    #[clap(
        long,
        default_value = "OAUTH_PROXY_REFRESH",
        env = "OAUTH_PROXY_REFRESH_COOKIE",
        help = "Name of the cookie to store the refresh token"
    )]
    pub refresh_cookie: String,

    #[clap(
        long,
        default_value = "/",
        env = "OAUTH_PROXY_COOKIE_PATH",
        help = "The cookie path to use"
    )]
    pub cookie_path: String,

    #[clap(
        long,
        env = "OAUTH_PROXY_COOKIE_SECURE",
        help = "Enforce the cookie secure flag"
    )]
    pub cookie_secure: bool,

    #[clap(
        long,
        env = "OAUTH_PROXY_COOKIE_DOMAIN",
        help = "The cookie domain to use"
    )]
    pub cookie_domain: Option<String>,
}
