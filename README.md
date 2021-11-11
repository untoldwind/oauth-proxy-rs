# oauth-proxy-rs

A minimalists implementation of an oauth-proxy (like [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) or similar) in rust with very little overhead.

Apart from that there are no real selling points, in most cases you probably want to use one of the existing solutions instead.

## Usage

The command-line help should (hopefully) explain it all:

```command-line
oauth-proxy-rs 0.1.4

USAGE:
    oauth-proxy-rs [OPTIONS] --client-id <CLIENT_ID> --client-secret <CLIENT_SECRET> --issuer <ISSUER> --backend <BACKEND>

OPTIONS:
        --auth-cookie <AUTH_COOKIE>
            Name of the cookie to store the id token (or access token if id token is not available)
            [env: OAUTH_PROXY_AUTH_COOKIE=] [default: OAUTH_PROXY_AUTH]

        --backend <BACKEND>
            Url of the backend service that should be proxies/protected [env: OAUTH_PROXY_BACKEND=]

        --bind-address <BIND_ADDRESS>
            Socket address to bind to [env: OAUTH_PROXY_BIND_ADDRESS=] [default: 0.0.0.0:8080]

        --client-id <CLIENT_ID>
            The client id to communicate with the openid provider [env: OAUTH_PROXY_CLIENT_ID=]

        --client-secret <CLIENT_SECRET>
            The client secret to communicate with the openid provider [env:
            OAUTH_PROXY_CLIENT_SECRET=]

        --cookie-domain <COOKIE_DOMAIN>
            The cookie domain to use [env: OAUTH_PROXY_COOKIE_DOMAIN=]

        --cookie-path <COOKIE_PATH>
            The cookie path to use [env: OAUTH_PROXY_COOKIE_PATH=] [default: /]

        --cookie-secret <COOKIE_SECRET>
            Shared secret for cookie hmac-signing (only relevant for the login flow) [env:
            OAUTH_PROXY_COOKIE_SECRET=] [default: 12345678]

        --cookie-secure
            Enforce the cookie secure flag [env: OAUTH_PROXY_COOKIE_SECURE=]

        --debug
            Enable debug messages in log [env: OAUTH_PROXY_DEBUG=]

    -h, --help
            Print help information

        --issuer <ISSUER>
            The issuer url of the openid provider (see openid discovery for details) [env:
            OAUTH_PROXY_ISSUER=]

        --json-log
            Log in json-format (ELK stack friendly) [env: OAUTH_PROXY_JSON_LOG=]

        --login-cookie <LOGIN_COOKIE>
            Name of the temporary cookie to use during the login flow [env:
            OAUTH_PROXY_LOGIN_COOKIE=] [default: OAUTH_PROXY_LOGIN]

        --permit-login
            Permit login flow. If disabled the login has to be implemented elsewhere, oauth-proxy
            just assumes that the cookies or bearer auth are present. [env:
            OAUTH_PROXY_PERMIT_LOGIN=]

        --refresh-cookie <REFRESH_COOKIE>
            Name of the cookie to store the refresh token [env: OAUTH_PROXY_REFRESH_COOKIE=]
            [default: OAUTH_PROXY_REFRESH]

        --scopes <SCOPES>
            Scopes to request on login [env: OAUTH_PROXY_SCOPES=] [default: "openid email profile"]

    -V, --version
            Print version information
```

## Example

The example folder contains a ready to go setup using keycloak as openid provider and `traefik/whoami` as backend:

```
cd example
docker-compose up -d
```

You can login to administrator console of keycloak via `http://localhost:8180` with user `admin` password `admin`, inside the demo realm you then should create any number of users.

Via `http://localhost:8080` you access the `oauth-proxy-rs` which is using the demo realm to authorize all requests to the underlying `whoami` service.
