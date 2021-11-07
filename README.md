# oauth-proxy-rs

A minimalists implementation of an oauth-proxy (like [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) or similar) in rust with very little overhead.

Apart from that there are no real selling points, in most cases you probably want to use one of the existing solutions instead.


## Example

The example folder contains a ready to go setup using keycloak as openid provider and `traefik/whoami` as backend:

```
cd example
docker-compose up -d
```

You can login to administrator console of keycloak via `http://localhost:8180` with user `admin` password `admin`, inside the demo realm you then should create any number of users.

Via `http://localhost:8080` you access the `oauth-proxy-rs` which is using the demo realm to authorize all requests to the underlying `whoami` service.
