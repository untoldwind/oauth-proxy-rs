use super::{api::LoginQuery, Settings};
use base64::{engine::general_purpose, Engine as _};
use bytes::{BufMut, BytesMut};
use chrono::{DateTime, TimeZone, Utc};
use futures::TryStreamExt;
use headers::HeaderMapExt;
use log::{error, info, warn};
use openid::Claims;
use reqwest::{header::HeaderMap, Method, Url};
use std::{convert::Infallible, sync::Arc};
use warp::http::{header, response, Response, StatusCode};

// Boiled down version of the openid::Bearer struct, only
// containing the tokens relevant to the proxy.
struct Token {
    raw: String,
    expires: Option<DateTime<Utc>>,
    raw_refresh: Option<String>,
}

// Handle an oauth callback, i.e. complete the openid login flow.
pub async fn oauth_callback(
    settings: Arc<Settings>,
    login_query: LoginQuery,
    headers: HeaderMap,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Verify that login is allowed and this is a legitimate reply from the openid provider.
    if !settings.permit_login {
        warn!("Invalid login attempt (login not permitted)");
        return Err(warp::reject());
    }
    let (expected_state, redirect_url, origin) =
        match validate_login_cookie(settings.clone(), &headers) {
            Some(validated) => validated,
            None => {
                error!("Login cookie validation failed");
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body("Unauthorized"));
            }
        };
    if login_query.state != Some(expected_state) {
        error!("Login state mismatch");
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body("Unauthorized"));
    }

    // Workaround: The redirect_uri might not be a constant as it might
    // depend on the X-Forwarded-Host/X-Forwarded-Proto headers
    let mut openid_client = settings.openid_client.clone();

    openid_client.redirect_uri = Some(redirect_url);

    // Exchange the authcode to an actual set of tokens
    match openid_client.request_token(&login_query.code).await {
        Ok(bearer) => {
            // If successful: Store the tokens in their corresponding cookies.
            let mut response = Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header(header::LOCATION, origin);
            if let Some(refresh_token) = bearer.refresh_token {
                response = add_refresh_cookie(settings.clone(), &refresh_token, response);
            }
            response = add_auth_cookie(
                settings.clone(),
                bearer.id_token.unwrap_or(bearer.access_token),
                bearer.expires,
                response,
            );

            let mut login_cookie = cookie::Cookie::build(&settings.login_cookie, "")
                .http_only(true)
                .path(&settings.cookie_path)
                .secure(settings.cookie_secure)
                .max_age(time::Duration::seconds(0));
            if let Some(cookie_domain) = &settings.cookie_domain {
                login_cookie = login_cookie.domain(cookie_domain);
            }
            response = response.header(header::SET_COOKIE, login_cookie.finish().to_string());

            Ok(response.body(""))
        }
        Err(err) => {
            error!("login error in call: {}", err);

            Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("Unauthorized"))
        }
    }
}

// Construct a response to redirect to the login-page of the openid-provider.
fn login_redirect(
    settings: Arc<Settings>,
    origin: Url,
) -> warp::http::Result<warp::http::Response<warp::hyper::Body>> {
    let state = uuid::Uuid::new_v4().to_string();
    // Construct redirect_uri based on the external hostname (that might come from X-Forwarded-Host)
    let redirect_url = if let Some(port) = origin.port() {
        format!(
            "{}://{}:{}/oauth/callback",
            origin.scheme(),
            origin.host_str().unwrap_or("localhost"),
            port
        )
    } else {
        format!(
            "{}://{}/oauth/callback",
            origin.scheme(),
            origin.host_str().unwrap_or("localhost")
        )
    };

    // Construct a hmac signed cookie so that the oauth callback can check if the request if legit.
    let mut payload = BytesMut::new();
    payload.put(state.as_bytes());
    payload.put_u8(0);
    payload.put(redirect_url.as_bytes());
    payload.put_u8(0);
    payload.put(origin.to_string().as_bytes());
    let hmac = hmac_sha256::HMAC::mac(&payload, settings.cookie_secret.as_bytes());

    let mut login_cookie = cookie::Cookie::build(
        &settings.login_cookie,
        format!(
            "{}.{}",
            general_purpose::URL_SAFE_NO_PAD.encode(payload),
            general_purpose::URL_SAFE_NO_PAD.encode(hmac),
        ),
    )
    .http_only(true)
    .path(&settings.cookie_path)
    .secure(settings.cookie_secure);
    if let Some(cookie_domain) = &settings.cookie_domain {
        login_cookie = login_cookie.domain(cookie_domain);
    }

    // Workaround: redirect_uri might not be constant
    let mut openid_client = settings.openid_client.clone();

    openid_client.redirect_uri = Some(redirect_url);

    // Actually build the entire uri to redirect to.
    let login_url = openid_client.auth_url(&openid::Options {
        state: Some(state),
        scope: Some(settings.scopes.clone()),
        ..Default::default()
    });

    return Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, login_url.as_str())
        .header(header::SET_COOKIE, login_cookie.finish().to_string())
        .body(warp::hyper::Body::empty());
}

// Validate the contents of the temporary cookie used during the login flow
// (i.e. that is constructed in login_redirect and consumed in oauth_callback)
fn validate_login_cookie(
    settings: Arc<Settings>,
    headers: &HeaderMap,
) -> Option<(String, String, String)> {
    let login_cookie = headers
        .typed_get::<headers::Cookie>()
        .and_then(|cookie| cookie.get(&settings.login_cookie).map(str::to_string))?;
    let mut parts = login_cookie.split('.');
    let payload = general_purpose::URL_SAFE_NO_PAD
        .decode(parts.next()?)
        .ok()?;
    let signature = general_purpose::URL_SAFE_NO_PAD
        .decode(parts.next()?)
        .ok()?;
    let hmac = hmac_sha256::HMAC::mac(&payload, settings.cookie_secret.as_bytes());

    // There is no need to be subtle here, all the information is already exposed
    if &hmac[..] != signature.as_slice() {
        return None;
    }
    let mut payload_parts = payload.split(|b| *b == 0u8);
    let state = String::from_utf8(payload_parts.next()?.to_vec()).ok()?;
    let redirect_url = String::from_utf8(payload_parts.next()?.to_vec()).ok()?;
    let origin = String::from_utf8(payload_parts.next()?.to_vec()).ok()?;

    Some((state, redirect_url, origin))
}

// Handle a request forward/proxy.
pub async fn proxy_request<S, B, E>(
    settings: Arc<Settings>,
    method: Method,
    mut url: Url,
    headers: HeaderMap,
    body: S,
) -> Result<impl warp::Reply, Infallible>
where
    S: futures::stream::Stream<Item = Result<B, E>> + Sync + Send + 'static,
    B: bytes::Buf,
    E: std::error::Error + Send + Sync + 'static,
{
    // Check if the request is authorized and maybe redirect to login-page if login is permitted.
    let token = match find_or_refresh_token(settings.clone(), &headers).await {
        Some(token) => token,
        None if settings.permit_login => {
            return Ok(login_redirect(settings.clone(), url));
        }
        None => {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(warp::hyper::Body::from("Unauthorized")))
        }
    };

    // Replace scheme/host/port/username with those of the backend
    url.set_scheme(settings.backend_url.scheme()).ok();
    url.set_host(settings.backend_url.host_str()).ok();
    url.set_port(settings.backend_url.port()).ok();
    url.set_username(settings.backend_url.username()).ok();

    // Execute the request on the backend and return the result with as little change as possible.
    let backend_response = settings
        .http_client
        .request(method, url)
        .headers(mangle_proxy_request_headers(headers))
        .bearer_auth(&token.raw)
        .body(reqwest::Body::wrap_stream(
            body.map_ok(|mut buf| buf.copy_to_bytes(buf.remaining())),
        ))
        .send()
        .await
        .unwrap();

    Ok(mangle_proxy_response_headers(
        settings,
        backend_response.headers(),
        token,
        Response::builder().status(backend_response.status()),
    )
    .body(warp::hyper::Body::wrap_stream(
        backend_response.bytes_stream(),
    )))
}

// Find and validate the id token in the auth cookie or in the authorization header.
// If token does not exists or has expired, try a refresh to get a new one
async fn find_or_refresh_token(settings: Arc<Settings>, headers: &HeaderMap) -> Option<Token> {
    let maybe_token = headers
        .typed_get::<headers::Authorization<headers::authorization::Bearer>>()
        .map(|auth| auth.0.token().to_string())
        .or_else(|| {
            headers
                .typed_get::<headers::Cookie>()
                .and_then(|cookie| cookie.get(&settings.auth_cookie).map(str::to_string))
        });

    match maybe_token.and_then(|raw_token| parse_and_validate_token(settings.clone(), raw_token)) {
        Some(token) => Some(token),
        None => refresh_token(settings, headers).await,
    }
}

// Try to get a new id token with the refresh token.
async fn refresh_token(settings: Arc<Settings>, headers: &HeaderMap) -> Option<Token> {
    let refresh_token = match headers
        .typed_get::<headers::Cookie>()
        .and_then(|cookie| cookie.get(&settings.refresh_cookie).map(str::to_string))
    {
        Some(token) => token,
        None => {
            info!("No refresh token present");
            return None;
        }
    };
    info!("Trying token refresh");
    match settings
        .openid_client
        .refresh_token(
            openid::Bearer {
                access_token: "".to_string(),
                refresh_token: Some(refresh_token),
                expires: None,
                id_token: None,
                scope: None,
            },
            None,
        )
        .await
    {
        Ok(bearer) => Some(Token {
            raw: bearer.id_token.unwrap_or(bearer.access_token),
            expires: bearer.expires,
            raw_refresh: bearer.refresh_token,
        }),
        Err(err) => {
            error!("Token refresh failed: {}", err);
            None
        }
    }
}

// Validate an id token.
fn parse_and_validate_token(settings: Arc<Settings>, raw: String) -> Option<Token> {
    let mut token = openid::IdToken::new_encoded(&raw);
    if let Err(err) = settings.openid_client.decode_token(&mut token) {
        warn!("Invalid id token, trying refresh: {}", err);
        return None;
    }
    if let Err(err) = settings.openid_client.validate_token(
        &token,
        token
            .payload()
            .ok()
            .and_then(|p| p.nonce())
            .map(String::as_str),
        None,
    ) {
        warn!("Token validation failed, trying refresh: {}", err);
        return None;
    }
    let expires = token
        .payload()
        .ok()
        .map(|claims| claims.exp)
        .filter(|exp| *exp > 0)
        .map(|exp| Utc.timestamp_opt(exp, 0).unwrap());
    Some(Token {
        raw,
        expires,
        raw_refresh: None,
    })
}

// Mangle the http request headers (proxy -> backend), i.e. remove
// everything that might in get way.
fn mangle_proxy_request_headers(mut headers: HeaderMap) -> HeaderMap {
    headers.remove(header::AUTHORIZATION);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::HOST);

    headers
}

// Mangle the http response headers (proxy <- backend), i.e. remove
// everything that might get in the way.
fn mangle_proxy_response_headers(
    settings: Arc<Settings>,
    headers: &HeaderMap,
    token: Token,
    mut response: response::Builder,
) -> response::Builder {
    for (key, value) in headers {
        match key {
            &header::TRANSFER_ENCODING => (),
            other_key => response = response.header(other_key, value),
        }
    }
    if let Some(refresh_token) = token.raw_refresh {
        response = add_refresh_cookie(settings.clone(), &refresh_token, response);
        response = add_auth_cookie(settings, token.raw, token.expires, response);
    }

    response
}

// Add a new refresh cookie to the response
fn add_refresh_cookie(
    settings: Arc<Settings>,
    refresh_token: &str,
    response: response::Builder,
) -> response::Builder {
    let mut refresh_cookie = cookie::Cookie::build(&settings.refresh_cookie, refresh_token)
        .http_only(true)
        .path(&settings.cookie_path)
        .secure(settings.cookie_secure);
    if let Some(cookie_domain) = &settings.cookie_domain {
        refresh_cookie = refresh_cookie.domain(cookie_domain);
    }
    response.header(header::SET_COOKIE, refresh_cookie.finish().to_string())
}

// Add a new auth cookie to the response
fn add_auth_cookie(
    settings: Arc<Settings>,
    auth_token: String,
    maybe_expires: Option<DateTime<Utc>>,
    response: response::Builder,
) -> response::Builder {
    let mut auth_cookie = cookie::Cookie::build(&settings.auth_cookie, auth_token)
        .http_only(true)
        .path(&settings.cookie_path)
        .secure(settings.cookie_secure);
    if let Some(cookie_domain) = &settings.cookie_domain {
        auth_cookie = auth_cookie.domain(cookie_domain);
    }
    if let Some(expires) = maybe_expires {
        let maxage = (expires - Utc::now()).num_seconds();
        if maxage > 0 {
            auth_cookie = auth_cookie.max_age(time::Duration::seconds(maxage));
        }
    }
    response.header(header::SET_COOKIE, auth_cookie.finish().to_string())
}
