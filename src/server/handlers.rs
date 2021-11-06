use super::{api::LoginQuery, Settings};
use chrono::{DateTime, NaiveDateTime, Utc};
use futures::TryStreamExt;
use headers::HeaderMapExt;
use log::{error, warn};
use reqwest::{header::HeaderMap, Method};
use std::{convert::Infallible, sync::Arc};
use warp::http::{header, response, Response, StatusCode};

struct Token {
    raw: String,
    expires: Option<DateTime<Utc>>,
    raw_refresh: Option<String>,
}

pub async fn oauth_callback(
    settings: Arc<Settings>,
    login_query: LoginQuery,
) -> Result<impl warp::Reply, warp::Rejection> {
    if !settings.permit_login {
        warn!("Invalid login attempt (login not permitted)");
        return Err(warp::reject());
    }
    match settings
        .openid_client
        .request_token(&login_query.code)
        .await
    {
        Ok(bearer) => {
            let mut response = Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header(header::LOCATION, "/");
            if let Some(refresh_token) = bearer.refresh_token {
                response = add_refresh_cookie(settings.clone(), &refresh_token, response);
            }
            response = add_auth_cookie(
                settings,
                bearer.id_token.unwrap_or(bearer.access_token),
                bearer.expires,
                response,
            );

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

pub async fn proxy_request<S, B, E>(
    settings: Arc<Settings>,
    method: Method,
    path: warp::path::FullPath,
    query: Option<String>,
    headers: HeaderMap,
    body: S,
) -> Result<impl warp::Reply, Infallible>
where
    S: futures::stream::Stream<Item = Result<B, E>> + Sync + Send + 'static,
    B: bytes::Buf,
    E: std::error::Error + Send + Sync + 'static,
{
    let mut url = match settings.backend_url.join(path.as_str()) {
        Ok(url) => url,
        Err(err) => {
            error!("Invalid proxy url: {}", err);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(warp::hyper::Body::from("Invalid url")));
        }
    };
    url.set_query(query.as_deref());

    let token = match find_or_refresh_token(settings.clone(), &headers).await {
        Some(token) => token,
        None if settings.permit_login => {
            let login_url = settings.openid_client.auth_url(&openid::Options {
                scope: Some("openid email profile".to_string()),
                ..Default::default()
            });
            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, login_url.as_str())
                .body(warp::hyper::Body::empty()));
        }
        None => {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(warp::hyper::Body::from("Unauthorized")))
        }
    };

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

async fn refresh_token(settings: Arc<Settings>, headers: &HeaderMap) -> Option<Token> {
    let refresh_token = match headers
        .typed_get::<headers::Cookie>()
        .and_then(|cookie| cookie.get(&settings.refresh_cookie).map(str::to_string))
    {
        Some(token) => token,
        None => return None,
    };
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

fn parse_and_validate_token(settings: Arc<Settings>, raw: String) -> Option<Token> {
    let mut token = openid::IdToken::new_encoded(&raw);
    if let Err(err) = settings.openid_client.decode_token(&mut token) {
        warn!("Invalid id token, trying refresh: {}", err);
        return None;
    }
    if let Err(err) = settings.openid_client.validate_token(&token, None, None) {
        warn!("Token validation failed, trying refresh: {}", err);
        return None;
    }
    let expires = token
        .payload()
        .ok()
        .map(|claims| claims.exp)
        .filter(|exp| *exp > 0)
        .map(|exp| DateTime::from_utc(NaiveDateTime::from_timestamp(exp, 0), Utc));
    Some(Token {
        raw,
        expires,
        raw_refresh: None,
    })
}

fn mangle_proxy_request_headers(mut headers: HeaderMap) -> HeaderMap {
    headers.remove(header::AUTHORIZATION);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::HOST);

    headers
}

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
