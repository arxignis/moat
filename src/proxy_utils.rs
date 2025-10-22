use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, Uri};
use hyper::header::HeaderValue;
use hyper::header::HOST;
// Client and HttpConnector types are not referenced directly here

use crate::http::ProxyContext;

pub type ProxyBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

pub fn header_json() -> (hyper::header::HeaderName, hyper::header::HeaderValue) {
    (
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    )
}

pub fn json(s: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::<Bytes>::from(Bytes::from(format!("{s}\n"))));
    let (k, v) = header_json();
    r.headers_mut().insert(k, v);
    r
}

pub fn build_upstream_uri(incoming: &Uri, upstream: &Uri) -> Result<Uri> {
    let mut parts = upstream.clone().into_parts();
    parts.path_and_query.replace(
        incoming
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| "/".parse().unwrap()),
    );
    Uri::from_parts(parts).map_err(|e| anyhow!("failed to construct upstream uri: {e}"))
}

pub fn build_proxy_error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let body = serde_json::json!({
        "ok": false,
        "error": message,
    })
    .to_string();
    let boxed = Full::new(Bytes::from(body))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(boxed)
        .expect("valid response")
}

pub async fn forward_to_upstream_with_body(
    req_parts: &hyper::http::request::Parts,
    body_bytes: bytes::Bytes,
    ctx: std::sync::Arc<ProxyContext>,
) -> Result<Response<ProxyBody>> {
    let upstream_uri = build_upstream_uri(&req_parts.uri, &ctx.upstream)?;
    let mut builder = Request::builder()
        .method(req_parts.method.clone())
        .version(req_parts.version)
        .uri(upstream_uri.clone());

    for (name, value) in req_parts.headers.iter() {
        if name != HOST {
            builder = builder.header(name, value.clone());
        }
    }

    let mut outbound = builder
        .body(Full::new(body_bytes))
        .map_err(|e| anyhow!("failed to build proxy request: {e}"))?;

    if let Some(authority) = upstream_uri.authority() {
        outbound.headers_mut().insert(
            HOST,
            HeaderValue::from_str(authority.as_str())
                .map_err(|e| anyhow!("invalid upstream authority: {e}"))?,
        );
    }

    let response = ctx
        .client
        .request(outbound)
        .await
        .map_err(|e| anyhow!("upstream request error: {e}"))?;
    let (parts, body) = response.into_parts();
    let boxed = body.boxed();
    Ok(Response::from_parts(parts, boxed))
}


