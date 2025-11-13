use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use log::{error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Start the captcha verification server on port 9181
pub async fn start_captcha_server() -> anyhow::Result<()> {
    let app = Router::new()
        .route("/cgi-bin/captcha/verify", post(handle_captcha_verification))
        .route("/health", get(health_check));

    let addr = "127.0.0.1:9181";
    let listener = TcpListener::bind(addr).await?;
    info!("Starting captcha verification server on: {}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Handle captcha verification requests
async fn handle_captcha_verification(
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    State(()): State<()>,
    body: Bytes,
) -> Response {
    use crate::waf::actions::captcha::{validate_and_mark_captcha, apply_captcha_challenge};

    info!("Starting captcha verification handler from: {} with body size: {}", peer_addr, body.len());

    // Parse form data from request body
    let form_data: HashMap<String, String> = match String::from_utf8(body.to_vec()) {
        Ok(body_str) => {
            info!("Captcha verification request body: {}", body_str);
            url::form_urlencoded::parse(body_str.as_bytes())
                .into_owned()
                .collect()
        }
        Err(e) => {
            error!("Failed to parse captcha verification request body as UTF-8: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid request body").into_response();
        }
    };

    info!("Parsed form data: {:?}", form_data);

    // Extract captcha response and JWT token from form data
    let captcha_response = match form_data.get("captcha_response") {
        Some(response) => response.clone(),
        None => {
            warn!("Missing captcha_response in verification request from {}", peer_addr.ip());
            return (StatusCode::BAD_REQUEST, "Missing captcha_response").into_response();
        }
    };

    let jwt_token = match form_data.get("jwt_token") {
        Some(token) => token.clone(),
        None => {
            warn!("Missing jwt_token in verification request from {}", peer_addr.ip());
            return (StatusCode::BAD_REQUEST, "Missing jwt_token").into_response();
        }
    };

    // Get user agent from request (would need to be passed in a real implementation)
    let user_agent = String::from("Mozilla/5.0"); // Placeholder

    // Validate captcha and mark token as validated
    match validate_and_mark_captcha(
        captcha_response,
        jwt_token.clone(),
        peer_addr.ip().to_string(),
        Some(user_agent),
    )
    .await
    {
        Ok(true) => {
            info!("Captcha verification successful for IP: {}", peer_addr.ip());

            // Return 302 redirect with Set-Cookie header
            Response::builder()
                .status(StatusCode::FOUND)
                .header("Location", "/")
                .header(
                    "Set-Cookie",
                    format!(
                        "captcha_token={}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax",
                        jwt_token
                    ),
                )
                .header("Cache-Control", "no-cache, no-store, must-revalidate")
                .header("Pragma", "no-cache")
                .header("Expires", "0")
                .body(Body::empty())
                .unwrap()
        }
        Ok(false) => {
            warn!("Captcha verification failed for IP: {}", peer_addr.ip());

            // Generate failure page with retry option
            let failure_html = apply_captcha_challenge().unwrap_or_else(|_| {
                r#"<!DOCTYPE html>
<html>
<head>
    <title>Verification Failed</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
        .error { color: red; margin: 20px 0; }
    </style>
</head>
<body>
    <h2>Verification Failed</h2>
    <div class="error">
        <p>Captcha verification failed. Please try again.</p>
        <p><a href="/">Return to main page</a></p>
    </div>
</body>
</html>"#
                .to_string()
            });

            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "text/html; charset=utf-8")
                .header("Cache-Control", "no-cache, no-store, must-revalidate")
                .header("Pragma", "no-cache")
                .header("Expires", "0")
                .body(Body::from(failure_html))
                .unwrap()
        }
        Err(e) => {
            error!("Captcha verification error for IP {}: {}", peer_addr.ip(), e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Verification error").into_response()
        }
    }
}

