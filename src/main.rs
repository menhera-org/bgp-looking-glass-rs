
use std::{env, collections::HashMap};
use std::net::{SocketAddr, IpAddr};
use std::str::FromStr;

use tokio::process;

use hyper::{Request, StatusCode};
use axum::{
    routing::get,
    Router,
    Server,
    response::{IntoResponse, Response},
    Json,
    middleware::Next,
    extract::Query,
};

use hyper::Method;

use tower_http::cors::{
    CorsLayer,
    AllowOrigin,
};


// const
static RESPONSE_HEADER_CSP: &str = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';";


async fn handler_404() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "Not found",
        })),
    )
}

fn make_error_response(msg: &str) -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": msg.to_string(),
        })),
    )
}

fn make_output_response(output: std::process::Output) -> impl IntoResponse {
    let stdout_orig = String::from_utf8_lossy(&output.stdout);
    let stderr_orig = String::from_utf8_lossy(&output.stderr);
    let stdout = stdout_orig.trim();
    let stderr = stderr_orig.trim();
    if stderr.is_empty() {
        return Json(serde_json::json!({
            "error": serde_json::Value::Null,
            "result": stdout,
        })).into_response();
    }

    Json(serde_json::json!({
        "error": stderr,
        "result": stdout,
    })).into_response()
}

async fn handler_api_v1_ping(
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let host = if let Some(host) = params.get("host") {
        host
    } else {
        return make_error_response("Missing host parameter").into_response();
    };

    let ping = process::Command::new("ping")
        .arg("-c3")
        .arg(&host)
        .output()
        .await;

    if let Ok(output) = ping {
        return make_output_response(output).into_response();
    }

    make_error_response("Failed to execute ping").into_response()
}

async fn handler_api_v1_traceroute(
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let host = if let Some(host) = params.get("host") {
        host
    } else {
        return make_error_response("Missing host parameter").into_response();
    };

    let ping = process::Command::new("traceroute")
        .arg("-q1")
        .arg("-w1")
        .arg(&host)
        .output()
        .await;

    if let Ok(output) = ping {
        return make_output_response(output).into_response();
    }

    make_error_response("Failed to execute traceroute").into_response()
}

async fn handler_api_v1_bgp(
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let address = if let Some(addr) = params.get("address") {
        addr
    } else {
        return make_error_response("Missing address parameter").into_response();
    };

    let address = if let Ok(addr) = IpAddr::from_str(address) {
        addr
    } else {
        return make_error_response("Malformed address").into_response();
    };

    let address = match address {
        IpAddr::V4(v4_addr) => {
            IpAddr::V4(v4_addr)
        }
        IpAddr::V6(v6_addr) => {
            if let Some(v4_addr) = v6_addr.to_ipv4_mapped() {
                IpAddr::V4(v4_addr)
            } else {
                IpAddr::V6(v6_addr)
            }
        }
    };

    let command = match address {
        IpAddr::V4(v4_addr) => {
            format!("sh bgp ipv4 unicast {v4_addr}")
        }
        IpAddr::V6(v6_addr) => {
            format!("sh bgp ipv6 unicast {v6_addr}")
        }
    };

    let vtysh = process::Command::new("vtysh")
        .arg("-c")
        .arg(&command)
        .output()
        .await;

    if let Ok(output) = vtysh {
        return make_output_response(output).into_response();
    }

    make_error_response("Failed to execute sh bgp").into_response()
}

async fn add_global_headers<B>(req: Request<B>, next: Next<B>) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.append("content-security-policy", RESPONSE_HEADER_CSP.parse().unwrap());
    res
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // bind address
    let addr_string = env::var("LISTEN_ADDR").unwrap_or("".to_string());
    let addr = SocketAddr::from_str(&addr_string).unwrap_or(SocketAddr::from(([127, 0, 0, 1], 7777)));

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::any())
        .allow_methods(vec![Method::GET]);

    // define routes
    let app = Router::new()
        .route("/api/v1/ping", get(handler_api_v1_ping))
        .route("/api/v1/traceroute", get(handler_api_v1_traceroute))
        .route("/api/v1/bgp", get(handler_api_v1_bgp))

        // 404 page
        .fallback(handler_404)

        .layer(cors)
        .layer(axum::middleware::from_fn(add_global_headers));

    // run server
    let server = Server::bind(&addr).serve(app.into_make_service());
    log::info!("Listening on http://{}", &addr);
    server.await?;

    Ok(())
}
