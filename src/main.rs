
use std::{env, collections::HashMap};
use std::net::SocketAddr;
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

use tower_http::cors::CorsLayer;


// const
static RESPONSE_HEADER_CSP: &str = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';";


fn get_vrf_name() -> Option<String> {
    let vrf_name = env::var("VRF_NAME").ok();
    if let Some(vrf_name) = vrf_name {
        let vrf_name = vrf_name.trim();
        if !vrf_name.is_empty() {
            return Some(vrf_name.to_owned());
        }
    }

    None
}

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

    let host = if let Ok(host) = menhera_inet::dns::DnsHostname::new(host) {
        host
    } else {
        return make_error_response("Malformed host").into_response();
    };

    let host = host.to_string();

    if let Some(vrf_name) = get_vrf_name() {
        let ping = process::Command::new("ping")
            .arg("-c3")
            .arg("-I")
            .arg(&vrf_name)
            .arg(&host)
            .output()
            .await;

        if let Ok(output) = ping {
            return make_output_response(output).into_response();
        }

        return make_error_response("Failed to execute ping").into_response();
    }

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

    let host = if let Ok(host) = menhera_inet::dns::DnsHostname::new(host) {
        host
    } else {
        return make_error_response("Malformed host").into_response();
    };

    let host = host.to_string();

    if let Some(vrf_name) = get_vrf_name() {
        let traceroute = process::Command::new("traceroute")
            .arg("-q1")
            .arg("-w1")
            .arg("-m30")
            .arg("-A")
            .arg("--mtu")
            .arg("-e")
            .arg("-i")
            .arg(&vrf_name)
            .arg(&host)
            .output()
            .await;

        if let Ok(output) = traceroute {
            return make_output_response(output).into_response();
        }

        return make_error_response("Failed to execute traceroute").into_response();
    }

    let traceroute = process::Command::new("traceroute")
        .arg("-q1")
        .arg("-w1")
        .arg("-m30")
        .arg("-A")
        .arg("--mtu")
        .arg("-e")
        .arg(&host)
        .output()
        .await;

    if let Ok(output) = traceroute {
        return make_output_response(output).into_response();
    }

    make_error_response("Failed to execute traceroute").into_response()
}

async fn handler_api_v1_mtr(
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let host = if let Some(host) = params.get("host") {
        host
    } else {
        return make_error_response("Missing host parameter").into_response();
    };

    let host = if let Ok(host) = menhera_inet::dns::DnsHostname::new(host) {
        host
    } else {
        return make_error_response("Malformed host").into_response();
    };

    let host = host.to_string();

    if let Some(vrf_name) = get_vrf_name() {
        let traceroute = process::Command::new("mtr")
            .arg("-zewc3")
            .arg("-I")
            .arg(&vrf_name)
            .arg(&host)
            .output()
            .await;

        if let Ok(output) = traceroute {
            return make_output_response(output).into_response();
        }

        return make_error_response("Failed to execute traceroute").into_response();
    }

    let traceroute = process::Command::new("mtr")
        .arg("-zewc3")
        .arg(&host)
        .output()
        .await;

    if let Ok(output) = traceroute {
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

    let target = if let Ok(target) = menhera_inet::inet::InetTarget::from_str(&address) {
        target
    } else {
        return make_error_response("Malformed address").into_response();
    };

    let command = if let Some(vrf_name) = get_vrf_name() {
        match target {
            menhera_inet::inet::InetTarget::V4(v4_addr) => {
                format!("sh bgp vrf {vrf_name} ipv4 unicast {v4_addr}")
            }
            menhera_inet::inet::InetTarget::V6(v6_addr) => {
                format!("sh bgp vrf {vrf_name} ipv6 unicast {v6_addr}")
            }
        }
    } else {
        match target {
            menhera_inet::inet::InetTarget::V4(v4_addr) => {
                format!("sh bgp ipv4 unicast {v4_addr}")
            }
            menhera_inet::inet::InetTarget::V6(v6_addr) => {
                format!("sh bgp ipv6 unicast {v6_addr}")
            }
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

    let origin = env::var("CORS_ORIGIN").unwrap_or("https://looking-glass.nc.menhera.org".to_string());
    let cors = CorsLayer::new()
        .allow_origin(origin.parse::<hyper::header::HeaderValue>().unwrap())
        .allow_credentials(true)
        .allow_methods(vec![Method::GET]);

    // define routes
    let app = Router::new()
        .route("/api/v1/ping", get(handler_api_v1_ping))
        .route("/api/v1/traceroute", get(handler_api_v1_traceroute))
        .route("/api/v1/mtr", get(handler_api_v1_mtr))
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
