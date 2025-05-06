
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
    extract::State,
};

use hyper::Method;

use tower_http::cors::CorsLayer;

use parking_lot::RwLock;

use std::sync::Arc;

// const
static RESPONSE_HEADER_CSP: &str = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';";

#[derive(Debug, Clone, serde::Serialize)]
struct AsInfo {
    as_number: u32,
    as_name: String,
    as_description: String,
    as_country: String,
}

#[derive(Debug, Clone)]
struct AppState {
    as_info: Arc<RwLock<HashMap<u32, AsInfo>>>,
}

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

fn make_json_response(output: &str) -> impl IntoResponse {
    Json(serde_json::from_str(output).map(|v: serde_json::Value| serde_json::json!({
        "error": serde_json::Value::Null,
        "result": v,
    })).unwrap_or_else(|_| serde_json::json!({
        "error": "Failed to parse JSON",
        "result": serde_json::Value::Null,
    }))).into_response()
}

fn validate_host(host: &str) -> Result<String, String> {
    let host = if let Ok(ip) = std::net::IpAddr::from_str(host) {
        ip.to_string()
    } else {
        let host = if let Ok(host) = menhera_inet::dns::DnsHostname::new(host) {
            host
        } else {
            return Err("Malformed host".to_string());
        };
        host.to_string()
    };

    Ok(host)
}

async fn handler_api_v1_ping(
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let host = if let Some(host) = params.get("host") {
        host
    } else {
        return make_error_response("Missing host parameter").into_response();
    };

    let host = match validate_host(host) {
        Ok(host) => host,
        Err(err) => return make_error_response(&err).into_response(),
    };

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

    let host = match validate_host(host) {
        Ok(host) => host,
        Err(err) => return make_error_response(&err).into_response(),
    };

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

    let host = match validate_host(host) {
        Ok(host) => host,
        Err(err) => return make_error_response(&err).into_response(),
    };

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

async fn handler_api_v1_bgp_json(
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
                format!("sh bgp vrf {vrf_name} ipv4 unicast {v4_addr} json")
            }
            menhera_inet::inet::InetTarget::V6(v6_addr) => {
                format!("sh bgp vrf {vrf_name} ipv6 unicast {v6_addr} json")
            }
        }
    } else {
        match target {
            menhera_inet::inet::InetTarget::V4(v4_addr) => {
                format!("sh bgp ipv4 unicast {v4_addr} json")
            }
            menhera_inet::inet::InetTarget::V6(v6_addr) => {
                format!("sh bgp ipv6 unicast {v6_addr} json")
            }
        }
    };

    let vtysh = process::Command::new("vtysh")
        .arg("-c")
        .arg(&command)
        .output()
        .await;

    if let Ok(output) = vtysh {
        return make_json_response(&String::from_utf8(output.stdout).unwrap_or("".to_string())).into_response();
    }

    make_error_response("Failed to execute sh bgp").into_response()
}

async fn handler_api_v1_bgp_asn_v4_json(
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let address = if let Some(addr) = params.get("asn") {
        addr
    } else {
        return make_error_response("Missing asn parameter").into_response();
    };

    let target = if let Ok(target) = u32::from_str(&address) {
        target
    } else {
        return make_error_response("Malformed asn").into_response();
    };

    let command = if let Some(vrf_name) = get_vrf_name() {
        format!("sh bgp vrf {vrf_name} ipv4 unicast regexp _{target}$ json")
    } else {
        format!("sh bgp ipv4 unicast regexp _{target}$ json")
    };

    let output_v4 = process::Command::new("vtysh")
        .arg("-c")
        .arg(&command)
        .output()
        .await;

    let res_v4 = if let Ok(output) = output_v4 {
        String::from_utf8_lossy(&output.stdout).to_string()
    } else {
        return make_error_response("Failed to execute sh bgp").into_response();
    };

    make_json_response(&res_v4).into_response()
}

async fn handler_api_v1_bgp_asn_v6_json(
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let address = if let Some(addr) = params.get("asn") {
        addr
    } else {
        return make_error_response("Missing asn parameter").into_response();
    };

    let target = if let Ok(target) = u32::from_str(&address) {
        target
    } else {
        return make_error_response("Malformed asn").into_response();
    };

    let command = if let Some(vrf_name) = get_vrf_name() {
        format!("sh bgp vrf {vrf_name} ipv6 unicast regexp _{target}$ json")
    } else {
        format!("sh bgp ipv6 unicast regexp _{target}$ json")
    };

    let output_v6 = process::Command::new("vtysh")
        .arg("-c")
        .arg(&command)
        .output()
        .await;

    let res_v6 = if let Ok(output) = output_v6 {
        String::from_utf8_lossy(&output.stdout).to_string()
    } else {
        return make_error_response("Failed to execute sh bgp").into_response();
    };

    make_json_response(&res_v6).into_response()
}

async fn handler_api_v1_as_info(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let as_number = if let Some(as_number) = params.get("asn") {
        as_number
    } else {
        return make_error_response("Missing as_number parameter").into_response();
    };

    let as_number = match as_number.parse::<u32>() {
        Ok(as_number) => as_number,
        Err(_) => return make_error_response("Invalid as_number").into_response(),
    };

    let as_info = state.as_info.read();
    if let Some(as_info) = as_info.get(&as_number) {
        return Json(serde_json::json!({
            "error": serde_json::Value::Null,
            "result": as_info,
        })).into_response();
    }

    make_error_response("AS number not found").into_response()
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

    let state = AppState {
        as_info: Arc::new(RwLock::new(HashMap::new())),
    };

    // define routes
    let app = Router::new()
        .route("/api/v1/ping", get(handler_api_v1_ping))
        .route("/api/v1/traceroute", get(handler_api_v1_traceroute))
        .route("/api/v1/mtr", get(handler_api_v1_mtr))
        .route("/api/v1/bgp", get(handler_api_v1_bgp))
        .route("/api/v1/bgp/json", get(handler_api_v1_bgp_json))
        .route("/api/v1/bgp/asn/v4/json", get(handler_api_v1_bgp_asn_v4_json))
        .route("/api/v1/bgp/asn/v6/json", get(handler_api_v1_bgp_asn_v6_json))
        .route("/api/v1/as_info", get(handler_api_v1_as_info))

        // 404 page
        .fallback(handler_404)

        .layer(cors)
        .layer(axum::middleware::from_fn(add_global_headers))
        .with_state(state.clone());

    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
        let asn_txt_url = "https://ftp.ripe.net/ripe/asnames/asn.txt";
        let sleep_intervals = vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768]; // in seconds
        loop {
            interval.tick().await;

            let mut as_info_new = HashMap::new();
            for i in 0..sleep_intervals.len() {
                let sleep_interval = sleep_intervals[i];
                let sleep_interval = std::time::Duration::from_secs(sleep_interval);
                tokio::time::sleep(sleep_interval).await;

                let response = client.get(asn_txt_url).send().await;
                if let Ok(response) = response {
                    let body = response.text().await;
                    if let Ok(body) = body {
                        for line in body.lines() {
                            if line.starts_with("#") {
                                continue;
                            }

                            let parts: Vec<&str> = line.splitn(2, ",").collect();
                            if parts.len() != 2 {
                                continue;
                            }

                            let country_code = parts[1].trim();
                            let parts = parts[0].splitn(3, " ").collect::<Vec<&str>>();
                            if parts.len() < 2 {
                                continue;
                            }

                            let as_name = parts[1].trim();
                            let as_description = parts[2..].join(" ").trim().to_string();

                            let as_number = parts[0].parse::<u32>();
                            if let Ok(as_number) = as_number {
                                as_info_new.insert(as_number, AsInfo {
                                    as_number: as_number,
                                    as_name: as_name.to_string(),
                                    as_description,
                                    as_country: country_code.to_string(),
                                });
                            }
                        }

                        let mut as_info = state.as_info.write();
                        *as_info = as_info_new.clone();
                        break;
                    }
                }
            }
        }
    });

    // run server
    let server = Server::bind(&addr).serve(app.into_make_service());
    log::info!("Listening on http://{}", &addr);
    server.await?;

    Ok(())
}
