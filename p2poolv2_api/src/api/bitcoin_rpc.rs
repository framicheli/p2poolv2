// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::Engine;
use bitcoindrpc::{BitcoinRpcConfig, BitcoindRpcClient, BitcoindRpcError};
use p2poolv2_lib::config::BitcoinRpcApiConfig;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::{sync::oneshot, task::JoinHandle};
use tracing::{info, warn};

const ALLOWED_METHODS: [&str; 16] = [
    "getbestblockhash",
    "getblock",
    "getblockchaininfo",
    "getblockcount",
    "getblockfilter",
    "getblockhash",
    "getblockheader",
    "getmempoolentry",
    "getnetworkinfo",
    "getrawmempool",
    "getrawtransaction",
    "gettxout",
    "estimatesmartfee",
    "sendrawtransaction",
    "testmempoolaccept",
    "decoderawtransaction",
];

const WALLET_METHODS: [&str; 13] = [
    "createrawtransaction",
    "createwallet",
    "getbalance",
    "getbalances",
    "gettransaction",
    "getwalletinfo",
    "importdescriptors",
    "listunspent",
    "listwallets",
    "loadwallet",
    "rescanblockchain",
    "signrawtransactionwithwallet",
    "unloadwallet",
];

const PARSE_ERROR: i32 = -32700;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;
const INTERNAL_ERROR: i32 = -32603;

#[derive(Clone)]
struct BitcoinRpcState {
    client: BitcoindRpcClient,
    max_batch_size: usize,
    wallet_rpc_enabled: bool,
    rpcuser: String,
    rpcpassword: String,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RpcVersion {
    Legacy,
    V2,
}

impl RpcVersion {
    fn from_request(request: &serde_json::Value) -> Self {
        if matches!(request.get("jsonrpc"), Some(serde_json::Value::String(version)) if version == "2.0")
        {
            Self::V2
        } else {
            Self::Legacy
        }
    }
}

fn make_success_response(
    version: RpcVersion,
    id: serde_json::Value,
    result: serde_json::Value,
) -> serde_json::Value {
    match version {
        RpcVersion::Legacy => json!({ "result": result, "error": null, "id": id }),
        RpcVersion::V2 => json!({ "jsonrpc": "2.0", "result": result, "id": id }),
    }
}

fn make_error_response(
    version: RpcVersion,
    id: serde_json::Value,
    error: RpcError,
) -> serde_json::Value {
    let error = json!({ "code": error.code, "message": error.message });
    match version {
        RpcVersion::Legacy => json!({ "result": null, "error": error, "id": id }),
        RpcVersion::V2 => json!({ "jsonrpc": "2.0", "error": error, "id": id }),
    }
}

fn bitcoind_error_to_rpc_error(error: BitcoindRpcError) -> RpcError {
    match error {
        BitcoindRpcError::RpcError { code, message } => RpcError { code, message },
        BitcoindRpcError::HttpError {
            status_code,
            message,
        } => RpcError {
            code: INTERNAL_ERROR,
            message: format!("HTTP error {status_code}: {message}"),
        },
        BitcoindRpcError::ParseError { message } => RpcError {
            code: INTERNAL_ERROR,
            message,
        },
        BitcoindRpcError::Other(message) => RpcError {
            code: INTERNAL_ERROR,
            message,
        },
    }
}

async fn handle_single(
    client: &BitcoindRpcClient,
    wallet_rpc_enabled: bool,
    wallet_name: Option<&str>,
    request: &serde_json::Value,
) -> Option<serde_json::Value> {
    let version = RpcVersion::from_request(request);
    let is_notification = version == RpcVersion::V2 && request.get("id").is_none();
    let id = request
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let response = if !request.is_object() {
        make_error_response(
            version,
            id,
            RpcError {
                code: INVALID_REQUEST,
                message: "Invalid Request".to_string(),
            },
        )
    } else if let Some(method) = request.get("method").and_then(serde_json::Value::as_str) {
        if !ALLOWED_METHODS.contains(&method)
            && !(wallet_rpc_enabled && WALLET_METHODS.contains(&method))
        {
            make_error_response(
                version,
                id,
                RpcError {
                    code: METHOD_NOT_FOUND,
                    message: "Method not found".to_string(),
                },
            )
        } else {
            let invalid_params = request.get("params").is_some_and(|params| {
                !params.is_null() && !params.is_array() && !params.is_object()
            });
            if invalid_params {
                make_error_response(
                    version,
                    id,
                    RpcError {
                        code: INVALID_PARAMS,
                        message: "Params must be an array or object".to_string(),
                    },
                )
            } else {
                let params = request.get("params").cloned();
                let result = match wallet_name {
                    Some(wallet_name) => {
                        client
                            .call_value_for_wallet(method, params, wallet_name)
                            .await
                    }
                    None => client.call_value(method, params).await,
                };
                match result {
                    Ok(result) => make_success_response(version, id, result),
                    Err(error) => {
                        make_error_response(version, id, bitcoind_error_to_rpc_error(error))
                    }
                }
            }
        }
    } else {
        make_error_response(
            version,
            id,
            RpcError {
                code: INVALID_REQUEST,
                message: "Missing or invalid method field".to_string(),
            },
        )
    };

    (!is_notification).then_some(response)
}

async fn handle_request_body(
    state: Arc<BitcoinRpcState>,
    wallet_name: Option<&str>,
    body: Bytes,
) -> Response {
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            warn!("bitcoin_rpc: failed to parse request body: {error}");
            return Json(make_error_response(
                RpcVersion::Legacy,
                serde_json::Value::Null,
                RpcError {
                    code: PARSE_ERROR,
                    message: "Parse error".to_string(),
                },
            ))
            .into_response();
        }
    };

    match &value {
        serde_json::Value::Array(requests) => {
            if requests.is_empty() {
                return Json(make_error_response(
                    RpcVersion::Legacy,
                    serde_json::Value::Null,
                    RpcError {
                        code: INVALID_REQUEST,
                        message: "Invalid Request".to_string(),
                    },
                ))
                .into_response();
            }

            if requests.len() > state.max_batch_size {
                return Json(make_error_response(
                    RpcVersion::Legacy,
                    serde_json::Value::Null,
                    RpcError {
                        code: INVALID_REQUEST,
                        message: format!(
                            "Batch too large: {} requests, max {}",
                            requests.len(),
                            state.max_batch_size
                        ),
                    },
                ))
                .into_response();
            }

            let mut responses = Vec::with_capacity(requests.len());
            // ponytail: use bounded concurrency if sequential batches become measurable.
            for request in requests {
                if let Some(response) = handle_single(
                    &state.client,
                    state.wallet_rpc_enabled,
                    wallet_name,
                    request,
                )
                .await
                {
                    responses.push(response);
                }
            }
            if responses.is_empty() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                Json(serde_json::Value::Array(responses)).into_response()
            }
        }
        _ => {
            match handle_single(&state.client, state.wallet_rpc_enabled, wallet_name, &value).await
            {
                Some(response) => Json(response).into_response(),
                None => StatusCode::NO_CONTENT.into_response(),
            }
        }
    }
}

async fn bitcoin_rpc_handler(State(state): State<Arc<BitcoinRpcState>>, body: Bytes) -> Response {
    handle_request_body(state, None, body).await
}

async fn bitcoin_wallet_rpc_handler(
    State(state): State<Arc<BitcoinRpcState>>,
    Path(wallet_name): Path<String>,
    body: Bytes,
) -> Response {
    handle_request_body(state, Some(&wallet_name), body).await
}

fn constant_time_eq_str(left: &str, right: &str) -> bool {
    let left_hash = Sha256::digest(left.as_bytes());
    let right_hash = Sha256::digest(right.as_bytes());
    left_hash.ct_eq(&right_hash).into()
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"jsonrpc\"")],
        "",
    )
        .into_response()
}

async fn bitcoin_rpc_auth_middleware(
    State(state): State<Arc<BitcoinRpcState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());

    match auth_header {
        Some(value) if value.starts_with("Basic ") => {
            let encoded = &value[6..];
            let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
                Ok(decoded) => decoded,
                Err(_) => {
                    warn!("bitcoin_rpc: failed to decode base64 credentials");
                    return unauthorized_response();
                }
            };
            let credentials = match String::from_utf8(decoded) {
                Ok(credentials) => credentials,
                Err(_) => {
                    warn!("bitcoin_rpc: invalid UTF-8 in credentials");
                    return unauthorized_response();
                }
            };
            let mut parts = credentials.splitn(2, ':');
            let (username, password) = match (parts.next(), parts.next()) {
                (Some(username), Some(password)) => (username, password),
                _ => {
                    warn!("bitcoin_rpc: invalid credentials format");
                    return unauthorized_response();
                }
            };
            if constant_time_eq_str(username, &state.rpcuser)
                & constant_time_eq_str(password, &state.rpcpassword)
            {
                next.run(request).await
            } else {
                warn!("bitcoin_rpc: invalid username or password");
                unauthorized_response()
            }
        }
        _ => {
            warn!("bitcoin_rpc: missing or invalid Authorization header");
            unauthorized_response()
        }
    }
}

fn build_router(state: Arc<BitcoinRpcState>) -> Router {
    build_handler_router(state.clone()).layer(middleware::from_fn_with_state(
        state,
        bitcoin_rpc_auth_middleware,
    ))
}

fn build_handler_router(state: Arc<BitcoinRpcState>) -> Router {
    let mut router = Router::new().route("/", post(bitcoin_rpc_handler));
    if state.wallet_rpc_enabled {
        router = router
            .route("/wallet/{wallet_name}", post(bitcoin_wallet_rpc_handler))
            .route("/wallet/{wallet_name}/", post(bitcoin_wallet_rpc_handler));
    }
    router.with_state(state)
}

/// Start the Bitcoin Core compatible JSON-RPC gateway on its own listener.
///
/// Returns the shutdown sender, server task, and actual bound port. The caller
/// must signal shutdown and await the task when the node stops.
pub async fn start_bitcoin_rpc_server(
    config: BitcoinRpcApiConfig,
    bitcoin_rpc: &BitcoinRpcConfig,
) -> Result<(oneshot::Sender<()>, JoinHandle<()>, u16), std::io::Error> {
    config
        .validate()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error.message))?;
    if !config.enabled {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bitcoin_rpc_api must be enabled before starting the listener",
        ));
    }

    let client = BitcoindRpcClient::new(
        &bitcoin_rpc.url,
        &bitcoin_rpc.username,
        &bitcoin_rpc.password,
    )
    .map_err(|error| std::io::Error::other(error.to_string()))?;

    let state = Arc::new(BitcoinRpcState {
        client,
        max_batch_size: config.max_batch_size,
        wallet_rpc_enabled: config.wallet_rpc_enabled,
        rpcuser: config
            .rpcuser
            .expect("enabled bitcoin_rpc_api config was validated"),
        rpcpassword: config
            .rpcpassword
            .expect("enabled bitcoin_rpc_api config was validated"),
    });

    let ip_address = config
        .host
        .parse()
        .expect("bitcoin_rpc_api host was validated");
    let address = SocketAddr::new(
        ip_address,
        config
            .port
            .expect("enabled bitcoin_rpc_api config was validated"),
    );

    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(address).await?;
    let actual_port = listener.local_addr()?.port();

    info!(
        "Bitcoin RPC gateway listening on {}:{}",
        config.host, actual_port
    );

    let (shutdown_sender, shutdown_receiver) = oneshot::channel::<()>();

    let server_handle = tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = shutdown_receiver.await;
                info!("Bitcoin RPC gateway shutdown signal received");
            })
            .await
        {
            warn!("Bitcoin RPC gateway stopped with an error: {error}");
        }

        info!("Bitcoin RPC gateway stopped");
    });

    Ok((shutdown_sender, server_handle, actual_port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http};
    use base64::Engine;
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

    #[tokio::test]
    async fn every_v1_method_is_forwarded() {
        let method_names = [
            "getbestblockhash",
            "getblock",
            "getblockchaininfo",
            "getblockcount",
            "getblockfilter",
            "getblockhash",
            "getblockheader",
            "getmempoolentry",
            "getnetworkinfo",
            "getrawmempool",
            "getrawtransaction",
            "gettxout",
            "estimatesmartfee",
            "sendrawtransaction",
            "testmempoolaccept",
            "decoderawtransaction",
        ];
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": true,
                "error": null,
                "id": 0
            })))
            .expect(method_names.len() as u64)
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });

        for (request_id, method_name) in method_names.into_iter().enumerate() {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "method": method_name,
                        "params": [],
                        "id": request_id
                    }))
                    .unwrap(),
                ))
                .unwrap();
            let response = build_handler_router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(body["result"], true, "method {method_name} was rejected");
            assert!(body["error"].is_null(), "method {method_name} failed");
        }
    }

    #[tokio::test]
    async fn wallet_methods_are_rejected_and_wallet_paths_are_absent_while_disabled() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });

        let root_request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"method": "getbalance", "params": [], "id": 1}))
                    .unwrap(),
            ))
            .unwrap();
        let root_response = build_handler_router(state.clone())
            .oneshot(root_request)
            .await
            .unwrap();
        let root_body = axum::body::to_bytes(root_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let root_body: serde_json::Value = serde_json::from_slice(&root_body).unwrap();
        assert_eq!(root_body["error"]["code"], METHOD_NOT_FOUND);

        let wallet_request = http::Request::builder()
            .method("POST")
            .uri("/wallet/trading/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"method": "getbalance", "params": [], "id": 2}))
                    .unwrap(),
            ))
            .unwrap();
        let wallet_response = build_handler_router(state)
            .oneshot(wallet_request)
            .await
            .unwrap();
        assert_eq!(wallet_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn every_wallet_method_is_forwarded_when_enabled() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": true,
                "error": null,
                "id": 0
            })))
            .expect(13)
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: true,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!([
                    {"method": "createrawtransaction", "params": [], "id": 0},
                    {"method": "createwallet", "params": [], "id": 1},
                    {"method": "getbalance", "params": [], "id": 2},
                    {"method": "getbalances", "params": [], "id": 3},
                    {"method": "gettransaction", "params": [], "id": 4},
                    {"method": "getwalletinfo", "params": [], "id": 5},
                    {"method": "importdescriptors", "params": [], "id": 6},
                    {"method": "listunspent", "params": [], "id": 7},
                    {"method": "listwallets", "params": [], "id": 8},
                    {"method": "loadwallet", "params": [], "id": 9},
                    {"method": "rescanblockchain", "params": [], "id": 10},
                    {"method": "signrawtransactionwithwallet", "params": [], "id": 11},
                    {"method": "unloadwallet", "params": [], "id": 12}
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body,
            json!([
                {"result": true, "error": null, "id": 0},
                {"result": true, "error": null, "id": 1},
                {"result": true, "error": null, "id": 2},
                {"result": true, "error": null, "id": 3},
                {"result": true, "error": null, "id": 4},
                {"result": true, "error": null, "id": 5},
                {"result": true, "error": null, "id": 6},
                {"result": true, "error": null, "id": 7},
                {"result": true, "error": null, "id": 8},
                {"result": true, "error": null, "id": 9},
                {"result": true, "error": null, "id": 10},
                {"result": true, "error": null, "id": 11},
                {"result": true, "error": null, "id": 12}
            ])
        );
    }

    #[tokio::test]
    async fn enabled_wallet_mode_preserves_root_and_wallet_endpoint_routing() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getbalance",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "root",
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/wallet/trading"))
            .and(body_json(json!({
                "method": "getblockcount",
                "params": [],
                "id": 1
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "wallet",
                "error": null,
                "id": 1
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: true,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });

        let root_request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"method": "getbalance", "params": [], "id": 10}))
                    .unwrap(),
            ))
            .unwrap();
        let root_response = build_handler_router(state.clone())
            .oneshot(root_request)
            .await
            .unwrap();
        let root_body = axum::body::to_bytes(root_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let root_body: serde_json::Value = serde_json::from_slice(&root_body).unwrap();
        assert_eq!(root_body["result"], "root");

        let wallet_request = http::Request::builder()
            .method("POST")
            .uri("/wallet/trading")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"method": "getblockcount", "params": [], "id": 11}))
                    .unwrap(),
            ))
            .unwrap();
        let wallet_response = build_handler_router(state)
            .oneshot(wallet_request)
            .await
            .unwrap();
        let wallet_body = axum::body::to_bytes(wallet_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let wallet_body: serde_json::Value = serde_json::from_slice(&wallet_body).unwrap();
        assert_eq!(wallet_body["result"], "wallet");
    }

    #[tokio::test]
    async fn wallet_name_is_forwarded_as_one_encoded_path_segment() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wallet/..%2Fhot%20wallet%25"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": true,
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: true,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/wallet/..%2Fhot%20wallet%25/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"method": "getwalletinfo", "params": [], "id": 1}))
                    .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["result"], true);
    }

    #[tokio::test]
    async fn wallet_endpoint_forwards_positional_and_named_parameters_unchanged() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wallet/trading"))
            .and(body_json(json!({
                "method": "listunspent",
                "params": [1, 6],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "positional",
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/wallet/trading"))
            .and(body_json(json!({
                "method": "listunspent",
                "params": {"minconf": 1, "maxconf": 6},
                "id": 1
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "named",
                "error": null,
                "id": 1
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: true,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/wallet/trading/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!([
                    {"method": "listunspent", "params": [1, 6], "id": 10},
                    {
                        "method": "listunspent",
                        "params": {"minconf": 1, "maxconf": 6},
                        "id": 11
                    }
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body[0]["result"], "positional");
        assert_eq!(body[1]["result"], "named");
    }

    #[tokio::test]
    async fn wallet_core_error_code_and_message_are_preserved() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wallet/missing"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "result": null,
                "error": {"code": -18, "message": "Requested wallet does not exist"},
                "id": 0
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: true,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/wallet/missing/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"method": "getwalletinfo", "params": [], "id": 1}))
                    .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], -18);
        assert_eq!(body["error"]["message"], "Requested wallet does not exist");
    }

    #[tokio::test]
    async fn wallet_endpoint_requires_authentication() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: true,
            rpcuser: "user".to_string(),
            rpcpassword: "password".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/wallet/trading/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"method": "getwalletinfo", "params": [], "id": 1}))
                    .unwrap(),
            ))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn parameters_reach_upstream_unchanged() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockhash",
                "params": [42],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "positional",
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockhash",
                "params": { "height": 42 },
                "id": 1
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "named",
                "error": null,
                "id": 1
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblock",
                "params": { "args": ["000000000000abc"], "verbosity": 2 },
                "id": 2
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "args",
                "error": null,
                "id": 2
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "params": null,
                "id": 3
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "null",
                "error": null,
                "id": 3
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "id": 4
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "absent",
                "error": null,
                "id": 4
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!([
                    { "method": "getblockhash", "params": [42], "id": 7 },
                    {
                        "method": "getblockhash",
                        "params": { "height": 42 },
                        "id": 8
                    },
                    {
                        "method": "getblock",
                        "params": { "args": ["000000000000abc"], "verbosity": 2 },
                        "id": 9
                    },
                    { "method": "getblockcount", "params": null, "id": 10 },
                    { "method": "getblockcount", "id": 11 }
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body[0]["result"], "positional");
        assert_eq!(body[1]["result"], "named");
        assert_eq!(body[2]["result"], "args");
        assert_eq!(body[3]["result"], "null");
        assert_eq!(body[4]["result"], "absent");
    }

    #[tokio::test]
    async fn incorrect_method_names_are_rejected() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });

        for (request_id, method_name) in [
            "getblockcounts",
            "getblockcoun",
            "GetBlockCount",
            "getblockcount ",
            "getblock.count",
            "listunspent",
        ]
        .into_iter()
        .enumerate()
        {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(
                        &json!({"method": method_name, "params": [], "id": request_id}),
                    )
                    .unwrap(),
                ))
                .unwrap();
            let response = build_handler_router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert!(body["result"].is_null(), "method {method_name}");
            assert_eq!(
                body["error"]["code"], METHOD_NOT_FOUND,
                "method {method_name}"
            );
            assert_eq!(body["id"], request_id, "method {method_name}");
        }
    }

    #[tokio::test]
    async fn json_result_types_are_relayed() {
        let mock_server = MockServer::start().await;
        let results = [
            json!(42),
            json!({ "height": 42 }),
            json!(["transaction", 42]),
            json!("000000000000abc"),
            json!(true),
            json!(null),
        ];

        for (upstream_id, result) in results.iter().enumerate() {
            Mock::given(method("POST"))
                .and(path("/"))
                .and(body_json(json!({
                    "method": "getblockcount",
                    "params": [],
                    "id": upstream_id
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": result,
                    "error": null,
                    "id": upstream_id
                })))
                .expect(1)
                .mount(&mock_server)
                .await;
        }
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });

        for (request_id, expected_result) in results.into_iter().enumerate() {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "method": "getblockcount",
                        "params": [],
                        "id": request_id
                    }))
                    .unwrap(),
                ))
                .unwrap();
            let response = build_handler_router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(body["result"], expected_result, "result case {request_id}");
            assert!(body["error"].is_null(), "result case {request_id}");
        }
    }

    #[tokio::test]
    async fn upstream_error_code_and_message_are_preserved() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "result": null,
                "error": {
                    "code": -5,
                    "message": "No such mempool or blockchain transaction"
                },
                "id": 0
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(
                    &json!({"method": "getrawtransaction", "params": ["deadbeef"], "id": 2}),
                )
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body.get("jsonrpc").is_none());
        assert!(body["result"].is_null());
        assert_eq!(body["error"]["code"], -5);
        assert_eq!(
            body["error"]["message"],
            "No such mempool or blockchain transaction"
        );
        assert_eq!(body["id"], 2);
    }

    #[tokio::test]
    async fn mixed_batch_omits_notifications_and_preserves_response_versions() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": 100,
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getbestblockhash",
                "params": [],
                "id": 1
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "000000000000abc",
                "error": null,
                "id": 1
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!([
                    {"method": "getblockcount", "params": [], "id": 10},
                    {"jsonrpc": "2.0", "method": "getbestblockhash", "params": []},
                    {"jsonrpc": "2.0", "method": "listunspent", "params": [], "id": 12}
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let responses = body.as_array().unwrap();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["id"], 10);
        assert_eq!(responses[0]["result"], 100);
        assert!(responses[0].get("jsonrpc").is_none());
        assert_eq!(responses[1]["jsonrpc"], "2.0");
        assert_eq!(responses[1]["id"], 12);
        assert_eq!(responses[1]["error"]["code"], METHOD_NOT_FOUND);
        assert!(responses[1].get("result").is_none());
    }

    #[tokio::test]
    async fn request_ids_are_preserved_without_batch_deduplication() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": true,
                "error": null,
                "id": 0
            })))
            .expect(8)
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!([
                    { "method": "getblockcount", "id": "string-id" },
                    { "jsonrpc": "2.0", "method": "getblockcount", "id": 42 },
                    { "method": "getblockcount", "id": null },
                    { "jsonrpc": "2.0", "method": "getblockcount", "id": null },
                    { "method": "getblockcount", "id": 7 },
                    { "jsonrpc": "2.0", "method": "getblockcount", "id": 7 },
                    { "method": "getblockcount" },
                    { "jsonrpc": "2.0", "method": "getblockcount" }
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            body,
            json!([
                { "result": true, "error": null, "id": "string-id" },
                { "jsonrpc": "2.0", "result": true, "id": 42 },
                { "result": true, "error": null, "id": null },
                { "jsonrpc": "2.0", "result": true, "id": null },
                { "result": true, "error": null, "id": 7 },
                { "jsonrpc": "2.0", "result": true, "id": 7 },
                { "result": true, "error": null, "id": null }
            ])
        );
    }

    #[tokio::test]
    async fn json_rpc_2_success_contains_only_result() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": 42,
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "method": "getblockcount",
                    "id": 1
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, json!({ "jsonrpc": "2.0", "result": 42, "id": 1 }));
    }

    #[tokio::test]
    async fn json_rpc_2_error_contains_only_error() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "method": "listunspent",
                    "id": 2
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(body["id"], 2);
        assert!(body.get("result").is_none());
    }

    #[tokio::test]
    async fn only_exact_json_rpc_2_marker_selects_version_2_envelope() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let cases = [
            (json!({ "method": "listunspent", "id": 1 }), false),
            (
                json!({ "jsonrpc": "1.0", "method": "listunspent", "id": 1 }),
                false,
            ),
            (
                json!({ "jsonrpc": "2", "method": "listunspent", "id": 1 }),
                false,
            ),
            (
                json!({ "jsonrpc": 2, "method": "listunspent", "id": 1 }),
                false,
            ),
            (
                json!({ "jsonrpc": "2.0", "method": "listunspent", "id": 1 }),
                true,
            ),
        ];

        for (request_body, is_version_2) in cases {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                .unwrap();
            let response = build_handler_router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(body.get("jsonrpc").is_some(), is_version_2);
            assert_eq!(body.get("result").is_none(), is_version_2);
            assert_eq!(body["error"]["code"], METHOD_NOT_FOUND);
            assert_eq!(body["id"], 1);
        }
    }

    #[tokio::test]
    async fn single_notification_is_executed_without_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": 42,
                "error": null,
                "id": 0
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "method": "getblockcount"
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn notification_only_batch_is_executed_without_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": 42,
                "error": null,
                "id": 0
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getbestblockhash",
                "id": 1
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "000000000000abc",
                "error": null,
                "id": 1
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!([
                    { "jsonrpc": "2.0", "method": "getblockcount" },
                    { "jsonrpc": "2.0", "method": "getbestblockhash" }
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn single_item_batch_returns_an_array() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": 42,
                "error": null,
                "id": 0
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!([
                    { "method": "getblockcount", "params": [], "id": 1 }
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body, json!([{ "result": 42, "error": null, "id": 1 }]));
    }

    #[tokio::test]
    async fn empty_batch_is_rejected() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from("[]"))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], INVALID_REQUEST);
        assert!(body["result"].is_null());
        assert!(body["id"].is_null());
    }

    #[tokio::test]
    async fn invalid_top_level_values_are_rejected() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });

        for value in [json!(null), json!(true), json!(1), json!("request")] {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&value).unwrap()))
                .unwrap();
            let response = build_handler_router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(body["error"]["code"], INVALID_REQUEST);
            assert!(body["result"].is_null());
            assert!(body["id"].is_null());
        }
    }

    #[tokio::test]
    async fn missing_and_invalid_methods_are_rejected() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });

        for request in [json!({ "id": 1 }), json!({ "method": 1, "id": 2 })] {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap();
            let response = build_handler_router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(body["error"]["code"], INVALID_REQUEST);
            assert!(body["result"].is_null());
        }
    }

    #[tokio::test]
    async fn invalid_params_are_rejected() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "method": "getblockcount",
                    "params": true,
                    "id": 1
                }))
                .unwrap(),
            ))
            .unwrap();
        let response = build_handler_router(state).oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["error"]["code"], INVALID_PARAMS);
        assert!(response.get("result").is_none());
    }

    #[tokio::test]
    async fn malformed_json_returns_parse_error() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from("{"))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], PARSE_ERROR);
        assert!(body["result"].is_null());
        assert!(body["id"].is_null());
    }

    #[tokio::test]
    async fn malformed_upstream_response_returns_internal_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(
                    &json!({ "jsonrpc": "2.0", "method": "getblockcount", "id": 1 }),
                )
                .unwrap(),
            ))
            .unwrap();
        let response = build_handler_router(state).oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(response["error"]["code"], INTERNAL_ERROR);
        assert!(response.get("result").is_none());
    }

    #[tokio::test]
    async fn upstream_http_failure_returns_internal_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(
                    &json!({ "jsonrpc": "2.0", "method": "getblockcount", "id": 1 }),
                )
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["error"]["code"], INTERNAL_ERROR);
        assert!(body.get("result").is_none());
    }

    #[tokio::test]
    async fn missing_credentials_return_unauthorized() {
        let mock_server = MockServer::start().await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "user".to_string(),
            rpcpassword: "pass".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"method": "getblockcount", "params": [], "id": 1}))
                    .unwrap(),
            ))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_credentials_return_unauthorized() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "user".to_string(),
            rpcpassword: "pass".to_string(),
        });
        let credentials_without_separator =
            base64::engine::general_purpose::STANDARD.encode("userpass");

        for authorization in [
            "Bearer token".to_string(),
            "Basic !!!".to_string(),
            format!("Basic {credentials_without_separator}"),
        ] {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .header("Authorization", authorization)
                .body(Body::from("{}"))
                .unwrap();

            let response = build_router(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn wrong_credentials_return_unauthorized() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "user".to_string(),
            rpcpassword: "pass".to_string(),
        });

        for credentials in ["wrong:pass", "user:wrong"] {
            let credentials = base64::engine::general_purpose::STANDARD.encode(credentials);
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Basic {credentials}"))
                .body(Body::from("{}"))
                .unwrap();

            let response = build_router(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn valid_credentials_are_accepted() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": 42,
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            wallet_rpc_enabled: false,
            rpcuser: "alice".to_string(),
            rpcpassword: "secret".to_string(),
        });
        let credentials = base64::engine::general_purpose::STANDARD.encode("alice:secret");
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Basic {credentials}"))
            .body(Body::from(
                serde_json::to_vec(&json!({"method": "getblockcount", "params": [], "id": 1}))
                    .unwrap(),
            ))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["result"], 42);
    }

    #[tokio::test]
    async fn listener_uses_ephemeral_port_and_shuts_down() {
        let config = BitcoinRpcApiConfig {
            enabled: true,
            port: Some(0),
            rpcuser: Some("user".to_string()),
            rpcpassword: Some("pass".to_string()),
            ..BitcoinRpcApiConfig::default()
        };
        let bitcoin_rpc = BitcoinRpcConfig {
            url: "http://127.0.0.1:1".to_string(),
            username: "upstream-user".to_string(),
            password: "upstream-password".to_string(),
        };

        let (shutdown_sender, server_handle, port) = start_bitcoin_rpc_server(config, &bitcoin_rpc)
            .await
            .unwrap();
        assert_ne!(port, 0);
        shutdown_sender.send(()).unwrap();
        server_handle.await.unwrap();

        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let rebound_listener = tokio::net::TcpListener::bind(address)
            .await
            .expect("Bitcoin RPC gateway did not release its listener");
        drop(rebound_listener);
    }

    #[tokio::test]
    #[ignore = "requires a locally running Bitcoin Core regtest node"]
    async fn regtest_matches_bitcoin_core_contract() {
        const SETUP: &str = "set P2POOL_REGTEST_RPC_URL, P2POOL_REGTEST_RPC_USERNAME, and P2POOL_REGTEST_RPC_PASSWORD to run this ignored test";
        const GATEWAY_USERNAME: &str = "contract-user";
        const GATEWAY_PASSWORD: &str = "contract-password";
        const MISSING_INPUT_TRANSACTION: &str = concat!(
            "0200000001",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000ffffffff01",
            "0000000000000000016a00000000"
        );

        let upstream_url = env::var("P2POOL_REGTEST_RPC_URL").expect(SETUP);
        let upstream_username = env::var("P2POOL_REGTEST_RPC_USERNAME").expect(SETUP);
        let upstream_password = env::var("P2POOL_REGTEST_RPC_PASSWORD").expect(SETUP);
        let gateway_config = BitcoinRpcApiConfig {
            enabled: true,
            port: Some(0),
            rpcuser: Some(GATEWAY_USERNAME.to_string()),
            rpcpassword: Some(GATEWAY_PASSWORD.to_string()),
            ..BitcoinRpcApiConfig::default()
        };
        let upstream_config = BitcoinRpcConfig {
            url: upstream_url.clone(),
            username: upstream_username.clone(),
            password: upstream_password.clone(),
        };
        let (shutdown_sender, server_handle, gateway_port) =
            start_bitcoin_rpc_server(gateway_config, &upstream_config)
                .await
                .expect("failed to start the Bitcoin RPC gateway");
        let gateway_url = format!("http://127.0.0.1:{gateway_port}");
        let http_client = reqwest::Client::new();
        let normalize = |mut response: serde_json::Value| {
            let responses = response
                .as_array_mut()
                .expect("Bitcoin Core and the gateway must return batch arrays");
            responses.sort_by_key(|item| item["id"].as_u64());
            for item in responses.iter_mut() {
                let object = item
                    .as_object_mut()
                    .expect("every batch response must be an object");
                object.remove("id");
                object.remove("jsonrpc");
                if object.get("error").is_some_and(serde_json::Value::is_null) {
                    object.remove("error");
                } else {
                    object.remove("result");
                }
            }
            responses.clone()
        };

        let genesis_request = json!({
            "method": "getblockhash",
            "params": { "height": 0 },
            "id": 0
        });
        let direct_genesis: serde_json::Value = http_client
            .post(&upstream_url)
            .basic_auth(&upstream_username, Some(&upstream_password))
            .json(&genesis_request)
            .send()
            .await
            .expect("failed to call Bitcoin Core directly")
            .error_for_status()
            .expect("Bitcoin Core returned an HTTP error")
            .json()
            .await
            .expect("Bitcoin Core returned invalid JSON");
        let gateway_genesis: serde_json::Value = http_client
            .post(&gateway_url)
            .basic_auth(GATEWAY_USERNAME, Some(GATEWAY_PASSWORD))
            .json(&genesis_request)
            .send()
            .await
            .expect("failed to call the Bitcoin RPC gateway")
            .error_for_status()
            .expect("the Bitcoin RPC gateway returned an HTTP error")
            .json()
            .await
            .expect("the Bitcoin RPC gateway returned invalid JSON");
        assert_eq!(
            normalize(json!([direct_genesis.clone()])),
            normalize(json!([gateway_genesis]))
        );
        let genesis_hash = direct_genesis["result"]
            .as_str()
            .expect("getblockhash for regtest genesis must return a hash");

        let requests = json!([
            { "method": "getblockcount", "params": [], "id": 1 },
            { "method": "getbestblockhash", "params": [], "id": 2 },
            { "method": "getblockchaininfo", "params": [], "id": 3 },
            { "method": "getrawmempool", "params": [], "id": 4 },
            { "method": "getnetworkinfo", "params": [], "id": 5 },
            {
                "method": "getblockheader",
                "params": { "blockhash": genesis_hash, "verbose": true },
                "id": 6
            },
            {
                "method": "getblock",
                "params": { "blockhash": genesis_hash, "verbosity": 1 },
                "id": 7
            },
            {
                "method": "gettxout",
                "params": ["0000000000000000000000000000000000000000000000000000000000000000", 0],
                "id": 8
            },
            {
                "method": "getrawtransaction",
                "params": ["0000000000000000000000000000000000000000000000000000000000000000"],
                "id": 9
            },
            {
                "method": "testmempoolaccept",
                "params": [[MISSING_INPUT_TRANSACTION]],
                "id": 10
            },
            {
                "method": "sendrawtransaction",
                "params": [MISSING_INPUT_TRANSACTION],
                "id": 11
            }
        ]);
        let direct_batch: serde_json::Value = http_client
            .post(&upstream_url)
            .basic_auth(&upstream_username, Some(&upstream_password))
            .json(&requests)
            .send()
            .await
            .expect("failed to send a batch directly to Bitcoin Core")
            .error_for_status()
            .expect("Bitcoin Core returned an HTTP error for the batch")
            .json()
            .await
            .expect("Bitcoin Core returned invalid batch JSON");
        let gateway_batch: serde_json::Value = http_client
            .post(&gateway_url)
            .basic_auth(GATEWAY_USERNAME, Some(GATEWAY_PASSWORD))
            .json(&requests)
            .send()
            .await
            .expect("failed to send a batch to the Bitcoin RPC gateway")
            .error_for_status()
            .expect("the Bitcoin RPC gateway returned an HTTP error for the batch")
            .json()
            .await
            .expect("the Bitcoin RPC gateway returned invalid batch JSON");
        assert!(
            direct_batch.as_array().is_some_and(|responses| responses
                .iter()
                .any(|response| response["id"] == 3 && response["result"]["chain"] == "regtest")),
            "P2POOL_REGTEST_RPC_URL must point to a regtest node"
        );
        assert_eq!(normalize(direct_batch), normalize(gateway_batch));

        let notification = json!({ "jsonrpc": "2.0", "method": "getblockcount" });
        let direct_notification = http_client
            .post(&upstream_url)
            .basic_auth(&upstream_username, Some(&upstream_password))
            .json(&notification)
            .send()
            .await
            .expect("failed to send a notification directly to Bitcoin Core");
        let direct_notification_success = direct_notification.status().is_success();
        let direct_notification_body = direct_notification
            .bytes()
            .await
            .expect("failed to read Bitcoin Core's notification response");
        let gateway_notification = http_client
            .post(&gateway_url)
            .basic_auth(GATEWAY_USERNAME, Some(GATEWAY_PASSWORD))
            .json(&notification)
            .send()
            .await
            .expect("failed to send a notification to the Bitcoin RPC gateway");
        let gateway_notification_success = gateway_notification.status().is_success();
        let gateway_notification_body = gateway_notification
            .bytes()
            .await
            .expect("failed to read the gateway's notification response");
        assert_eq!(direct_notification_success, gateway_notification_success);
        assert_eq!(direct_notification_body, gateway_notification_body);
        assert!(gateway_notification_body.is_empty());

        shutdown_sender
            .send(())
            .expect("Bitcoin RPC gateway stopped before test shutdown");
        server_handle.await.expect("failed to join gateway task");
    }

    #[tokio::test]
    #[ignore = "requires a disposable Bitcoin Core regtest node with wallet support"]
    async fn wallet_regtest_lifecycle_matches_bitcoin_core() {
        const SETUP: &str = "set P2POOL_REGTEST_RPC_URL, P2POOL_REGTEST_RPC_USERNAME, and P2POOL_REGTEST_RPC_PASSWORD to run this ignored test";
        const GATEWAY_USERNAME: &str = "wallet-contract-user";
        const GATEWAY_PASSWORD: &str = "wallet-contract-password";

        let upstream_url = env::var("P2POOL_REGTEST_RPC_URL").expect(SETUP);
        let upstream_username = env::var("P2POOL_REGTEST_RPC_USERNAME").expect(SETUP);
        let upstream_password = env::var("P2POOL_REGTEST_RPC_PASSWORD").expect(SETUP);
        let upstream_client =
            BitcoindRpcClient::new(&upstream_url, &upstream_username, &upstream_password)
                .expect("failed to build the direct Bitcoin Core client");
        let blockchain_info = upstream_client
            .call_value("getblockchaininfo", None)
            .await
            .expect("failed to query Bitcoin Core");
        assert_eq!(blockchain_info["chain"], "regtest");

        let unique_suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is before the Unix epoch")
            .as_nanos();
        let wallet_name = format!("p2poolv2-wallet-contract-{unique_suffix}");
        let gateway_config = BitcoinRpcApiConfig {
            enabled: true,
            wallet_rpc_enabled: true,
            port: Some(0),
            rpcuser: Some(GATEWAY_USERNAME.to_string()),
            rpcpassword: Some(GATEWAY_PASSWORD.to_string()),
            ..BitcoinRpcApiConfig::default()
        };
        let upstream_config = BitcoinRpcConfig {
            url: upstream_url,
            username: upstream_username,
            password: upstream_password,
        };
        let (shutdown_sender, server_handle, gateway_port) =
            start_bitcoin_rpc_server(gateway_config, &upstream_config)
                .await
                .expect("failed to start the wallet RPC gateway");
        let gateway_client = BitcoindRpcClient::new(
            &format!("http://127.0.0.1:{gateway_port}"),
            GATEWAY_USERNAME,
            GATEWAY_PASSWORD,
        )
        .expect("failed to build the gateway client");

        let created_wallet = gateway_client
            .call_value("createwallet", Some(json!({"wallet_name": wallet_name})))
            .await
            .expect("createwallet failed through the gateway");
        assert_eq!(created_wallet["name"], wallet_name);

        gateway_client
            .call_value("unloadwallet", Some(json!([wallet_name])))
            .await
            .expect("unloadwallet failed after creation");
        let loaded_wallet = gateway_client
            .call_value("loadwallet", Some(json!([wallet_name])))
            .await
            .expect("loadwallet failed through the gateway");
        assert_eq!(loaded_wallet["name"], wallet_name);

        let wallet_descriptors = upstream_client
            .call_value_for_wallet("listdescriptors", Some(json!([true])), &wallet_name)
            .await
            .expect("failed to read the disposable wallet descriptors");
        let descriptor = wallet_descriptors["descriptors"][0]["desc"]
            .as_str()
            .expect("listdescriptors did not return a private descriptor");
        let imported_descriptors = gateway_client
            .call_value_for_wallet(
                "importdescriptors",
                Some(json!([[{
                    "desc": descriptor,
                    "timestamp": "now",
                    "range": [0, 1000]
                }]])),
                &wallet_name,
            )
            .await
            .expect("importdescriptors failed through the wallet endpoint");
        assert_eq!(
            imported_descriptors[0]["success"], true,
            "unexpected importdescriptors result: {imported_descriptors}"
        );

        let mining_address = upstream_client
            .call_value_for_wallet("getnewaddress", None, &wallet_name)
            .await
            .expect("failed to obtain a regtest mining address");
        upstream_client
            .call_value("generatetoaddress", Some(json!([101, mining_address])))
            .await
            .expect("failed to mine mature wallet funds");
        let rescan = gateway_client
            .call_value_for_wallet(
                "rescanblockchain",
                Some(json!({"start_height": 0})),
                &wallet_name,
            )
            .await
            .expect("rescanblockchain failed through the wallet endpoint");
        assert_eq!(rescan["start_height"], 0);

        let unspent_outputs = gateway_client
            .call_value_for_wallet("listunspent", Some(json!([101])), &wallet_name)
            .await
            .expect("listunspent failed through the wallet endpoint");
        let spendable_output = &unspent_outputs[0];
        assert_eq!(spendable_output["spendable"], true);
        let raw_transaction = gateway_client
            .call_value_for_wallet(
                "createrawtransaction",
                Some(json!([
                    [{
                        "txid": spendable_output["txid"],
                        "vout": spendable_output["vout"]
                    }],
                    {"data": "00"}
                ])),
                &wallet_name,
            )
            .await
            .expect("createrawtransaction failed through the wallet endpoint");
        let signed_transaction = gateway_client
            .call_value_for_wallet(
                "signrawtransactionwithwallet",
                Some(json!([raw_transaction])),
                &wallet_name,
            )
            .await
            .expect("signrawtransactionwithwallet failed through the wallet endpoint");
        assert_eq!(signed_transaction["complete"], true);

        gateway_client
            .call_value("unloadwallet", Some(json!([wallet_name])))
            .await
            .expect("final unloadwallet failed through the gateway");
        shutdown_sender
            .send(())
            .expect("wallet RPC gateway stopped before test shutdown");
        server_handle
            .await
            .expect("failed to join wallet RPC gateway task");
    }

    #[tokio::test]
    async fn oversized_batch_is_rejected() {
        let mock_server = MockServer::start().await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 2,
            wallet_rpc_enabled: false,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!([
                    {"method": "getblockcount", "params": [], "id": 1},
                    {"method": "getblockcount", "params": [], "id": 2},
                    {"method": "getblockcount", "params": [], "id": 3}
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body["result"].is_null());
        assert_eq!(body["error"]["code"], INVALID_REQUEST);
    }
}
