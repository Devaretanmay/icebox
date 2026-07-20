use std::net::SocketAddr;
use std::time::Duration;

use icebox::core::executor::ModuleExecutor;
use icebox::core::framework::new_shared_framework;
use icebox::core::safety::{Charter, RiskLevel, ScopeManager};
use icebox::interfaces::rest::{serve, AuthState};
use reqwest::Client;

fn free_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

fn make_fw() -> icebox::core::framework::SharedFramework {
    new_shared_framework(ModuleExecutor::new(
        Charter::accept("test", vec!["auth".into()]),
        ScopeManager::new(vec!["127.0.0.1".into()]),
        RiskLevel::Low,
    ))
}

#[tokio::test]
async fn test_rest_requires_token() {
    let addr = free_addr();
    let fw = make_fw();
    tokio::spawn(async move {
        let _ = serve(
            fw,
            addr,
            AuthState {
                token: Some("secret".into()),
            },
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = Client::new();
    let url = format!("http://{addr}/api/v1/modules");

    let no_auth = client.get(&url).send().await.unwrap();
    assert_eq!(no_auth.status(), reqwest::StatusCode::UNAUTHORIZED);

    let with_auth = client
        .get(&url)
        .header("Authorization", "Bearer secret")
        .send()
        .await
        .unwrap();
    assert_eq!(with_auth.status(), reqwest::StatusCode::OK);

    let wrong = client
        .get(&url)
        .header("Authorization", "Bearer wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_rest_noauth_flag() {
    let addr = free_addr();
    let fw = make_fw();
    tokio::spawn(async move {
        let _ = serve(fw, addr, AuthState { token: None }).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = Client::new();
    let url = format!("http://{addr}/api/v1/modules");

    let no_auth = client.get(&url).send().await.unwrap();
    assert_eq!(no_auth.status(), reqwest::StatusCode::OK);
}
