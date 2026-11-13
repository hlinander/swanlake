use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use arrow_flight::{flight_service_client::FlightServiceClient, Action};
use swanlake_core::{
    config::{ServerConfig, SessionIdMode},
    engine::EngineFactory,
    metrics::Metrics,
    service::SwanFlightService,
    session::registry::SessionRegistry,
};
use tokio::net::TcpListener;
use tonic::{transport::Channel, Code, Request};

const MIB: usize = 1024 * 1024;

fn action(sql: String) -> Request<Action> {
    let mut request = Request::new(Action {
        r#type: "execute_guarded".into(),
        body: sql.into_bytes().into(),
    });
    request.metadata_mut().insert(
        "airport-client-session-id",
        tonic::metadata::MetadataValue::from_static("receive-limit-test"),
    );
    request
}

fn padded(sql: &str, bytes: usize) -> String {
    format!("{sql} /*{}*/", "x".repeat(bytes))
}

async fn completed(client: &mut FlightServiceClient<Channel>, sql: String) -> Result<()> {
    let mut response = client.do_action(action(sql)).await?.into_inner();
    let result = response.message().await?.context("missing completion")?;
    let completion: serde_json::Value = serde_json::from_slice(&result.body)?;
    ensure!(completion["completed"] == true, "incomplete statement");
    ensure!(completion["error"].is_null(), "SQL failed: {completion}");
    ensure!(response.message().await?.is_none(), "extra completion");
    Ok(())
}

#[tokio::test]
async fn guarded_writes_obey_configured_receive_limit() -> Result<()> {
    for limit in [4 * MIB, 64 * MIB] {
        let mut config = ServerConfig::default();
        if limit == 64 * MIB {
            config.max_decoding_message_size = limit;
        }
        let factory = Arc::new(EngineFactory::new_without_extension_bootstrap(&config));
        let registry = Arc::new(SessionRegistry::new(&config, factory)?);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let service = SwanFlightService::new(
            registry,
            Arc::new(Metrics::new(1000, 8)),
            SessionIdMode::PeerAddr,
            format!("grpc://{addr}"),
        );
        // Exercise the same Flight service builder that main installs.
        let flight = super::flight_server(service, &config);
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(flight)
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });
        let result: Result<()> = async {
            let channel = Channel::from_shared(format!("http://{addr}"))?.connect().await?;
            let mut client = FlightServiceClient::new(channel);
            let sql = padded("CREATE TEMP VIEW large_view AS SELECT 42 AS value", 5 * MIB);
            if limit == 4 * MIB {
                let error = client.do_action(action(sql)).await.err().context("default accepted 5 MiB")?;
                ensure!(error.code() == Code::OutOfRange, "unexpected error: {error}");
                ensure!(error.message().contains("4194304"), "wrong default limit: {error}");
                // The rejected statement must not have created the view.
                completed(&mut client, "CREATE TEMP VIEW large_view AS SELECT 42 AS value".into()).await?;
            } else {
                completed(&mut client, sql).await?;
            }
            completed(&mut client, "SELECT CASE WHEN value = 42 THEN 1 ELSE error('wrong view value') END FROM large_view".into()).await?;

            let sql = padded("CREATE TEMP TABLE rejected(value INTEGER)", limit + 1);
            let error = client.do_action(action(sql)).await.err().context("accepted over-limit message")?;
            ensure!(error.code() == Code::OutOfRange, "unexpected error: {error}");
            ensure!(error.message().contains(&limit.to_string()), "wrong configured limit: {error}");
            completed(&mut client, "CREATE TEMP TABLE rejected(value INTEGER)".into()).await?;
            Ok(())
        }.await;
        server.abort();
        let _ = server.await;
        result?;
    }
    Ok(())
}
