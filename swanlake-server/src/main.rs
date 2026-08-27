use std::sync::Arc;

use anyhow::{Context, Result};
use swanlake_core::config::ServerConfig;
use swanlake_core::engine::EngineFactory;
use swanlake_core::maintenance::CheckpointService;
use swanlake_core::metrics::Metrics;
use swanlake_core::service::SwanFlightService;
use tonic::transport::{Identity, Server, ServerTlsConfig};

use tracing::info;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

mod status;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let config = ServerConfig::load().context("failed to load configuration")?;
    init_tracing(&config);
    info!("service config:\n{:?}", config);
    let addr = config
        .bind_addr()
        .context("failed to resolve bind address")?;

    let factory =
        Arc::new(EngineFactory::new(&config).context("failed to initialize engine factory")?);

    // Spawn DuckLake checkpoint maintenance task
    CheckpointService::spawn_from_config(&config, factory.clone())
        .await
        .context("failed to start checkpoint service")?;

    // Create session registry (Phase 2: connection-based session persistence)
    let registry = Arc::new(
        swanlake_core::session::registry::SessionRegistry::new(&config, factory.clone())
            .context("failed to initialize session registry")?,
    );

    // Spawn periodic session cleanup task
    let registry_clone = registry.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            let removed = registry_clone.cleanup_idle_sessions();
            if removed > 0 {
                info!(removed, "cleaned up idle sessions");
            }
        }
    });

    let metrics = Arc::new(Metrics::new(
        config.metrics_slow_query_threshold_ms.unwrap_or(5000),
        config.metrics_history_size.unwrap_or(200),
    ));

    let duckvis = swanlake_core::duckvis::DuckvisAuth::from_config(&config)
        .map_err(|e| anyhow::anyhow!("failed to initialize duckvis mode: {e}"))?;
    if duckvis.is_some() {
        info!("duckvis mode enabled: authenticating all Flight requests");
    }

    let flight_scheme = if config.tls_enabled() {
        "grpc+tls"
    } else {
        "grpc"
    };
    let flight_location = format!(
        "{flight_scheme}://{}:{}",
        config.advertise_host, config.port
    );
    let flight_service = SwanFlightService::with_duckvis(
        registry.clone(),
        metrics.clone(),
        config.session_id_mode.clone(),
        flight_location,
        duckvis,
    );

    status::spawn_status_server(&config, metrics, registry.clone())?;

    // Set up gRPC health service
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter.set_serving::<arrow_flight::flight_service_server::FlightServiceServer<SwanFlightService>>().await;

    info!(%addr, "starting SwanLake Flight SQL server");

    // Set up graceful shutdown
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Clone registry for use in shutdown handler
    let registry_for_shutdown = registry.clone();

    tokio::spawn(async move {
        let ctrl_c = async {
            if let Err(err) = tokio::signal::ctrl_c().await {
                tracing::error!(%err, "failed to install CTRL+C handler");
                std::future::pending::<()>().await;
            }
        };

        #[cfg(unix)]
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(err) => {
                    tracing::error!(%err, "failed to install SIGTERM handler");
                    std::future::pending::<()>().await;
                }
            }
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            () = ctrl_c => {
                info!("received SIGINT, initiating graceful shutdown");
            }
            () = terminate => {
                info!("received SIGTERM, initiating graceful shutdown");
            }
        }

        // Interrupt all running queries so they stop promptly
        registry_for_shutdown.interrupt_all();

        // Set health status to NOT_SERVING before shutdown
        health_reporter.set_not_serving::<arrow_flight::flight_service_server::FlightServiceServer<SwanFlightService>>().await;

        let _ = shutdown_tx.send(());
    });

    let mut server = Server::builder();
    if let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path) {
        let cert = std::fs::read(cert_path).context("failed to read SWANLAKE_TLS_CERT_PATH")?;
        let key = std::fs::read(key_path).context("failed to read SWANLAKE_TLS_KEY_PATH")?;
        server = server
            .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(cert, key)))
            .context("failed to configure Flight server TLS")?;
        info!("TLS enabled on the Flight server");
    }

    server
        .add_service(health_service)
        .add_service(arrow_flight::flight_service_server::FlightServiceServer::new(flight_service))
        .serve_with_shutdown(addr, async {
            shutdown_rx.await.ok();
        })
        .await
        .context("Flight SQL server terminated unexpectedly")?;

    info!("server shutdown complete");
    Ok(())
}

fn init_tracing(config: &ServerConfig) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,swanlake::service=debug"));

    if config.log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_target(false)
            .with_file(true)
            .with_line_number(true)
            .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
            .init();
    } else {
        tracing_subscriber::fmt()
            .compact()
            .with_env_filter(filter)
            .with_target(false)
            .with_file(true)
            .with_line_number(true)
            .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
            .init();
    }
}
