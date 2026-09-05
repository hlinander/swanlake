//! VARIANT conversion through raw Airport SQL and prepared Flight SQL queries.

use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use arrow_flight::{
    decode::FlightRecordBatchStream, flight_service_client::FlightServiceClient,
    flight_service_server::FlightServiceServer, sql::client::FlightSqlServiceClient,
    FlightDescriptor, FlightInfo,
};
use duckdb::arrow::{
    array::{Array, Int32Array, StringArray},
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use futures::TryStreamExt;
use swanlake_core::{
    config::{ServerConfig, SessionIdMode},
    engine::EngineFactory,
    metrics::Metrics,
    service::SwanFlightService,
    session::registry::SessionRegistry,
};
use tokio::net::TcpListener;
use tonic::{transport::Channel, Request};

fn request<T>(value: T) -> Request<T> {
    let mut request = Request::new(value);
    request.metadata_mut().insert(
        "airport-client-session-id",
        tonic::metadata::MetadataValue::from_static("variant-test"),
    );
    request
}

async fn read_result(
    client: &mut FlightServiceClient<Channel>,
    info: FlightInfo,
) -> Result<Vec<RecordBatch>> {
    let schema = Schema::try_from(info.clone())?;
    let endpoint = info.endpoint.first().context("missing endpoint")?;
    let ticket = endpoint.ticket.clone().context("missing ticket")?;
    let data = client.do_get(request(ticket)).await?.into_inner();
    let batches = FlightRecordBatchStream::new_from_flight_data(data.map_err(Into::into))
        .try_collect::<Vec<_>>()
        .await?;
    for batch in &batches {
        ensure!(batch.schema().as_ref() == &schema, "schema/stream mismatch");
    }
    Ok(batches)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn variant_results_are_json_through_flight() -> Result<()> {
    let config = ServerConfig {
        ducklake_init_sql: Some(
            "ATTACH ':memory:' AS feed; \
            CREATE TABLE feed.main.run(id INTEGER, config VARIANT); \
            INSERT INTO feed.main.run VALUES (1, {'width': 64}::VARIANT), (2, NULL);"
                .into(),
        ),
        ..ServerConfig::default()
    };
    let factory = Arc::new(EngineFactory::new_without_extension_bootstrap(&config));
    let registry = Arc::new(SessionRegistry::new(&config, factory)?);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let service = SwanFlightService::new(
        registry,
        Arc::new(Metrics::new(1000, 64)),
        SessionIdMode::PeerAddr,
        format!("grpc://{addr}"),
    );
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(FlightServiceServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
    });
    let channel = Channel::from_shared(format!("http://{addr}"))?
        .connect()
        .await?;
    let mut client = FlightServiceClient::new(channel.clone());
    let result: Result<()> = async {
        let info = client
            .get_flight_info(request(FlightDescriptor::new_cmd(
                "SELECT * FROM feed.main.run ORDER BY id",
            )))
            .await?
            .into_inner();
        let batches = read_result(&mut client, info).await?;
        let batch = batches.first().context("missing rows")?;
        let configs = batch
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .context("config is not text")?;
        ensure!(
            serde_json::from_str::<serde_json::Value>(configs.value(0))?
                == serde_json::json!({"width": 64})
        );
        ensure!(configs.is_null(1), "SQL NULL was changed");

        let mut sql_client = FlightSqlServiceClient::new(channel);
        sql_client.set_header("airport-client-session-id", "variant-test");
        let mut prepared = sql_client
            .prepare("SELECT config FROM feed.main.run WHERE id = ?".into(), None)
            .await?;
        ensure!(prepared.dataset_schema()?.field(0).data_type() == &DataType::Utf8);
        prepared.set_parameters(RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)])),
            vec![Arc::new(Int32Array::from(vec![1]))],
        )?)?;
        let batches = read_result(&mut client, prepared.execute().await?).await?;
        let batch = batches.first().context("missing prepared rows")?;
        ensure!(batch.num_rows() == 1 && batch.schema().field(0).data_type() == &DataType::Utf8);
        Ok(())
    }
    .await;
    server.abort();
    result
}
