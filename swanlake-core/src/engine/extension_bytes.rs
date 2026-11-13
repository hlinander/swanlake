//! Checks the bytes that loadable extensions transfer (duckvis#815, C15).
//!
//! `postgres_scanner` and `httpfs` each carry their own copy of the engine.
//! The test establishes that their transfers reach the host's totals and
//! the operator scope the host opened, and that the HTTP count counts no
//! byte twice.
//!
//! It runs when `SWANLAKE_TEST_EXTENSION_DIR` names a directory holding the
//! extension set built for this engine and `SWANLAKE_TEST_PG_DSN` names a
//! Postgres database, and is skipped otherwise.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::Value;

use crate::config::ServerConfig;
use crate::engine::{DuckDbConnection, EngineFactory};
use crate::usage::testing::record_of;
use crate::usage::ExecutionLabel;

const EXTENSIONS: [&str; 4] = ["parquet", "httpfs", "postgres_scanner", "ducklake"];

fn literal(text: &str) -> String {
    text.replace('\'', "''")
}

/// The statements that load the extension set from `dir`. A directory that
/// holds the extension files themselves loads each by path; otherwise `dir`
/// is an extension directory in the engine's own layout and each loads by
/// name. Either way the engine looks in no other directory.
fn load_sql(dir: &str) -> String {
    let mut sql = format!("SET extension_directory = '{}';", literal(dir));
    for name in EXTENSIONS {
        let file = Path::new(dir).join(format!("{name}.duckdb_extension"));
        if file.is_file() {
            sql.push_str(&format!(" LOAD '{}';", literal(&file.to_string_lossy())));
        } else {
            sql.push_str(&format!(" LOAD {name};"));
        }
    }
    sql
}

/// Serves `body` over HTTP on the loopback address, answering `HEAD`, `GET`,
/// and ranged `GET`, and adds every body byte it sends to `sent`.
fn serve(body: Arc<Vec<u8>>, sent: Arc<AtomicU64>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the HTTP listener");
    let port = listener.local_addr().expect("listener address").port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let body = Arc::clone(&body);
            let sent = Arc::clone(&sent);
            std::thread::spawn(move || {
                let _ = answer(stream, &body, &sent);
            });
        }
    });
    port
}

/// The inclusive byte range a `Range` header value names within `len` bytes.
fn byte_range(value: &str, len: usize) -> Option<(usize, usize)> {
    let (first, last) = value.trim().strip_prefix("bytes=")?.split_once('-')?;
    let end = len.checked_sub(1)?;
    if first.is_empty() {
        let suffix: usize = last.parse().ok()?;
        return Some((len.saturating_sub(suffix), end));
    }
    let first: usize = first.parse().ok()?;
    let last = match last {
        "" => end,
        last => last.parse::<usize>().ok()?.min(end),
    };
    (first <= last).then_some((first, last))
}

fn answer(stream: TcpStream, body: &[u8], sent: &AtomicU64) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut stream = stream;
    loop {
        let mut request = String::new();
        if reader.read_line(&mut request)? == 0 {
            return Ok(());
        }
        let head = request.starts_with("HEAD ");
        let mut range = None;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header)? == 0 || header.trim().is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                if name.eq_ignore_ascii_case("range") {
                    range = byte_range(value, body.len());
                }
            }
        }
        let (status, slice, content_range) = match range {
            Some((first, last)) => (
                "206 Partial Content",
                &body[first..=last],
                format!("Content-Range: bytes {first}-{last}/{}\r\n", body.len()),
            ),
            None => ("200 OK", body, String::new()),
        };
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\n\
             Content-Type: application/octet-stream\r\n{content_range}\r\n",
            slice.len()
        )?;
        if !head {
            stream.write_all(slice)?;
            sent.fetch_add(slice.len() as u64, Ordering::SeqCst);
        }
        stream.flush()?;
    }
}

/// Runs `sql` as one request on the route that discards results and returns
/// the entry of its one statement.
fn bracketed(conn: &DuckDbConnection, sql: &str, dsn: &str) -> Value {
    let (result, record) = record_of(|accounting| {
        conn.execute_statement_with_telemetry(sql, None, None, Some(accounting))
    });
    if let Err(error) = result {
        // The engine's text can repeat the catalog's connection string.
        panic!("statement failed: {}", error.to_string().replace(dsn, "<dsn>"));
    }
    let record = record.expect("the request recorded its statement");
    let entries = record["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 1, "one statement, one entry");
    assert_eq!(entries[0]["provenance"], "CLIENT");
    entries[0].clone()
}

fn bytes(entry: &Value, field: &str) -> u64 {
    entry[field]
        .as_u64()
        .unwrap_or_else(|| panic!("{field} is missing from {entry}"))
}

/// The sum of `operator_bytes_read` over a breakdown tree.
fn operator_bytes_read(node: &Value) -> u64 {
    let below: u64 = node["children"]
        .as_array()
        .map(|children| children.iter().map(operator_bytes_read).sum())
        .unwrap_or(0);
    node["operator_bytes_read"].as_u64().unwrap_or(0) + below
}

#[test]
fn extension_transfers_reach_the_totals_and_the_operators() {
    let (Ok(dir), Ok(dsn)) = (
        std::env::var("SWANLAKE_TEST_EXTENSION_DIR"),
        std::env::var("SWANLAKE_TEST_PG_DSN"),
    ) else {
        eprintln!("skipped: SWANLAKE_TEST_EXTENSION_DIR and SWANLAKE_TEST_PG_DSN are not both set");
        return;
    };

    let config = ServerConfig {
        ducklake_init_sql: Some(load_sql(&dir)),
        ..ServerConfig::default()
    };
    let conn = EngineFactory::new_for_tests(&config)
        .create_connection()
        .expect("a connection with the extension set loaded");

    let scratch = tempfile::tempdir().expect("scratch directory");
    let data_path = scratch.path().join("lake");
    std::fs::create_dir_all(&data_path).expect("data path");
    let schema = format!(
        "c15_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default()
    );
    let setup = format!(
        "SET enable_profiling = 'no_output'; \
         SET profiling_coverage = 'all'; \
         SET custom_profiling_settings = '{{\"OPERATOR_CPU_TIME\": \"true\", \
         \"OPERATOR_TIMING\": \"true\", \"OPERATOR_CARDINALITY\": \"true\", \
         \"OPERATOR_BYTES_READ\": \"true\", \"OPERATOR_BYTES_WRITTEN\": \"true\"}}'; \
         ATTACH 'ducklake:postgres:{}' AS lake (DATA_PATH '{}', METADATA_SCHEMA '{schema}')",
        literal(&dsn),
        literal(&data_path.to_string_lossy()),
    );
    if let Err(error) = conn.execute_batch(&setup, ExecutionLabel::SwanLake, None) {
        panic!(
            "attaching the DuckLake failed: {}",
            error.to_string().replace(&dsn, "<dsn>")
        );
    }

    // The file the listener serves.
    let served = scratch.path().join("served.parquet");
    conn.execute_batch(
        &format!(
            "COPY (SELECT i, i::VARCHAR AS s FROM range(50000) t(i)) TO '{}' (FORMAT parquet)",
            literal(&served.to_string_lossy())
        ),
        ExecutionLabel::SwanLake,
        None,
    )
    .expect("write the served parquet file");
    let sent = Arc::new(AtomicU64::new(0));
    let port = serve(
        Arc::new(std::fs::read(&served).expect("read the served file")),
        Arc::clone(&sent),
    );

    let created = bracketed(&conn, "CREATE TABLE lake.transfers (i BIGINT, s VARCHAR)", &dsn);
    let inserted = bracketed(
        &conn,
        "INSERT INTO lake.transfers SELECT i, i::VARCHAR FROM range(20000) t(i)",
        &dsn,
    );
    let read = bracketed(
        &conn,
        "SELECT count(*), sum(i), max(s) FROM lake.transfers",
        &dsn,
    );
    for (statement, entry) in [("create", &created), ("insert", &inserted), ("read", &read)] {
        assert!(
            bytes(entry, "bytes_read") > 0,
            "the {statement} statement read no byte: {entry}"
        );
        assert!(
            bytes(entry, "bytes_written") > 0,
            "the {statement} statement wrote no byte: {entry}"
        );
    }
    assert!(
        operator_bytes_read(&read["breakdown"]) > 0,
        "no operator of the reading statement read a byte: {read}"
    );

    let before = sent.load(Ordering::SeqCst);
    let http = bracketed(
        &conn,
        &format!(
            "SELECT count(*), sum(i), max(s) FROM read_parquet('http://127.0.0.1:{port}/served.parquet')"
        ),
        &dsn,
    );
    let served_bytes = sent.load(Ordering::SeqCst) - before;
    let http_read = bytes(&http, "bytes_read");
    assert!(http_read > 0, "the HTTP statement read no byte: {http}");
    assert!(
        http_read <= served_bytes,
        "the HTTP statement counted {http_read} bytes and the listener sent {served_bytes}"
    );
}
