use anyhow::{bail, ensure, Context, Result};
use arrow_array::Int32Array;
use swanlake_client::{FlightSQLClient, QueryResult};
use tracing::info;

use crate::CliArgs;

/// Transaction abort tests
///
/// A session behaves as a DuckDB connection does. The server neither rolls a
/// transaction back nor runs a statement a second time:
/// - after an execution error inside a transaction, DuckDB refuses every
///   statement until the client sends ROLLBACK;
/// - a COMMIT that loses a conflict returns the conflict error, and nothing of
///   the losing transaction is committed;
/// - an error outside a transaction leaves the session usable.
pub fn run_transaction_abort(args: &CliArgs) -> Result<()> {
    info!("Running transaction abort tests");

    let mut client = FlightSQLClient::connect(&args.endpoint)
        .context("failed to connect to FlightSQL server")?;
    client.update("use swanlake")?;

    test_abort_refuses_statements_until_rollback(&mut client, "tx_abort")?;
    test_abort_refuses_statements_until_rollback(&mut client, "swanlake.tx_abort_catalog")?;
    test_commit_conflict_returns_the_conflict(args)?;
    test_session_usable_after_autocommit_error(&mut client)?;
    test_new_session_after_abort(args)?;

    info!("Transaction abort tests completed successfully");
    Ok(())
}

fn test_abort_refuses_statements_until_rollback(
    client: &mut FlightSQLClient,
    table: &str,
) -> Result<()> {
    client.update(&format!("DROP TABLE IF EXISTS {table}"))?;
    let result = (|| -> Result<()> {
        client.update(&format!("CREATE TABLE {table} (id INT)"))?;

        client.update("BEGIN")?;
        client.update(&format!("INSERT INTO {table} VALUES (1)"))?;

        // An execution error inside the transaction aborts it.
        let type_err = match client.update(&format!("INSERT INTO {table} VALUES ('oops')")) {
            Ok(_) => bail!("expected type error inside transaction"),
            Err(err) => err,
        };
        let err_text = type_err.to_string().to_lowercase();
        ensure!(
            err_text.contains("type")
                || err_text.contains("conversion")
                || err_text.contains("cast"),
            "expected a type-related error, got {err_text}"
        );

        // The next statement is refused; it must not run outside the transaction.
        let refused = match client.update(&format!("INSERT INTO {table} VALUES (2)")) {
            Ok(_) => bail!("expected the aborted transaction to refuse a statement"),
            Err(err) => err.to_string(),
        };
        ensure!(
            refused.contains("Current transaction is aborted"),
            "expected the aborted-transaction error, got {refused}"
        );

        client.update("ROLLBACK")?;
        client.update(&format!("INSERT INTO {table} VALUES (3)"))?;

        let ids = fetch_ids(client, &format!("SELECT id FROM {table} ORDER BY id"))?;
        ensure!(
            ids == vec![3],
            "expected only the insert after ROLLBACK for {table}, got {ids:?}"
        );
        Ok(())
    })();

    // Leave no open transaction behind when an assertion failed midway.
    let _ = client.update("ROLLBACK");
    client.update(&format!("DROP TABLE IF EXISTS {table}"))?;
    result
}

fn test_commit_conflict_returns_the_conflict(args: &CliArgs) -> Result<()> {
    let connect = || -> Result<FlightSQLClient> {
        let mut client = FlightSQLClient::connect(&args.endpoint)
            .context("failed to connect to FlightSQL server for conflict test")?;
        client.update("use swanlake")?;
        Ok(client)
    };
    let mut winner = connect()?;
    let mut loser = connect()?;

    winner.update("DROP TABLE IF EXISTS swanlake.tx_conflict_lock")?;
    winner.update("DROP TABLE IF EXISTS swanlake.tx_conflict_rows")?;
    let result = (|| -> Result<()> {
        winner.update("CREATE TABLE swanlake.tx_conflict_lock (id INT)")?;
        winner.update("CREATE TABLE swanlake.tx_conflict_rows (id INT)")?;
        winner.update("INSERT INTO swanlake.tx_conflict_lock VALUES (0)")?;

        // Both transactions read before either writes, so they share a snapshot.
        winner.update("BEGIN")?;
        loser.update("BEGIN")?;
        fetch_ids(&mut winner, "SELECT id FROM swanlake.tx_conflict_lock")?;
        fetch_ids(&mut loser, "SELECT id FROM swanlake.tx_conflict_lock")?;

        winner.update("INSERT INTO swanlake.tx_conflict_rows VALUES (1)")?;
        winner.update("UPDATE swanlake.tx_conflict_lock SET id = 1")?;
        loser.update("INSERT INTO swanlake.tx_conflict_rows VALUES (2)")?;
        loser.update("UPDATE swanlake.tx_conflict_lock SET id = 2")?;

        winner.update("COMMIT")?;
        let conflict = match loser.update("COMMIT") {
            Ok(_) => bail!("expected the second COMMIT to lose the conflict"),
            Err(err) => err.to_string(),
        };
        ensure!(
            conflict.to_lowercase().contains("conflict"),
            "expected the conflict error, got {conflict}"
        );
        ensure!(
            !conflict.contains("no transaction is active"),
            "COMMIT ran a second time: {conflict}"
        );

        // The losing transaction is gone, and the session works in autocommit.
        let rows = fetch_ids(
            &mut loser,
            "SELECT id FROM swanlake.tx_conflict_rows ORDER BY id",
        )?;
        ensure!(
            rows == vec![1],
            "expected only the winner's row, got {rows:?}"
        );
        let lock = fetch_ids(&mut loser, "SELECT id FROM swanlake.tx_conflict_lock")?;
        ensure!(
            lock == vec![1],
            "expected the winner's lock value, got {lock:?}"
        );
        Ok(())
    })();

    let _ = winner.update("ROLLBACK");
    let _ = loser.update("ROLLBACK");
    winner.update("DROP TABLE IF EXISTS swanlake.tx_conflict_lock")?;
    winner.update("DROP TABLE IF EXISTS swanlake.tx_conflict_rows")?;
    result?;
    info!("Commit conflict test passed");
    Ok(())
}

fn test_session_usable_after_autocommit_error(client: &mut FlightSQLClient) -> Result<()> {
    client.update("DROP TABLE IF EXISTS autocommit_error_test")?;
    client.update("CREATE TABLE autocommit_error_test (id INT, name VARCHAR)")?;
    client.update("INSERT INTO autocommit_error_test VALUES (1, 'test')")?;

    // A catalog error outside a transaction aborts nothing.
    let err = match client.execute("SELECT * FROM non_existent_table_xyz LIMIT 10") {
        Ok(_) => bail!("expected error for non-existent table"),
        Err(err) => err,
    };
    let err_text = err.to_string().to_lowercase();
    ensure!(
        err_text.contains("catalog")
            || err_text.contains("not found")
            || err_text.contains("does not exist"),
        "expected catalog/not found error, got {err_text}"
    );

    let result = client.execute("SHOW TABLES")?;
    ensure!(
        result.total_rows > 0,
        "expected SHOW TABLES to succeed after the error"
    );

    let result = client.execute("SELECT COUNT(*) FROM autocommit_error_test")?;
    ensure!(
        result.total_rows == 1,
        "expected to query the existing table after the error"
    );

    client.update("DROP TABLE IF EXISTS autocommit_error_test")?;
    info!("Autocommit error test passed");
    Ok(())
}

fn test_new_session_after_abort(args: &CliArgs) -> Result<()> {
    // A fresh connection works after another session's transaction aborted.
    let mut client = FlightSQLClient::connect(&args.endpoint)
        .context("failed to connect to FlightSQL server for new session test")?;
    client.update("use swanlake")?;
    let QueryResult { total_rows, .. } = client.execute("SELECT 1")?;
    ensure!(total_rows == 1, "expected SELECT 1 to return a single row");
    Ok(())
}

fn fetch_ids(client: &mut FlightSQLClient, sql: &str) -> Result<Vec<i32>> {
    let QueryResult { batches, .. } = client.execute(sql)?;
    let Some(batch) = batches.first() else {
        return Ok(Vec::new());
    };
    let array = batch
        .column(0)
        .as_any()
        .downcast_ref::<Int32Array>()
        .context("expected Int32 array for id column")?;
    Ok((0..array.len()).map(|i| array.value(i)).collect())
}
