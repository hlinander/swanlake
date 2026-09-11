## Handler Overview

This directory contains the Flight SQL handler implementations that plug into `FlightSqlService` for the Swanlake server. Handlers are split by feature area (statements, prepared statements, tickets, SQL info metadata, and transactions) and mostly delegate into `SwanFlightSqlService`/session helpers.

### Architecture (happy-path)

```
CommandStatementQuery / CommandPreparedStatementQuery
                │
                ▼
     get_flight_info_* (plan schema if query; ticket includes returns_rows)
                │
                ▼
     DoGet statement/prepared
       ├─ returns_rows=true  → execute_prepared_query_handle (stream batches)
       └─ returns_rows=false → execute_prepared_update_handle (empty stream + affected rows)

CommandStatementUpdate / CommandPreparedStatementUpdate
                │
                ▼
            DoPut update (handles parameters, appender fast paths)
```

### Statement Handlers (`statement.rs`)
- `get_flight_info_statement`: Plans a schema for an ad-hoc SQL string and returns a `FlightInfo`/ticket; supports both queries (planned schema) and commands (empty schema) so ExecuteQuery callers can send any SQL.
- `do_get_statement`: Resolves a ticket and streams results for a prepared or ephemeral statement; executes non-query tickets and reports affected rows when applicable. Falls back to SQL embedded in the ticket if a handle is missing.
- `do_put_statement_update`: Executes an ad-hoc update statement via DoPut (no result set), returning affected rows.

### Prepared Statement Handlers (`prepared.rs`)
- `do_action_create_prepared_statement`: Creates a prepared statement, infers whether it is a query, and caches schema when possible.
- `get_flight_info_prepared_statement`/`do_get_prepared_statement`: Fetch schema and stream results for query prepared statements; execute updates/DDL via DoGet with affected-row metadata when a prepared statement does not return rows.
- `do_put_prepared_statement_query`: Binds parameters for prepared statements (query or command) without executing them.
- `do_put_prepared_statement_update`: Executes prepared statements that mutate data/schema, with optimized paths for inserts and fallback parameter batching for other updates/DDL.
- `do_action_close_prepared_statement`: Closes a prepared statement handle.

### Ticket Helpers (`ticket.rs`)
- Defines the serialized payload carried in Flight tickets, including prepared vs. ephemeral handles, optional fallback SQL, and whether the statement returns rows.

### SQL Info Handlers (`sql_info.rs`)
- Serves static SQL capability metadata via Flight's SqlInfo endpoints.

### Transaction Handlers (`transaction.rs`)
- Starts and completes transactions (commit/rollback) for a session, tolerating autocommit no-ops.

## Guarded loader execution

`execute_guarded` accepts the same SQL body and authentication headers as
`execute`, with optional `x-swanlake-request-id` (UUID). Its single JSON result
contains `version: 1`, `completed: true`, and `error: null` on success. A rejected
request or finished SQL error contains `error: {code, message}` using the gRPC
status code. The envelope is emitted after execution returns; it also covers
authentication and nonce rejection. Guarded requests omit SQL and body contents
from action logs because source setup can carry credentials.

`cancel_execution` requests an interrupt for the UUID; its `cancelled` response
does not acknowledge completion. A caller that must serialize mutations waits
for the original completion envelope. A lost envelope leaves the result unknown,
even when cancellation was requested. Existing `execute` results remain MsgPack.


`execution_identity` authenticates the caller and returns `{version: 1, owner,
generation}`. `SWANLAKE_EXECUTION_OWNER_PATH` enables restart recovery: the
server exclusively locks this persistent local file before starting execution
threads and retains the lock until OS process exit. Each start generates a new
generation UUID. A different generation with the same owner proves that the
previous process exited. Without this setting, `owner` is null and clients
cannot infer termination from a restart.

Create the parent directory for the service user. Keep the file outside release
and temporary directories; never copy, replace, or unlink it while a server is
running. Losing the owner file changes identity and requires manual recovery of
old uncertain writes. Use a separate file for each independent server.

Guarded statements carrying `x-swanlake-generation` execute only on that
generation. A mismatch returns a completed rejection before SQL execution, so a
delayed old request cannot execute after recovery. Deploy the server before a
client that requires `execution_identity`.

Live CPU sampling retains the actual query connection until the sampler thread
exits. The response also retains that connection throughout progress polling.
The CPU reader and profiler updates use DuckDB's profiler mutex. Flight metadata
includes `cpu_time_us` when profiling data is available; memory and progress
telemetry continue independently.
