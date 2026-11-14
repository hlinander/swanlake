//! The record of one request: its JSON form, the SQL text rules, and the size
//! bound.

use bytes::Bytes;
use serde::Serialize;

use libduckdb_sys as ffi;

use super::accounting::Entry;

/// Largest SQL text a record carries, in bytes.
pub const MAX_SQL_BYTES: usize = 65_536;

/// Largest serialized record, in bytes. Equals the declared bound of the
/// audit field that holds the record in the duckvis API.
pub const MAX_RECORD_BYTES: usize = 4_194_304;

/// Most levels a stored breakdown has, its root being the first. A level
/// serializes as an object inside an array, and the duckvis API's JSON
/// parser refuses a body nested deeper than 128.
pub const MAX_BREAKDOWN_LEVELS: usize = 48;

/// Largest serialized size of a request's entries, in bytes, at which an
/// entry is still stored with its breakdown.
pub const MAX_ENTRIES_BYTES_WITH_BREAKDOWN: usize = 2_097_152;

/// Largest serialized size of the entries a request stores, in bytes.
pub const MAX_ENTRIES_BYTES: usize = MAX_RECORD_BYTES;

/// The bytes an entry's serialized form gains from the name of its
/// `breakdown` member, ahead of the breakdown's own bytes.
pub(super) const BREAKDOWN_MEMBER_BYTES: usize = r#","breakdown":"#.len();

/// The number of bytes `value` serializes to as JSON.
pub(super) fn serialized_len<T: Serialize>(value: &T) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    // The writer never fails, and the values measured here hold no map
    // with a key that is not a string.
    let _ = serde_json::to_writer(&mut count, value);
    count.0
}

/// What a record carries of the SQL text a client sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct SqlText {
    /// The text, cut to [`MAX_SQL_BYTES`]. `None` when it is redacted.
    pub(super) text: Option<String>,
    pub(super) truncated: bool,
    pub(super) redacted: bool,
}

impl SqlText {
    /// Applies the redaction test to the whole of `sql`, then keeps at most
    /// [`MAX_SQL_BYTES`] of a text that passes it.
    pub(super) fn capture(sql: &str) -> Self {
        if can_carry_credential(sql) {
            return Self {
                text: None,
                truncated: false,
                redacted: true,
            };
        }
        let kept = truncate_at_char_boundary(sql, MAX_SQL_BYTES);
        Self {
            text: Some(kept.to_owned()),
            truncated: kept.len() < sql.len(),
            redacted: false,
        }
    }
}

/// The longest prefix of `text` that holds at most `max_bytes` bytes and ends
/// at a UTF-8 character boundary.
fn truncate_at_char_boundary(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Substrings that mark a text as able to carry a credential. Each is
/// lowercase ASCII and is compared without ASCII case.
const CREDENTIAL_MARKERS: [&[u8]; 15] = [
    b"secret",
    b"password",
    b"passwd",
    b"pwd",
    b"token",
    b"_key",
    b"credential",
    b"connection_string",
    b"authorization",
    b"bearer",
    b"sig=",
    b"signature=",
    b"api-key",
    b"apikey",
    b"cookie",
];

/// Whether `sql` contains a credential marker, or a `://` followed by an `@`
/// ahead of the next `/`. One pass over the bytes.
fn can_carry_credential(sql: &str) -> bool {
    let bytes = sql.as_bytes();
    // Set between a `://` and the next `/`.
    let mut in_authority = false;
    let mut at = 0;
    while at < bytes.len() {
        let rest = &bytes[at..];
        match rest[0] {
            b':' if rest.starts_with(b"://") => {
                in_authority = true;
                at += 3;
                continue;
            }
            b'/' => in_authority = false,
            b'@' if in_authority => return true,
            _ => {}
        }
        if CREDENTIAL_MARKERS.iter().any(|marker| {
            rest.len() >= marker.len() && rest[..marker.len()].eq_ignore_ascii_case(marker)
        }) {
            return true;
        }
        at += 1;
    }
    false
}

/// The name of a `duckdb_error_type` constant without its `DUCKDB_ERROR_`
/// prefix. `DUCKDB_INVALID_CONFIGURATION` has no such prefix and is
/// `INVALID_CONFIGURATION`. `None` for a value that is no constant of the
/// enum.
pub(super) fn error_type_name(error_type: ffi::duckdb_error_type) -> Option<&'static str> {
    let name = match error_type {
        ffi::duckdb_error_type_DUCKDB_ERROR_INVALID => "INVALID",
        ffi::duckdb_error_type_DUCKDB_ERROR_OUT_OF_RANGE => "OUT_OF_RANGE",
        ffi::duckdb_error_type_DUCKDB_ERROR_CONVERSION => "CONVERSION",
        ffi::duckdb_error_type_DUCKDB_ERROR_UNKNOWN_TYPE => "UNKNOWN_TYPE",
        ffi::duckdb_error_type_DUCKDB_ERROR_DECIMAL => "DECIMAL",
        ffi::duckdb_error_type_DUCKDB_ERROR_MISMATCH_TYPE => "MISMATCH_TYPE",
        ffi::duckdb_error_type_DUCKDB_ERROR_DIVIDE_BY_ZERO => "DIVIDE_BY_ZERO",
        ffi::duckdb_error_type_DUCKDB_ERROR_OBJECT_SIZE => "OBJECT_SIZE",
        ffi::duckdb_error_type_DUCKDB_ERROR_INVALID_TYPE => "INVALID_TYPE",
        ffi::duckdb_error_type_DUCKDB_ERROR_SERIALIZATION => "SERIALIZATION",
        ffi::duckdb_error_type_DUCKDB_ERROR_TRANSACTION => "TRANSACTION",
        ffi::duckdb_error_type_DUCKDB_ERROR_NOT_IMPLEMENTED => "NOT_IMPLEMENTED",
        ffi::duckdb_error_type_DUCKDB_ERROR_EXPRESSION => "EXPRESSION",
        ffi::duckdb_error_type_DUCKDB_ERROR_CATALOG => "CATALOG",
        ffi::duckdb_error_type_DUCKDB_ERROR_PARSER => "PARSER",
        ffi::duckdb_error_type_DUCKDB_ERROR_PLANNER => "PLANNER",
        ffi::duckdb_error_type_DUCKDB_ERROR_SCHEDULER => "SCHEDULER",
        ffi::duckdb_error_type_DUCKDB_ERROR_EXECUTOR => "EXECUTOR",
        ffi::duckdb_error_type_DUCKDB_ERROR_CONSTRAINT => "CONSTRAINT",
        ffi::duckdb_error_type_DUCKDB_ERROR_INDEX => "INDEX",
        ffi::duckdb_error_type_DUCKDB_ERROR_STAT => "STAT",
        ffi::duckdb_error_type_DUCKDB_ERROR_CONNECTION => "CONNECTION",
        ffi::duckdb_error_type_DUCKDB_ERROR_SYNTAX => "SYNTAX",
        ffi::duckdb_error_type_DUCKDB_ERROR_SETTINGS => "SETTINGS",
        ffi::duckdb_error_type_DUCKDB_ERROR_BINDER => "BINDER",
        ffi::duckdb_error_type_DUCKDB_ERROR_NETWORK => "NETWORK",
        ffi::duckdb_error_type_DUCKDB_ERROR_OPTIMIZER => "OPTIMIZER",
        ffi::duckdb_error_type_DUCKDB_ERROR_NULL_POINTER => "NULL_POINTER",
        ffi::duckdb_error_type_DUCKDB_ERROR_IO => "IO",
        ffi::duckdb_error_type_DUCKDB_ERROR_INTERRUPT => "INTERRUPT",
        ffi::duckdb_error_type_DUCKDB_ERROR_FATAL => "FATAL",
        ffi::duckdb_error_type_DUCKDB_ERROR_INTERNAL => "INTERNAL",
        ffi::duckdb_error_type_DUCKDB_ERROR_INVALID_INPUT => "INVALID_INPUT",
        ffi::duckdb_error_type_DUCKDB_ERROR_OUT_OF_MEMORY => "OUT_OF_MEMORY",
        ffi::duckdb_error_type_DUCKDB_ERROR_PERMISSION => "PERMISSION",
        ffi::duckdb_error_type_DUCKDB_ERROR_PARAMETER_NOT_RESOLVED => "PARAMETER_NOT_RESOLVED",
        ffi::duckdb_error_type_DUCKDB_ERROR_PARAMETER_NOT_ALLOWED => "PARAMETER_NOT_ALLOWED",
        ffi::duckdb_error_type_DUCKDB_ERROR_DEPENDENCY => "DEPENDENCY",
        ffi::duckdb_error_type_DUCKDB_ERROR_HTTP => "HTTP",
        ffi::duckdb_error_type_DUCKDB_ERROR_MISSING_EXTENSION => "MISSING_EXTENSION",
        ffi::duckdb_error_type_DUCKDB_ERROR_AUTOLOAD => "AUTOLOAD",
        ffi::duckdb_error_type_DUCKDB_ERROR_SEQUENCE => "SEQUENCE",
        ffi::duckdb_error_type_DUCKDB_INVALID_CONFIGURATION => "INVALID_CONFIGURATION",
        _ => return None,
    };
    Some(name)
}

/// The parts of a record that [`serialize`] puts into one JSON object.
pub(super) struct RecordParts<'a> {
    pub(super) request_id: uuid::Uuid,
    pub(super) project_id: &'a str,
    pub(super) subject: &'a str,
    pub(super) endpoint: &'a str,
    pub(super) sql: &'a SqlText,
    pub(super) ended_at: chrono::DateTime<chrono::Utc>,
    pub(super) error_type: Option<&'static str>,
    /// Set when an entry was stored without the breakdown its attempt had.
    pub(super) breakdown_omitted: bool,
    pub(super) entries: Vec<Entry>,
}

#[derive(Serialize)]
struct RecordJson<'a> {
    request_id: String,
    project_id: &'a str,
    subject: &'a str,
    endpoint: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql: Option<&'a str>,
    sql_truncated: bool,
    sql_redacted: bool,
    ended_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_type: Option<&'static str>,
    breakdown_omitted: bool,
    entries: &'a [Entry],
}

/// The outcome of serializing a record against [`MAX_RECORD_BYTES`].
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Serialized {
    /// The record's bytes, within the bound.
    Record(Bytes),
    /// The record passes the bound without its breakdowns, or its
    /// accounting stopped storing entries. It is discarded.
    Oversized,
}

/// Serializes a record once. A record that passes [`MAX_RECORD_BYTES`] drops
/// every breakdown and sets `breakdown_omitted`. The request accounting
/// bounds the entries it stores by an estimate, and this is the test on the
/// serialized record itself.
pub(super) fn serialize(parts: RecordParts<'_>) -> Serialized {
    serialize_within(parts, MAX_RECORD_BYTES)
}

fn serialize_within(mut parts: RecordParts<'_>, max_bytes: usize) -> Serialized {
    let full = to_json(&parts, parts.breakdown_omitted);
    if full.len() <= max_bytes {
        return Serialized::Record(full.into());
    }
    for entry in &mut parts.entries {
        entry.breakdown = None;
    }
    let reduced = to_json(&parts, true);
    if reduced.len() <= max_bytes {
        return Serialized::Record(reduced.into());
    }
    Serialized::Oversized
}

fn to_json(parts: &RecordParts<'_>, breakdown_omitted: bool) -> Vec<u8> {
    let record = RecordJson {
        request_id: parts.request_id.hyphenated().to_string(),
        project_id: parts.project_id,
        subject: parts.subject,
        endpoint: parts.endpoint,
        sql: parts.sql.text.as_deref(),
        sql_truncated: parts.sql.truncated,
        sql_redacted: parts.sql.redacted,
        ended_at: parts
            .ended_at
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        error_type: parts.error_type,
        breakdown_omitted,
        entries: &parts.entries,
    };
    // `serde_json::to_vec` fails only on a `Serialize` impl that fails or a
    // map key that is not a string, and the record holds neither. An empty
    // body would be refused by the API with 400, discarded, and counted.
    serde_json::to_vec(&record).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::super::accounting::{BreakdownNode, ExecutionLabel};
    use super::*;

    fn entry(attempt_id: u64, breakdown: Option<BreakdownNode>) -> Entry {
        Entry {
            attempt_id,
            provenance: ExecutionLabel::Client,
            cpu_seconds: 1.5,
            bytes_read: 10,
            bytes_written: 20,
            connection_cpu_seconds: 0.5,
            connection_bytes_read: 3,
            connection_bytes_written: 4,
            memory_peak_bytes: 4096,
            memory_byte_seconds: 2.25,
            memory_open_bytes: 1024,
            abandoned: false,
            breakdown,
        }
    }

    fn node(name: &str, children: Vec<BreakdownNode>) -> BreakdownNode {
        BreakdownNode {
            operator_type: "SEQ_SCAN".to_owned(),
            operator_name: name.to_owned(),
            operator_cpu_time: 0.25,
            operator_timing: 0.5,
            operator_cardinality: 7,
            operator_bytes_read: 8,
            operator_bytes_written: 9,
            children,
        }
    }

    fn parts<'a>(sql: &'a SqlText, entries: Vec<Entry>) -> RecordParts<'a> {
        RecordParts {
            request_id: uuid::Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_0001),
            project_id: "project-1",
            subject: "subject-1",
            endpoint: "DoGet",
            sql,
            ended_at: chrono::DateTime::from_timestamp(1_700_000_000, 123_456_789)
                .expect("valid timestamp"),
            error_type: None,
            breakdown_omitted: false,
            entries,
        }
    }

    fn entry_json(
        attempt_id: u64,
        provenance: &str,
        abandoned: bool,
        breakdown: Option<Value>,
    ) -> Value {
        let mut entry = json!({
            "attempt_id": attempt_id,
            "provenance": provenance,
            "cpu_seconds": 1.5,
            "bytes_read": 10,
            "bytes_written": 20,
            "connection_cpu_seconds": 0.5,
            "connection_bytes_read": 3,
            "connection_bytes_written": 4,
            "memory_peak_bytes": 4096,
            "memory_byte_seconds": 2.25,
            "memory_open_bytes": 1024,
            "abandoned": abandoned
        });
        if let Some(breakdown) = breakdown {
            entry["breakdown"] = breakdown;
        }
        entry
    }

    fn node_json(name: &str, children: Value) -> Value {
        json!({
            "operator_type": "SEQ_SCAN",
            "operator_name": name,
            "operator_cpu_time": 0.25,
            "operator_timing": 0.5,
            "operator_cardinality": 7,
            "operator_bytes_read": 8,
            "operator_bytes_written": 9,
            "children": children
        })
    }

    fn parse(serialized: Serialized) -> Value {
        match serialized {
            Serialized::Record(bytes) => serde_json::from_slice(&bytes).expect("record is JSON"),
            Serialized::Oversized => panic!("record was discarded"),
        }
    }

    #[test]
    fn record_carries_the_specified_fields() {
        let sql = SqlText::capture("SELECT 1");
        let mut record_parts = parts(
            &sql,
            vec![
                entry(0, Some(node("t", vec![node("child", vec![])]))),
                Entry {
                    provenance: ExecutionLabel::SwanLake,
                    abandoned: true,
                    ..entry(1, None)
                },
            ],
        );
        record_parts.error_type = error_type_name(ffi::duckdb_error_type_DUCKDB_ERROR_TRANSACTION);

        assert_eq!(
            parse(serialize(record_parts)),
            json!({
                "request_id": "01900000-0000-7000-8000-000000000001",
                "project_id": "project-1",
                "subject": "subject-1",
                "endpoint": "DoGet",
                "sql": "SELECT 1",
                "sql_truncated": false,
                "sql_redacted": false,
                "ended_at": "2023-11-14T22:13:20.123Z",
                "error_type": "TRANSACTION",
                "breakdown_omitted": false,
                "entries": [
                    entry_json(0, "CLIENT", false, Some(node_json("t", json!([node_json("child", json!([]))])))),
                    entry_json(1, "SWANLAKE", true, None),
                ]
            })
        );
    }

    #[test]
    fn a_breakdown_time_that_is_not_finite_reports_as_zero() {
        let sql = SqlText::default();
        let mut child = node("child", vec![]);
        child.operator_cpu_time = f64::NEG_INFINITY;
        child.operator_timing = 0.125;
        let mut root = node("root", vec![child]);
        root.operator_cpu_time = f64::NAN;
        root.operator_timing = f64::INFINITY;

        let record = parse(serialize(parts(&sql, vec![entry(0, Some(root))])));

        let root = &record["entries"][0]["breakdown"];
        assert_eq!(root["operator_cpu_time"], json!(0.0));
        assert_eq!(root["operator_timing"], json!(0.0));
        let child = &root["children"][0];
        assert_eq!(child["operator_cpu_time"], json!(0.0));
        // A finite time is reported as it is.
        assert_eq!(child["operator_timing"], json!(0.125));
    }

    #[test]
    fn record_without_sql_or_error_type_omits_both() {
        let sql = SqlText::default();
        let record = parse(serialize(parts(&sql, vec![entry(0, None)])));
        let object = record.as_object().expect("record is an object");

        assert!(!object.contains_key("sql"));
        assert!(!object.contains_key("error_type"));
        assert_eq!(object["sql_truncated"], json!(false));
        assert_eq!(object["sql_redacted"], json!(false));
    }

    #[test]
    fn ended_at_is_utc_with_millisecond_precision() {
        let sql = SqlText::default();
        let mut record_parts = parts(&sql, vec![entry(0, None)]);
        record_parts.ended_at =
            chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");

        let record = parse(serialize(record_parts));

        assert_eq!(record["ended_at"], json!("2023-11-14T22:13:20.000Z"));
    }

    #[test]
    fn error_type_names_drop_the_constant_prefix() {
        assert_eq!(
            error_type_name(ffi::duckdb_error_type_DUCKDB_ERROR_INVALID),
            Some("INVALID")
        );
        assert_eq!(
            error_type_name(ffi::duckdb_error_type_DUCKDB_ERROR_TRANSACTION),
            Some("TRANSACTION")
        );
        assert_eq!(
            error_type_name(ffi::duckdb_error_type_DUCKDB_ERROR_PARAMETER_NOT_RESOLVED),
            Some("PARAMETER_NOT_RESOLVED")
        );
        assert_eq!(
            error_type_name(ffi::duckdb_error_type_DUCKDB_ERROR_SEQUENCE),
            Some("SEQUENCE")
        );
        // Every value from the first constant to the last has a distinct
        // name.
        assert_eq!(ffi::duckdb_error_type_DUCKDB_ERROR_INVALID, 0);
        assert_eq!(ffi::duckdb_error_type_DUCKDB_INVALID_CONFIGURATION, 42);
        let names = (0..=42)
            .map(error_type_name)
            .collect::<Option<std::collections::BTreeSet<_>>>()
            .expect("a name for each constant");
        assert_eq!(names.len(), 43);
    }

    #[test]
    fn the_constant_without_the_prefix_reports_as_invalid_configuration() {
        assert_eq!(
            error_type_name(ffi::duckdb_error_type_DUCKDB_INVALID_CONFIGURATION),
            Some("INVALID_CONFIGURATION")
        );
    }

    #[test]
    fn a_value_that_is_no_constant_has_no_name() {
        assert_eq!(error_type_name(43), None);
        assert_eq!(error_type_name(ffi::duckdb_error_type::MAX), None);
    }

    #[test]
    fn sql_within_the_bound_is_kept_whole() {
        let text = "x".repeat(MAX_SQL_BYTES);
        let sql = SqlText::capture(&text);

        assert_eq!(sql.text.as_deref(), Some(text.as_str()));
        assert!(!sql.truncated);
    }

    #[test]
    fn sql_is_cut_at_a_character_boundary() {
        // 'é' is two bytes, so byte 65,536 falls inside the last character
        // that starts within the bound.
        let text = format!("x{}", "é".repeat(MAX_SQL_BYTES));
        let sql = SqlText::capture(&text);
        let kept = sql.text.expect("text is kept");

        assert_eq!(kept.len(), MAX_SQL_BYTES - 1);
        assert!(text.starts_with(&kept));
        assert!(kept.ends_with('é'));
        assert!(sql.truncated);
        assert!(!sql.redacted);
    }

    #[test]
    fn four_byte_characters_are_never_split() {
        let text = "🦆".repeat(MAX_SQL_BYTES / 4 + 1);
        for lead in 0..4 {
            let shifted = format!("{}{text}", "x".repeat(lead));
            let kept = SqlText::capture(&shifted).text.expect("text is kept");
            assert!(kept.len() <= MAX_SQL_BYTES);
            assert!(kept.len() > MAX_SQL_BYTES - 4);
            assert!(shifted.starts_with(&kept));
        }
    }

    #[test]
    fn each_credential_marker_redacts() {
        for text in [
            "CREATE SECRET s (TYPE s3)",
            "ATTACH 'dbname=x password=hunter2' AS pg",
            "select passwd from users",
            "SELECT PWD FROM t",
            "select token_count from t",
            "SET s3_access_key_id = 'x'",
            "select api_KEY from t",
            "select Credential from t",
            "select connection_string from t",
            "SET VARIABLE h = MAP {'Authorization': 'x'}",
            "SELECT * FROM read_json('https://host/x', headers = MAP {'a': 'BEARER abc'})",
            "select bearer from t",
            // An Azure shared access signature URL.
            "COPY t FROM 'https://acct.blob.core.windows.net/c/f.parquet?sv=2022-11-02&ss=b&srt=o&sp=r&se=2026-12-01T00:00:00Z&sig=dGhpcyBpcyBub3QgYSBrZXk%3D'",
            "SELECT * FROM 'https://acct.blob.core.windows.net/c/f.parquet?sp=r&SIG=abc'",
            // An AWS presigned URL with a version 2 signature.
            "SELECT * FROM read_parquet('https://bucket.s3.amazonaws.com/f.parquet?AWSAccessKeyId=AKIAEXAMPLE&Expires=1790000000&Signature=abc%2Bdef%3D')",
            "SELECT * FROM 'https://host/f?X-Amz-Signature=0123abcd'",
            "SELECT * FROM read_json('https://host/x', headers = MAP {'x-api-key': 'abc'})",
            "SELECT * FROM read_json('https://host/x', headers = MAP {'Api-Key': 'abc'})",
            "SELECT * FROM read_json('https://host/x', headers = MAP {'ApiKey': 'abc'})",
            "SELECT * FROM read_json('https://host/x', headers = MAP {'Cookie': 'session=abc'})",
            "ATTACH 'postgres://user:pw@host/db' AS pg",
            "COPY t TO 's3://key:secr@bucket'",
        ] {
            let sql = SqlText::capture(text);
            assert!(sql.redacted, "expected redaction of {text:?}");
            assert_eq!(sql.text, None);
            assert!(!sql.truncated);
        }
    }

    #[test]
    fn redaction_tests_the_whole_text() {
        let text = format!("SELECT '{}' -- password", "x".repeat(MAX_SQL_BYTES));
        let sql = SqlText::capture(&text);

        assert!(sql.redacted);
        assert_eq!(sql.text, None);
    }

    #[test]
    fn texts_without_a_marker_are_kept() {
        for text in [
            "SELECT 1",
            "SELECT key, pw, tok FROM t",
            "SELECT author, bear FROM t",
            "SELECT sig, signature, api, cook FROM t",
            "SELECT * FROM 'https://host/f.parquet?sv=2022-11-02&sp=r'",
            "SELECT * FROM read_parquet('s3://bucket/path/file@v2.parquet')",
            "SELECT 'a@b.c' FROM 'https://host/path'",
            "SELECT 'a@b' || ':/' || '/'",
            "SELECT email FROM t WHERE email = 'a@b.c'",
        ] {
            let sql = SqlText::capture(text);
            assert!(!sql.redacted, "unexpected redaction of {text:?}");
            assert_eq!(sql.text.as_deref(), Some(text));
        }
    }

    #[test]
    fn redacted_record_omits_the_text_and_keeps_the_figures() {
        let sql = SqlText::capture("CREATE SECRET s (TYPE s3)");
        let record = parse(serialize(parts(&sql, vec![entry(0, None)])));
        let object = record.as_object().expect("record is an object");

        assert!(!object.contains_key("sql"));
        assert_eq!(object["sql_redacted"], json!(true));
        assert_eq!(object["entries"][0]["cpu_seconds"], json!(1.5));
    }

    #[test]
    fn record_over_the_bound_drops_every_breakdown() {
        let sql = SqlText::capture("SELECT 1");
        let wide = node("root", (0..64).map(|_| node("leaf", vec![])).collect());
        let entries = vec![entry(0, Some(wide.clone())), entry(1, Some(wide))];

        let bare = entries
            .iter()
            .cloned()
            .map(|mut entry| {
                entry.breakdown = None;
                entry
            })
            .collect::<Vec<_>>();
        let with_breakdowns = to_json(&parts(&sql, entries.clone()), false).len();
        let without_breakdowns = to_json(&parts(&sql, bare), true).len();
        assert!(without_breakdowns < with_breakdowns);

        // At the bound the record is whole.
        let whole = parse(serialize_within(
            parts(&sql, entries.clone()),
            with_breakdowns,
        ));
        assert_eq!(whole["breakdown_omitted"], json!(false));
        assert!(whole["entries"][0].get("breakdown").is_some());

        // One byte under it, every breakdown goes and every entry stays.
        for max_bytes in [with_breakdowns - 1, without_breakdowns] {
            let reduced = parse(serialize_within(parts(&sql, entries.clone()), max_bytes));
            assert_eq!(reduced["breakdown_omitted"], json!(true));
            let reduced_entries = reduced["entries"].as_array().expect("entries");
            assert_eq!(reduced_entries.len(), 2);
            for entry in reduced_entries {
                assert!(entry.get("breakdown").is_none());
                assert_eq!(entry["cpu_seconds"], json!(1.5));
            }
        }

        // A record that passes the bound without breakdowns is discarded.
        assert_eq!(
            serialize_within(parts(&sql, entries), without_breakdowns - 1),
            Serialized::Oversized
        );
    }

    #[test]
    fn a_record_within_the_bound_keeps_the_flag_its_accounting_set() {
        let sql = SqlText::default();
        let mut record_parts = parts(
            &sql,
            vec![entry(0, None), entry(1, Some(node("kept", vec![])))],
        );
        record_parts.breakdown_omitted = true;

        let record = parse(serialize(record_parts));

        assert_eq!(record["breakdown_omitted"], json!(true));
        assert!(record["entries"][0].get("breakdown").is_none());
        assert!(record["entries"][1].get("breakdown").is_some());
    }

    #[test]
    fn serialized_len_is_the_length_of_the_json() {
        let with_breakdown = entry(7, Some(node("root", vec![node("leaf", vec![])])));
        let bare = entry(7, None);
        let breakdown = with_breakdown.breakdown.clone().expect("breakdown");

        assert_eq!(
            serialized_len(&with_breakdown),
            serde_json::to_vec(&with_breakdown).expect("JSON").len()
        );
        // An entry's size is its size without the breakdown, the member's
        // name, and the breakdown.
        assert_eq!(
            serialized_len(&with_breakdown),
            serialized_len(&bare) + BREAKDOWN_MEMBER_BYTES + serialized_len(&breakdown)
        );
    }

    #[test]
    fn the_bounds_are_the_specified_ones() {
        assert_eq!(MAX_RECORD_BYTES, 4_194_304);
        assert_eq!(MAX_BREAKDOWN_LEVELS, 48);
        assert_eq!(MAX_ENTRIES_BYTES_WITH_BREAKDOWN, 2_097_152);
        assert_eq!(MAX_ENTRIES_BYTES, 4_194_304);
    }

    #[test]
    fn record_over_the_real_bound_is_discarded() {
        let sql = SqlText::default();
        // Each entry serializes to more than 200 bytes, so 25,000 pass 4 MiB.
        let entries = (0..25_000).map(|id| entry(id, None)).collect();

        assert_eq!(serialize(parts(&sql, entries)), Serialized::Oversized);
    }
}
