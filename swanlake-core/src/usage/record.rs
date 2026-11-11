//! The record of one request: its JSON form, the SQL text rules, and the size
//! bound.
//!
//! The record carries neither `ended_at` nor `error_type`: the specification
//! defines no encoding for either.

use bytes::Bytes;
use serde::Serialize;

use super::accounting::Entry;

/// Largest SQL text a record carries, in bytes.
pub const MAX_SQL_BYTES: usize = 65_536;

/// Largest serialized record, in bytes. Equals the declared bound of the
/// audit field that holds the record in the duckvis API.
pub const MAX_RECORD_BYTES: usize = 4_194_304;

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
const CREDENTIAL_MARKERS: [&[u8]; 8] = [
    b"secret",
    b"password",
    b"passwd",
    b"pwd",
    b"token",
    b"_key",
    b"credential",
    b"connection_string",
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

/// The parts of a record that [`serialize`] puts into one JSON object.
pub(super) struct RecordParts<'a> {
    pub(super) request_id: uuid::Uuid,
    pub(super) project_id: &'a str,
    pub(super) subject: &'a str,
    pub(super) endpoint: &'a str,
    pub(super) sql: &'a SqlText,
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
    breakdown_omitted: bool,
    entries: &'a [Entry],
}

/// The outcome of serializing a record against [`MAX_RECORD_BYTES`].
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Serialized {
    /// The record's bytes, within the bound.
    Record(Bytes),
    /// The record passes the bound without its breakdowns.
    Oversized,
}

/// Serializes a record once. A record that passes [`MAX_RECORD_BYTES`] drops
/// every breakdown and sets `breakdown_omitted`.
pub(super) fn serialize(parts: RecordParts<'_>) -> Serialized {
    serialize_within(parts, MAX_RECORD_BYTES)
}

fn serialize_within(mut parts: RecordParts<'_>, max_bytes: usize) -> Serialized {
    let full = to_json(&parts, false);
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
        let record_parts = parts(
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
                "breakdown_omitted": false,
                "entries": [
                    entry_json(0, "CLIENT", false, Some(node_json("t", json!([node_json("child", json!([]))])))),
                    entry_json(1, "SWANLAKE", true, None),
                ]
            })
        );
    }

    #[test]
    fn record_without_sql_omits_it() {
        let sql = SqlText::default();
        let record = parse(serialize(parts(&sql, vec![entry(0, None)])));
        let object = record.as_object().expect("record is an object");

        assert!(!object.contains_key("sql"));
        assert_eq!(object["sql_truncated"], json!(false));
        assert_eq!(object["sql_redacted"], json!(false));
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
    fn record_over_the_real_bound_is_discarded() {
        let sql = SqlText::default();
        // Each entry serializes to more than 200 bytes, so 25,000 pass 4 MiB.
        let entries = (0..25_000).map(|id| entry(id, None)).collect();

        assert_eq!(serialize(parts(&sql, entries)), Serialized::Oversized);
    }
}
