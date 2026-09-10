//! ATTACH statement normalization and a quote/comment-aware SQL statement
//! splitter shared with the C6 raw-ATTACH guard.
//!
//! `normalize_attach` ports the semantics of duckvis's `wrap_attach_query_string`
//! (`duckvis-workspace/src/lib.rs`): it rewrites a single `ATTACH` statement to
//! `ATTACH OR REPLACE <path> AS "<name>"[ (options)]`, preserving the path and
//! any trailing options and using the attachment name as the alias.

use super::DuckvisError;

/// Split SQL into top-level statements, respecting single/double quoted strings,
/// `--` line comments, and `/* */` block comments. Semicolons inside quotes or
/// comments do not split. Returned segments retain their original text (minus the
/// separating semicolons) so callers can inspect leading keywords.
pub fn split_top_level_statements(sql: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let bytes = sql.as_bytes();
    let mut i = 0usize;
    let n = bytes.len();

    while i < n {
        let ch = bytes[i] as char;
        match ch {
            '\'' | '"' => {
                // Consume a quoted string. A doubled quote inside the same quote
                // kind is an escaped quote (SQL semantics) and does not close it.
                let quote = ch;
                current.push(ch);
                i += 1;
                while i < n {
                    let c = bytes[i] as char;
                    current.push(c);
                    i += 1;
                    if c == quote {
                        if i < n && bytes[i] as char == quote {
                            // Escaped quote: consume the second quote and continue.
                            current.push(quote);
                            i += 1;
                            continue;
                        }
                        break;
                    }
                }
            }
            '-' if i + 1 < n && bytes[i + 1] as char == '-' => {
                // Line comment: consume until end of line (keep the newline).
                current.push('-');
                current.push('-');
                i += 2;
                while i < n {
                    let c = bytes[i] as char;
                    current.push(c);
                    i += 1;
                    if c == '\n' {
                        break;
                    }
                }
            }
            '/' if i + 1 < n && bytes[i + 1] as char == '*' => {
                // Block comment: consume until closing `*/`.
                current.push('/');
                current.push('*');
                i += 2;
                while i < n {
                    let c = bytes[i] as char;
                    current.push(c);
                    i += 1;
                    if c == '*' && i < n && bytes[i] as char == '/' {
                        current.push('/');
                        i += 1;
                        break;
                    }
                }
            }
            ';' => {
                segments.push(std::mem::take(&mut current));
                i += 1;
            }
            _ => {
                current.push(ch);
                i += 1;
            }
        }
    }

    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

/// Return the leading SQL keyword of a statement, skipping leading whitespace and
/// leading `--`/`/* */` comments. Returns an uppercased keyword, or `None` when the
/// statement is empty/comment-only.
pub fn leading_keyword(statement: &str) -> Option<String> {
    let bytes = statement.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;

    loop {
        // Skip whitespace.
        while i < n && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        if i >= n {
            return None;
        }
        // Skip a line comment.
        if bytes[i] as char == '-' && i + 1 < n && bytes[i + 1] as char == '-' {
            i += 2;
            while i < n && bytes[i] as char != '\n' {
                i += 1;
            }
            continue;
        }
        // Skip a block comment.
        if bytes[i] as char == '/' && i + 1 < n && bytes[i + 1] as char == '*' {
            i += 2;
            while i < n {
                if bytes[i] as char == '*' && i + 1 < n && bytes[i + 1] as char == '/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }
        break;
    }

    let start = i;
    while i < n {
        let c = bytes[i] as char;
        if c.is_alphanumeric() || c == '_' {
            i += 1;
        } else {
            break;
        }
    }
    if i == start {
        return None;
    }
    Some(statement[start..i].to_uppercase())
}

/// Replace `--` line comments and `/* */` block comments with a single space,
/// preserving quoted strings, so token scans over the result cannot be steered
/// by comment text.
pub fn strip_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let bytes = sql.as_bytes();
    let mut i = 0usize;
    let n = bytes.len();

    while i < n {
        let ch = bytes[i] as char;
        match ch {
            '\'' | '"' => {
                let quote = ch;
                out.push(ch);
                i += 1;
                while i < n {
                    let c = bytes[i] as char;
                    out.push(c);
                    i += 1;
                    if c == quote {
                        if i < n && bytes[i] as char == quote {
                            out.push(quote);
                            i += 1;
                            continue;
                        }
                        break;
                    }
                }
            }
            '-' if i + 1 < n && bytes[i + 1] as char == '-' => {
                i += 2;
                while i < n && bytes[i] as char != '\n' {
                    i += 1;
                }
                out.push(' ');
            }
            '/' if i + 1 < n && bytes[i + 1] as char == '*' => {
                i += 2;
                while i < n {
                    if bytes[i] as char == '*' && i + 1 < n && bytes[i + 1] as char == '/' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
                out.push(' ');
            }
            _ => {
                out.push(ch);
                i += 1;
            }
        }
    }
    out
}

/// The data root an armed ATTACH grants read access to: the value of the
/// option block's `DATA_PATH` entry, unquoted. `None` for a statement with no
/// option block or no `DATA_PATH` (a remote metadata-only attach).
pub fn attach_data_path(statement: &str) -> Option<String> {
    let parsed = parse_attach(statement)?;
    let tokens = tokenize(&parsed.options);
    let mut idx = 0usize;
    while idx + 1 < tokens.len() {
        if tokens[idx].eq_ignore_ascii_case("DATA_PATH") {
            return Some(unquote(&tokens[idx + 1]));
        }
        idx += 1;
    }
    None
}

/// Whether a `CALL` statement invokes a `ducklake_*` function, under any
/// catalog qualification or identifier quoting — DuckLake maintenance calls
/// are writer operations (write-hardening §3).
pub fn call_targets_ducklake(statement: &str) -> bool {
    let tokens = tokenize(&strip_comments(statement));
    if !tokens.first().is_some_and(|t| t.eq_ignore_ascii_case("CALL")) {
        return false;
    }
    // Reassemble the function name from the tokens before the argument list;
    // quoting splits a qualified name across tokens.
    let mut name = String::new();
    for token in &tokens[1..] {
        if token == "(" {
            break;
        }
        name.push_str(&unquote(token).to_ascii_lowercase());
    }
    name.rsplit('.').next().is_some_and(|f| f.starts_with("ducklake_"))
}

/// Whether a `COPY` statement's sink is a file: the first top-level
/// `TO`/`FROM` keyword after `COPY` decides — `TO` writes a file, `FROM`
/// loads into a table. A `COPY` with neither classifies as a file write
/// (fail-safe).
pub fn copy_writes_file(statement: &str) -> bool {
    let tokens = tokenize(&strip_comments(statement));
    if !tokens.first().is_some_and(|t| t.eq_ignore_ascii_case("COPY")) {
        return false;
    }
    let mut depth = 0i32;
    for token in &tokens[1..] {
        match token.as_str() {
            "(" => depth += 1,
            ")" => depth -= 1,
            _ if depth == 0 => {
                if token.eq_ignore_ascii_case("TO") {
                    return true;
                }
                if token.eq_ignore_ascii_case("FROM") {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// Strip one level of matching outer quotes and collapse doubled inner quotes.
fn unquote(token: &str) -> String {
    let bytes = token.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0] as char;
        if (first == '\'' || first == '"') && bytes[bytes.len() - 1] as char == first {
            let inner = &token[1..token.len() - 1];
            let doubled = format!("{first}{first}");
            return inner.replace(&doubled, &first.to_string());
        }
    }
    token.to_string()
}

/// Normalize an ATTACH statement to `ATTACH OR REPLACE <path> AS "<name>"[ (options)]`.
///
/// The input must be a single ATTACH statement (any surrounding whitespace/comments
/// are tolerated, but a second top-level statement is rejected). The path (single-,
/// double-quoted, or bare) is preserved verbatim; the alias is replaced with the
/// attachment `name` quoted as a double-quoted identifier (embedded double quotes
/// doubled); any trailing `(...)` option block is preserved.
///
/// `read_only` replaces any configured `READ_ONLY [value]` option with the bare
/// `READ_ONLY` flag. This prevents `READ_ONLY false` from weakening a session's
/// authorization-derived access mode.
pub fn normalize_attach(
    secret_config: &str,
    name: &str,
    read_only: bool,
) -> Result<String, DuckvisError> {
    let statements: Vec<String> = split_top_level_statements(secret_config)
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .collect();

    let statement = match statements.as_slice() {
        [only] => only.trim().to_string(),
        _ => return Err(DuckvisError::AttachInvalid),
    };

    if leading_keyword(&statement).as_deref() != Some("ATTACH") {
        return Err(DuckvisError::AttachInvalid);
    }

    let parsed = parse_attach(&statement).ok_or(DuckvisError::AttachInvalid)?;
    let alias = quote_identifier(name);
    let options = if read_only {
        enforce_read_only(&parsed.options)
    } else {
        parsed.options.trim().to_string()
    };
    let options_suffix = if options.is_empty() {
        String::new()
    } else {
        format!(" {options}")
    };
    Ok(format!(
        "ATTACH OR REPLACE {} AS {}{}",
        parsed.path, alias, options_suffix
    ))
}

/// Replace any existing `READ_ONLY [value]` entry and append the bare flag.
fn enforce_read_only(options: &str) -> String {
    let trimmed = options.trim();
    if trimmed.is_empty() {
        return "(READ_ONLY)".to_string();
    }

    let tokens = tokenize(trimmed);
    let inner = if tokens.len() >= 2 {
        &tokens[1..tokens.len() - 1]
    } else {
        &[]
    };
    let mut entries: Vec<Vec<String>> = vec![Vec::new()];
    for token in inner {
        if token == "," {
            entries.push(Vec::new());
        } else if let Some(entry) = entries.last_mut() {
            entry.push(token.clone());
        }
    }
    entries.retain(|entry| {
        !entry.is_empty() && !entry[0].eq_ignore_ascii_case("READ_ONLY")
    });
    entries.push(vec!["READ_ONLY".to_string()]);

    let mut output = vec!["(".to_string()];
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            output.push(",".to_string());
        }
        output.extend(entry.iter().cloned());
    }
    output.push(")".to_string());
    rebuild_options(&output)
}

/// Set one safely-named attached catalog as the session's lookup path. The
/// default database is deliberately unchanged, so Duckvis can continue to
/// create its workspace schemas there while unqualified reads such as `runs`
/// resolve from the project data catalog.
pub fn catalog_search_path_sql(name: &str) -> Result<String, DuckvisError> {
    let mut chars = name.chars();
    if !matches!(chars.next(), Some('a'..='z' | 'A'..='Z' | '_'))
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(DuckvisError::AttachInvalid);
    }
    // Keep the session's existing `main` schema first. Qualifying the attached
    // entry with its catalog prevents DuckDB from making that catalog the
    // current database while still allowing unqualified fallback reads.
    Ok(format!("SET search_path = 'main,{name}.main'"))
}

struct ParsedAttach {
    path: String,
    options: String,
}

/// Parse an ATTACH statement into its path token and trailing option block,
/// discarding the (replaced) `AS <alias>` clause. Quote-aware so semicolons or
/// `AS`-like text inside quoted DSNs do not confuse the scan.
fn parse_attach(statement: &str) -> Option<ParsedAttach> {
    let tokens = tokenize(statement);
    let mut idx = 0usize;

    // Leading keyword must be ATTACH.
    if !tokens.get(idx)?.eq_ignore_ascii_case("ATTACH") {
        return None;
    }
    idx += 1;

    // Optional OR REPLACE.
    if token_eq(&tokens, idx, "OR") && token_eq(&tokens, idx + 1, "REPLACE") {
        idx += 2;
    }
    // Optional DATABASE.
    if token_eq(&tokens, idx, "DATABASE") {
        idx += 1;
    }
    // Optional IF NOT EXISTS.
    if token_eq(&tokens, idx, "IF") && token_eq(&tokens, idx + 1, "NOT") && token_eq(&tokens, idx + 2, "EXISTS")
    {
        idx += 3;
    }

    // The path token (quoted or bare, but not an opening paren).
    let path = tokens.get(idx)?.clone();
    if path == "(" {
        return None;
    }
    idx += 1;

    // Optional AS <alias> — skip the alias token.
    if token_eq(&tokens, idx, "AS") {
        idx += 1;
        // Skip the alias token if present and not an option block.
        if let Some(tok) = tokens.get(idx) {
            if tok != "(" {
                idx += 1;
            }
        }
    }

    // Remaining tokens (if any) must form an option block `( ... )`.
    let options = if let Some(tok) = tokens.get(idx) {
        if tok == "(" {
            rebuild_options(&tokens[idx..])
        } else {
            // Unexpected trailing token — not a well-formed ATTACH.
            return None;
        }
    } else {
        String::new()
    };

    Some(ParsedAttach { path, options })
}

/// Rebuild the option block text from tokens, joining with single spaces except
/// around parentheses. Quoted tokens keep their quotes.
fn rebuild_options(tokens: &[String]) -> String {
    let mut out = String::new();
    for (i, tok) in tokens.iter().enumerate() {
        if i == 0 {
            out.push_str(tok);
            continue;
        }
        let prev = &tokens[i - 1];
        let no_space_before = tok == ")" || tok == ",";
        let no_space_after_prev = prev == "(";
        if !no_space_before && !no_space_after_prev {
            out.push(' ');
        }
        out.push_str(tok);
    }
    out
}

fn token_eq(tokens: &[String], idx: usize, kw: &str) -> bool {
    tokens.get(idx).is_some_and(|t| t.eq_ignore_ascii_case(kw))
}

/// Tokenize a SQL fragment into words, quoted strings (kept with quotes), and
/// single-character punctuation `(`, `)`, `,`.
fn tokenize(sql: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let bytes = sql.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;

    while i < n {
        let ch = bytes[i] as char;
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        match ch {
            '\'' | '"' => {
                let quote = ch;
                let mut tok = String::new();
                tok.push(ch);
                i += 1;
                while i < n {
                    let c = bytes[i] as char;
                    tok.push(c);
                    i += 1;
                    if c == quote {
                        if i < n && bytes[i] as char == quote {
                            tok.push(quote);
                            i += 1;
                            continue;
                        }
                        break;
                    }
                }
                tokens.push(tok);
            }
            '(' | ')' | ',' => {
                tokens.push(ch.to_string());
                i += 1;
            }
            _ => {
                let start = i;
                while i < n {
                    let c = bytes[i] as char;
                    if c.is_whitespace() || c == '(' || c == ')' || c == ',' || c == '\'' || c == '"'
                    {
                        break;
                    }
                    i += 1;
                }
                tokens.push(sql[start..i].to_string());
            }
        }
    }
    tokens
}

/// Quote a string as a double-quoted SQL identifier, doubling embedded quotes.
fn quote_identifier(name: &str) -> String {
    let escaped = name.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_bare_path() {
        let out = normalize_attach("ATTACH 'db.duckdb'", "mydb", false).unwrap();
        assert_eq!(out, "ATTACH OR REPLACE 'db.duckdb' AS \"mydb\"");
    }

    #[test]
    fn normalize_rewrites_existing_alias() {
        let out = normalize_attach("ATTACH 'db.duckdb' AS original", "mydb", false).unwrap();
        assert_eq!(out, "ATTACH OR REPLACE 'db.duckdb' AS \"mydb\"");
    }

    #[test]
    fn normalize_preserves_options() {
        let out = normalize_attach(
            "ATTACH 'pg.db' AS pg (TYPE postgres, READ_ONLY)",
            "warehouse",
            false,
        )
        .unwrap();
        assert_eq!(
            out,
            "ATTACH OR REPLACE 'pg.db' AS \"warehouse\" (TYPE postgres, READ_ONLY)"
        );
    }

    #[test]
    fn normalize_preserves_or_replace_and_type_option() {
        let out = normalize_attach(
            "ATTACH OR REPLACE 'file.db' AS x (TYPE DUCKDB)",
            "attname",
            false,
        )
        .unwrap();
        assert_eq!(
            out,
            "ATTACH OR REPLACE 'file.db' AS \"attname\" (TYPE DUCKDB)"
        );
    }

    #[test]
    fn normalize_escapes_embedded_quotes_in_name() {
        let out = normalize_attach("ATTACH 'db.duckdb'", "we\"ird", false).unwrap();
        assert_eq!(out, "ATTACH OR REPLACE 'db.duckdb' AS \"we\"\"ird\"");
    }

    #[test]
    fn normalize_semicolon_inside_quoted_dsn() {
        let out = normalize_attach(
            "ATTACH 'host=x;port=5432;dbname=y' AS pg (TYPE postgres)",
            "wh",
            false,
        )
        .unwrap();
        assert_eq!(
            out,
            "ATTACH OR REPLACE 'host=x;port=5432;dbname=y' AS \"wh\" (TYPE postgres)"
        );
    }

    #[test]
    fn non_writer_adds_read_only_block_when_absent() {
        let out = normalize_attach("ATTACH 'db.duckdb'", "mydb", true).unwrap();
        assert_eq!(out, "ATTACH OR REPLACE 'db.duckdb' AS \"mydb\" (READ_ONLY)");
    }

    #[test]
    fn non_writer_appends_read_only_to_existing_block() {
        let out = normalize_attach(
            "ATTACH 'pg.db' AS pg (TYPE postgres)",
            "wh",
            true,
        )
        .unwrap();
        assert_eq!(
            out,
            "ATTACH OR REPLACE 'pg.db' AS \"wh\" (TYPE postgres, READ_ONLY)"
        );
    }

    #[test]
    fn non_writer_does_not_duplicate_read_only() {
        let out = normalize_attach(
            "ATTACH 'pg.db' AS pg (TYPE postgres, READ_ONLY)",
            "wh",
            true,
        )
        .unwrap();
        assert_eq!(
            out,
            "ATTACH OR REPLACE 'pg.db' AS \"wh\" (TYPE postgres, READ_ONLY)"
        );
    }

    #[test]
    fn non_writer_overrides_read_only_false() {
        let out = normalize_attach(
            "ATTACH 'pg.db' AS pg (TYPE postgres, READ_ONLY false)",
            "wh",
            true,
        )
        .unwrap();
        assert_eq!(
            out,
            "ATTACH OR REPLACE 'pg.db' AS \"wh\" (TYPE postgres, READ_ONLY)"
        );
    }

    #[test]
    fn writer_preserves_attachment_options() {
        let out = normalize_attach(
            "ATTACH 'pg.db' AS pg (TYPE postgres, READ_ONLY false)",
            "wh",
            false,
        )
        .unwrap();
        assert_eq!(
            out,
            "ATTACH OR REPLACE 'pg.db' AS \"wh\" (TYPE postgres, READ_ONLY false)"
        );
    }

    #[test]
    fn normalize_rejects_multi_statement() {
        let err = normalize_attach("ATTACH 'a.db' AS a; SELECT 1", "a", false);
        assert!(matches!(err, Err(DuckvisError::AttachInvalid)));
    }

    #[test]
    fn normalize_rejects_non_attach() {
        let err = normalize_attach("SELECT 1", "a", false);
        assert!(matches!(err, Err(DuckvisError::AttachInvalid)));
    }

    #[test]
    fn concise_catalog_can_be_installed_on_the_search_path() {
        assert_eq!(
            catalog_search_path_sql("feed").unwrap(),
            "SET search_path = 'main,feed.main'"
        );
        assert!(matches!(
            catalog_search_path_sql("Duckfeed project data"),
            Err(DuckvisError::AttachInvalid)
        ));
    }

    #[test]
    fn catalog_search_path_resolves_unqualified_tables_without_changing_default() {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "ATTACH ':memory:' AS feed; \
             CREATE TABLE feed.runs (id INTEGER); \
             INSERT INTO feed.runs VALUES (1); \
             SET search_path = 'main,feed.main';",
        )
        .unwrap();

        let count: i64 = conn
            .query_row("SELECT count(*) FROM runs", [], |row| row.get(0))
            .unwrap();
        let current: String = conn
            .query_row("SELECT current_database()", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(current, "memory");
    }

    #[test]
    fn splitter_ignores_semicolons_in_quotes() {
        let segs = split_top_level_statements("ATTACH 'a;b' AS x; SELECT 1");
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0], "ATTACH 'a;b' AS x");
    }

    #[test]
    fn splitter_ignores_semicolons_in_line_comment() {
        let segs = split_top_level_statements("SELECT 1 -- a;b\n; SELECT 2");
        assert_eq!(segs.len(), 2);
    }

    #[test]
    fn splitter_ignores_semicolons_in_block_comment() {
        let segs = split_top_level_statements("SELECT 1 /* a;b;c */; SELECT 2");
        assert_eq!(segs.len(), 2);
    }

    #[test]
    fn strip_comments_removes_comments_and_keeps_quotes() {
        let stripped = strip_comments("SELECT 1 -- COPY TO\n, 2 /* EXPORT */, ' -- inside '");
        assert!(!stripped.contains("COPY"));
        assert!(!stripped.contains("EXPORT"));
        assert!(stripped.contains("' -- inside '"));
        assert!(stripped.contains('\n'));
    }

    #[test]
    fn data_path_extracts_the_lake_root() {
        let statement = "ATTACH OR REPLACE 'ducklake:postgres:host=x dbname=y' AS \"lake\" \
                         (DATA_PATH '/data/lakes/lake1', ENCRYPTED, READ_ONLY)";
        assert_eq!(
            attach_data_path(statement).as_deref(),
            Some("/data/lakes/lake1")
        );
    }

    #[test]
    fn data_path_absent_for_metadata_only_attach() {
        assert_eq!(
            attach_data_path("ATTACH OR REPLACE 'pg.db' AS \"wh\" (TYPE postgres, READ_ONLY)"),
            None
        );
        assert_eq!(attach_data_path("ATTACH OR REPLACE 'db.duckdb' AS \"x\""), None);
    }

    #[test]
    fn data_path_unquotes_escaped_paths() {
        let statement = "ATTACH 'x' AS a (DATA_PATH '/data/it''s here')";
        assert_eq!(attach_data_path(statement).as_deref(), Some("/data/it's here"));
    }

    #[test]
    fn call_classifier_matches_ducklake_functions() {
        assert!(call_targets_ducklake("CALL ducklake_expire_snapshots('lake')"));
        assert!(call_targets_ducklake("cAlL DuckLake_Merge_Adjacent_Files()"));
        assert!(call_targets_ducklake("CALL lake.ducklake_expire_snapshots()"));
        assert!(call_targets_ducklake("CALL \"ducklake_expire_snapshots\"()"));
        assert!(call_targets_ducklake("CALL /* c */ ducklake_cleanup_old_files()"));
        assert!(!call_targets_ducklake("CALL pragma_version()"));
        assert!(!call_targets_ducklake("SELECT 1"));
    }

    #[test]
    fn copy_classifier_separates_file_sinks_from_loads() {
        assert!(copy_writes_file("COPY t TO 'f.csv'"));
        assert!(copy_writes_file("COPY (SELECT a FROM t) TO 'out.parquet' (FORMAT parquet)"));
        assert!(copy_writes_file("copy /* to */ t tO 'f'"));
        assert!(copy_writes_file("COPY t TO 's3://bucket/f.parquet'"));
        assert!(copy_writes_file("COPY t"));
        assert!(!copy_writes_file("COPY t FROM 'f.csv'"));
        assert!(!copy_writes_file("COPY t (a, b) FROM 'f.csv'"));
        assert!(!copy_writes_file("COPY FROM DATABASE a TO b"));
        assert!(!copy_writes_file("SELECT 1"));
    }

    #[test]
    fn leading_keyword_skips_comments() {
        assert_eq!(
            leading_keyword("  -- note\n /* x */ ATTACH 'a'").as_deref(),
            Some("ATTACH")
        );
        assert_eq!(leading_keyword("select 1").as_deref(), Some("SELECT"));
        assert_eq!(leading_keyword("   \n  ").as_deref(), None);
    }
}
