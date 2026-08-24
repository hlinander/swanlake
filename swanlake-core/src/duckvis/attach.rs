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

/// Normalize an ATTACH statement to `ATTACH OR REPLACE <path> AS "<name>"[ (options)]`.
///
/// The input must be a single ATTACH statement (any surrounding whitespace/comments
/// are tolerated, but a second top-level statement is rejected). The path (single-,
/// double-quoted, or bare) is preserved verbatim; the alias is replaced with the
/// attachment `name` quoted as a double-quoted identifier (embedded double quotes
/// doubled); any trailing `(...)` option block is preserved.
pub fn normalize_attach(secret_config: &str, name: &str) -> Result<String, DuckvisError> {
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
    let options = parsed.options.trim();
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
        let out = normalize_attach("ATTACH 'db.duckdb'", "mydb").unwrap();
        assert_eq!(out, "ATTACH OR REPLACE 'db.duckdb' AS \"mydb\"");
    }

    #[test]
    fn normalize_rewrites_existing_alias() {
        let out = normalize_attach("ATTACH 'db.duckdb' AS original", "mydb").unwrap();
        assert_eq!(out, "ATTACH OR REPLACE 'db.duckdb' AS \"mydb\"");
    }

    #[test]
    fn normalize_preserves_options() {
        let out = normalize_attach(
            "ATTACH 'pg.db' AS pg (TYPE postgres, READ_ONLY)",
            "warehouse",
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
        )
        .unwrap();
        assert_eq!(
            out,
            "ATTACH OR REPLACE 'file.db' AS \"attname\" (TYPE DUCKDB)"
        );
    }

    #[test]
    fn normalize_escapes_embedded_quotes_in_name() {
        let out = normalize_attach("ATTACH 'db.duckdb'", "we\"ird").unwrap();
        assert_eq!(out, "ATTACH OR REPLACE 'db.duckdb' AS \"we\"\"ird\"");
    }

    #[test]
    fn normalize_semicolon_inside_quoted_dsn() {
        let out = normalize_attach(
            "ATTACH 'host=x;port=5432;dbname=y' AS pg (TYPE postgres)",
            "wh",
        )
        .unwrap();
        assert_eq!(
            out,
            "ATTACH OR REPLACE 'host=x;port=5432;dbname=y' AS \"wh\" (TYPE postgres)"
        );
    }

    #[test]
    fn normalize_rejects_multi_statement() {
        let err = normalize_attach("ATTACH 'a.db' AS a; SELECT 1", "a");
        assert!(matches!(err, Err(DuckvisError::AttachInvalid)));
    }

    #[test]
    fn normalize_rejects_non_attach() {
        let err = normalize_attach("SELECT 1", "a");
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
    fn leading_keyword_skips_comments() {
        assert_eq!(
            leading_keyword("  -- note\n /* x */ ATTACH 'a'").as_deref(),
            Some("ATTACH")
        );
        assert_eq!(leading_keyword("select 1").as_deref(), Some("SELECT"));
        assert_eq!(leading_keyword("   \n  ").as_deref(), None);
    }
}
