//! Convert VARIANT query outputs before DuckDB exports the result to Arrow.

use duckdb::{params_from_iter, types::Value, Connection};
use sqlparser::{
    dialect::DuckDbDialect,
    tokenizer::{Token, Tokenizer},
};

use crate::error::ServerError;

/// Return a final projection for a single read query containing VARIANT outputs.
/// DESCRIBE binds the query with its parameters without evaluating its rows.
pub(super) fn for_query(
    conn: &Connection,
    sql: &str,
    params: Option<&[Value]>,
) -> Result<Option<String>, ServerError> {
    let Some(body) = query_body(sql) else {
        return Ok(None);
    };
    let Ok(mut describe) = conn.prepare(&format!("DESCRIBE {body}")) else {
        // WITH can also introduce DML, which DESCRIBE cannot wrap.
        return Ok(None);
    };
    let nulls = vec![Value::Null; describe.parameter_count()];
    let columns = describe
        .query_map(params_from_iter(params.unwrap_or(&nulls)), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let variants = columns
        .iter()
        .map(|(_, ty)| contains_variant(ty))
        .collect::<Vec<_>>();
    if !variants.iter().any(|variant| *variant) {
        return Ok(None);
    }

    // Assign internal names by position so duplicate output names remain distinct.
    let names = (0..columns.len())
        .map(|i| format!("\"c{i}\""))
        .collect::<Vec<_>>();
    let projection = columns
        .iter()
        .zip(&variants)
        .zip(&names)
        .map(|(((name, _), variant), internal)| {
            let source = format!("\"__swanlake_result\".{internal}");
            // DuckDB casts a NULL VARIANT to JSON 'null'; retain SQL nulls.
            let value = if *variant {
                format!(
                    "CASE WHEN {source} IS NULL THEN NULL::JSON ELSE CAST({source} AS JSON) END"
                )
            } else {
                source
            };
            format!("{value} AS \"{}\"", name.replace('"', "\"\""))
        })
        .collect::<Vec<_>>()
        .join(", ");
    Ok(Some(format!(
        "SELECT {projection} FROM (\n{body}\n) AS \"__swanlake_result\"({})",
        names.join(", ")
    )))
}

/// DESCRIBE emits VARIANT types before an array suffix, container delimiter or
/// end of input. A field named VARIANT is followed by its type instead.
pub(super) fn contains_variant(data_type: &str) -> bool {
    let Ok(tokens) = Tokenizer::new(&DuckDbDialect {}, data_type).tokenize() else {
        return false;
    };
    let tokens = tokens
        .iter()
        .filter(|t| !matches!(t, Token::Whitespace(_)))
        .collect::<Vec<_>>();
    tokens.iter().enumerate().any(|(index, token)| {
        matches!(token, Token::Word(word) if word.quote_style.is_none() && word.value.eq_ignore_ascii_case("VARIANT"))
            && tokens.get(index + 1).is_none_or(|next| matches!(next, Token::LBracket | Token::Comma | Token::RParen))
    })
}

/// Preserve the original SQL text while removing trailing terminators/comments.
/// Commands and batches keep their existing execution path; probing a batch
/// could execute its earlier statements a second time.
fn query_body(sql: &str) -> Option<&str> {
    let tokens = Tokenizer::new(&DuckDbDialect {}, sql)
        .tokenize_with_location()
        .ok()?;
    let mut significant = tokens
        .iter()
        .filter(|t| !matches!(t.token, Token::Whitespace(_)))
        .collect::<Vec<_>>();
    while significant
        .last()
        .is_some_and(|t| t.token == Token::SemiColon)
    {
        significant.pop();
    }
    if significant.iter().any(|t| t.token == Token::SemiColon) {
        return None;
    }
    match &significant.first()?.token {
        Token::Word(word)
            if word.quote_style.is_none()
                && matches!(
                    word.value.to_ascii_uppercase().as_str(),
                    "SELECT" | "FROM" | "WITH" | "VALUES" | "TABLE" | "PIVOT" | "UNPIVOT"
                ) => {}
        Token::LParen => {}
        _ => return None,
    }
    let end = significant.last()?.span.end;
    let mut lines = sql.split_inclusive('\n');
    let prefix = lines
        .by_ref()
        .take(end.line as usize - 1)
        .map(str::len)
        .sum::<usize>();
    let line = lines.next().unwrap_or_default();
    let column = line
        .char_indices()
        .nth(end.column as usize - 1)
        .map_or(line.len(), |(i, _)| i);
    sql.get(..prefix + column)
}
