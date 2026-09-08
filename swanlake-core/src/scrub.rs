//! Redaction for error text that can echo connection strings
//! (linstromcloud/duckvis#215). A DuckLake attach failure embeds the metadata
//! DSN verbatim in the engine error, `password=` value included; every surface
//! that logs or relays engine error text routes it through [`scrub_error_text`]
//! first — `ServerError`'s `Display` for the engine-derived variants, and the
//! `status_from_error` arms that format the inner error directly.

/// Replace each `password=<value>` value with `[redacted]`. Matches any case,
/// optional whitespace around `=`, and both DSN value forms: a single-quoted
/// string (doubled quotes escape) and a bare run ending at whitespace or a
/// quote. Text without a match returns unchanged.
pub fn scrub_error_text(text: &str) -> String {
    const KEY: &str = "password";
    let lower = text.to_ascii_lowercase();
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut emitted = 0usize;
    let mut search = 0usize;
    while let Some(off) = lower[search..].find(KEY) {
        let key_start = search + off;
        let key_end = key_start + KEY.len();
        // Optional whitespace, then `=`; a bare "password" word passes through.
        let mut k = key_end;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if bytes.get(k) != Some(&b'=') {
            search = key_end;
            continue;
        }
        k += 1;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        // The value: quoted (doubled-quote escapes) or bare. Every stop byte is
        // ASCII, so the end always lands on a char boundary.
        let value_end = if bytes.get(k) == Some(&b'\'') {
            let mut m = k + 1;
            loop {
                match bytes.get(m) {
                    None => break m,
                    Some(b'\'') if bytes.get(m + 1) == Some(&b'\'') => m += 2,
                    Some(b'\'') => break m + 1,
                    Some(_) => m += 1,
                }
            }
        } else {
            let mut m = k;
            while m < bytes.len()
                && !bytes[m].is_ascii_whitespace()
                && bytes[m] != b'\''
                && bytes[m] != b'"'
            {
                m += 1;
            }
            m
        };
        out.push_str(&text[emitted..key_end]);
        out.push_str("=[redacted]");
        emitted = value_end;
        search = value_end;
    }
    out.push_str(&text[emitted..]);
    out
}

#[cfg(test)]
mod tests {
    use super::scrub_error_text;

    #[test]
    fn quoted_value_in_an_engine_error_is_redacted() {
        let input = "Invalid Input Error: Existing DuckLake at metadata catalog \
                     \"postgres:dbname=lakes host=172.26.1.17 user=lake_x \
                     password='c3ab16e72314ddf7'\" does not exist - and creating \
                     a new DuckLake is explicitly disabled";
        let out = scrub_error_text(input);
        assert!(!out.contains("c3ab16e72314ddf7"), "{out}");
        assert!(out.contains("password=[redacted]\" does not exist"), "{out}");
        assert!(out.contains("user=lake_x"), "{out}");
    }

    #[test]
    fn doubled_quotes_stay_inside_the_redacted_value() {
        let out = scrub_error_text("x password='ab''cd' host=h");
        assert_eq!(out, "x password=[redacted] host=h");
    }

    #[test]
    fn bare_value_and_casing_and_spacing() {
        assert_eq!(
            scrub_error_text("PASSWORD = hunter2 sslmode=prefer"),
            "PASSWORD=[redacted] sslmode=prefer"
        );
    }

    #[test]
    fn unterminated_quote_redacts_to_the_end() {
        assert_eq!(scrub_error_text("password='abc"), "password=[redacted]");
    }

    #[test]
    fn text_without_a_password_value_is_unchanged() {
        let plain = "Binder Error: Catalog \"awd\" does not exist; password prompt";
        assert_eq!(scrub_error_text(plain), plain);
        assert_eq!(scrub_error_text(""), "");
    }

    #[test]
    fn multiple_values_all_redact() {
        assert_eq!(
            scrub_error_text("a password=x b password='y' c"),
            "a password=[redacted] b password=[redacted] c"
        );
    }
}
