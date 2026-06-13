pub(crate) fn redact_sensitive(input: &str) -> String {
    let mut output = input.to_string();
    for key in [
        "AWS_ACCESS_KEY_ID=",
        "AWS_SECRET_ACCESS_KEY=",
        "AWS_SESSION_TOKEN=",
        "aws_access_key_id=",
        "aws_secret_access_key=",
        "aws_session_token=",
        "AccessKeyId=",
        "SecretAccessKey=",
        "SessionToken=",
        "X-Amz-Credential=",
        "X-Amz-Signature=",
        "X-Amz-Security-Token=",
    ] {
        output = redact_value_after_key(&output, key);
    }
    redact_aws_access_key_tokens(&output)
}

pub(crate) fn format_error(err: &anyhow::Error, verbose: bool) -> String {
    if verbose {
        format!("{err:#}")
    } else {
        err.to_string()
    }
}

fn redact_value_after_key(input: &str, key: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut remaining = input;
    while let Some(index) = remaining.find(key) {
        let (before, after_before) = remaining.split_at(index);
        output.push_str(before);
        output.push_str(key);
        output.push_str("[REDACTED]");
        let value_start = key.len();
        let after_key = &after_before[value_start..];
        let value_end = sensitive_value_end(after_key);
        remaining = &after_key[value_end..];
    }
    output.push_str(remaining);
    output
}

fn sensitive_value_end(value: &str) -> usize {
    if let Some(quote) = value.chars().next().filter(|c| *c == '"' || *c == '\'') {
        let quote_len = quote.len_utf8();
        return value[quote_len..]
            .find(quote)
            .map(|index| quote_len + index + quote_len)
            .unwrap_or(value.len());
    }
    value
        .find(is_sensitive_value_delimiter)
        .unwrap_or(value.len())
}

fn is_sensitive_value_delimiter(character: char) -> bool {
    matches!(
        character,
        '&' | ' ' | '\n' | '\r' | '\t' | '"' | '\'' | ')' | ']' | '}'
    )
}

fn redact_aws_access_key_tokens(input: &str) -> String {
    input
        .split_inclusive(char::is_whitespace)
        .map(|token| {
            let trimmed = token.trim_end();
            let suffix = &token[trimmed.len()..];
            if is_aws_access_key_id(trimmed) {
                format!("[REDACTED]{suffix}")
            } else {
                token.to_string()
            }
        })
        .collect()
}

fn is_aws_access_key_id(value: &str) -> bool {
    value.len() == 20
        && (value.starts_with("AKIA") || value.starts_with("ASIA"))
        && value
            .chars()
            .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit())
}
