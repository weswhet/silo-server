//! `github.com/joho/godotenv`'s parser.

use silo_gocompat::regexp::GoRegex;
use silo_gocompat::strconv::{quote, quote_bytes};
use silo_gocompat::strings::decode_runes;
use silo_gocompat::unicode;
use std::collections::HashMap;
use std::sync::OnceLock;

/// A `.env` file that does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DotenvError(pub String);

impl std::fmt::Display for DotenvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DotenvError {}

// The next rune and its size, with an invalid byte as U+FFFD of size 1.
fn next_rune(b: &[u8]) -> (char, usize) {
    let n = b.len().min(4);
    for len in 1..=n {
        if let Ok(s) = std::str::from_utf8(&b[..len])
            && let Some(c) = s.chars().next()
        {
            return (c, c.len_utf8());
        }
    }
    ('\u{FFFD}', 1)
}

fn index_func(b: &[u8], f: impl Fn(char) -> bool) -> Option<usize> {
    let mut i = 0;
    while i < b.len() {
        let (r, size) = next_rune(&b[i..]);
        if f(r) {
            return Some(i);
        }
        i += size;
    }
    None
}

fn trim_left_func(b: &[u8], f: impl Fn(char) -> bool) -> &[u8] {
    match index_func(b, |r| !f(r)) {
        Some(i) => &b[i..],
        None => &[],
    }
}

fn is_space(r: char) -> bool {
    matches!(
        r,
        '\t' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{85}' | '\u{a0}'
    )
}

fn is_line_end(r: char) -> bool {
    r == '\n' || r == '\r'
}

/// `godotenv.UnmarshalBytes`.
pub fn parse_dotenv(src: &[u8]) -> Result<HashMap<String, String>, DotenvError> {
    let replaced: Vec<u8> = {
        let mut out = Vec::with_capacity(src.len());
        let mut i = 0;
        while i < src.len() {
            if src[i] == b'\r' && src.get(i + 1) == Some(&b'\n') {
                out.push(b'\n');
                i += 2;
            } else {
                out.push(src[i]);
                i += 1;
            }
        }
        out
    };
    let mut out = HashMap::new();
    let mut cutset: &[u8] = &replaced;
    while let Some(start) = get_statement_start(cutset) {
        let (key, left) = locate_key_name(start)?;
        let (value, left) = extract_var_value(left, &out)?;
        out.insert(key, value);
        cutset = left;
    }
    Ok(out)
}

fn get_statement_start(mut src: &[u8]) -> Option<&[u8]> {
    loop {
        let pos = index_func(src, |r| !unicode::is_space(r as u32))?;
        src = &src[pos..];
        if src[0] != b'#' {
            return Some(src);
        }
        let pos = src.iter().position(|&c| c == b'\n')?;
        src = &src[pos..];
    }
}

fn locate_key_name(src: &[u8]) -> Result<(String, &[u8]), DotenvError> {
    let mut src = trim_left_func(src, is_space);
    if src.starts_with(b"export") {
        let trimmed = &src[6..];
        if index_func(trimmed, is_space) == Some(0) {
            src = trim_left_func(trimmed, is_space);
        }
    }
    let mut key_bytes: &[u8] = &[];
    let mut offset = 0;
    for (i, &ch) in src.iter().enumerate() {
        let rchar = ch as char;
        if is_space(rchar) {
            continue;
        }
        match ch {
            b'=' | b':' => {
                key_bytes = &src[..i];
                offset = i + 1;
                break;
            }
            b'_' => {}
            _ => {
                if unicode::is_letter(rchar as u32)
                    || unicode::is_number(rchar as u32)
                    || rchar == '.'
                {
                    continue;
                }
                return Err(DotenvError(format!(
                    "unexpected character {} in variable name near {}",
                    quote(&rchar.to_string()),
                    quote_bytes(src)
                )));
            }
        }
    }
    if src.is_empty() {
        return Err(DotenvError("zero length string".to_owned()));
    }
    let key = decode_runes(key_bytes).into_owned();
    let key = key
        .trim_end_matches(|r| unicode::is_space(r as u32))
        .to_owned();
    Ok((key, trim_left_func(&src[offset..], is_space)))
}

fn extract_var_value<'a>(
    src: &'a [u8],
    vars: &HashMap<String, String>,
) -> Result<(String, &'a [u8]), DotenvError> {
    let quote_char = match src.first() {
        Some(&c @ (b'"' | b'\'')) => c,
        _ => {
            let end_of_line = index_func(src, is_line_end);
            let end_of_line = match end_of_line {
                Some(i) => i,
                None => {
                    if src.is_empty() {
                        return Ok((String::new(), &[]));
                    }
                    src.len()
                }
            };
            let line: Vec<char> = decode_runes(&src[..end_of_line]).chars().collect();
            let mut end_of_var = line.len();
            if end_of_var == 0 {
                return Ok((String::new(), &src[end_of_line..]));
            }
            let mut i = end_of_var;
            while i > 0 {
                i -= 1;
                if line[i] == '#' && i > 0 && is_space(line[i - 1]) {
                    end_of_var = i;
                    break;
                }
            }
            let text: String = line[..end_of_var].iter().collect();
            let trimmed = text.trim_matches(is_space);
            return Ok((expand_variables(trimmed, vars), &src[end_of_line..]));
        }
    };
    for i in 1..src.len() {
        if src[i] != quote_char || src[i - 1] == b'\\' {
            continue;
        }
        let mut body = &src[..i];
        while body.last() == Some(&quote_char) {
            body = &body[..body.len() - 1];
        }
        while body.first() == Some(&quote_char) {
            body = &body[1..];
        }
        let mut value = decode_runes(body).into_owned();
        if quote_char == b'"' {
            value = expand_variables(&expand_escapes(&value), vars);
        }
        return Ok((value, &src[i + 1..]));
    }
    let end = src.iter().position(|&c| c == b'\n').unwrap_or(src.len());
    Err(DotenvError(format!(
        "unterminated quoted value {}",
        decode_runes(&src[..end])
    )))
}

fn escape_regex() -> &'static GoRegex {
    static RE: OnceLock<GoRegex> = OnceLock::new();
    RE.get_or_init(|| GoRegex::must_compile(r"\\."))
}

fn expand_var_regex() -> &'static GoRegex {
    static RE: OnceLock<GoRegex> = OnceLock::new();
    RE.get_or_init(|| GoRegex::must_compile(r"(\\)?(\$)(\()?\{?([A-Z0-9_]+)?\}?"))
}

fn unescape_chars_regex() -> &'static GoRegex {
    static RE: OnceLock<GoRegex> = OnceLock::new();
    RE.get_or_init(|| GoRegex::must_compile(r"\\([^$])"))
}

fn expand_escapes(s: &str) -> String {
    let out =
        escape_regex().replace_all_string_func(s, |m| match m.strip_prefix('\\').unwrap_or(m) {
            "n" => "\n".to_owned(),
            "r" => "\r".to_owned(),
            _ => m.to_owned(),
        });
    unescape_chars_regex().replace_all_string(&out, "$1")
}

fn expand_variables(v: &str, m: &HashMap<String, String>) -> String {
    expand_var_regex().replace_all_string_func(v, |s| {
        let Some(sub) = expand_var_regex().find_string_submatch(s) else {
            return s.to_owned();
        };
        if sub[1] == "\\" || sub[2] == "(" {
            return sub[0][1..].to_owned();
        }
        if !sub[4].is_empty() {
            return m.get(sub[4]).cloned().unwrap_or_default();
        }
        s.to_owned()
    })
}
