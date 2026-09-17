//! RFC 4515 LDAP search-filter parser.

use rasn::types::{OctetString, SetOf};

use super::message::{
    AttributeValueAssertion, Filter, LdapString, MatchingRuleAssertion, SubstringChoice,
    SubstringFilter,
};

const MAX_FILTER_LENGTH: usize = 64 * 1024;
const MAX_FILTER_DEPTH: usize = 64;

pub(crate) fn parse_filter(input: &str) -> Result<Filter, String> {
    if input.len() > MAX_FILTER_LENGTH {
        return Err("filter exceeds 64 KiB limit".into());
    }
    let mut parser = Parser {
        input: input.as_bytes(),
        position: 0,
    };
    let filter = parser.parse_filter(0)?;
    if parser.position != parser.input.len() {
        return Err(format!("trailing input at byte {}", parser.position));
    }
    Ok(filter)
}

struct Parser<'a> {
    input: &'a [u8],
    position: usize,
}

impl Parser<'_> {
    fn parse_filter(&mut self, depth: usize) -> Result<Filter, String> {
        if depth >= MAX_FILTER_DEPTH {
            return Err("filter nesting exceeds 64 levels".into());
        }
        self.expect(b'(')?;
        let filter = match self.peek() {
            Some(b'&') => {
                self.position += 1;
                Filter::And(self.parse_filter_set(depth + 1)?)
            }
            Some(b'|') => {
                self.position += 1;
                Filter::Or(self.parse_filter_set(depth + 1)?)
            }
            Some(b'!') => {
                self.position += 1;
                let inner = self.parse_filter(depth + 1)?;
                Filter::Not(Box::new(inner))
            }
            Some(_) => self.parse_item()?,
            None => return Err("unexpected end of filter".into()),
        };
        self.expect(b')')?;
        Ok(filter)
    }

    fn parse_filter_set(&mut self, depth: usize) -> Result<SetOf<Filter>, String> {
        let mut filters = SetOf::new();
        while self.peek() == Some(b'(') {
            filters.insert(self.parse_filter(depth)?);
        }
        if filters.is_empty() {
            return Err("and/or filters require at least one child".into());
        }
        Ok(filters)
    }

    fn parse_item(&mut self) -> Result<Filter, String> {
        let start = self.position;
        let mut escaped = false;
        while let Some(byte) = self.peek() {
            if !escaped && byte == b')' {
                break;
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            }
            self.position += 1;
        }
        if escaped {
            return Err("truncated escape at end of assertion".into());
        }
        let item = &self.input[start..self.position];
        parse_item(item)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn expect(&mut self, expected: u8) -> Result<(), String> {
        if self.peek() != Some(expected) {
            return Err(format!(
                "expected '{}' at byte {}",
                char::from(expected),
                self.position
            ));
        }
        self.position += 1;
        Ok(())
    }
}

fn parse_item(item: &[u8]) -> Result<Filter, String> {
    if let Some(operator) = find_bytes(item, b":=") {
        return parse_extensible(&item[..operator], &item[operator + 2..]);
    }
    for (operator, kind) in [
        (b">=".as_slice(), Comparison::GreaterOrEqual),
        (b"<=".as_slice(), Comparison::LessOrEqual),
        (b"~=".as_slice(), Comparison::Approximate),
        (b"=".as_slice(), Comparison::Equality),
    ] {
        if let Some(position) = find_bytes(item, operator) {
            let attribute = parse_attribute(&item[..position])?;
            let raw_value = &item[position + operator.len()..];
            return comparison(attribute, raw_value, kind);
        }
    }
    Err("filter item has no valid operator".into())
}

#[derive(Clone, Copy)]
enum Comparison {
    Equality,
    GreaterOrEqual,
    LessOrEqual,
    Approximate,
}

fn comparison(attribute: LdapString, raw: &[u8], kind: Comparison) -> Result<Filter, String> {
    if matches!(kind, Comparison::Equality) {
        let (parts, wildcards) = split_substrings(raw)?;
        if wildcards == 1 && parts.len() == 2 && parts.iter().all(Vec::is_empty) {
            return Ok(Filter::Present(attribute));
        }
        if wildcards > 0 {
            let mut substrings = Vec::new();
            if let Some(first) = parts.first().filter(|value| !value.is_empty()) {
                substrings.push(SubstringChoice::Initial(OctetString::from(first.clone())));
            }
            for value in parts
                .iter()
                .skip(1)
                .take(parts.len().saturating_sub(2))
                .filter(|value| !value.is_empty())
            {
                substrings.push(SubstringChoice::Any(OctetString::from(value.clone())));
            }
            if let Some(last) = parts.last().filter(|value| !value.is_empty()) {
                substrings.push(SubstringChoice::Final(OctetString::from(last.clone())));
            }
            if substrings.is_empty() {
                return Err("substring filter requires a non-empty component".into());
            }
            return Ok(Filter::Substrings(SubstringFilter::new(
                attribute, substrings,
            )));
        }
    }
    let assertion = AttributeValueAssertion::new(attribute, OctetString::from(decode_value(raw)?));
    Ok(match kind {
        Comparison::Equality => Filter::EqualityMatch(assertion),
        Comparison::GreaterOrEqual => Filter::GreaterOrEqual(assertion),
        Comparison::LessOrEqual => Filter::LessOrEqual(assertion),
        Comparison::Approximate => Filter::ApproxMatch(assertion),
    })
}

fn parse_extensible(left: &[u8], raw_value: &[u8]) -> Result<Filter, String> {
    let text = std::str::from_utf8(left).map_err(|_| "extensible match header is not UTF-8")?;
    let mut components = text.split(':');
    let first = components.next().unwrap_or_default();
    let attribute = if first.is_empty() {
        None
    } else {
        Some(parse_attribute(first.as_bytes())?)
    };
    let mut dn_attributes = false;
    let mut matching_rule = None;
    for component in components {
        if component.eq_ignore_ascii_case("dn") {
            if dn_attributes {
                return Err("duplicate dn flag in extensible match".into());
            }
            dn_attributes = true;
        } else if component.is_empty() || matching_rule.is_some() {
            return Err("invalid extensible match header".into());
        } else {
            matching_rule = Some(LdapString::from(component));
        }
    }
    if attribute.is_none() && matching_rule.is_none() {
        return Err("extensible match requires an attribute or matching rule".into());
    }
    Ok(Filter::ExtensibleMatch(MatchingRuleAssertion::new(
        matching_rule,
        attribute,
        OctetString::from(decode_value(raw_value)?),
        dn_attributes,
    )))
}

fn parse_attribute(raw: &[u8]) -> Result<LdapString, String> {
    let value = std::str::from_utf8(raw).map_err(|_| "attribute description is not UTF-8")?;
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b';'))
    {
        return Err("invalid attribute description".into());
    }
    Ok(LdapString::from(value))
}

fn split_substrings(raw: &[u8]) -> Result<(Vec<Vec<u8>>, usize), String> {
    let mut parts = vec![Vec::new()];
    let mut index = 0;
    let mut wildcards = 0;
    while index < raw.len() {
        if raw[index] == b'*' {
            wildcards += 1;
            parts.push(Vec::new());
            index += 1;
        } else if raw[index] == b'\\' {
            let byte = decode_escape(raw, index)?;
            parts.last_mut().expect("initialized").push(byte);
            index += 3;
        } else if matches!(raw[index], 0 | b'(' | b')') {
            return Err("reserved assertion byte must be escaped".into());
        } else {
            parts.last_mut().expect("initialized").push(raw[index]);
            index += 1;
        }
    }
    Ok((parts, wildcards))
}

fn decode_value(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'\\' {
            decoded.push(decode_escape(raw, index)?);
            index += 3;
        } else if matches!(raw[index], 0 | b'(' | b')' | b'*') {
            return Err("reserved assertion byte must be escaped".into());
        } else {
            decoded.push(raw[index]);
            index += 1;
        }
    }
    Ok(decoded)
}

fn decode_escape(raw: &[u8], index: usize) -> Result<u8, String> {
    let high = *raw
        .get(index + 1)
        .ok_or_else(|| "truncated hexadecimal escape".to_owned())?;
    let low = *raw
        .get(index + 2)
        .ok_or_else(|| "truncated hexadecimal escape".to_owned())?;
    let high = hex_value(high).ok_or_else(|| "invalid hexadecimal escape".to_owned())?;
    let low = hex_value(low).ok_or_else(|| "invalid hexadecimal escape".to_owned())?;
    Ok((high << 4) | low)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_comparison_and_boolean_forms() {
        for filter in [
            "(cn=alice)",
            "(cn>=alice)",
            "(cn<=alice)",
            "(cn~=alice)",
            "(cn=*)",
            "(&(a=1)(b=2))",
            "(|(a=1)(b=2))",
            "(!(a=1))",
        ] {
            assert!(parse_filter(filter).is_ok(), "{filter}");
        }
    }

    #[test]
    fn decodes_hex_escapes_as_assertion_bytes() {
        let filter = parse_filter(r"(cn=Alice\2aSmith\00)").unwrap();
        let Filter::EqualityMatch(assertion) = filter else {
            panic!("expected equality");
        };
        assert_eq!(assertion.assertion_value.as_ref(), b"Alice*Smith\0");
    }

    #[test]
    fn parses_substrings_and_extensible_matches() {
        assert!(matches!(
            parse_filter("(cn=Al*ce*Smith)").unwrap(),
            Filter::Substrings(_)
        ));
        let filter =
            parse_filter("(memberOf:dn:1.2.840.113556.1.4.1941:=CN=Admins,DC=example,DC=test)")
                .unwrap();
        let Filter::ExtensibleMatch(assertion) = filter else {
            panic!("expected extensible match");
        };
        assert!(assertion.dn_attributes);
        assert_eq!(
            assertion.matching_rule.as_deref().map(String::as_str),
            Some("1.2.840.113556.1.4.1941")
        );
    }

    #[test]
    fn rejects_malformed_trailing_empty_and_deep_filters() {
        for filter in ["(cn=alice)tail", "(&)", "(|)", "(cn=bad\\zz)"] {
            assert!(parse_filter(filter).is_err(), "{filter}");
        }
        let deeply_nested = format!("{}(cn=a){}", "(!".repeat(65), ")".repeat(65));
        assert!(parse_filter(&deeply_nested).is_err());
    }

    #[test]
    fn rejects_unescaped_reserved_bytes_and_empty_substrings() {
        for filter in ["(cn=a(b)", "(cn=raw\0nul)", "(cn=**)"] {
            assert!(parse_filter(filter).is_err(), "{filter:?}");
        }
    }
}
