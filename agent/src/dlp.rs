//! Lightweight local DLP content inspection. Runs on the endpoint before data leaves it,
//! so sensitive content is classified at the source. The server re-inspects for defense in
//! depth, but local scanning lets the agent enforce block decisions immediately.

use regex::Regex;
use std::sync::OnceLock;

pub struct Finding {
    pub classifier: String,
    pub label: String,
    pub severity: String,
    pub matches: usize,
    pub sample: String,
}

struct Pattern {
    name: &'static str,
    label: &'static str,
    severity: &'static str,
    re: Regex,
    luhn: bool,
}

fn patterns() -> &'static Vec<Pattern> {
    static P: OnceLock<Vec<Pattern>> = OnceLock::new();
    P.get_or_init(|| {
        vec![
            Pattern {
                name: "pci_card",
                label: "Payment card number",
                severity: "high",
                re: Regex::new(r"\b(?:\d[ -]?){13,19}\b").unwrap(),
                luhn: true,
            },
            Pattern {
                name: "pii_ssn",
                label: "US Social Security Number",
                severity: "high",
                re: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                luhn: false,
            },
            Pattern {
                name: "secret_aws",
                label: "AWS access key",
                severity: "critical",
                re: Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
                luhn: false,
            },
            Pattern {
                name: "secret_privkey",
                label: "Private key material",
                severity: "critical",
                re: Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
                    .unwrap(),
                luhn: false,
            },
        ]
    })
}

pub fn scan(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if text.is_empty() {
        return out;
    }
    for p in patterns() {
        let mut count = 0;
        let mut sample = String::new();
        for m in p.re.find_iter(text) {
            let s = m.as_str().trim();
            if p.luhn && !luhn_valid(s) {
                continue;
            }
            count += 1;
            if sample.is_empty() {
                // Fully mask PII/PAN at the source so no partial value is ever persisted to
                // the DB / console / SIEM. Other classifiers keep a first-2/last-2 hint.
                let full = matches!(p.name, "pci_card" | "pii_ssn");
                sample = redact(s, full);
            }
        }
        if count > 0 {
            out.push(Finding {
                classifier: p.name.into(),
                label: p.label.into(),
                severity: p.severity.into(),
                matches: count,
                sample,
            });
        }
    }
    out
}

fn luhn_valid(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    let mut dbl = false;
    for &d in digits.iter().rev() {
        let mut x = d;
        if dbl {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        sum += x;
        dbl = !dbl;
    }
    sum % 10 == 0
}

fn redact(s: &str, full: bool) -> String {
    // Operate on chars, not bytes — byte slicing panics on multibyte UTF-8.
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    if full || n <= 4 {
        return "*".repeat(n);
    }
    let head: String = chars[..2].iter().collect();
    let tail: String = chars[n - 2..].iter().collect();
    format!("{}{}{}", head, "*".repeat(n - 4), tail)
}

#[cfg(test)]
mod redact_tests {
    use super::*;

    // N5: PII/PAN samples must be fully masked — no digit of the card/SSN may persist.
    #[test]
    fn pii_pan_fully_masked() {
        let f = scan("payment 4111 1111 1111 1111 ssn 123-45-6789 done");
        let card = f.iter().find(|x| x.classifier == "pci_card").expect("card");
        assert!(
            card.sample.chars().all(|c| c == '*'),
            "card sample not fully masked: {}",
            card.sample
        );
        let ssn = f.iter().find(|x| x.classifier == "pii_ssn").expect("ssn");
        assert!(
            ssn.sample.chars().all(|c| c == '*'),
            "ssn sample not fully masked: {}",
            ssn.sample
        );
        assert!(!ssn.sample.contains('6'), "ssn digit leaked: {}", ssn.sample);
    }

    // Non-PII classifiers keep the first-2/last-2 hint.
    #[test]
    fn secrets_keep_partial_hint() {
        assert_eq!(redact("AKIAIOSFODNN7EXAMPLE", false).chars().filter(|&c| c == '*').count(), 16);
    }
}
