use crate::types::Utm;
use url::{Host, Url};

/// eTLD+1 of a referrer URL, or None for non-http(s) / IP-literal / no-public-suffix hosts.
pub fn registrable_domain(input: &str) -> Option<String> {
    let url = Url::parse(input).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = match url.host()? {
        Host::Domain(d) => d.trim_end_matches('.').to_ascii_lowercase(),
        Host::Ipv4(_) | Host::Ipv6(_) => return None,
    };
    psl::domain_str(&host).map(|d| d.to_string())
}

/// Parse UTM params (with common aliases) from a URL's query.
pub fn extract_utm(input: &str) -> Utm {
    let mut u = Utm::default();
    if let Ok(url) = Url::parse(input) {
        for (k, v) in url.query_pairs() {
            let v = v.to_string();
            match k.as_ref() {
                "utm_source" | "source" | "ref" => {
                    u.source.get_or_insert(v);
                }
                "utm_medium" | "medium" => {
                    u.medium.get_or_insert(v);
                }
                "utm_campaign" | "campaign" => {
                    u.campaign.get_or_insert(v);
                }
                "utm_content" | "content" => {
                    u.content.get_or_insert(v);
                }
                "utm_term" | "term" => {
                    u.term.get_or_insert(v);
                }
                _ => {}
            }
        }
    }
    u
}

/// Reliable paid-click signal from a URL's query: (source_name, medium). None if absent.
/// gclid/gbraid/wbraid => Google Ads, msclkid => Microsoft Ads. fbclid/ttclid are NOT paid signals.
pub fn paid_click(input: &str) -> Option<(&'static str, &'static str)> {
    let url = Url::parse(input).ok()?;
    for (k, _) in url.query_pairs() {
        match k.as_ref() {
            "gclid" | "gbraid" | "wbraid" => return Some(("google", "cpc")),
            "msclkid" => return Some(("bing", "cpc")),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_etld_plus_one() {
        assert_eq!(
            registrable_domain("https://m.facebook.com/x?y=1"),
            Some("facebook.com".into())
        );
        assert_eq!(
            registrable_domain("https://www.google.com:8080/s"),
            Some("google.com".into())
        );
    }

    #[test]
    fn userinfo_does_not_fool_host() {
        assert_eq!(
            registrable_domain("https://google.com@evil.com/"),
            Some("evil.com".into())
        );
    }

    #[test]
    fn rejects_non_http_ip_localhost() {
        assert_eq!(registrable_domain("javascript:alert(1)"), None);
        assert_eq!(registrable_domain("http://1.2.3.4/"), None);
        assert_eq!(registrable_domain("http://localhost/"), None);
    }

    #[test]
    fn trailing_dot_stripped() {
        assert_eq!(
            registrable_domain("https://example.com./"),
            Some("example.com".into())
        );
    }

    #[test]
    fn extract_utm_from_query() {
        let u = extract_utm("https://x/?utm_source=google&utm_medium=cpc");
        assert_eq!(u.source.as_deref(), Some("google"));
        assert_eq!(u.medium.as_deref(), Some("cpc"));
    }

    #[test]
    fn paid_click_signals() {
        assert_eq!(paid_click("https://x/?gclid=abc"), Some(("google", "cpc")));
        assert_eq!(paid_click("https://x/?msclkid=abc"), Some(("bing", "cpc")));
        assert_eq!(paid_click("https://x/?fbclid=xyz"), None);
        assert_eq!(paid_click("https://x/?foo=bar"), None);
    }
}
