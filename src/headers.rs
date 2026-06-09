use std::net::IpAddr;

const ORDER: &[&str] = &[
    "cf-connecting-ip",
    "fly-client-ip",
    "true-client-ip",
    "x-real-ip",
    "x-forwarded-for",
];

/// Extract a client IP from headers via a caller-supplied getter.
/// For `x-forwarded-for`, takes the first entry. No proxy-trust logic (caller's responsibility).
pub fn client_ip<'a, F>(get: F) -> Option<IpAddr>
where
    F: Fn(&str) -> Option<&'a str>,
{
    for name in ORDER {
        if let Some(v) = get(name) {
            let first = v.split(',').next().unwrap_or("").trim();
            if let Ok(ip) = first.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn prefers_known_forwarding_header() {
        let get = |name: &str| match name {
            "x-forwarded-for" => Some("203.0.113.7, 10.0.0.1"),
            _ => None,
        };
        assert_eq!(
            client_ip(get),
            Some("203.0.113.7".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn none_when_no_headers() {
        assert_eq!(client_ip(|_| None), None);
    }
}
