use crate::types::{BrowserInfo, DeviceInfo, OperatingSystemInfo, ParsedUa};
use std::sync::OnceLock;
use ua_parser::Extractor;

pub trait UaParser: Send + Sync {
    fn parse(&self, ua: &str) -> ParsedUa;
}

static EXTRACTOR: OnceLock<Extractor<'static>> = OnceLock::new();

fn extractor() -> &'static Extractor<'static> {
    EXTRACTOR.get_or_init(|| {
        let defs: ua_parser::Regexes =
            yaml_serde::from_str(include_str!("../resources/ua_regexes.yaml"))
                .expect("bundled ua_regexes.yaml is valid");
        Extractor::try_from(defs).expect("bundled ua regexes build")
    })
}

#[derive(Default)]
pub struct UaParserBuiltin;

impl UaParserBuiltin {
    pub fn new() -> Self {
        UaParserBuiltin
    }
}

impl UaParser for UaParserBuiltin {
    fn parse(&self, ua: &str) -> ParsedUa {
        let (uav, osv, devv) = extractor().extract(ua);

        let browser = uav
            .map(|parsed| BrowserInfo {
                name: parsed.family.to_string(),
                version: join_version(parsed.major, parsed.minor, parsed.patch),
            })
            .unwrap_or_default();

        let os = osv
            .map(|parsed| OperatingSystemInfo {
                family: parsed.os.to_string(),
                major: parsed.major.map(|s| s.to_string()),
                minor: parsed.minor.map(|s| s.to_string()),
                patch: parsed.patch.map(|s| s.to_string()),
            })
            .unwrap_or_default();

        let (device_family, brand, model) = devv
            .map(|parsed| {
                (
                    parsed.device.to_string(),
                    parsed.brand.map(|s| s.to_string()),
                    parsed.model.map(|s| s.to_string()),
                )
            })
            .unwrap_or_else(|| ("Other".to_string(), None, None));

        let is_bot = device_family == "Spider"
            || browser.name == "HeadlessChrome"
            || is_self_identifying_bot(ua);

        let device_type = derive_device_type(is_bot, &device_family, &brand, &model, &os.family);

        let device = DeviceInfo {
            family: device_family,
            brand,
            model,
            device_type,
        };

        ParsedUa {
            device,
            browser,
            os,
            is_bot,
        }
    }
}

/// UA-string-only best-effort: agents that name themselves. Will not catch bots that spoof a browser UA.
fn is_self_identifying_bot(ua: &str) -> bool {
    const MARKERS: &[&str] = &[
        "gptbot",
        "claudebot",
        "claude-web",
        "anthropic-ai",
        "perplexitybot",
        "bytespider",
        "amazonbot",
        "ccbot",
        "google-extended",
        "applebot",
        "bingbot",
        "yandexbot",
        "duckduckbot",
        "baiduspider",
        "curl/",
        "wget/",
        "python-requests",
        "go-http-client",
        "node-fetch",
        "axios/",
        "okhttp",
        "libwww-perl",
        "scrapy",
    ];
    let ua = ua.to_ascii_lowercase();
    MARKERS.iter().any(|m| ua.contains(m))
}

/// Best-effort device bucket from already-parsed signals.
fn derive_device_type(
    is_bot: bool,
    device_family: &str,
    brand: &Option<String>,
    model: &Option<String>,
    os_family: &str,
) -> Option<String> {
    if is_bot {
        return Some("bot".to_string());
    }
    let mut haystack = String::new();
    haystack.push_str(device_family);
    if let Some(b) = brand {
        haystack.push_str(b);
    }
    if let Some(m) = model {
        haystack.push_str(m);
    }
    haystack.push_str(os_family);
    let haystack = haystack.to_ascii_lowercase();

    if ["ipad", "tablet", "kindle"]
        .iter()
        .any(|m| haystack.contains(m))
    {
        return Some("tablet".to_string());
    }
    if os_family == "iOS"
        || os_family == "Android"
        || ["mobile", "phone", "iphone"]
            .iter()
            .any(|m| haystack.contains(m))
    {
        return Some("mobile".to_string());
    }
    const DESKTOP: &[&str] = &[
        "Windows",
        "Mac OS X",
        "Linux",
        "Chrome OS",
        "Ubuntu",
        "Fedora",
        "Debian",
        "Chromium OS",
    ];
    if DESKTOP.contains(&os_family) {
        return Some("desktop".to_string());
    }
    None
}

fn join_version(major: Option<&str>, minor: Option<&str>, patch: Option<&str>) -> Option<String> {
    let parts: Vec<&str> = [major, minor, patch].into_iter().flatten().collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_a_common_ua() {
        let p = UaParserBuiltin::new();
        let parsed = p.parse("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36");
        assert_eq!(parsed.browser.name, "Chrome");
        assert!(!parsed.is_bot);
    }
    #[test]
    fn detects_bot() {
        let p = UaParserBuiltin::new();
        let parsed = p.parse("Googlebot/2.1 (+http://www.google.com/bot.html)");
        assert!(parsed.is_bot);
    }
    #[test]
    fn self_identifying_bots() {
        let p = UaParserBuiltin::new();
        assert!(p.parse("GPTBot/1.0 (+https://openai.com/gptbot)").is_bot);
        assert!(p.parse("python-requests/2.31").is_bot);
        assert!(!p
            .parse("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
            .is_bot);
    }
    #[test]
    fn device_type_buckets() {
        let p = UaParserBuiltin::new();
        let iphone = p.parse("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1");
        assert_eq!(iphone.device.device_type.as_deref(), Some("mobile"));
        let ipad = p.parse("Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1");
        assert_eq!(ipad.device.device_type.as_deref(), Some("tablet"));
        let win = p.parse("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36");
        assert_eq!(win.device.device_type.as_deref(), Some("desktop"));
        let bot = p.parse("Googlebot/2.1 (+http://www.google.com/bot.html)");
        assert_eq!(bot.device.device_type.as_deref(), Some("bot"));
    }
}
