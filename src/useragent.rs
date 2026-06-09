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
            serde_yaml::from_str(include_str!("../resources/ua_regexes.yaml"))
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

        let is_bot = device_family == "Spider" || browser.name == "HeadlessChrome";

        let device = DeviceInfo {
            family: device_family,
            brand,
            model,
            device_type: None,
        };

        ParsedUa {
            device,
            browser,
            os,
            is_bot,
        }
    }
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
}
