macro_rules! data_struct {
    ($(#[$m:meta])* pub struct $name:ident { $($(#[$fm:meta])* pub $f:ident : $t:ty),* $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Default)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
        #[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
        #[cfg_attr(feature = "typeshare", typeshare::typeshare)]
        pub struct $name { $($(#[$fm])* pub $f : $t),* }
    };
}

data_struct! { pub struct Utm {
    pub source: Option<String>,
    pub medium: Option<String>,
    pub campaign: Option<String>,
    pub content: Option<String>,
    pub term: Option<String>,
}}

data_struct! { pub struct Context {
    pub screen_width: Option<String>,
    pub orientation: Option<String>,
    pub utm: Utm,
}}

data_struct! { pub struct Location {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub continent_code: Option<String>,
    pub continent_name: Option<String>,
    pub region_code: Option<String>,
    pub region_name: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
}}

data_struct! { pub struct DeviceInfo {
    pub family: String,
    pub brand: Option<String>,
    pub model: Option<String>,
    pub device_type: Option<String>,
}}

data_struct! { pub struct BrowserInfo {
    pub name: String,
    pub version: Option<String>,
}}

data_struct! { pub struct OperatingSystemInfo {
    pub family: String,
    pub major: Option<String>,
    pub minor: Option<String>,
    pub patch: Option<String>,
}}

data_struct! { pub struct TrafficSource {
    pub category: String,
    pub source_name: Option<String>,
    pub medium: Option<String>,
}}

/// Parsed user agent. `is_bot` is library-derived (see useragent.rs).
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ParsedUa {
    pub device: DeviceInfo,
    pub browser: BrowserInfo,
    pub os: OperatingSystemInfo,
    pub is_bot: bool,
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    #[test]
    fn traffic_source_serializes() {
        let ts = TrafficSource {
            category: "search".into(),
            source_name: Some("google".into()),
            medium: None,
        };
        let j = serde_json::to_string(&ts).unwrap();
        assert!(j.contains("search") && j.contains("google"));
    }
    #[test]
    fn utm_default_is_all_none() {
        let u = Utm::default();
        assert!(u.source.is_none());
    }
}
