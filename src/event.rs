use crate::error::{Field, ProcessError};
use crate::types::{
    BrowserInfo, Context, DeviceInfo, Location, OperatingSystemInfo, ParsedUa, TrafficSource,
};
use crate::visitor::VisitorId;
use chrono::{DateTime, Utc};
use std::net::IpAddr;

const MAX_CUSTOM: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EventKind {
    PageView,
    Click,
    FormSubmit,
    Conversation,
    View,
    Custom(String),
}

impl EventKind {
    pub fn as_wire(&self) -> &str {
        match self {
            EventKind::PageView => "page_view",
            EventKind::Click => "click",
            EventKind::FormSubmit => "form_submit",
            EventKind::Conversation => "conversation",
            EventKind::View => "view",
            EventKind::Custom(s) => s,
        }
    }

    /// Build from a string. Reserved strings fold into known variants (exact, case-sensitive).
    /// Otherwise validates a Custom value (1..=64 printable ASCII bytes).
    pub fn custom(s: impl Into<String>) -> Result<Self, ProcessError> {
        let s = s.into();
        match s.as_str() {
            "page_view" => return Ok(EventKind::PageView),
            "click" => return Ok(EventKind::Click),
            "form_submit" => return Ok(EventKind::FormSubmit),
            "conversation" => return Ok(EventKind::Conversation),
            "view" => return Ok(EventKind::View),
            _ => {}
        }
        let ok =
            !s.is_empty() && s.len() <= MAX_CUSTOM && s.bytes().all(|b| (0x20..=0x7E).contains(&b));
        if ok {
            Ok(EventKind::Custom(s))
        } else {
            Err(ProcessError::InvalidInput {
                field: Field::EventKindCustom,
                limit: MAX_CUSTOM,
            })
        }
    }
}

impl From<EventKind> for String {
    fn from(k: EventKind) -> String {
        match k {
            EventKind::Custom(s) => s,
            other => other.as_wire().to_string(),
        }
    }
}

impl TryFrom<String> for EventKind {
    type Error = ProcessError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        EventKind::custom(s)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for EventKind {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_wire())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EventKind {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        EventKind::custom(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for EventKind {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "EventKind".into()
    }
    fn json_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
        String::json_schema(g)
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for EventKind {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        String::schema()
    }
}
#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for EventKind {
    fn name() -> std::borrow::Cow<'static, str> {
        "EventKind".into()
    }
}

/// Input event. Carries raw IP/UA/referrer (PII): intentionally NOT `Serialize`.
#[derive(Clone)]
pub struct RawEvent {
    pub kind: EventKind,
    pub ip: Option<IpAddr>,
    pub visitor_id: Option<VisitorId>,
    pub user_agent: Option<String>,
    pub parsed_ua: Option<ParsedUa>,
    pub referrer: Option<String>,
    pub page_url: String,
    pub entity_id: Option<String>,
    pub session_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub context: Context,
}

impl RawEvent {
    /// Minimal constructor; fill the rest with field syntax.
    pub fn new(kind: EventKind, page_url: String, timestamp: DateTime<Utc>) -> Self {
        RawEvent {
            kind,
            ip: None,
            visitor_id: None,
            user_agent: None,
            parsed_ua: None,
            referrer: None,
            page_url,
            entity_id: None,
            session_id: None,
            timestamp,
            context: Context::default(),
        }
    }
}

impl std::fmt::Debug for RawEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawEvent")
            .field("kind", &self.kind)
            .field("ip", &self.ip.map(|_| "<redacted>"))
            .field("visitor_id", &self.visitor_id)
            .field(
                "user_agent",
                &self.user_agent.as_ref().map(|_| "<redacted>"),
            )
            .field("parsed_ua", &self.parsed_ua)
            .field("referrer", &self.referrer.as_ref().map(|_| "<redacted>"))
            .field("page_url", &self.page_url)
            .field("entity_id", &self.entity_id)
            .field("session_id", &self.session_id)
            .field("timestamp", &self.timestamp)
            .field("context", &self.context)
            .finish()
    }
}

/// Enriched output event. IP-free; safe to serialize.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Event {
    pub kind: EventKind,
    pub visitor_id: Option<VisitorId>,
    pub location: Option<Location>,
    pub device: Option<DeviceInfo>,
    pub browser: Option<BrowserInfo>,
    pub os: Option<OperatingSystemInfo>,
    pub bot: Option<bool>,
    pub referrer: Option<String>,
    pub raw_referrer: Option<String>,
    pub traffic_source: Option<TrafficSource>,
    pub page_url: String,
    pub entity_id: Option<String>,
    pub session_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub context: Context,
}

#[cfg(test)]
mod raw_event_tests {
    use super::*;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn debug_redacts_ip() {
        let mut raw = RawEvent::new(EventKind::PageView, "https://x/".into(), Utc::now());
        raw.ip = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
        let dbg = format!("{:?}", raw);
        assert!(!dbg.contains("203.0.113.5"));
        assert!(dbg.contains("redacted"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_folds_reserved_names() {
        assert_eq!(EventKind::custom("page_view").unwrap(), EventKind::PageView);
        assert_eq!(EventKind::custom("view").unwrap(), EventKind::View);
    }

    #[test]
    fn custom_keeps_unknown_and_is_case_sensitive() {
        assert_eq!(
            EventKind::custom("form_view").unwrap(),
            EventKind::Custom("form_view".into())
        );
        assert_eq!(
            EventKind::custom("Page_View").unwrap(),
            EventKind::Custom("Page_View".into())
        );
    }

    #[test]
    fn custom_rejects_empty_overlong_nonascii() {
        assert!(EventKind::custom("").is_err());
        assert!(EventKind::custom("x".repeat(65)).is_err());
        assert!(EventKind::custom("emoji\u{1F600}").is_err());
    }

    #[test]
    fn wire_string_roundtrip() {
        assert_eq!(EventKind::FormSubmit.as_wire(), "form_submit");
        assert_eq!(EventKind::Custom("form_view".into()).as_wire(), "form_view");
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;
    #[test]
    fn deserializing_reserved_string_yields_known_variant() {
        let k: EventKind = serde_json::from_str("\"page_view\"").unwrap();
        assert_eq!(k, EventKind::PageView);
        let s = serde_json::to_string(&EventKind::Custom("form_view".into())).unwrap();
        assert_eq!(s, "\"form_view\"");
        let back: EventKind = serde_json::from_str("\"form_view\"").unwrap();
        assert_eq!(back, EventKind::Custom("form_view".into()));
    }
}
