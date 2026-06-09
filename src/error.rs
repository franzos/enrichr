use thiserror::Error;

/// Identifies which input field violated a constraint. Carries no field *value* (PII-safe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    PageUrl,
    Referrer,
    EntityId,
    SessionId,
    EventKindCustom,
    UtmSource,
    UtmMedium,
    UtmCampaign,
    UtmContent,
    UtmTerm,
    VisitorId,
}

impl Field {
    pub fn as_str(self) -> &'static str {
        match self {
            Field::PageUrl => "page_url",
            Field::Referrer => "referrer",
            Field::EntityId => "entity_id",
            Field::SessionId => "session_id",
            Field::EventKindCustom => "event_kind_custom",
            Field::UtmSource => "utm_source",
            Field::UtmMedium => "utm_medium",
            Field::UtmCampaign => "utm_campaign",
            Field::UtmContent => "utm_content",
            Field::UtmTerm => "utm_term",
            Field::VisitorId => "visitor_id",
        }
    }
}

/// Returned by `Processor::process`. The only failure mode is invalid input (bounds).
/// Error messages never include the offending value (it may be PII).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProcessError {
    #[error("{} exceeds maximum length of {limit} bytes", field.as_str())]
    InvalidInput { field: Field, limit: usize },
}

/// Errors from loading / reloading a GeoIP database.
#[derive(Debug, Error)]
#[cfg(feature = "geoip")]
pub enum GeoIpError {
    #[error("failed to read geoip database: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid geoip database: {0}")]
    Decode(String),
    #[error("rejected candidate: {0}")]
    Rejected(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_input_display_does_not_echo_value() {
        let e = ProcessError::InvalidInput {
            field: Field::PageUrl,
            limit: 2048,
        };
        let s = e.to_string();
        assert!(s.contains("page_url"));
        assert!(s.contains("2048"));
    }

    #[test]
    fn field_is_comparable() {
        assert_eq!(Field::EntityId, Field::EntityId);
        assert_ne!(Field::EntityId, Field::SessionId);
    }
}
