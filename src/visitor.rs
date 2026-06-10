use crate::error::Field;

const MAX_VISITOR_ID: usize = 128;

/// An opaque, validated visitor identifier. The library never interprets the value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VisitorId(String);

impl VisitorId {
    /// Validates: non-empty, ≤128 bytes, printable non-whitespace ASCII.
    ///
    /// Does NOT hash. It accepts any printable ASCII up to the limit, so callers
    /// MUST pass an already-opaque/hashed value — never raw PII such as an IP or
    /// email address.
    pub fn new(s: impl Into<String>) -> Result<Self, crate::error::ProcessError> {
        let s = s.into();
        if s.is_empty() || !s.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
            return Err(crate::error::ProcessError::InvalidFormat {
                field: Field::VisitorId,
            });
        }
        if s.len() > MAX_VISITOR_ID {
            return Err(crate::error::ProcessError::InvalidInput {
                field: Field::VisitorId,
                limit: MAX_VISITOR_ID,
            });
        }
        Ok(VisitorId(s))
    }

    /// Construct without validation. For internal generation where the value is known-valid.
    pub(crate) fn new_unchecked(s: String) -> Self {
        VisitorId(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for VisitorId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for VisitorId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        VisitorId::new(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for VisitorId {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "VisitorId".into()
    }
    fn json_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
        String::json_schema(g)
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for VisitorId {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        String::schema()
    }
}
#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for VisitorId {
    fn name() -> std::borrow::Cow<'static, str> {
        "VisitorId".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_hex_and_base64() {
        assert!(VisitorId::new("a1b2c3d4e5f6").is_ok());
        assert!(VisitorId::new("YWJjZA+/=").is_ok()); // base64 chars
    }

    #[test]
    fn rejects_empty_too_long_and_whitespace() {
        assert!(VisitorId::new("").is_err());
        assert!(VisitorId::new("x".repeat(129)).is_err());
        assert!(VisitorId::new("has space").is_err());
        assert!(VisitorId::new("tab\tted").is_err());
    }

    #[test]
    fn as_str_roundtrips() {
        let v = VisitorId::new("abc").unwrap();
        assert_eq!(v.as_str(), "abc");
    }
}
