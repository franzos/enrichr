use crate::types::{TrafficSource, Utm};

/// Context handed to a classifier.
pub struct ClassifyCtx<'a> {
    pub registrable_domain: Option<&'a str>,
    pub raw_referrer: Option<&'a str>,
    pub utm: &'a Utm,
    pub page_url: &'a str,
}

pub trait Classifier: Send + Sync {
    fn classify(&self, ctx: &ClassifyCtx) -> Option<TrafficSource>;
}

/// (registrable_domain, category, source_name)
const TABLE: &[(&str, &str, &str)] = &[
    ("google.com", "search", "google"),
    ("bing.com", "search", "bing"),
    ("duckduckgo.com", "search", "duckduckgo"),
    ("yahoo.com", "search", "yahoo"),
    ("facebook.com", "social", "facebook"),
    ("youtube.com", "social", "youtube"),
    ("instagram.com", "social", "instagram"),
    ("tiktok.com", "social", "tiktok"),
    ("twitter.com", "social", "twitter"),
    ("x.com", "social", "twitter"),
    ("t.co", "social", "twitter"),
    ("linkedin.com", "social", "linkedin"),
    ("reddit.com", "social", "reddit"),
    ("pinterest.com", "social", "pinterest"),
    ("t.me", "social", "telegram"),
    ("telegram.org", "social", "telegram"),
    ("bsky.app", "social", "bluesky"),
];

/// Built-in classifier backed by a static referrer table.
#[derive(Default)]
pub struct ReferrerListClassifier;

impl ReferrerListClassifier {
    pub fn new() -> Self {
        ReferrerListClassifier
    }
}

impl Classifier for ReferrerListClassifier {
    fn classify(&self, ctx: &ClassifyCtx) -> Option<TrafficSource> {
        let known = ctx
            .registrable_domain
            .and_then(|d| TABLE.iter().find(|(dom, _, _)| *dom == d));
        let category = match (ctx.registrable_domain, known) {
            (None, _) => "direct",
            (Some(_), Some((_, cat, _))) => cat,
            (Some(_), None) => "referral",
        };
        let source_name = ctx
            .utm
            .source
            .clone()
            .or_else(|| known.map(|(_, _, name)| name.to_string()))
            .or_else(|| match (ctx.registrable_domain, known) {
                (Some(d), None) => Some(d.to_string()),
                _ => None,
            });
        Some(TrafficSource {
            category: category.to_string(),
            source_name,
            medium: ctx.utm.medium.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Utm;

    fn ctx<'a>(dom: Option<&'a str>, utm: &'a Utm) -> ClassifyCtx<'a> {
        ClassifyCtx {
            registrable_domain: dom,
            raw_referrer: None,
            utm,
            page_url: "https://x/",
        }
    }

    #[test]
    fn direct_when_no_referrer() {
        let c = ReferrerListClassifier::new();
        let utm = Utm::default();
        let ts = c.classify(&ctx(None, &utm)).unwrap();
        assert_eq!(ts.category, "direct");
        assert!(ts.source_name.is_none());
    }

    #[test]
    fn known_search_engine() {
        let c = ReferrerListClassifier::new();
        let utm = Utm::default();
        let ts = c.classify(&ctx(Some("google.com"), &utm)).unwrap();
        assert_eq!(ts.category, "search");
        assert_eq!(ts.source_name.as_deref(), Some("google"));
    }

    #[test]
    fn unknown_is_referral_with_domain() {
        let c = ReferrerListClassifier::new();
        let utm = Utm::default();
        let ts = c.classify(&ctx(Some("example.com"), &utm)).unwrap();
        assert_eq!(ts.category, "referral");
        assert_eq!(ts.source_name.as_deref(), Some("example.com"));
    }

    #[test]
    fn utm_overrides_source_and_medium() {
        let c = ReferrerListClassifier::new();
        let utm = Utm {
            source: Some("newsletter".into()),
            medium: Some("email".into()),
            ..Default::default()
        };
        let ts = c.classify(&ctx(None, &utm)).unwrap();
        assert_eq!(ts.category, "direct");
        assert_eq!(ts.source_name.as_deref(), Some("newsletter"));
        assert_eq!(ts.medium.as_deref(), Some("email"));
    }
}
