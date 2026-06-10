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

/// SLD label of a registrable domain (eTLD+1), e.g. "google.co.uk" -> "google".
fn sld_label(d: &str) -> Option<&str> {
    let suffix = psl::suffix_str(d)?;
    let label = d.strip_suffix(suffix)?.strip_suffix('.')?;
    (!label.is_empty()).then_some(label)
}

/// (registrable_domain, category, source_name)
const TABLE: &[(&str, &str, &str)] = &[
    // search — single-domain / brand-specific (multi-ccTLD operators go in LABEL_TABLE)
    ("duckduckgo.com", "search", "duckduckgo"),
    ("brave.com", "search", "brave"),
    ("naver.com", "search", "naver"),
    ("sogou.com", "search", "sogou"),
    ("seznam.cz", "search", "seznam"),
    ("ask.com", "search", "ask"),
    ("aol.com", "search", "aol"),
    ("kagi.com", "search", "kagi"),
    ("ya.ru", "search", "yandex"),
    // social
    ("facebook.com", "social", "facebook"),
    ("fb.com", "social", "facebook"),
    ("youtube.com", "social", "youtube"),
    ("youtu.be", "social", "youtube"),
    ("instagram.com", "social", "instagram"),
    ("tiktok.com", "social", "tiktok"),
    ("twitter.com", "social", "twitter"),
    ("x.com", "social", "twitter"),
    ("t.co", "social", "twitter"),
    ("linkedin.com", "social", "linkedin"),
    ("lnkd.in", "social", "linkedin"),
    ("reddit.com", "social", "reddit"),
    ("pinterest.com", "social", "pinterest"),
    ("t.me", "social", "telegram"),
    ("telegram.org", "social", "telegram"),
    ("bsky.app", "social", "bluesky"),
    ("snapchat.com", "social", "snapchat"),
    ("threads.net", "social", "threads"),
    ("threads.com", "social", "threads"),
    ("whatsapp.com", "social", "whatsapp"),
    ("wa.me", "social", "whatsapp"),
    ("discord.com", "social", "discord"),
    ("discord.gg", "social", "discord"),
    ("tumblr.com", "social", "tumblr"),
    ("vk.com", "social", "vk"),
    ("weibo.com", "social", "weibo"),
    ("quora.com", "social", "quora"),
    ("medium.com", "social", "medium"),
    ("twitch.tv", "social", "twitch"),
    ("substack.com", "social", "substack"),
    ("ycombinator.com", "social", "hackernews"),
    ("line.me", "social", "line"),
    ("xing.com", "social", "xing"),
    ("flipboard.com", "social", "flipboard"),
    ("mastodon.social", "social", "mastodon"),
];

/// Multi-ccTLD operators matched by SLD label, so google.com / google.co.uk /
/// google.de all resolve to one entry. Kept small to avoid false positives.
const LABEL_TABLE: &[(&str, &str, &str)] = &[
    ("google", "search", "google"),
    ("bing", "search", "bing"),
    ("yahoo", "search", "yahoo"),
    ("yandex", "search", "yandex"),
    ("baidu", "search", "baidu"),
    ("ecosia", "search", "ecosia"),
    ("qwant", "search", "qwant"),
    ("startpage", "search", "startpage"),
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
        let known = ctx.registrable_domain.and_then(|d| {
            TABLE.iter().find(|(dom, _, _)| *dom == d).or_else(|| {
                sld_label(d).and_then(|label| LABEL_TABLE.iter().find(|(lbl, _, _)| *lbl == label))
            })
        });
        let category = match (ctx.registrable_domain, known) {
            (None, _) => "direct",
            (Some(_), Some((_, cat, _))) => cat,
            (Some(_), None) => "referral",
        };
        let paid = crate::referrer::paid_click(ctx.page_url);
        let source_name = ctx
            .utm
            .source
            .clone()
            .or_else(|| paid.map(|(s, _)| s.to_string()))
            .or_else(|| known.map(|(_, _, name)| name.to_string()))
            .or_else(|| match (ctx.registrable_domain, known) {
                (Some(d), None) => Some(d.to_string()),
                _ => None,
            });
        let medium = ctx
            .utm
            .medium
            .clone()
            .or_else(|| paid.map(|(_, m)| m.to_string()))
            .or_else(|| match category {
                "search" => Some("organic".to_string()),
                "social" => Some("social".to_string()),
                "referral" => Some("referral".to_string()),
                _ => None,
            });
        Some(TrafficSource {
            category: category.to_string(),
            source_name,
            medium,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Utm;

    fn ctx<'a>(dom: Option<&'a str>, utm: &'a Utm) -> ClassifyCtx<'a> {
        ctx_url(dom, utm, "https://x/")
    }

    fn ctx_url<'a>(dom: Option<&'a str>, utm: &'a Utm, page_url: &'a str) -> ClassifyCtx<'a> {
        ClassifyCtx {
            registrable_domain: dom,
            raw_referrer: None,
            utm,
            page_url,
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
    fn cctld_resolves_to_operator() {
        let c = ReferrerListClassifier::new();
        let utm = Utm::default();
        let ts = c.classify(&ctx(Some("google.co.uk"), &utm)).unwrap();
        assert_eq!(ts.category, "search");
        assert_eq!(ts.source_name.as_deref(), Some("google"));
    }

    #[test]
    fn yandex_ru_is_search() {
        let c = ReferrerListClassifier::new();
        let utm = Utm::default();
        let ts = c.classify(&ctx(Some("yandex.ru"), &utm)).unwrap();
        assert_eq!(ts.category, "search");
        assert_eq!(ts.source_name.as_deref(), Some("yandex"));
    }

    #[test]
    fn ecosia_org_is_search() {
        let c = ReferrerListClassifier::new();
        let utm = Utm::default();
        let ts = c.classify(&ctx(Some("ecosia.org"), &utm)).unwrap();
        assert_eq!(ts.category, "search");
        assert_eq!(ts.source_name.as_deref(), Some("ecosia"));
    }

    #[test]
    fn snapchat_is_social() {
        let c = ReferrerListClassifier::new();
        let utm = Utm::default();
        let ts = c.classify(&ctx(Some("snapchat.com"), &utm)).unwrap();
        assert_eq!(ts.category, "social");
        assert_eq!(ts.source_name.as_deref(), Some("snapchat"));
    }

    #[test]
    fn hackernews_is_social() {
        let c = ReferrerListClassifier::new();
        let utm = Utm::default();
        let ts = c.classify(&ctx(Some("ycombinator.com"), &utm)).unwrap();
        assert_eq!(ts.category, "social");
        assert_eq!(ts.source_name.as_deref(), Some("hackernews"));
    }

    #[test]
    fn label_table_does_not_false_positive() {
        let c = ReferrerListClassifier::new();
        let utm = Utm::default();
        let ts = c.classify(&ctx(Some("googleblog.com"), &utm)).unwrap();
        assert_eq!(ts.category, "referral");
        assert_eq!(ts.source_name.as_deref(), Some("googleblog.com"));
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

    #[test]
    fn search_referrer_derives_organic() {
        let c = ReferrerListClassifier::new();
        let utm = Utm::default();
        let ts = c.classify(&ctx(Some("google.com"), &utm)).unwrap();
        assert_eq!(ts.category, "search");
        assert_eq!(ts.medium.as_deref(), Some("organic"));
    }

    #[test]
    fn gclid_is_cpc_google() {
        let c = ReferrerListClassifier::new();
        let utm = Utm::default();
        let ts = c
            .classify(&ctx_url(None, &utm, "https://x/?gclid=abc"))
            .unwrap();
        assert_eq!(ts.source_name.as_deref(), Some("google"));
        assert_eq!(ts.medium.as_deref(), Some("cpc"));
    }

    #[test]
    fn fbclid_is_not_cpc() {
        let c = ReferrerListClassifier::new();
        let utm = Utm::default();
        let ts = c
            .classify(&ctx_url(None, &utm, "https://x/?fbclid=xyz"))
            .unwrap();
        assert_eq!(ts.category, "direct");
        assert!(ts.medium.is_none());
    }

    #[test]
    fn social_referrer_derives_social_medium() {
        let c = ReferrerListClassifier::new();
        let utm = Utm::default();
        let ts = c.classify(&ctx(Some("twitter.com"), &utm)).unwrap();
        assert_eq!(ts.category, "social");
        assert_eq!(ts.medium.as_deref(), Some("social"));
    }
}
