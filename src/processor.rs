#[cfg(feature = "referrer-list")]
use crate::classify::{Classifier, ClassifyCtx};
use crate::error::{Field, ProcessError};
use crate::event::{Event, RawEvent};
#[cfg(feature = "geoip")]
use crate::geoip::GeoIpDb;
use crate::strategy::VisitorIdStrategy;
#[cfg(feature = "useragent")]
use crate::useragent::UaParser;

const MAX_URL: usize = 2048;
const MAX_ID: usize = 128;
const MAX_UTM: usize = 256;

#[derive(Default)]
pub struct ProcessorBuilder {
    visitor_id: Option<Box<dyn VisitorIdStrategy>>,
    keep_raw_referrer: bool,
    #[cfg(feature = "geoip")]
    geoip: Option<GeoIpDb>,
    #[cfg(feature = "useragent")]
    ua: Option<Box<dyn UaParser>>,
    #[cfg(feature = "referrer-list")]
    classifier: Option<Box<dyn Classifier>>,
}

impl ProcessorBuilder {
    pub fn visitor_id_strategy(mut self, s: impl VisitorIdStrategy + 'static) -> Self {
        self.visitor_id = Some(Box::new(s));
        self
    }

    pub fn keep_raw_referrer(mut self, yes: bool) -> Self {
        self.keep_raw_referrer = yes;
        self
    }

    #[cfg(feature = "geoip")]
    pub fn geoip(mut self, db: GeoIpDb) -> Self {
        self.geoip = Some(db);
        self
    }

    #[cfg(feature = "useragent")]
    pub fn ua_parser(mut self, p: impl UaParser + 'static) -> Self {
        self.ua = Some(Box::new(p));
        self
    }

    #[cfg(feature = "referrer-list")]
    pub fn classifier(mut self, c: impl Classifier + 'static) -> Self {
        self.classifier = Some(Box::new(c));
        self
    }

    #[must_use]
    pub fn build(self) -> Processor {
        Processor {
            visitor_id: self.visitor_id,
            keep_raw_referrer: self.keep_raw_referrer,
            #[cfg(feature = "geoip")]
            geoip: self.geoip,
            #[cfg(feature = "useragent")]
            ua: self.ua,
            #[cfg(feature = "referrer-list")]
            classifier: self.classifier,
        }
    }
}

/// Long-lived, `Send + Sync`, share behind an `Arc`.
pub struct Processor {
    visitor_id: Option<Box<dyn VisitorIdStrategy>>,
    keep_raw_referrer: bool,
    #[cfg(feature = "geoip")]
    geoip: Option<GeoIpDb>,
    #[cfg(feature = "useragent")]
    ua: Option<Box<dyn UaParser>>,
    #[cfg(feature = "referrer-list")]
    classifier: Option<Box<dyn Classifier>>,
}

impl Processor {
    pub fn builder() -> ProcessorBuilder {
        ProcessorBuilder::default()
    }

    pub fn process(&self, raw: RawEvent) -> Result<Event, ProcessError> {
        validate(&raw)?;

        // (1) visitor id
        let visitor_id = match &raw.visitor_id {
            Some(v) => Some(v.clone()),
            None => self.visitor_id.as_ref().and_then(|s| s.visitor_id(&raw)),
        };

        // (2) geoip
        #[cfg(feature = "geoip")]
        let location = match (&self.geoip, raw.ip) {
            (Some(db), Some(ip)) => db.lookup(ip),
            _ => None,
        };
        #[cfg(not(feature = "geoip"))]
        let location = None;

        // (3) UA
        let parsed = self.resolve_ua(&raw);
        let bot = parsed.as_ref().map(|p| p.is_bot);
        let (device, browser, os) = match parsed {
            Some(p) => (Some(p.device), Some(p.browser), Some(p.os)),
            None => (None, None, None),
        };

        // (4) referrer
        let (referrer, traffic_source) = self.resolve_referrer(&raw);
        let raw_referrer = if self.keep_raw_referrer {
            raw.referrer.clone()
        } else {
            None
        };

        // (5) assemble
        let RawEvent {
            kind,
            page_url,
            entity_id,
            session_id,
            timestamp,
            context,
            ..
        } = raw;
        Ok(Event {
            kind,
            visitor_id,
            location,
            device,
            browser,
            os,
            bot,
            referrer,
            raw_referrer,
            traffic_source,
            page_url,
            entity_id,
            session_id,
            timestamp,
            context,
        })
    }

    fn resolve_ua(&self, raw: &RawEvent) -> Option<crate::types::ParsedUa> {
        if let Some(p) = &raw.parsed_ua {
            return Some(p.clone());
        }
        #[cfg(feature = "useragent")]
        {
            if let (Some(parser), Some(ua)) = (&self.ua, &raw.user_agent) {
                return Some(parser.parse(ua));
            }
        }
        None
    }

    #[cfg(feature = "referrer-list")]
    fn resolve_referrer(
        &self,
        raw: &RawEvent,
    ) -> (Option<String>, Option<crate::types::TrafficSource>) {
        let domain = raw
            .referrer
            .as_deref()
            .and_then(crate::referrer::registrable_domain);
        let traffic_source = self.classifier.as_ref().and_then(|c| {
            c.classify(&ClassifyCtx {
                registrable_domain: domain.as_deref(),
                raw_referrer: raw.referrer.as_deref(),
                utm: &raw.context.utm,
                page_url: &raw.page_url,
            })
        });
        (domain, traffic_source)
    }

    #[cfg(not(feature = "referrer-list"))]
    fn resolve_referrer(
        &self,
        _raw: &RawEvent,
    ) -> (Option<String>, Option<crate::types::TrafficSource>) {
        (None, None)
    }
}

#[cfg(feature = "geoip")]
impl Processor {
    /// Borrow the configured GeoIP database (if any), e.g. to call `reload_from_path`
    /// on your own schedule. Reload is `&self` and lock-free, so this works through a
    /// shared `Arc<Processor>`.
    pub fn geoip(&self) -> Option<&crate::geoip::GeoIpDb> {
        self.geoip.as_ref()
    }
}

fn check(s: &str, field: Field, limit: usize) -> Result<(), ProcessError> {
    if s.len() > limit {
        Err(ProcessError::InvalidInput { field, limit })
    } else {
        Ok(())
    }
}

fn validate(raw: &RawEvent) -> Result<(), ProcessError> {
    check(&raw.page_url, Field::PageUrl, MAX_URL)?;
    if let Some(r) = &raw.referrer {
        check(r, Field::Referrer, MAX_URL)?;
    }
    if let Some(e) = &raw.entity_id {
        check(e, Field::EntityId, MAX_ID)?;
    }
    if let Some(s) = &raw.session_id {
        check(s, Field::SessionId, MAX_ID)?;
    }
    let u = &raw.context.utm;
    if let Some(v) = &u.source {
        check(v, Field::UtmSource, MAX_UTM)?;
    }
    if let Some(v) = &u.medium {
        check(v, Field::UtmMedium, MAX_UTM)?;
    }
    if let Some(v) = &u.campaign {
        check(v, Field::UtmCampaign, MAX_UTM)?;
    }
    if let Some(v) = &u.content {
        check(v, Field::UtmContent, MAX_UTM)?;
    }
    if let Some(v) = &u.term {
        check(v, Field::UtmTerm, MAX_UTM)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, RawEvent};
    use chrono::Utc;

    #[test]
    fn passthrough_minimal() {
        let p = Processor::builder().build();
        let raw = RawEvent::new(EventKind::PageView, "https://x/".into(), Utc::now());
        let ev = p.process(raw).unwrap();
        assert_eq!(ev.kind, EventKind::PageView);
        assert!(ev.visitor_id.is_none());
    }

    #[test]
    fn rejects_overlong_page_url() {
        let p = Processor::builder().build();
        let raw = RawEvent::new(EventKind::PageView, "x".repeat(2049), Utc::now());
        assert_eq!(
            p.process(raw),
            Err(crate::error::ProcessError::InvalidInput {
                field: crate::error::Field::PageUrl,
                limit: 2048,
            })
        );
    }

    #[test]
    fn prehashed_visitor_id_used_verbatim() {
        use crate::visitor::VisitorId;
        let p = Processor::builder().build();
        let mut raw = RawEvent::new(EventKind::PageView, "https://x/".into(), Utc::now());
        raw.visitor_id = Some(VisitorId::new("abc123").unwrap());
        let ev = p.process(raw).unwrap();
        assert_eq!(ev.visitor_id.unwrap().as_str(), "abc123");
    }

    #[cfg(feature = "geoip")]
    #[test]
    fn geoip_getter_exposes_db_for_reload() {
        use crate::geoip::GeoIpDb;
        let db = GeoIpDb::from_path("tests/fixtures/city.mmdb".as_ref()).unwrap();
        let p = Processor::builder().geoip(db).build();
        assert!(p.geoip().is_some());
        // reload through the shared borrow compiles & runs (re-reading the same file is accepted):
        p.geoip()
            .unwrap()
            .reload_from_path("tests/fixtures/city.mmdb".as_ref())
            .unwrap();
    }

    #[test]
    fn is_deterministic() {
        let p = Processor::builder().build();
        let raw = RawEvent::new(EventKind::View, "https://x/".into(), Utc::now());
        assert_eq!(p.process(raw.clone()).unwrap(), p.process(raw).unwrap());
    }
}
