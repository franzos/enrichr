use chrono::Utc;
use enrichr::*;
use std::net::{IpAddr, Ipv4Addr};

#[cfg(all(feature = "blake3", feature = "useragent", feature = "referrer-list"))]
#[test]
fn full_enrichment_with_default_features() {
    let p = Processor::builder()
        .visitor_id_strategy(MaskedHashedStrategy::new(
            enrichr::hash::blake3::Blake3Hasher,
            StaticSalt::new(vec![42u8; 32]),
            IpMaskMode::Balanced,
        ))
        .ua_parser(enrichr::useragent::UaParserBuiltin::new())
        .classifier(enrichr::classify::ReferrerListClassifier::new())
        .keep_raw_referrer(true)
        .build();

    let mut raw = RawEvent::new(
        EventKind::PageView,
        "https://site/page?utm_source=google".into(),
        Utc::now(),
    );
    raw.ip = Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    raw.user_agent = Some(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36".into(),
    );
    raw.referrer = Some("https://www.google.com/search?q=test".into());
    raw.entity_id = Some("tenant-1".into());
    raw.context.utm = enrichr::referrer::extract_utm(&raw.page_url);

    let ev = p.process(raw).unwrap();
    assert!(ev.visitor_id.is_some());
    assert_eq!(ev.referrer.as_deref(), Some("google.com"));
    assert_eq!(
        ev.raw_referrer.as_deref(),
        Some("https://www.google.com/search?q=test")
    );
    // utm_source=google → source_name google
    assert_eq!(
        ev.traffic_source.unwrap().source_name.as_deref(),
        Some("google")
    );
    assert_eq!(ev.bot, Some(false));
}

#[cfg(feature = "serde")]
#[test]
fn event_serializes() {
    let p = Processor::builder().build();
    let ev = p
        .process(RawEvent::new(
            EventKind::View,
            "https://x/".into(),
            Utc::now(),
        ))
        .unwrap();
    let _ = serde_json::to_string(&ev).unwrap();
    // RawEvent intentionally has NO Serialize impl — attempting it would not compile.
}
