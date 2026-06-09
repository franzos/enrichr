# enrichr

Database-independent analytics event enrichment library. Takes a `RawEvent` (URL, IP, user-agent, referrer, UTM params) and produces a clean `Event` with visitor id, location, device/browser/OS info, and traffic source — with no storage, no HTTP, no async. You own the database and the HTTP layer; this crate just does the enrichment pipeline. It replaces `amplyco-analytics`, inspired by [liwan](https://liwan.dev).

## Privacy

**A secret, high-entropy salt is not optional.** IPv4 has only 2³² addresses — a hash without a salt is a lookup table. Pass at least 128 random bits (16 bytes) of binary salt to `StaticSalt::new` or `ArcSwapSalt::new`.

`MaskedHashedStrategy` is the recommended choice over `SaltedHasher`: it zeroes the last octet(s) before hashing (`IpMaskMode::Balanced` → /24 for IPv4, /56 for IPv6), so the hash never encodes a specific host address. The hash algorithm (sha256 vs blake3) is a performance/standardization choice, not a privacy one — the salt is what protects users.

## Install

```toml
[dependencies]
enrichr = "0.1"
```

## Usage

```rust
use enrichr::{
    Processor, RawEvent, EventKind, MaskedHashedStrategy, StaticSalt, IpMaskMode,
};
use enrichr::hash::blake3::Blake3Hasher;
use enrichr::useragent::UaParserBuiltin;
use enrichr::classify::ReferrerListClassifier;
use chrono::Utc;
use std::net::{IpAddr, Ipv4Addr};

// Build once, share behind an Arc — Processor is Send + Sync.
let processor = Processor::builder()
    .visitor_id_strategy(MaskedHashedStrategy::new(
        Blake3Hasher,
        StaticSalt::new(vec![/* 16+ random bytes */]),
        IpMaskMode::Balanced,
    ))
    .ua_parser(UaParserBuiltin::new())
    .classifier(ReferrerListClassifier::new())
    .keep_raw_referrer(false)   // true to preserve full referrer URL
    .build();

let mut raw = RawEvent::new(
    EventKind::PageView,
    "https://example.com/post?utm_source=newsletter".into(),
    Utc::now(),
);
raw.ip = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
raw.user_agent = Some("Mozilla/5.0 (Macintosh; ...)".into());
raw.referrer = Some("https://www.google.com/".into());

let event = processor.process(raw)?;
// event.visitor_id  — base62, 16 chars, stable per (masked-ip, ua, entity)
// event.referrer    — eTLD+1 ("google.com"), or None
// event.traffic_source — category + source_name
// event.device / .browser / .os / .bot
// event.location    — None unless geoip feature + GeoIpDb configured
```

The `visitor_id` field on `RawEvent` is an escape hatch: if you set it yourself, `Processor` passes it through unchanged — useful when you've already computed a hash upstream.

## Features

| Feature | What it adds | Default |
|---|---|---|
| `serde` | `Serialize`/`Deserialize` for `Event`, `EventKind`, value types | yes |
| `blake3` | `Blake3Hasher` | yes |
| `useragent` | `UaParserBuiltin` (bundled regexes via `ua-parser`) | yes |
| `referrer-list` | `ReferrerListClassifier` + `referrer::extract_utm` | yes |
| `sha256` | `Sha256Hasher` | no |
| `geoip` | `GeoIpDb` (MaxMind city database reader) | no |
| `http-headers` | `headers::client_ip` helper | no |
| `utoipa` | `utoipa::ToSchema` on output types | no |
| `typeshare` | `#[typeshare]` on output types | no |
| `schemars` | `JsonSchema` on output types | no |

`default = ["serde", "blake3", "useragent", "referrer-list"]`

`full` enables everything.

## GeoIP

The library doesn't download databases. `GeoIpDb::from_path` loads a MaxMind-format city MMDB at startup; call `reload_from_path` on whatever schedule you like (e.g. a 24 h timer). Reloads are integrity-gated: the candidate must parse, its `build_epoch` must be ≥ the current one, and its file size must be ≥ 80% of the current — a failed reload leaves the existing database in place.

```rust
#[cfg(feature = "geoip")]
{
    use enrichr::geoip::GeoIpDb;
    let db = GeoIpDb::from_path("GeoLite2-City.mmdb".as_ref())?;
    let processor = Processor::builder().geoip(db).build();

    // On your own schedule (e.g. every 24h), reload the GeoIP DB in place:
    if let Some(geoip) = processor.geoip() {
        geoip.reload_from_path("GeoLite2-City.mmdb".as_ref())?;
    }
}
```

## License

MIT OR Apache-2.0
