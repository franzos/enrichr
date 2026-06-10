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
// event.visitor_id  — base62 of the full digest (~43 chars), stable per (masked-ip, ua, entity)
// event.referrer    — eTLD+1 ("google.com"), or None
// event.traffic_source — category + source_name + medium (organic/social/referral/cpc)
// event.device / .browser / .os / .bot   — device.device_type: mobile/tablet/desktop/bot
// event.location    — None unless geoip feature + GeoIpDb configured
```

The `visitor_id` field on `RawEvent` is an escape hatch: if you set it yourself, `Processor` passes it through unchanged — useful when you've already computed a hash upstream.

## Features

Everything beyond the core pipeline (`Processor`, `RawEvent`/`Event`, the `Hasher`/`SaltProvider`/`VisitorIdStrategy`/`UaParser`/`Classifier` traits, `mask_ip`) is feature-gated, so you only pull the dependencies you use.

`default = ["serde", "blake3", "useragent", "referrer-list"]` — the batteries-included set: it hashes visitor ids, parses user agents, classifies referrers, and (de)serializes the output. `full` turns on everything.

### Hashing

| Feature | Adds | Pulls | Default |
|---|---|---|---|
| `blake3` | `Blake3Hasher` (32-byte BLAKE3 digest) — fast, recommended | `blake3` | yes |
| `sha256` | `Sha256Hasher` (32-byte SHA-256) — standardized, pick it if an audit/compliance regime expects SHA-2 | `sha2` | no |

The built-in `SaltedHasher` / `MaskedHashedStrategy` are generic over `Hasher`, so **you need at least one of these two features** to use them out of the box — or implement `Hasher` (or the whole `VisitorIdStrategy`) yourself. The choice between BLAKE3 and SHA-256 is performance/standardization; neither protects users without a secret salt (see [Privacy](#privacy)).

### Enrichment

| Feature | Adds | Pulls | Default |
|---|---|---|---|
| `useragent` | `UaParserBuiltin` — device/browser/OS, a `device_type` bucket (mobile/tablet/desktop/bot), and a best-effort `is_bot` (uap-core spiders + self-identifying agents like GPTBot/curl), via `ua-parser` with a regex DB embedded at compile time (one parse per event) | `ua-parser`, `yaml_serde` | yes |
| `referrer-list` | `ReferrerListClassifier` (built-in domain→category/source table; derives `medium`, and detects paid clicks via `gclid`/`msclkid`) and the `referrer` utils: `registrable_domain` (eTLD+1 via the Public Suffix List), `extract_utm`, and `paid_click` | `psl`, `url` | yes |
| `geoip` | `GeoIpDb` — hot-reloadable MaxMind `.mmdb` city reader (see [GeoIP](#geoip)); `lookup` returns a `Location` | `maxminddb` | no |

**Caveat for `referrer-list`:** `Event.referrer` (the eTLD+1) is computed by `registrable_domain`, which lives behind this feature. With the feature **off**, `Event.referrer` and `Event.traffic_source` are always `None` regardless of the incoming referrer — the pipeline simply doesn't parse it. `keep_raw_referrer(true)` still preserves the full URL in `Event.raw_referrer` either way.

### Serialization & codegen

These are additive derives on the public output types (`Event`, `Location`, `Context`, `Utm`, `DeviceInfo`, `BrowserInfo`, `OperatingSystemInfo`, `ParsedUa`, `TrafficSource`, plus `EventKind`/`VisitorId`). `RawEvent` is deliberately **never** `Serialize` — it carries the raw IP/UA/referrer.

| Feature | Adds | Pulls | Default |
|---|---|---|---|
| `serde` | `Serialize`/`Deserialize`; also enables `chrono/serde` for the timestamp. `EventKind`/`VisitorId` deserialize through their validating constructors | `serde` | yes |
| `utoipa` | `utoipa::ToSchema` (OpenAPI); `EventKind`/`VisitorId` render as `string` | `utoipa` | no |
| `schemars` | `schemars::JsonSchema` | `schemars` | no |
| `typeshare` | `#[typeshare]` annotations for TypeScript type generation | `typeshare` | no |

### Helpers

| Feature | Adds | Pulls | Default |
|---|---|---|---|
| `http-headers` | `headers::client_ip(getter)` — framework-agnostic client-IP extraction from forwarding headers (`X-Forwarded-For`, `CF-Connecting-IP`, …). You supply proxy trust | — (std only) | no |

### No-default build

With `default-features = false` and nothing else, `enrichr` is a near-identity pipeline: it validates and passes fields through but does no hashing, UA parsing, referrer classification, or geo lookup. It's only useful in that mode if you wire in your own `VisitorIdStrategy` / `Classifier` / `UaParser` implementations.

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
