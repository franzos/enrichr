# Changelog

## [0.1.1] - 2026-06-10

### Added
- `device_type` bucket on `DeviceInfo` (bot/mobile/tablet/desktop)
- `is_bot` now catches self-identifying agents (AI crawlers, http clients)
- Paid-click detection via `gclid`/`msclkid` → cpc
- Derived `traffic_source.medium` from referrer category
- Checked salt constructors `try_new` rejecting short salts

## [0.1.0] - 2026-06-09

### Added
- Initial release
