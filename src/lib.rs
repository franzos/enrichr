//! enrichr — database-independent analytics event enrichment.

pub mod error;
pub mod event;
pub mod hash;
pub mod ip;
pub mod processor;
pub mod strategy;
pub mod types;
pub mod visitor;

#[cfg(feature = "referrer-list")]
pub mod classify;
#[cfg(feature = "geoip")]
pub mod geoip;
#[cfg(feature = "http-headers")]
pub mod headers;
#[cfg(feature = "referrer-list")]
pub mod referrer;
#[cfg(feature = "useragent")]
pub mod useragent;

pub use error::{Field, ProcessError};
pub use event::{Event, EventKind, RawEvent};
pub use hash::{ArcSwapSalt, Hasher, SaltProvider, StaticSalt};
pub use ip::{mask_ip, IpMaskMode};
pub use processor::{Processor, ProcessorBuilder};
pub use strategy::{MaskedHashedStrategy, SaltedHasher, VisitorIdStrategy};
pub use types::{
    BrowserInfo, Context, DeviceInfo, Location, OperatingSystemInfo, ParsedUa, TrafficSource, Utm,
};
pub use visitor::VisitorId;

#[cfg(test)]
mod tests {
    fn assert_send_sync<T: Send + Sync>() {}
    #[test]
    fn processor_is_send_sync() {
        assert_send_sync::<crate::Processor>();
        assert_send_sync::<std::sync::Arc<crate::Processor>>();
    }
}
