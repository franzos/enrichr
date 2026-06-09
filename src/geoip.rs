use crate::error::GeoIpError;
use crate::types::Location;
use arc_swap::ArcSwapOption;
use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

struct Loaded {
    reader: Reader<Vec<u8>>,
    build_epoch: u64,
    len: usize,
}

pub struct GeoIpDb {
    inner: ArcSwapOption<Loaded>,
}

// reject a candidate whose size is below 80% of the current
const SIZE_FLOOR_RATIO: usize = 80;

impl GeoIpDb {
    pub fn from_path(p: &Path) -> Result<Self, GeoIpError> {
        let bytes = std::fs::read(p)?;
        let loaded = Self::build(bytes)?;
        Ok(GeoIpDb {
            inner: ArcSwapOption::from(Some(Arc::new(loaded))),
        })
    }

    pub fn reload_from_path(&self, p: &Path) -> Result<(), GeoIpError> {
        self.reload_from_bytes(std::fs::read(p)?)
    }

    pub fn reload_from_bytes(&self, bytes: Vec<u8>) -> Result<(), GeoIpError> {
        let candidate = Self::build(bytes)?;
        if let Some(cur) = self.inner.load_full() {
            if candidate.build_epoch < cur.build_epoch {
                return Err(GeoIpError::Rejected("build_epoch older than current"));
            }
            if candidate.len * 100 < cur.len * SIZE_FLOOR_RATIO {
                return Err(GeoIpError::Rejected("candidate too small vs current"));
            }
        }
        self.inner.store(Some(Arc::new(candidate)));
        Ok(())
    }

    fn build(bytes: Vec<u8>) -> Result<Loaded, GeoIpError> {
        let len = bytes.len();
        let reader = Reader::from_source(bytes).map_err(|e| GeoIpError::Decode(e.to_string()))?;
        let build_epoch = reader.metadata.build_epoch;
        Ok(Loaded {
            reader,
            build_epoch,
            len,
        })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<Location> {
        let loaded = self.inner.load_full()?;
        let result = loaded.reader.lookup(ip).ok()?;
        let city: geoip2::City = result.decode().ok()??;
        Some(to_location(&city))
    }
}

fn to_location(c: &geoip2::City) -> Location {
    let region = c.subdivisions.first();
    Location {
        country_code: c.country.iso_code.map(str::to_owned),
        country_name: c.country.names.english.map(str::to_owned),
        continent_code: c.continent.code.map(str::to_owned),
        continent_name: c.continent.names.english.map(str::to_owned),
        region_code: region.and_then(|s| s.iso_code).map(str::to_owned),
        region_name: region.and_then(|s| s.names.english).map(str::to_owned),
        city: c.city.names.english.map(str::to_owned),
        latitude: c.location.latitude,
        longitude: c.location.longitude,
        timezone: c.location.time_zone.map(str::to_owned),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    // fixture: tests/fixtures/city.mmdb
    // source: /home/franz/git_personal/mono/backend/formshive/GeoLite2-City.mmdb

    #[test]
    fn loads_and_looks_up() {
        let db = GeoIpDb::from_path("tests/fixtures/city.mmdb".as_ref()).unwrap();
        // fixture-dependent: just assert it does not panic and returns a value (Some or None)
        let _ = db.lookup("89.160.20.112".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn corrupt_bytes_rejected_old_reader_kept() {
        let db = GeoIpDb::from_path("tests/fixtures/city.mmdb".as_ref()).unwrap();
        assert!(db.reload_from_bytes(vec![0u8; 32]).is_err());
        // still functional after a failed reload:
        let _ = db.lookup("1.1.1.1".parse::<IpAddr>().unwrap());
    }
}
