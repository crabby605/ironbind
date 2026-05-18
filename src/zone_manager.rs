/// Zone Manager — Handle zone reloading, signing, and lifecycle
///
/// Features:
/// - Hot reloading zones via SIGHUP signal
/// - Zone version tracking
/// - Atomic zone updates

use std::sync::{Arc, RwLock};
use std::collections::{HashMap, VecDeque};
use crate::proto::{Record, RType, Parser};
use crate::zone::Zone;

/// One step in a zone's edit history — the diff between two consecutive
/// serials. The RFC 1995 IXFR response stitches a chain of these together.
#[derive(Debug, Clone)]
pub struct ZoneDelta {
    pub from_serial: u32,
    pub to_serial:   u32,
    pub from_soa:    Record,
    pub to_soa:      Record,
    /// Records present in the old zone but not the new one.
    pub removed:     Vec<Record>,
    /// Records present in the new zone but not the old one.
    pub added:       Vec<Record>,
}

/// Manages zones with support for hot-reloading and signing
pub struct ZoneManager {
    /// Current active zones: origin → Zone
    zones: RwLock<HashMap<String, Arc<Zone>>>,
    /// Zone file paths: origin → file path
    zone_files: HashMap<String, String>,
    /// Zone versions for tracking updates
    versions: RwLock<HashMap<String, u32>>,
    /// Bounded IXFR history per zone, oldest first.
    history: RwLock<HashMap<String, VecDeque<ZoneDelta>>>,
    /// Max deltas to retain per zone before the oldest is dropped.
    history_cap: usize,
}

impl ZoneManager {
    pub fn new() -> Self {
        Self {
            zones: RwLock::new(HashMap::new()),
            zone_files: HashMap::new(),
            versions: RwLock::new(HashMap::new()),
            history: RwLock::new(HashMap::new()),
            history_cap: 32,
        }
    }

    /// Load a zone from file
    /// origin: zone origin (e.g., "example.com")
    /// path: path to zone file
    pub fn load_zone(&mut self, origin: &str, path: &str) -> std::io::Result<()> {
        let mut z = Zone::new(origin);
        z.load_file(path)?;
        let new_zone = Arc::new(z);

        // If a previous version exists, compute the diff and append to history.
        let prev = self.zones.read().unwrap().get(origin).cloned();
        if let Some(old) = prev {
            if let Some(delta) = build_delta(&old, &new_zone) {
                if delta.from_serial != delta.to_serial {
                    let mut hist = self.history.write().unwrap();
                    let queue = hist.entry(origin.to_string()).or_default();
                    queue.push_back(delta);
                    while queue.len() > self.history_cap { queue.pop_front(); }
                }
            }
        }

        // Track file path for reloading
        self.zone_files.insert(origin.to_string(), path.to_string());

        // Update version
        let mut versions = self.versions.write().unwrap();
        let version = versions.get(origin).unwrap_or(&0) + 1;
        versions.insert(origin.to_string(), version);

        // Store zone (atomically)
        let mut zones = self.zones.write().unwrap();
        zones.insert(origin.to_string(), new_zone);

        eprintln!("[zone-manager] loaded {} (v{})", origin, version);
        Ok(())
    }

    /// Return the chain of deltas that transforms `from_serial` into the
    /// current zone serial. Returns None if we can't reconstruct that history
    /// (caller should fall back to AXFR).
    pub fn ixfr_chain(&self, origin: &str, from_serial: u32) -> Option<Vec<ZoneDelta>> {
        let hist = self.history.read().unwrap();
        let queue = hist.get(origin)?;
        // Find the earliest delta that starts at `from_serial`, then walk
        // forward through contiguous links.
        let start = queue.iter().position(|d| d.from_serial == from_serial)?;
        let mut chain = vec![queue[start].clone()];
        let mut expected = queue[start].to_serial;
        for d in queue.iter().skip(start + 1) {
            if d.from_serial != expected { return None; }
            chain.push(d.clone());
            expected = d.to_serial;
        }
        Some(chain)
    }

    /// Reload all zones from their source files
    /// Called on SIGHUP signal
    /// Returns number of zones reloaded successfully
    pub fn reload_all(&mut self) -> usize {
        let mut count = 0;

        // Get list of zones to reload (clone to avoid holding lock)
        let zone_list: Vec<(String, String)> = self.zone_files
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (origin, path) in zone_list {
            match self.load_zone(&origin, &path) {
                Ok(_) => {
                    count += 1;
                    eprintln!("[zone-manager] reloaded {}", origin);
                }
                Err(e) => eprintln!("[zone-manager] failed to reload {}: {}", origin, e),
            }
        }

        eprintln!("[zone-manager] reload complete: {}/{} zones", count, self.zone_files.len());
        count
    }

    /// Get list of all zones (returns Arc for thread-safe sharing)
    pub fn get_zones(&self) -> Vec<Arc<Zone>> {
        let zones = self.zones.read().unwrap();
        zones.values().cloned().collect()
    }

    /// Get a specific zone by origin
    pub fn get_zone(&self, origin: &str) -> Option<Arc<Zone>> {
        let zones = self.zones.read().unwrap();
        zones.get(origin).cloned()
    }

    /// Get zone version for change tracking
    pub fn get_version(&self, origin: &str) -> u32 {
        self.versions.read().unwrap()
            .get(origin)
            .copied()
            .unwrap_or(0)
    }

    /// Sign all RRsets in a zone with DNSSEC, producing RRSIG records.
    /// Reads the ZSK from `<key_dir>/K<origin>+008+zsk.private`.
    pub fn sign_zone(&self, origin: &str, key_dir: &str) -> std::io::Result<usize> {
        use crate::zone_signing::{DnsKey, ZoneSigner, compute_key_tag};

        let zsk_path = format!("{}/K{}+008+zsk.private", key_dir, origin);
        let mut zsk = DnsKey::from_pem_file(&zsk_path)?;
        zsk.key_name = origin.to_string();

        let key_tag = compute_key_tag(&zsk.private_key);
        let signer = ZoneSigner::new(zsk, None);

        let zone = self.get_zone(origin).ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("zone {} not loaded", origin),
        ))?;

        let mut rrsigs = 0;
        for rrset in zone.iter_rrsets() {
            if signer.sign_rrset(rrset, origin, key_tag).is_ok() {
                rrsigs += 1;
            }
        }

        eprintln!("[zone-manager] signed {} RRsets in {}", rrsigs, origin);
        Ok(rrsigs)
    }
}

/// Compute the diff between two zone snapshots. Returns None if either zone
/// lacks an SOA — in which case IXFR isn't representable for this transition.
fn build_delta(old: &Zone, new: &Zone) -> Option<ZoneDelta> {
    let old_soa = old.soa().and_then(|s| s.first().cloned())?;
    let new_soa = new.soa().and_then(|s| s.first().cloned())?;
    let from_serial = soa_serial(&old_soa.rdata)?;
    let to_serial   = soa_serial(&new_soa.rdata)?;

    // Hash each side by (name, type, rdata) so we can do set difference.
    let old_set: std::collections::HashSet<(String, u16, Vec<u8>)> = old.iter_rrsets()
        .flat_map(|r| r.iter())
        .filter(|r| r.rtype != RType::SOA)
        .map(|r| (r.name.to_ascii_lowercase(), u16::from(&r.rtype), r.rdata.clone()))
        .collect();
    let new_set: std::collections::HashSet<(String, u16, Vec<u8>)> = new.iter_rrsets()
        .flat_map(|r| r.iter())
        .filter(|r| r.rtype != RType::SOA)
        .map(|r| (r.name.to_ascii_lowercase(), u16::from(&r.rtype), r.rdata.clone()))
        .collect();

    let removed: Vec<Record> = old.iter_rrsets()
        .flat_map(|r| r.iter().cloned())
        .filter(|r| r.rtype != RType::SOA)
        .filter(|r| !new_set.contains(&(r.name.to_ascii_lowercase(), u16::from(&r.rtype), r.rdata.clone())))
        .collect();
    let added: Vec<Record> = new.iter_rrsets()
        .flat_map(|r| r.iter().cloned())
        .filter(|r| r.rtype != RType::SOA)
        .filter(|r| !old_set.contains(&(r.name.to_ascii_lowercase(), u16::from(&r.rtype), r.rdata.clone())))
        .collect();

    Some(ZoneDelta { from_serial, to_serial, from_soa: old_soa, to_soa: new_soa, removed, added })
}

fn soa_serial(rdata: &[u8]) -> Option<u32> {
    let mut p = Parser::new(rdata);
    p.name().ok()?; p.name().ok()?; p.u32().ok()
}

/// Configuration for zone signing
#[derive(Debug, Clone)]
pub struct ZoneSigningConfig {
    /// Path to zone signing key (ZSK)
    pub zsk_path: Option<String>,
    /// Path to key signing key (KSK)
    pub ksk_path: Option<String>,
    /// Algorithm: 5=RSA-SHA1, 8=RSA-SHA256, etc.
    pub algorithm: u8,
    /// TTL for RRSIG records
    pub rrsig_ttl: u32,
}

impl ZoneSigningConfig {
    pub fn new() -> Self {
        Self {
            zsk_path: None,
            ksk_path: None,
            algorithm: 8, // RSA-SHA256
            rrsig_ttl: 86400,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zone_manager_create() {
        let manager = ZoneManager::new();
        assert_eq!(manager.get_zones().len(), 0);
    }

    #[test]
    fn test_zone_version_tracking() {
        let manager = ZoneManager::new();
        assert_eq!(manager.get_version("test.com"), 0);
    }
}
