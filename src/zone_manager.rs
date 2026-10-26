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

/// Directory holding the DNSSEC keys written by setup.sh
const KEY_DIRECTORY: &str = "keys";

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

        // Sign the zone when a ZSK for it exists in the key directory
        let zsk_path = format!("{}/K{}+008+zsk.private", KEY_DIRECTORY, z.origin);
        if std::path::Path::new(&zsk_path).exists() {
            if let Err(e) = Self::sign_zone(&mut z, KEY_DIRECTORY) {
                eprintln!("[zone-manager] failed to sign {}: {}", z.origin, e);
            }
        }
        let new_zone = Arc::new(z);

        // If a previous version exists, compute the diff and append to history.
        let prev = self.zones.read().unwrap_or_else(std::sync::PoisonError::into_inner).get(origin).cloned();
        if let Some(old) = prev {
            if let Some(delta) = build_delta(&old, &new_zone) {
                if delta.from_serial != delta.to_serial {
                    let mut hist = self.history.write().unwrap_or_else(std::sync::PoisonError::into_inner);
                    let queue = hist.entry(origin.to_string()).or_default();
                    queue.push_back(delta);
                    while queue.len() > self.history_cap { queue.pop_front(); }
                }
            }
        }

        // Track file path for reloading
        self.zone_files.insert(origin.to_string(), path.to_string());

        // Update version
        let mut versions = self.versions.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        let version = versions.get(origin).unwrap_or(&0) + 1;
        versions.insert(origin.to_string(), version);

        // Store zone (atomically)
        let mut zones = self.zones.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        zones.insert(origin.to_string(), new_zone);

        eprintln!("[zone-manager] loaded {} (v{})", origin, version);
        Ok(())
    }

    /// Return the chain of deltas that transforms `from_serial` into the
    /// current zone serial. Returns None if we can't reconstruct that history
    /// (caller should fall back to AXFR).
    pub fn ixfr_chain(&self, origin: &str, from_serial: u32) -> Option<Vec<ZoneDelta>> {
        let hist = self.history.read().unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let zones = self.zones.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        zones.values().cloned().collect()
    }

    /// Get a specific zone by origin
    pub fn get_zone(&self, origin: &str) -> Option<Arc<Zone>> {
        let zones = self.zones.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        zones.get(origin).cloned()
    }

    /// Get zone version for change tracking
    pub fn get_version(&self, origin: &str) -> u32 {
        self.versions.read().unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(origin)
            .copied()
            .unwrap_or(0)
    }

    /// Sign all RRsets in a zone with DNSSEC, producing RRSIG records.
    /// Reads the ZSK from `<key_dir>/K<origin>+008+zsk.private` and, when present,
    /// the KSK from `<key_dir>/K<origin>+008+ksk.private`. The DNSKEY records and
    /// every RRSIG are added to the zone before it is published.
    pub fn sign_zone(zone: &mut Zone, key_dir: &str) -> std::io::Result<usize> {
        use crate::zone_signing::{DnsKey, ZoneSigner};

        let origin = zone.origin.clone();
        if zone.lookup(&origin, &RType::DNSKEY).is_some() {
            eprintln!("[zone-manager] {} already carries DNSKEY records, leaving it unsigned", origin);
            return Ok(0);
        }

        let zsk_path = format!("{}/K{}+008+zsk.private", key_dir, origin);
        let mut zsk = DnsKey::from_pem_file(&zsk_path)?;
        zsk.key_name = origin.clone();

        let ksk_path = format!("{}/K{}+008+ksk.private", key_dir, origin);
        let ksk = match DnsKey::from_pem_file(&ksk_path) {
            Ok(mut key) => {
                key.key_name = origin.clone();
                key.flags = 257; // zone key + secure entry point
                Some(key)
            }
            Err(_) => None,
        };

        let zsk_tag = zsk.key_tag()?;
        let dnskey_ttl = zone.soa().and_then(|soa| soa.first()).map(|soa| soa.ttl).unwrap_or(3600);
        zone.add(zsk.dnskey_record(dnskey_ttl)?);
        let ksk_tag = match &ksk {
            Some(key) => {
                zone.add(key.dnskey_record(dnskey_ttl)?);
                Some(key.key_tag()?)
            }
            None => None,
        };

        // Negative TTL per RFC 9077: the smaller of the SOA TTL and its MINIMUM field
        let nsec_ttl = zone.soa().and_then(|soa| soa.first())
            .map(|soa| soa.ttl.min(crate::cache::soa_minimum_ttl(&soa.rdata)))
            .unwrap_or(3600);
        zone.build_nsec_chain(nsec_ttl);

        let signer = ZoneSigner::new(zsk, ksk);
        let rrsets: Vec<Vec<Record>> = zone.iter_rrsets().cloned().collect();

        let mut rrsigs = Vec::new();
        for rrset in &rrsets {
            match signer.sign_rrset(rrset, &origin, zsk_tag) {
                Ok(rrsig) => rrsigs.push(rrsig),
                Err(e) => eprintln!("[zone-manager] failed to sign {} {:?}: {}", rrset[0].name, rrset[0].rtype, e),
            }
            // The DNSKEY RRset is also signed by the KSK so resolvers can anchor it via DS
            if rrset[0].rtype == RType::DNSKEY {
                if let (Some(key), Some(tag)) = (signer.ksk(), ksk_tag) {
                    rrsigs.push(signer.sign_rrset_with_key(key, rrset, &origin, tag)?);
                }
            }
        }

        let count = rrsigs.len();
        for rrsig in rrsigs {
            zone.add(rrsig);
        }

        eprintln!("[zone-manager] signed {} RRsets in {}", count, origin);
        Ok(count)
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
    fn test_signed_zone_has_valid_canonical_nsec_chain() {
        use rsa::pkcs8::EncodePrivateKey;
        use crate::dnssec::{Validator, ValidationResult};

        // RFC 4034 §6.1 example order, minus the escaped labels
        let expected = ["example", "a.example", "yljkjljk.a.example", "z.a.example", "zabc.a.example", "z.example", "*.z.example"];
        let mut shuffled = expected.to_vec();
        shuffled.reverse();
        shuffled.sort_by(|a, b| crate::zone::canonical_order(a, b));
        assert_eq!(shuffled, expected);

        let directory = std::env::temp_dir().join(format!("ironbind-sign-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        std::fs::write(directory.join("Kexample.com+008+zsk.private"), pem.as_bytes()).unwrap();
        let zone_path = directory.join("example.com.zone");
        std::fs::write(&zone_path, "$ORIGIN example.com.\n$TTL 3600\n\
            @ IN SOA ns1 admin 1 3600 900 604800 300\n\
            @ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\n").unwrap();

        let mut zone = Zone::new("example.com");
        zone.load_file(zone_path.to_str().unwrap()).unwrap();
        ZoneManager::sign_zone(&mut zone, directory.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_dir_all(&directory);

        assert!(zone.is_signed());
        // "mail" sorts between "example.com" and "ns1"; "*.example.com" right after the apex
        assert_eq!(zone.nsec_covering_owner("mail.example.com"), Some("example.com"));
        assert_eq!(zone.nsec_covering_owner("*.example.com"), Some("example.com"));
        assert_eq!(zone.nsec_covering_owner("zzz.example.com"), Some("www.example.com"));
        assert_eq!(zone.closest_encloser("a.b.example.com"), "example.com");

        let dnskeys = zone.lookup("example.com", &RType::DNSKEY).unwrap().clone();
        for owner in ["example.com", "ns1.example.com", "www.example.com"] {
            let nsec = zone.lookup(owner, &RType::NSEC).unwrap().clone();
            let rrsigs: Vec<Record> = zone.lookup(owner, &RType::RRSIG).unwrap().iter()
                .filter(|r| crate::proto::parse_rrsig(&r.rdata).unwrap().type_covered == u16::from(&RType::NSEC))
                .cloned().collect();
            assert!(matches!(Validator::validate_rrset(&nsec, &rrsigs, &dnskeys), ValidationResult::Secure), "{}", owner);
        }
    }

    #[test]
    fn test_zone_version_tracking() {
        let manager = ZoneManager::new();
        assert_eq!(manager.get_version("test.com"), 0);
    }
}
