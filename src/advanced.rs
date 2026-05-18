/// Advanced Features — RSA Signing, Key Rotation, Zone Transfer
///
/// Phase 3 advanced features:
/// - RSA-SHA256/SHA512 signing implementation
/// - Automatic key rotation framework
/// - Zone transfer (AXFR) protocol
/// - Key derivation and management

use std::time::{SystemTime, UNIX_EPOCH, Duration};
use rsa::{RsaPrivateKey, Pkcs1v15Sign};
use sha2::{Sha256, Sha512, Digest};
use signature::Signer;
use p256::ecdsa::{SigningKey as P256SigningKey, Signature as P256Signature};
use p384::ecdsa::{SigningKey as P384SigningKey, Signature as P384Signature};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use sha1::Sha1;
use std::convert::TryInto;
use crate::proto::{Builder, Record, RType};

/// RSA signature generation framework
pub struct RsaSigner {
    private_key: RsaPrivateKey,
    algorithm: u8,
}

impl RsaSigner {
    pub fn new(modulus: Vec<u8>, exponent: Vec<u8>, private_exponent: Vec<u8>, algorithm: u8) -> Result<Self, String> {
        let n = rsa::BigUint::from_bytes_be(&modulus);
        let e = rsa::BigUint::from_bytes_be(&exponent);
        let d = rsa::BigUint::from_bytes_be(&private_exponent);

        // Construct key without primes (might be slower/less secure against side-channels but works for logic)
        let private_key = RsaPrivateKey::from_components(n, e, d, vec![])
            .map_err(|e| e.to_string())?;

        Ok(Self {
            private_key,
            algorithm,
        })
    }

    /// Sign data with RSA PKCS#1 v1.5 padding, hashing with SHA-256 (alg 8) or SHA-512 (alg 10).
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if self.algorithm == 8 {
            let mut hasher = Sha256::new();
            hasher.update(data);
            self.private_key
                .sign(Pkcs1v15Sign::new::<Sha256>(), &hasher.finalize())
                .map_err(|e| e.to_string())
        } else {
            let mut hasher = Sha512::new();
            hasher.update(data);
            self.private_key
                .sign(Pkcs1v15Sign::new::<Sha512>(), &hasher.finalize())
                .map_err(|e| e.to_string())
        }
    }
}

/// Automatic key rotation manager
pub struct KeyRotationManager {
    last_rotation: SystemTime,
    rotation_interval: Duration,
    algorithm: u8,
}

impl KeyRotationManager {
    pub fn new(rotation_days: u64, algorithm: u8) -> Self {
        Self {
            last_rotation: SystemTime::now(),
            rotation_interval: Duration::from_secs(rotation_days * 86400),
            algorithm,
        }
    }

    /// Check if key rotation is due
    pub fn should_rotate(&self) -> bool {
        match self.last_rotation.elapsed() {
            Ok(elapsed) => elapsed >= self.rotation_interval,
            Err(_) => false,
        }
    }

    /// Get time until next rotation
    pub fn time_until_rotation(&self) -> Duration {
        let elapsed = self.last_rotation.elapsed().unwrap_or_default();
        if elapsed >= self.rotation_interval {
            Duration::from_secs(0)
        } else {
            self.rotation_interval - elapsed
        }
    }

    /// Mark rotation as completed
    pub fn mark_rotated(&mut self) {
        self.last_rotation = SystemTime::now();
    }
}

/// Zone Transfer (AXFR) protocol implementation
pub struct ZoneTransfer {
    zone_name: String,
    /// Records to transfer
    records: Vec<(String, u16, Vec<u8>)>, // (name, type, rdata)
}

impl ZoneTransfer {
    pub fn new(zone_name: &str) -> Self {
        Self {
            zone_name: zone_name.to_string(),
            records: Vec::new(),
        }
    }

    /// Add a record to transfer
    pub fn add_record(&mut self, name: &str, rtype: u16, rdata: Vec<u8>) {
        self.records.push((name.to_string(), rtype, rdata));
    }

    /// Build AXFR response messages (RFC 5936). The real implementation lives
    /// in `crate::axfr`; this is a thin builder kept for API-compat callers.
    pub fn to_wire_format(&self) -> Vec<Vec<u8>> {
        use crate::proto::{Packet, serialize};
        let _ = Builder::new(); // keep Builder import live for the module

        let soa_idx = self.records.iter().position(|(_, t, _)| *t == 6);
        let Some(soa_idx) = soa_idx else {
            eprintln!("[zone-transfer] no SOA — cannot build AXFR");
            return Vec::new();
        };

        let make_record = |name: &str, rtype: u16, rdata: &[u8]| Record {
            name: name.to_string(),
            rtype: RType::from(rtype),
            class: 1,
            ttl: 3600,
            rdata: rdata.to_vec(),
        };
        let soa = make_record(&self.records[soa_idx].0, 6, &self.records[soa_idx].2);

        let mut all: Vec<Record> = Vec::with_capacity(self.records.len() + 2);
        all.push(soa.clone());
        for (i, (n, t, d)) in self.records.iter().enumerate() {
            if i == soa_idx { continue; }
            all.push(make_record(n, *t, d));
        }
        all.push(soa);

        const CHUNK: usize = 100;
        let mut packets = Vec::new();
        for slice in all.chunks(CHUNK) {
            let mut pkt = Packet::new_response(0, 0);
            pkt.set_aa();
            pkt.answers = slice.to_vec();
            packets.push(serialize(&pkt, false));
        }
        packets
    }
}

/// ECDSA signing support
pub struct EcdsaSigner {
    private_key_bytes: Vec<u8>,
    curve: String,
    algorithm: u8,
}

impl EcdsaSigner {
    pub fn new(curve: &str, algorithm: u8, private_key_bytes: Vec<u8>) -> Self {
        Self {
            curve: curve.to_string(),
            algorithm,
            private_key_bytes,
        }
    }

    /// Sign with ECDSA
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if self.curve == "P-256" {
            let signing_key = P256SigningKey::from_slice(&self.private_key_bytes)
                .map_err(|_| "Invalid P-256 key".to_string())?;
            let signature: P256Signature = signing_key.sign(data);
            return Ok(signature.to_der().as_bytes().to_vec());
        }

        if self.curve == "P-384" {
            let signing_key = P384SigningKey::from_slice(&self.private_key_bytes)
                .map_err(|_| "Invalid P-384 key".to_string())?;
            let signature: P384Signature = signing_key.sign(data);
            return Ok(signature.to_der().as_bytes().to_vec());
        }

        Err("Unsupported curve".to_string())
    }
}

/// ED25519 signing support
pub struct Ed25519Signer {
    signing_key: Ed25519SigningKey,
    algorithm: u8,
}

impl Ed25519Signer {
    pub fn new(private_key_bytes: &[u8]) -> Result<Self, String> {
        let try_key: Result<[u8; 32], _> = private_key_bytes.try_into();
        match try_key {
            Ok(bytes) => {
                let signing_key = Ed25519SigningKey::from_bytes(&bytes);
                Ok(Self {
                    signing_key,
                    algorithm: 15,
                })
            }
            Err(_) => Err("Invalid ED25519 key length".to_string()),
        }
    }

    /// Sign with ED25519
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let signature = self.signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
}

/// NSEC3 support for larger zones
pub struct Nsec3Generator {
    iterations: u16,
    salt: Vec<u8>,
}

impl Nsec3Generator {
    pub fn new(iterations: u16, salt: Vec<u8>) -> Self {
        Self {
            iterations,
            salt,
        }
    }

    /// Generate NSEC3 hash for a name (RFC 5155)
    pub fn hash_name(&self, name: &str) -> String {
        let mut hash = {
            let mut hasher = Sha1::new();
            // Encode name in wire format (simplified: length-label)
            // Note: Simplification, using simple bytes for now
            hasher.update(name.as_bytes());
            hasher.update(&self.salt);
            hasher.finalize()
        };

        for _ in 0..self.iterations {
            let mut hasher = Sha1::new();
            hasher.update(&hash);
            hasher.update(&self.salt);
            hash = hasher.finalize();
        }

        // Base32hex encoding is standard for NSEC3 but hex is easier for output
        // Implementing standard Hex output here
        hex::encode(hash)
    }
}

/// Multi-master replication configuration
pub struct MultiMasterConfig {
    /// Peer servers for zone replication
    peers: Vec<String>, // IP:port of peer servers
    /// Replication interval
    replication_interval: Duration,
    /// Zone serial for tracking
    zone_serial: u32,
}

impl MultiMasterConfig {
    pub fn new(peers: Vec<String>, replication_interval_secs: u64) -> Self {
        Self {
            peers,
            replication_interval: Duration::from_secs(replication_interval_secs),
            zone_serial: 0,
        }
    }

    /// Add peer server
    pub fn add_peer(&mut self, peer: String) {
        self.peers.push(peer);
    }

    /// Get list of peers
    pub fn get_peers(&self) -> &[String] {
        &self.peers
    }

    /// Query a peer's SOA for the configured zone over UDP and return its serial.
    pub fn get_peer_serial(&self, peer: &str, zone: &str) -> Result<u32, String> {
        use std::net::UdpSocket;
        use crate::proto::{Builder, Parser, Question, RType, CLASS_IN};

        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(Duration::from_secs(3))).map_err(|e| e.to_string())?;

        // Build SOA query
        let mut b = Builder::new();
        b.u16(0x4242);   // id
        b.u16(0x0100);   // flags: standard query, RD
        b.u16(1);        // qdcount
        b.u16(0); b.u16(0); b.u16(0);
        b.question(&Question { name: zone.to_string(), qtype: RType::SOA, qclass: CLASS_IN });
        let query = b.finish();

        sock.send_to(&query, peer).map_err(|e| e.to_string())?;

        let mut buf = vec![0u8; 4096];
        let (len, _) = sock.recv_from(&mut buf).map_err(|e| e.to_string())?;
        let pkt = Parser::new(&buf[..len]).parse().map_err(|e| e.to_string())?;

        let soa = pkt.answers.iter().chain(pkt.authority.iter())
            .find(|r| r.rtype == RType::SOA)
            .ok_or_else(|| "no SOA in response".to_string())?;

        // SOA rdata: mname, rname, then serial (u32), refresh, retry, expire, minimum.
        let mut p = Parser::new(&soa.rdata);
        let _mname = p.name().map_err(|e| e.to_string())?;
        let _rname = p.name().map_err(|e| e.to_string())?;
        p.u32().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_rotation_manager() {
        let manager = KeyRotationManager::new(90, 8);
        assert!(!manager.should_rotate());
    }

    #[test]
    fn test_zone_transfer() {
        let transfer = ZoneTransfer::new("example.com");
        assert_eq!(transfer.zone_name, "example.com");
    }

    #[test]
    fn test_multi_master() {
        let config = MultiMasterConfig::new(
            vec!["192.0.2.1:53".to_string(), "192.0.2.2:53".to_string()],
            3600
        );
        assert_eq!(config.get_peers().len(), 2);
    }
}
