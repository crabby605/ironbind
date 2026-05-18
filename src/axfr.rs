/// Zone transfer protocol (AXFR + IXFR, RFC 5936 / RFC 1995).
///
/// Generates the wire-format response stream that an authoritative server
/// sends to a secondary asking for a zone. AXFR starts with the SOA, lists
/// every RR in the zone, and ends with the SOA again. IXFR falls back to
/// AXFR when no delta is available (we don't keep history yet).

use crate::proto::{Packet, Record, RType, serialize};
use crate::zone::Zone;
use crate::zone_manager::ZoneDelta;

/// Produce the AXFR message stream for `zone`. Each returned packet should be
/// length-prefixed and written to the TCP stream in order.
pub fn axfr_stream(req: &Packet, zone: &Zone) -> Vec<Vec<u8>> {
    let soa = match zone.soa() {
        Some(s) if !s.is_empty() => s[0].clone(),
        _ => return vec![],
    };

    // Collect every RR (skip the SOA itself; we add it at the boundaries).
    let mut body: Vec<Record> = zone.iter_rrsets()
        .flat_map(|rrset| rrset.iter().cloned())
        .filter(|r| r.rtype != RType::SOA)
        .collect();
    body.sort_by(|a, b| a.name.cmp(&b.name).then(rtype_ord(&a.rtype).cmp(&rtype_ord(&b.rtype))));

    // RFC 5936 §2.2: pack RRs into messages up to a reasonable size cap.
    const MAX_RRS_PER_MSG: usize = 64;
    let mut packets = Vec::new();
    let mut current: Vec<Record> = vec![soa.clone()];

    for rr in body {
        if current.len() >= MAX_RRS_PER_MSG {
            packets.push(build_axfr_msg(req, std::mem::take(&mut current)));
        }
        current.push(rr);
    }

    // Append closing SOA in the final message.
    if current.len() >= MAX_RRS_PER_MSG {
        packets.push(build_axfr_msg(req, std::mem::take(&mut current)));
    }
    current.push(soa);
    packets.push(build_axfr_msg(req, current));

    packets
}

/// IXFR per RFC 1995. Three cases:
///   1. requester's serial == ours: single SOA "up to date" reply.
///   2. delta chain available: emit "new SOA, [old SOA, deletions, new SOA, additions]*, new SOA".
///   3. otherwise: fall back to a full AXFR.
pub fn ixfr_stream(req: &Packet, zone: &Zone, requester_serial: u32, history: Option<Vec<ZoneDelta>>) -> Vec<Vec<u8>> {
    let our_soa = match zone.soa().and_then(|s| s.first().cloned()) {
        Some(s) => s,
        None => return vec![],
    };
    let our_serial = extract_serial(&our_soa.rdata).unwrap_or(0);

    if our_serial == requester_serial {
        return vec![build_axfr_msg(req, vec![our_soa])];
    }

    if let Some(deltas) = history {
        if !deltas.is_empty() && deltas.last().map(|d| d.to_serial) == Some(our_serial) {
            // Build the IXFR record stream and chunk into messages.
            let mut rrs: Vec<Record> = Vec::new();
            rrs.push(our_soa.clone());
            for d in &deltas {
                rrs.push(d.from_soa.clone());
                rrs.extend(d.removed.iter().cloned());
                rrs.push(d.to_soa.clone());
                rrs.extend(d.added.iter().cloned());
            }
            rrs.push(our_soa);

            const MAX_RRS_PER_MSG: usize = 64;
            let mut packets = Vec::new();
            for chunk in rrs.chunks(MAX_RRS_PER_MSG) {
                packets.push(build_axfr_msg(req, chunk.to_vec()));
            }
            return packets;
        }
    }

    axfr_stream(req, zone)
}

fn build_axfr_msg(req: &Packet, answers: Vec<Record>) -> Vec<u8> {
    let mut resp = Packet::new_response(req.id, req.flags);
    resp.questions = req.questions.clone();
    resp.set_aa();
    resp.answers = answers;
    serialize(&resp, false)
}

fn rtype_ord(t: &RType) -> u16 { u16::from(t) }

/// Parse SOA rdata to extract the SERIAL field (after mname, rname).
fn extract_serial(rdata: &[u8]) -> Option<u32> {
    let mut p = crate::proto::Parser::new(rdata);
    p.name().ok()?;
    p.name().ok()?;
    p.u32().ok()
}
