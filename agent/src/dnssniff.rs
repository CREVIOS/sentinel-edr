//! Real forward-DNS capture. The TCP layer only exposes a remote IP, and that IP's reverse
//! PTR is the *hosting provider's* name (e.g. `ns…ip-15-235-182.net`), not the domain the host
//! actually connected to (`app2.makebell.com`). The only correct, kernel-free way to learn the
//! real name is to read the DNS answers the host receives: this sniffs UDP/53 responses with
//! libpcap and records each answer's IP→queried-name into the shared cache as authoritative.
//!
//! Needs libpcap at runtime + CAP_NET_RAW. If either is missing the thread logs once and exits;
//! the cache then falls back to forward-confirmed reverse DNS (see [`crate::dnscache`]).

use crate::dnscache::{is_global, DnsCache};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{info, warn};

/// Start the sniffer on a background thread. Never blocks the caller; never panics the process.
pub fn spawn(cache: DnsCache) {
    std::thread::Builder::new()
        .name("dns-sniff".into())
        .spawn(move || {
            if let Err(e) = run(cache) {
                warn!(error = %e, "DNS sniffer unavailable — falling back to reverse DNS");
            }
        })
        .ok();
}

fn run(cache: DnsCache) -> anyhow::Result<()> {
    // "any" captures every interface (the host resolver's upstream query on eth0, container
    // forwards on the docker bridge, local stub traffic on lo) under one uniform link type.
    let mut cap = pcap::Capture::from_device("any")?
        .immediate_mode(true)
        .snaplen(2048)
        .timeout(1000)
        .open()?;
    // Kernel-side BPF prefilter so we only wake for DNS, not every packet on a busy host.
    cap.filter("udp port 53", true)?;
    let link_off = link_header_len(cap.get_datalink());
    info!(datalink = cap.get_datalink().0, "DNS sniffer active (forward-DNS attribution)");

    loop {
        match cap.next_packet() {
            Ok(pkt) => {
                for (ip, name) in parse_packet(pkt.data, link_off) {
                    if is_global(ip) && !name.is_empty() {
                        cache.insert(ip, name);
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

/// Bytes of link-layer header to skip for a given libpcap datalink type, so parsing starts at
/// the IP header regardless of interface ("any" yields Linux cooked SLL/SLL2).
fn link_header_len(dl: pcap::Linktype) -> usize {
    match dl.0 {
        1 => 14,   // EN10MB (Ethernet)
        113 => 16, // LINUX_SLL  (cooked v1)
        276 => 20, // LINUX_SLL2 (cooked v2)
        12 => 0,   // RAW (no link header)
        0 => 4,    // NULL/loopback (4-byte family)
        _ => 16,   // sensible default for "any"
    }
}

/// Decode a captured frame into (answer-IP, queried-name) pairs from a DNS *response*.
fn parse_packet(frame: &[u8], link_off: usize) -> Vec<(IpAddr, String)> {
    let pkt = match frame.get(link_off..) {
        Some(p) if !p.is_empty() => p,
        _ => return Vec::new(),
    };
    let version = pkt[0] >> 4;
    let (proto, l4) = match version {
        4 => {
            if pkt.len() < 20 {
                return Vec::new();
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if pkt.len() < ihl {
                return Vec::new();
            }
            (pkt[9], &pkt[ihl..])
        }
        6 => {
            if pkt.len() < 40 {
                return Vec::new();
            }
            // Only the simple case (next-header == UDP); skip packets with extension headers.
            (pkt[6], &pkt[40..])
        }
        _ => return Vec::new(),
    };
    if proto != 17 || l4.len() < 8 {
        return Vec::new(); // not UDP
    }
    let sport = u16::from_be_bytes([l4[0], l4[1]]);
    // Responses originate from port 53; ignore the outbound queries.
    if sport != 53 {
        return Vec::new();
    }
    parse_dns(&l4[8..])
}

/// Parse a DNS response message: take the first question's name and map every A/AAAA answer
/// IP to it. Bounds-checked; tolerates compression pointers.
fn parse_dns(msg: &[u8]) -> Vec<(IpAddr, String)> {
    let mut out = Vec::new();
    if msg.len() < 12 {
        return out;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 == 0 {
        return out; // not a response (QR=0)
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    if qd == 0 || an == 0 {
        return out;
    }

    let mut pos = 12;
    // First question name (the queried domain).
    let (qname, mut p) = read_name(msg, pos);
    p += 4; // qtype + qclass
            // skip any further questions
    pos = p;
    for _ in 1..qd {
        let (_, np) = read_name(msg, pos);
        pos = np + 4;
        if pos > msg.len() {
            return out;
        }
    }
    if qname.is_empty() {
        return out;
    }

    for _ in 0..an {
        if pos + 10 > msg.len() {
            break;
        }
        let (_, after_name) = read_name(msg, pos);
        pos = after_name;
        if pos + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            break;
        }
        match (rtype, rdlen) {
            (1, 4) => {
                let ip = Ipv4Addr::new(msg[pos], msg[pos + 1], msg[pos + 2], msg[pos + 3]);
                out.push((IpAddr::V4(ip), qname.clone()));
            }
            (28, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&msg[pos..pos + 16]);
                out.push((IpAddr::V6(Ipv6Addr::from(b)), qname.clone()));
            }
            _ => {} // CNAME/NS/etc: ignore; the question name is what we attribute
        }
        pos += rdlen;
    }
    out
}

/// Decode a (possibly compressed) DNS name starting at `start`. Returns the lowercased
/// dotted name and the offset in `msg` immediately after the name *in the record stream*
/// (i.e. the position after the first pointer, when compression is used).
fn read_name(msg: &[u8], start: usize) -> (String, usize) {
    let mut labels: Vec<String> = Vec::new();
    let mut p = start;
    let mut next = start;
    let mut jumped = false;
    let mut hops = 0;
    loop {
        if p >= msg.len() {
            break;
        }
        let len = msg[p];
        if len & 0xc0 == 0xc0 {
            if p + 1 >= msg.len() {
                break;
            }
            if !jumped {
                next = p + 2;
            }
            let ptr = (((len & 0x3f) as usize) << 8) | msg[p + 1] as usize;
            p = ptr;
            jumped = true;
            hops += 1;
            if hops > 16 {
                break; // pointer loop guard
            }
            continue;
        }
        if len == 0 {
            if !jumped {
                next = p + 1;
            }
            break;
        }
        let len = len as usize;
        p += 1;
        if p + len > msg.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&msg[p..p + len]).to_string());
        p += len;
        if !jumped {
            next = p;
        }
    }
    (labels.join(".").trim_end_matches('.').to_lowercase(), next)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal DNS response for `name` → A `ip`, then assert we extract it.
    fn build_response(name: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        // question
        let q_start = m.len();
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]); // A, IN
                                            // answer: pointer to the question name
        let ptr = 0xc000 | (q_start as u16);
        m.extend_from_slice(&ptr.to_be_bytes());
        m.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        m.extend_from_slice(&[0, 0, 0, 60]); // ttl
        m.extend_from_slice(&[0, 4]); // rdlen
        m.extend_from_slice(&ip);
        m
    }

    #[test]
    fn extracts_a_record() {
        let msg = build_response("app2.makebell.com", [15, 235, 182, 11]);
        let pairs = parse_dns(&msg);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "15.235.182.11".parse::<IpAddr>().unwrap());
        assert_eq!(pairs[0].1, "app2.makebell.com");
    }

    #[test]
    fn ignores_queries() {
        let mut msg = build_response("example.com", [1, 2, 3, 4]);
        msg[2] = 0x01; // flip QR=0 (query)
        assert!(parse_dns(&msg).is_empty());
    }

    #[test]
    fn name_compression_pointer() {
        let msg = build_response("a.b.example.com", [9, 9, 9, 9]);
        let (name, _) = read_name(&msg, 12);
        assert_eq!(name, "a.b.example.com");
    }
}
