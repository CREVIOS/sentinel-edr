//! Connection→domain attribution. The TCP layer only exposes a remote IP; this cache maps
//! IP → domain so network events can carry the real hostname (and category).
//!
//! Two fill paths share one map:
//!   1. AUTHORITATIVE (eBPF tier, see ebpf.rs): parse DNS *responses* in-kernel and record each
//!      answer's IP→name with the record TTL. This is exact, process-attributed, and the
//!      industry approach (Falco/Tetragon/Cilium/Calico). Wired when running with --features ebpf.
//!   2. BEST-EFFORT (this module, always available): forward-confirmed reverse DNS (PTR then
//!      verify the name resolves back to the IP, to drop spoofed/junk PTRs). Reverse DNS has no
//!      coverage guarantee (no PTR for many IPs, CDN junk), so it's enrichment, not truth —
//!      results are cached with a positive/negative TTL and resolved on a background thread so
//!      the collector poll never blocks.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const POS_TTL: Duration = Duration::from_secs(3600); // good answer cached 1h
const NEG_TTL: Duration = Duration::from_secs(300); // "no name" cached 5m (avoid re-querying)
const MAX_ENTRIES: usize = 50_000; // hard cap so the map can't grow unbounded
const MAX_INFLIGHT: usize = 64; // bound concurrent background resolves

#[derive(Clone)]
struct Entry {
    domain: Option<String>, // None = confirmed no name (negative cache)
    at: Instant,
}

#[derive(Clone)]
pub struct DnsCache {
    map: Arc<Mutex<HashMap<IpAddr, Entry>>>,
    inflight: Arc<Mutex<HashSet<IpAddr>>>,
    /// reverse-DNS enrichment toggle (off when an authoritative eBPF feed is active)
    rdns: bool,
}

impl DnsCache {
    pub fn new(rdns_enabled: bool) -> Self {
        DnsCache {
            map: Arc::new(Mutex::new(HashMap::new())),
            inflight: Arc::new(Mutex::new(HashSet::new())),
            rdns: rdns_enabled,
        }
    }

    /// Authoritative insert (called by the eBPF DNS-response path). Overrides any cached value.
    pub fn insert(&self, ip: IpAddr, domain: String) {
        let mut m = self.map.lock().unwrap();
        if m.len() >= MAX_ENTRIES {
            m.clear(); // coarse but safe backstop under flooding
        }
        m.insert(ip, Entry { domain: Some(domain), at: Instant::now() });
    }

    /// Look up a domain for `ip`. Returns the cached name if fresh; on a miss, kicks off a
    /// bounded background reverse-DNS resolve (if enabled) and returns None for now — the next
    /// poll picks up the answer. Never blocks.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        {
            let mut m = self.map.lock().unwrap();
            if let Some(e) = m.get(&ip) {
                let ttl = if e.domain.is_some() { POS_TTL } else { NEG_TTL };
                if e.at.elapsed() < ttl {
                    return e.domain.clone();
                }
                m.remove(&ip); // expired
            }
        }
        if self.rdns && !ip.is_loopback() && is_global(ip) {
            self.spawn_resolve(ip);
        }
        None
    }

    fn spawn_resolve(&self, ip: IpAddr) {
        {
            let mut inf = self.inflight.lock().unwrap();
            if inf.contains(&ip) || inf.len() >= MAX_INFLIGHT {
                return;
            }
            inf.insert(ip);
        }
        let map = self.map.clone();
        let inflight = self.inflight.clone();
        std::thread::spawn(move || {
            let domain = forward_confirmed_rdns(ip);
            {
                let mut m = map.lock().unwrap();
                if m.len() < MAX_ENTRIES {
                    m.insert(ip, Entry { domain, at: Instant::now() });
                }
            }
            inflight.lock().unwrap().remove(&ip);
        });
    }
}

/// Forward-confirmed reverse DNS: PTR(ip) → name, then verify name resolves back to ip. Drops
/// spoofed/stale PTRs. Returns None when there's no usable name.
fn forward_confirmed_rdns(ip: IpAddr) -> Option<String> {
    let name = dns_lookup::lookup_addr(&ip).ok()?;
    let name = name.trim_end_matches('.').to_lowercase();
    if name.is_empty() || name == ip.to_string() {
        return None;
    }
    // forward-confirm: the name must resolve back to this IP
    let confirmed = dns_lookup::lookup_host(&name)
        .map(|ips| ips.into_iter().any(|a| a == ip))
        .unwrap_or(false);
    if confirmed {
        Some(name)
    } else {
        None
    }
}

/// Exclude private/link-local/CGNAT — those never have meaningful public PTRs and pointlessly
/// query the local resolver.
fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
        }
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authoritative_insert_wins() {
        let c = DnsCache::new(false);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(c.lookup(ip), None); // rdns disabled, no entry
        c.insert(ip, "evil.test".into());
        assert_eq!(c.lookup(ip).as_deref(), Some("evil.test"));
    }

    #[test]
    fn private_ips_not_resolved() {
        assert!(!is_global("10.0.0.5".parse().unwrap()));
        assert!(!is_global("192.168.1.1".parse().unwrap()));
        assert!(!is_global("127.0.0.1".parse().unwrap()));
        assert!(!is_global("100.64.0.1".parse().unwrap())); // CGNAT
        assert!(is_global("8.8.8.8".parse().unwrap()));
    }

    // Live network test (run: cargo test --release live_ -- --ignored --nocapture).
    #[test]
    #[ignore]
    fn live_forward_confirmed_rdns() {
        // 8.8.8.8 has a forward-confirmed PTR → dns.google
        let d = forward_confirmed_rdns("8.8.8.8".parse().unwrap());
        println!("8.8.8.8 -> {:?}", d);
        assert_eq!(d.as_deref(), Some("dns.google"));
        // 1.1.1.1 -> one.one.one.one
        println!("1.1.1.1 -> {:?}", forward_confirmed_rdns("1.1.1.1".parse().unwrap()));
    }

    #[test]
    #[ignore]
    fn live_cache_populates_async() {
        let c = DnsCache::new(true);
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(c.lookup(ip), None); // miss → spawns background resolve
        // poll the cache for up to 3s for the background resolve to land
        let mut got = None;
        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if let Some(d) = c.lookup(ip) {
                got = Some(d);
                break;
            }
        }
        println!("async resolved 8.8.8.8 -> {:?}", got);
        assert_eq!(got.as_deref(), Some("dns.google"));
    }

    #[test]
    fn negative_cache_holds() {
        // rdns disabled → lookup of an unknown global IP stays None without spawning
        let c = DnsCache::new(false);
        assert_eq!(c.lookup("8.8.8.8".parse().unwrap()), None);
    }
}
