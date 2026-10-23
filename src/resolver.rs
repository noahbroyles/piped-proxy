use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// DNS resolver for the upstream client that refuses to connect allowed domains to non-public
// addresses.
//
// The domain allowlist only checks hostnames, so without this a subdomain of an allowed domain
// that resolves to e.g. 127.0.0.1, 10.0.0.0/8 or 169.254.169.254 (cloud metadata) would make the
// proxy connect to internal services and return their responses to the client. The connector
// uses exactly the addresses returned here, so DNS rebinding between a check and the connection
// is not possible either.
//
// Only names on the domain allowlist are filtered. Every upstream request and followed redirect
// has already been checked against the allowlist, so any other name looked up here was configured
// by the operator: the PROXY (or HTTP_PROXY / HTTPS_PROXY / ALL_PROXY) host, which may
// legitimately live on a private network.
//
// HTTP and socks5h proxies resolve the upstream host themselves, so this filter only applies to
// direct connections and socks5 proxies.
pub struct PublicOnlyResolver;

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();

        Box::pin(async move {
            // port 0 is replaced with the default port of the URL's scheme by reqwest
            let addrs = tokio::net::lookup_host((host.as_str(), 0)).await?;

            if !crate::is_host_allowed(&host) {
                return Ok(Box::new(addrs.collect::<Vec<_>>().into_iter()) as Addrs);
            }

            let addrs: Vec<SocketAddr> = addrs.filter(|addr| is_public_ip(addr.ip())).collect();

            if addrs.is_empty() {
                return Err(format!("{} does not resolve to a public IP address", host).into());
            }

            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

// Whether an address is publicly routable, i.e. not loopback, private, link-local, shared,
// multicast, reserved or documentation space. IPv6 addresses that embed an IPv4 address
// (IPv4-mapped, NAT64, 6to4) are judged by that IPv4 address.
fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();

    let non_public = a == 0 // 0.0.0.0/8 "this network"
        || ip.is_private() // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || ip.is_loopback() // 127.0.0.0/8
        || ip.is_link_local() // 169.254.0.0/16, includes cloud metadata endpoints
        || (a == 100 && (b & 0b1100_0000) == 64) // 100.64.0.0/10 shared address space (CGNAT)
        || (a == 192 && b == 0 && c == 0) // 192.0.0.0/24 IETF protocol assignments
        || ip.is_documentation() // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        || (a == 198 && (b & 0b1111_1110) == 18) // 198.18.0.0/15 benchmarking
        || a >= 224; // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved, 255.255.255.255 broadcast

    !non_public
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();

    // ::ffff:0:0/96 IPv4-mapped
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(ipv4);
    }

    // 64:ff9b::/96 NAT64, the IPv4 address is in the last 32 bits
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return is_public_ipv4(ipv4_from_segments(segments[6], segments[7]));
    }

    // 2002::/16 6to4, the IPv4 address is in the 32 bits after the prefix
    if segments[0] == 0x2002 {
        return is_public_ipv4(ipv4_from_segments(segments[1], segments[2]));
    }

    let non_public = segments[..6] == [0; 6] // ::/96 unspecified, loopback, IPv4-compatible
        || segments[..3] == [0x64, 0xff9b, 1] // 64:ff9b:1::/48 local-use NAT64
        || segments[..4] == [0x100, 0, 0, 0] // 100::/64 discard-only
        || segments[..2] == [0x2001, 0] // 2001::/32 Teredo
        || segments[..2] == [0x2001, 0xdb8] // 2001:db8::/32 documentation
        || (segments[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (segments[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (segments[0] & 0xffc0) == 0xfec0 // fec0::/10 site-local (deprecated)
        || (segments[0] & 0xff00) == 0xff00; // ff00::/8 multicast

    !non_public
}

fn ipv4_from_segments(high: u16, low: u16) -> Ipv4Addr {
    Ipv4Addr::from(((high as u32) << 16) | low as u32)
}
