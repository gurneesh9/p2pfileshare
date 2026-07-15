pub mod dht;
pub mod lan_broadcast;
pub mod lan_multicast;
pub mod mdns;
pub mod presence;
pub mod share_code;

pub use dht::DhtLayer;
pub use share_code::{generate_share_code, to_infohash, to_recv_infohash};

// ── Network interface helpers ──────────────────────────────────────────────────

use std::net::{IpAddr, Ipv4Addr};

/// Returns the IPv4 address of the local WiFi interface.
///
/// On real iPhones, the default-route trick (`connect("8.8.8.8")`) returns the
/// *cellular* IP when cellular data is active, which causes multicast sends to
/// fail with EHOSTUNREACH.  On iOS, WiFi is always `en0`, so we enumerate
/// interface addresses directly.  On all other platforms the connect trick is
/// used as before.
pub(super) fn local_wifi_ip() -> Option<Ipv4Addr> {
    #[cfg(target_os = "ios")]
    if let Some(ip) = en0_ipv4() {
        return Some(ip);
    }

    // Fallback: connect-without-send finds the local IP for the default route.
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

/// Returns the IPv4 address assigned to `en0` (the WiFi interface on iOS).
#[cfg(target_os = "ios")]
fn en0_ipv4() -> Option<Ipv4Addr> {
    use std::ffi::CStr;
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return None;
        }
        let mut result = None;
        let mut ifa = ifap;
        while !ifa.is_null() {
            let ifa_ref = &*ifa;
            if !ifa_ref.ifa_name.is_null() && !ifa_ref.ifa_addr.is_null() {
                let name = CStr::from_ptr(ifa_ref.ifa_name).to_str().unwrap_or("");
                let sa = &*ifa_ref.ifa_addr;
                if name == "en0" && sa.sa_family as libc::c_int == libc::AF_INET {
                    let sin = &*(ifa_ref.ifa_addr as *const libc::sockaddr_in);
                    // s_addr is in network byte order; to_ne_bytes() reads the
                    // raw memory bytes which are already octet order for Ipv4Addr.
                    result = Some(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()));
                    break;
                }
            }
            ifa = (*ifa).ifa_next;
        }
        libc::freeifaddrs(ifap);
        result
    }
}
