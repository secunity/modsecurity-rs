//! Port of `src/unique_id.cc`, `src/unique_id.h`.
//!
//! A per machine identifier (the `server_id` of the JSON audit logs and the
//! `ModSec-unique-id` header of the HTTPS client): the SHA-1 hex digest of
//! the first ethernet MAC address followed by the machine name.

use std::sync::OnceLock;

use sha1::{Digest, Sha1};

use crate::utils::string::string_to_hex;

pub const MAC_ADDRESS_SIZE: usize = 19;
pub const MAX_MACHINE_NAME_SIZE: usize = 256;

pub struct UniqueId;

impl UniqueId {
    /// The identifier, computed once per process.
    pub fn unique_id() -> &'static str {
        static UNIQUE_ID: OnceLock<String> = OnceLock::new();
        UNIQUE_ID.get_or_init(Self::fill_unique_id)
    }

    /// `fillUniqueId`
    fn fill_unique_id() -> String {
        let mac_address = Self::ethernet_mac_address();
        let name = Self::machine_name();

        let data = mac_address + &name;

        // `Utils::Sha1::hexdigest` (cannot fail here).
        string_to_hex(&Sha1::digest(data.as_bytes()))
    }

    /// `machineName`: the `uname` node name, or an empty string.
    // Based on:
    // http://stackoverflow.com/questions/16858782/how-to-obtain-almost-unique-system-identifier-in-a-cross-platform-way
    pub fn machine_name() -> String {
        // SAFETY: utsname is a plain C struct that uname fills in.
        let mut u: libc::utsname = unsafe { std::mem::zeroed() };
        // SAFETY: `u` is a valid, writable utsname.
        if unsafe { libc::uname(&mut u) } < 0 {
            return String::new();
        }
        let bytes: Vec<u8> = u.nodename.iter().take_while(|&&c| c != 0).map(|&c| c.to_ne_bytes()[0]).collect();
        // snprintf(machine_name, MAX_MACHINE_NAME_SIZE - 1, "%s", ...)
        let max = MAX_MACHINE_NAME_SIZE - 2;
        String::from_utf8_lossy(&bytes[..bytes.len().min(max)]).into_owned()
    }

    /// `ethernetMacAddress`: the hardware address of the first interface
    /// with a non zero one, as `xx:xx:xx:xx:xx:xx`, or an empty string.
    ///
    /// Deviation (C++ bug): the C++ loop bound mixes the byte length
    /// returned by `SIOCGIFCONF` with `ifreq` pointer arithmetic and can
    /// read past its buffer; only the returned entries are walked here.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn ethernet_mac_address() -> String {
        // SAFETY: plain socket creation.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_IP) };
        if sock < 0 {
            return String::new();
        }

        const N: usize = 128;
        // SAFETY: ifreq is a plain C struct (name + union), all zeroes is valid.
        let mut ifconfbuf: Vec<libc::ifreq> = (0..N).map(|_| unsafe { std::mem::zeroed() }).collect();
        // SAFETY: ifconf is a plain C struct, all zeroes is valid.
        let mut conf: libc::ifconf = unsafe { std::mem::zeroed() };
        conf.ifc_len = (N * std::mem::size_of::<libc::ifreq>()) as libc::c_int;
        conf.ifc_ifcu.ifcu_req = ifconfbuf.as_mut_ptr();
        // SAFETY: `conf` describes the writable buffer `ifconfbuf` of
        // `ifc_len` bytes, which outlives the call.
        if unsafe { libc::ioctl(sock, libc::SIOCGIFCONF as _, &mut conf) } != 0 {
            // SAFETY: closing the socket opened above.
            unsafe { libc::close(sock) };
            return String::new();
        }

        let count = (conf.ifc_len.max(0) as usize / std::mem::size_of::<libc::ifreq>()).min(N);
        let mut mac = String::new();
        for ifr in ifconfbuf.iter_mut().take(count) {
            // SAFETY: `ifr` is a valid ifreq naming an interface.
            if unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, ifr as *mut libc::ifreq) } != 0 {
                continue; // failed to get flags, skip it
            }

            // SAFETY: as above.
            if unsafe { libc::ioctl(sock, libc::SIOCGIFHWADDR as _, ifr as *mut libc::ifreq) } == 0 {
                // SAFETY: SIOCGIFHWADDR filled the hwaddr member of the union.
                // (`c_char` is signed or not depending on the target.)
                let d = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data }.map(|c| c.to_ne_bytes()[0]);
                if d[0] == 0 && d[1] == 0 && d[2] == 0 {
                    continue;
                }

                mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", d[0], d[1], d[2], d[3], d[4], d[5]);
                break;
            }
        }
        // SAFETY: closing the socket opened above.
        unsafe { libc::close(sock) };
        mac
    }

    /// `ethernetMacAddress` on the other platforms: as the C++ code does
    /// there (its Darwin branch can never match), no address is found.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub fn ethernet_mac_address() -> String {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_id_is_stable_sha1_hex() {
        let a = UniqueId::unique_id();
        assert_eq!(a.len(), 40);
        assert!(a.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
        assert_eq!(a, UniqueId::unique_id());
        let expected =
            string_to_hex(&Sha1::digest((UniqueId::ethernet_mac_address() + &UniqueId::machine_name()).as_bytes()));
        assert_eq!(a, expected);
    }

    #[test]
    fn mac_address_format() {
        let mac = UniqueId::ethernet_mac_address();
        if !mac.is_empty() {
            assert_eq!(mac.len(), MAC_ADDRESS_SIZE - 2);
            assert_eq!(mac.matches(':').count(), 5);
        }
    }
}
