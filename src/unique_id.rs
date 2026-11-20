//! A per machine identifier (the `server_id` of the JSON audit logs and the
//! `ModSec-unique-id` header of the HTTPS client): the SHA-1 hex digest of
//! the first ethernet MAC address followed by the machine name.

use std::sync::OnceLock;

use crate::utils::hash::sha1_hex;

pub const MAX_MACHINE_NAME_SIZE: usize = 256;

pub struct UniqueId;

impl UniqueId {
    /// The identifier, computed once per process.
    pub fn unique_id() -> &'static str {
        static UNIQUE_ID: OnceLock<String> = OnceLock::new();
        UNIQUE_ID.get_or_init(Self::fill_unique_id)
    }

    /// Computes the identifier: the SHA-1 hex digest of the MAC address
    /// followed by the machine name.
    fn fill_unique_id() -> String {
        let mac_address = Self::ethernet_mac_address();
        let name = Self::machine_name();

        let data = mac_address + &name;

        sha1_hex(data.as_bytes())
    }

    /// The machine name: the `uname` node name.
    // Based on:
    // http://stackoverflow.com/questions/16858782/how-to-obtain-almost-unique-system-identifier-in-a-cross-platform-way
    pub fn machine_name() -> String {
        let uname = rustix::system::uname();
        let name = uname.nodename().to_bytes();
        // snprintf(machine_name, MAX_MACHINE_NAME_SIZE - 1, "%s", ...)
        let max = MAX_MACHINE_NAME_SIZE - 2;
        String::from_utf8_lossy(&name[..name.len().min(max)]).into_owned()
    }

    /// The hardware address of the first interface with an IPv4 address
    /// whose hardware address does not start with three zero bytes, as
    /// `xx:xx:xx:xx:xx:xx`, or an empty string.
    ///
    /// The interfaces are taken from `getifaddrs`, in the order it gives
    /// them. Those with an IPv4 address are the ones the `SIOCGIFCONF`
    /// ioctl lists, in the same order.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn ethernet_mac_address() -> String {
        let Ok(addrs) = nix::ifaddrs::getifaddrs() else {
            return String::new();
        };
        let addrs: Vec<_> = addrs.collect();
        let hardware = |name: &str| {
            addrs.iter().filter(|a| a.interface_name == name).find_map(|a| a.address.as_ref()?.as_link_addr()?.addr())
        };
        addrs
            .iter()
            .filter(|a| a.address.as_ref().is_some_and(|ad| ad.as_sockaddr_in().is_some()))
            .filter_map(|a| hardware(&a.interface_name))
            .find(|d| d[..3] != [0, 0, 0])
            .map(|d| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", d[0], d[1], d[2], d[3], d[4], d[5]))
            .unwrap_or_default()
    }

    /// The MAC address on the other platforms: none is looked up, and
    /// the string is empty.
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
        let expected = sha1_hex((UniqueId::ethernet_mac_address() + &UniqueId::machine_name()).as_bytes());
        assert_eq!(a, expected);
    }

    #[test]
    fn mac_address_format() {
        let mac = UniqueId::ethernet_mac_address();
        if !mac.is_empty() {
            // `xx:xx:xx:xx:xx:xx`
            assert_eq!(mac.len(), 17);
            assert_eq!(mac.matches(':').count(), 5);
        }
    }
}
