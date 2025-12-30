//! Source IP address pool management.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Manages a pool of source IP addresses for outbound connections.
///
/// Uses round-robin selection to cycle through available IPs, preventing
/// ephemeral port exhaustion at high connection counts.
#[derive(Debug)]
pub struct SourceIpPool {
    ips: Vec<IpAddr>,
    counter: AtomicUsize,
}

impl SourceIpPool {
    /// Create a new source IP pool.
    ///
    /// # Panics
    /// Panics if `ips` is empty.
    pub fn new(ips: Vec<IpAddr>) -> Self {
        assert!(!ips.is_empty(), "SourceIpPool cannot be empty");
        Self {
            ips,
            counter: AtomicUsize::new(0),
        }
    }

    /// Get next IP address using round-robin selection.
    pub fn next_ip(&self) -> IpAddr {
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.ips.len();
        self.ips[idx]
    }

    /// Number of IPs in pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ips.len()
    }

    /// Check if pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty()
    }
}

/// Configure socket for outbound connection with source IP binding.
///
/// On Linux, sets `IP_BIND_ADDRESS_NO_PORT` to delay port allocation until connect(),
/// allowing the kernel to choose a port that doesn't conflict with the destination.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // Will be used by proxy implementation
pub fn configure_outbound_socket(
    socket: &socket2::Socket,
    source_ip: IpAddr,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    // IP_BIND_ADDRESS_NO_PORT = 24 on Linux
    const IP_BIND_ADDRESS_NO_PORT: libc::c_int = 24;

    unsafe {
        let optval: libc::c_int = 1;
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            IP_BIND_ADDRESS_NO_PORT,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Bind to source IP with port 0
    let bind_addr = SocketAddr::new(source_ip, 0);
    socket.bind(&bind_addr.into())?;

    Ok(())
}

/// Configure socket for outbound connection with source IP binding.
///
/// Fallback implementation for non-Linux platforms. Binds to source IP without
/// `IP_BIND_ADDRESS_NO_PORT` optimization.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)] // Will be used by proxy implementation
pub fn configure_outbound_socket(
    socket: &socket2::Socket,
    source_ip: IpAddr,
) -> std::io::Result<()> {
    // Fallback: just bind to source IP (no IP_BIND_ADDRESS_NO_PORT)
    let bind_addr = SocketAddr::new(source_ip, 0);
    socket.bind(&bind_addr.into())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_round_robin() {
        let pool = SourceIpPool::new(vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)),
        ]);

        let ip1 = pool.next_ip();
        let ip2 = pool.next_ip();
        let ip3 = pool.next_ip();
        let ip4 = pool.next_ip(); // wraps around

        assert_ne!(ip1, ip2);
        assert_ne!(ip2, ip3);
        assert_eq!(ip1, ip4); // wrapped
    }

    #[test]
    fn test_round_robin_distribution() {
        // Verify that round-robin distributes evenly
        let pool = SourceIpPool::new(vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        ]);

        let mut counts = HashMap::new();
        for _ in 0..300 {
            let ip = pool.next_ip();
            *counts.entry(ip).or_insert(0) += 1;
        }

        // Each IP should be selected exactly 100 times
        assert_eq!(counts.len(), 3);
        for count in counts.values() {
            assert_eq!(*count, 100);
        }
    }

    #[test]
    fn test_single_ip() {
        let pool = SourceIpPool::new(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);

        assert_eq!(pool.next_ip(), pool.next_ip());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_ipv6_pool() {
        let pool = SourceIpPool::new(vec![
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        ]);

        let ip1 = pool.next_ip();
        let ip2 = pool.next_ip();
        let ip3 = pool.next_ip();

        assert_ne!(ip1, ip2);
        assert_eq!(ip1, ip3); // wrapped
    }

    #[test]
    fn test_mixed_ipv4_ipv6() {
        let pool = SourceIpPool::new(vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ]);

        let ip1 = pool.next_ip();
        let _ip2 = pool.next_ip();
        let _ip3 = pool.next_ip();
        let ip4 = pool.next_ip();

        assert_eq!(pool.len(), 3);
        assert_eq!(ip1, ip4); // wrapped
    }

    #[test]
    fn test_len() {
        let pool = SourceIpPool::new(vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
        ]);

        assert_eq!(pool.len(), 2);
        assert!(!pool.is_empty());
    }

    #[test]
    fn test_wraparound_after_many_calls() {
        // Test that counter wraps correctly after many calls
        let pool = SourceIpPool::new(vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ]);

        // Call many times to test wraparound
        let first_ip = pool.next_ip();
        for _ in 0..9999 {
            pool.next_ip();
        }
        // After 10000 calls with 2 IPs, we should be back to the first IP
        // (10000 % 2 = 0, so we're at index 0)
        let after_many = pool.next_ip();
        assert_eq!(first_ip, after_many);
    }

    #[test]
    fn test_thread_safety() {
        // Test concurrent access from multiple threads
        let pool = Arc::new(SourceIpPool::new(vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        ]));

        let mut handles = vec![];
        for _ in 0..10 {
            let pool_clone = Arc::clone(&pool);
            let handle = thread::spawn(move || {
                let mut ips = vec![];
                for _ in 0..100 {
                    ips.push(pool_clone.next_ip());
                }
                ips
            });
            handles.push(handle);
        }

        // Collect all IPs from all threads
        let mut all_ips = vec![];
        for handle in handles {
            all_ips.extend(handle.join().unwrap());
        }

        // Should have 1000 total IPs (10 threads * 100 calls)
        assert_eq!(all_ips.len(), 1000);

        // All IPs should be from the pool
        for ip in &all_ips {
            assert!(
                *ip == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
                    || *ip == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
                    || *ip == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))
            );
        }
    }

    #[test]
    fn test_thread_safety_distribution() {
        // Verify distribution is reasonable under concurrent access
        let pool = Arc::new(SourceIpPool::new(vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        ]));

        let mut handles = vec![];
        for _ in 0..3 {
            let pool_clone = Arc::clone(&pool);
            let handle = thread::spawn(move || {
                let mut ips = vec![];
                for _ in 0..300 {
                    ips.push(pool_clone.next_ip());
                }
                ips
            });
            handles.push(handle);
        }

        let mut all_ips = vec![];
        for handle in handles {
            all_ips.extend(handle.join().unwrap());
        }

        // Count distribution
        let mut counts = HashMap::new();
        for ip in all_ips {
            *counts.entry(ip).or_insert(0) += 1;
        }

        // Each IP should be used (exact distribution may vary due to concurrency)
        assert_eq!(counts.len(), 3);
        for count in counts.values() {
            // Should be roughly 300 each, but allow some variance
            assert!(*count > 250 && *count < 350);
        }
    }

    #[test]
    #[should_panic(expected = "SourceIpPool cannot be empty")]
    fn test_empty_pool_panics() {
        SourceIpPool::new(vec![]);
    }

    #[test]
    fn test_large_pool() {
        // Test with a large number of IPs
        let mut ips = vec![];
        for i in 1..=255 {
            ips.push(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)));
        }

        let pool = SourceIpPool::new(ips);
        assert_eq!(pool.len(), 255);

        // Verify round-robin works with large pool
        let first = pool.next_ip();
        for _ in 0..254 {
            pool.next_ip();
        }
        let after_cycle = pool.next_ip();
        assert_eq!(first, after_cycle);
    }
}
