//! Test helpers for wicket e2e tests.
//!
//! Provides:
//! - `HttpMockBackend`: A minimal HTTP/1.1 mock server
//! - `TestProxy`: Starts a real Pingora server with WicketProxy

pub mod http_backend;

pub use http_backend::HttpMockBackend;

use pingora_core::prelude::*;
use pingora_core::server::configuration::ServerConf;
use pingora_proxy::http_proxy_service;
use std::net::SocketAddr;
use wicket_config::Config;
use wicket_core::{HttpReloadHandle, WicketProxy};

/// A test harness that runs a real Pingora proxy on a background thread.
pub struct TestProxy {
    pub addr: SocketAddr,
    pub reload_handle: HttpReloadHandle,
    // The thread is leaked on drop; Pingora's run_forever() has no clean
    // shutdown API, but the thread dies with the test process.
    _thread: Option<std::thread::JoinHandle<()>>,
}

impl TestProxy {
    /// Start a proxy from a TOML config string.
    ///
    /// The proxy listens on the address specified in `[server].listen`.
    /// Use `free_port()` to pick a port before calling this.
    pub fn start(config: &Config) -> Self {
        let addr = config.server.listen;
        let wicket_proxy = WicketProxy::new(config).expect("WicketProxy::new");
        let reload_handle = wicket_proxy.reload_handle();

        let listen_str = addr.to_string();

        let thread = std::thread::spawn(move || {
            let mut pingora_conf = ServerConf::default();
            pingora_conf.threads = 1;
            pingora_conf.graceful_shutdown_timeout_seconds = Some(1);

            let mut server = Server::new_with_opt_and_conf(
                Some(Opt {
                    upgrade: false,
                    daemon: false,
                    nocapture: false,
                    test: false,
                    conf: None,
                }),
                pingora_conf,
            );

            server.bootstrap();

            let mut proxy_service = http_proxy_service(&server.configuration, wicket_proxy);
            proxy_service.add_tcp(&listen_str);

            server.add_service(proxy_service);
            server.run_forever();
        });

        // Wait for the proxy to become connectable
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if std::net::TcpStream::connect(addr).is_ok() {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("TestProxy: proxy did not become connectable within 5s");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        TestProxy {
            addr,
            reload_handle,
            _thread: Some(thread),
        }
    }
}

/// Get a free port by binding to 127.0.0.1:0.
pub fn free_port() -> u16 {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind for free port");
    listener.local_addr().expect("local addr").port()
}
