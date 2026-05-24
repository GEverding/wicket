#![cfg(unix)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixDatagram};
use tokio::sync::{Mutex, Notify};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_upgrade_handoff_successful_http_handoff() {
    run_successful_handoff_scenario(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_upgrade_handoff_successful_http_handoff_incumbent_exits() {
    run_successful_handoff_scenario(true).await;
}

async fn run_successful_handoff_scenario(assert_incumbent_exits: bool) {
    let temp_dir = TempDir::new().expect("create temp dir");
    let config_path = temp_dir.path().join("wicket.toml");
    let pid_file = temp_dir.path().join("wicket.pid");
    let upgrade_sock = temp_dir.path().join("upgrade.sock");
    let notify_sock = temp_dir.path().join("notify.sock");

    let proxy_port = free_port();
    let metrics_port = free_port();
    let backend = SlowHttpBackend::start().await;
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build client");
    let mut cleanup = ProcessGuard::new(pid_file.clone());

    fs::write(&pid_file, b"999999\n").expect("write stale pid file");
    write_valid_config(&config_path, proxy_port, backend.addr.port());

    let notify = NotifySocket::bind(&notify_sock).await;
    let mut incumbent = spawn_wicket(
        &config_path,
        &pid_file,
        &upgrade_sock,
        &notify_sock,
        metrics_port,
        false,
    );
    let incumbent_pid = incumbent.id();
    cleanup.track_incumbent(incumbent_pid);

    notify
        .wait_for_ready(incumbent_pid, Duration::from_secs(10))
        .await;
    assert_eq!(
        read_pid(&pid_file),
        incumbent_pid,
        "startup should overwrite stale pid file"
    );
    wait_for_http_body(
        &client,
        proxy_port,
        "/ready",
        "fast ok",
        Duration::from_secs(10),
    )
    .await;

    fs::write(&upgrade_sock, b"stale").expect("write stale upgrade artifact");

    let slow_request = tokio::spawn({
        let client = client.clone();
        async move {
            let response = client
                .get(format!("http://127.0.0.1:{proxy_port}/slow"))
                .header(reqwest::header::CONNECTION, "close")
                .send()
                .await
                .expect("slow request should send");
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            response.text().await.expect("slow response body")
        }
    });

    backend.wait_for_slow_request(Duration::from_secs(10)).await;

    let helper_status = run_upgrade_helper(
        &config_path,
        &pid_file,
        &upgrade_sock,
        &notify_sock,
        Duration::from_secs(15),
    )
    .await;
    assert!(
        helper_status.success(),
        "upgrade helper should succeed: {helper_status}"
    );

    let replacement_pid = read_pid(&pid_file);
    assert_ne!(
        replacement_pid, incumbent_pid,
        "pid file should switch to replacement pid"
    );
    cleanup.track_pid(replacement_pid);

    notify
        .wait_for_ready(replacement_pid, Duration::from_secs(10))
        .await;

    let slow_body = slow_request.await.expect("join slow request task");
    assert_eq!(
        slow_body, "slow ok",
        "in-flight request should finish cleanly"
    );

    wait_for_http_body(
        &client,
        proxy_port,
        "/after",
        "fast ok",
        Duration::from_secs(10),
    )
    .await;

    if assert_incumbent_exits {
        let incumbent_status = wait_for_child_exit(&mut incumbent, Duration::from_secs(30))
            .await
            .expect("incumbent should exit after handoff");
        assert!(
            incumbent_status.success() || incumbent_status.code().is_none(),
            "incumbent should exit cleanly, got {incumbent_status}"
        );
    } else if incumbent.try_wait().expect("poll incumbent exit").is_none() {
        terminate_child(&mut incumbent);
        let _ = wait_for_child_exit(&mut incumbent, Duration::from_secs(10)).await;
    }

    terminate_pid(replacement_pid);
    cleanup.disarm();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_upgrade_handoff_invalid_replacement_config_keeps_incumbent_serving() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let config_path = temp_dir.path().join("wicket.toml");
    let pid_file = temp_dir.path().join("wicket.pid");
    let upgrade_sock = temp_dir.path().join("upgrade.sock");
    let notify_sock = temp_dir.path().join("notify.sock");

    let proxy_port = free_port();
    let metrics_port = free_port();
    let backend = SlowHttpBackend::start().await;
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build client");
    let mut cleanup = ProcessGuard::new(pid_file.clone());

    write_valid_config(&config_path, proxy_port, backend.addr.port());

    let notify = NotifySocket::bind(&notify_sock).await;
    let mut incumbent = spawn_wicket(
        &config_path,
        &pid_file,
        &upgrade_sock,
        &notify_sock,
        metrics_port,
        false,
    );
    let incumbent_pid = incumbent.id();
    cleanup.track_incumbent(incumbent_pid);

    notify
        .wait_for_ready(incumbent_pid, Duration::from_secs(10))
        .await;
    wait_for_http_body(
        &client,
        proxy_port,
        "/before",
        "fast ok",
        Duration::from_secs(10),
    )
    .await;

    fs::write(&config_path, b"this is not valid toml = [").expect("write broken config");

    let helper_status = run_upgrade_helper(
        &config_path,
        &pid_file,
        &upgrade_sock,
        &notify_sock,
        Duration::from_secs(15),
    )
    .await;
    assert!(
        !helper_status.success(),
        "upgrade helper should fail for invalid replacement config"
    );

    wait_for_http_body(
        &client,
        proxy_port,
        "/after",
        "fast ok",
        Duration::from_secs(10),
    )
    .await;
    assert_eq!(
        read_pid(&pid_file),
        incumbent_pid,
        "incumbent pid should remain authoritative after failed upgrade"
    );

    terminate_child(&mut incumbent);
    let _ = wait_for_child_exit(&mut incumbent, Duration::from_secs(10)).await;
    cleanup.disarm();
}

struct ProcessGuard {
    pid_file: PathBuf,
    tracked_pids: Vec<u32>,
    armed: bool,
}

impl ProcessGuard {
    fn new(pid_file: PathBuf) -> Self {
        Self {
            pid_file,
            tracked_pids: Vec::new(),
            armed: true,
        }
    }

    fn track_incumbent(&mut self, pid: u32) {
        self.track_pid(pid);
    }

    fn track_pid(&mut self, pid: u32) {
        if !self.tracked_pids.contains(&pid) {
            self.tracked_pids.push(pid);
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        if let Ok(contents) = fs::read_to_string(&self.pid_file) {
            if let Ok(pid) = contents.trim().parse::<u32>() {
                self.track_pid(pid);
            }
        }

        for pid in &self.tracked_pids {
            terminate_pid(*pid);
        }
    }
}

struct SlowHttpBackend {
    addr: std::net::SocketAddr,
    slow_requests: Arc<AtomicUsize>,
    slow_request_notify: Arc<Notify>,
    _task: tokio::task::JoinHandle<()>,
}

impl SlowHttpBackend {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind slow backend");
        let addr = listener.local_addr().expect("backend local addr");
        let slow_requests = Arc::new(AtomicUsize::new(0));
        let slow_request_notify = Arc::new(Notify::new());

        let task = tokio::spawn({
            let slow_requests = Arc::clone(&slow_requests);
            let slow_request_notify = Arc::clone(&slow_request_notify);
            async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(connection) => connection,
                        Err(_) => break,
                    };

                    let slow_requests = Arc::clone(&slow_requests);
                    let slow_request_notify = Arc::clone(&slow_request_notify);

                    tokio::spawn(async move {
                        let (reader, mut writer) = stream.into_split();
                        let mut reader = BufReader::new(reader);

                        let mut request_line = String::new();
                        if reader.read_line(&mut request_line).await.is_err() {
                            return;
                        }

                        let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
                        if parts.len() < 2 {
                            return;
                        }
                        let path = parts[1];

                        loop {
                            let mut line = String::new();
                            if reader.read_line(&mut line).await.is_err() {
                                return;
                            }
                            if line.trim().is_empty() {
                                break;
                            }
                        }

                        let body = if path == "/slow" {
                            slow_requests.fetch_add(1, Ordering::SeqCst);
                            slow_request_notify.notify_waiters();
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            "slow ok"
                        } else {
                            "fast ok"
                        };

                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = writer.write_all(response.as_bytes()).await;
                        let _ = writer.flush().await;
                    });
                }
            }
        });

        Self {
            addr,
            slow_requests,
            slow_request_notify,
            _task: task,
        }
    }

    async fn wait_for_slow_request(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if self.slow_requests.load(Ordering::SeqCst) > 0 {
                return;
            }
            let now = Instant::now();
            assert!(now < deadline, "timed out waiting for slow backend request");
            tokio::time::timeout(deadline - now, self.slow_request_notify.notified())
                .await
                .expect("wait for slow request notification");
        }
    }
}

struct NotifySocket {
    socket: UnixDatagram,
    messages: Arc<Mutex<Vec<String>>>,
}

impl NotifySocket {
    async fn bind(path: &Path) -> Self {
        if path.exists() {
            fs::remove_file(path).expect("remove stale notify socket");
        }

        let socket = UnixDatagram::bind(path).expect("bind notify socket");
        Self {
            socket,
            messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn wait_for_ready(&self, pid: u32, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let messages = self.messages.lock().await;
                if messages
                    .iter()
                    .any(|message| is_ready_for_pid(message, pid))
                {
                    return;
                }
            }

            let now = Instant::now();
            assert!(
                now < deadline,
                "timed out waiting for READY=1 for pid {pid}"
            );

            let mut buffer = [0_u8; 1024];
            let received = tokio::time::timeout(deadline - now, self.socket.recv(&mut buffer))
                .await
                .expect("wait for notify datagram")
                .expect("receive notify datagram");
            let message = String::from_utf8_lossy(&buffer[..received]).into_owned();
            self.messages.lock().await.push(message);
        }
    }
}

fn is_ready_for_pid(message: &str, pid: u32) -> bool {
    let ready = message.lines().any(|line| line == "READY=1");
    let mainpid = message
        .lines()
        .find_map(|line| line.strip_prefix("MAINPID="))
        .and_then(|value| value.parse::<u32>().ok());

    ready && mainpid == Some(pid)
}

fn spawn_wicket(
    config_path: &Path,
    pid_file: &Path,
    upgrade_sock: &Path,
    notify_sock: &Path,
    metrics_port: u16,
    upgrade: bool,
) -> Child {
    let mut command = Command::new(wicket_binary());
    command
        .arg("--config")
        .arg(config_path)
        .arg("--pid-file")
        .arg(pid_file)
        .arg("--upgrade-sock")
        .arg(upgrade_sock)
        .arg("--metrics-addr")
        .arg(format!("127.0.0.1:{metrics_port}"))
        .env("NOTIFY_SOCKET", notify_sock)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if upgrade {
        command.arg("--upgrade");
    }

    command.spawn().expect("spawn wicket")
}

async fn run_upgrade_helper(
    config_path: &Path,
    pid_file: &Path,
    upgrade_sock: &Path,
    notify_sock: &Path,
    timeout: Duration,
) -> ExitStatus {
    let script = upgrade_script();
    let wicket_bin = wicket_binary();
    let config_path = config_path.to_path_buf();
    let pid_file = pid_file.to_path_buf();
    let upgrade_sock = upgrade_sock.to_path_buf();
    let notify_sock = notify_sock.to_path_buf();

    tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || {
            Command::new("sh")
                .arg(script)
                .arg(wicket_bin)
                .arg("--config")
                .arg(config_path)
                .arg("--pid-file")
                .arg(pid_file)
                .arg("--upgrade-sock")
                .arg(upgrade_sock)
                .env("NOTIFY_SOCKET", notify_sock)
                .env("WICKET_UPGRADE_TIMEOUT_SECONDS", "10")
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .expect("run upgrade helper")
        }),
    )
    .await
    .expect("upgrade helper timeout")
    .expect("join upgrade helper task")
}

async fn wait_for_http_body(
    client: &reqwest::Client,
    port: u16,
    path: &str,
    expected_body: &str,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    let url = format!("http://127.0.0.1:{port}{path}");

    loop {
        match client
            .get(&url)
            .header(reqwest::header::CONNECTION, "close")
            .send()
            .await
        {
            Ok(response) if response.status() == reqwest::StatusCode::OK => {
                let body = response.text().await.expect("read response body");
                assert_eq!(body, expected_body, "unexpected body from {url}");
                return;
            }
            Ok(_) | Err(_) => {}
        }

        assert!(
            Instant::now() < deadline,
            "timed out waiting for {url} to serve traffic"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child did not exit",
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn terminate_child(child: &mut Child) {
    let pid = child.id();
    terminate_pid(pid);
}

fn terminate_pid(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
}

fn read_pid(path: &Path) -> u32 {
    fs::read_to_string(path)
        .expect("read pid file")
        .trim()
        .parse()
        .expect("parse pid file")
}

fn write_valid_config(path: &Path, proxy_port: u16, backend_port: u16) {
    let config = format!(
        r#"
[server]
listen = "127.0.0.1:{proxy_port}"
workers = 1
json_logs = false
log_level = "info"
shutdown_timeout = 5

[upstreams.backend]
backends = ["127.0.0.1:{backend_port}"]

[[routes]]
name = "default"
upstream = "backend"
[routes.match]
path_prefix = "/"
"#
    );

    fs::write(path, config).expect("write config file");
}

fn wicket_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wicket"))
}

fn upgrade_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/systemd/wicket-upgrade")
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind for free port");
    listener.local_addr().expect("local addr").port()
}
