//! Regression for header-read slowloris (L3 [H]).
//!
//! `handle_client` used a per-read 5s timeout that reset on EVERY byte, so a
//! 1B/4s drip (no `\r\n\r\n`, < 4096B) held one Semaphore permit + task
//! forever — for GET, POST or garbage, pre-routing. Fixed with a total header
//! deadline: headers must complete within 5s of connect regardless of drip
//! rate. Also locks that slow POST bodies hold nothing (server never reads
//! past headers end).
//!
//! Tests (sequential, same ports as the other suites):
//! 1. header_drip_reaped_despite_keepalives: partial headers + 1B/2s
//!    keepalives must be reaped (~5s total) — unfixed code holds them 12s+.
//!    Afterwards a normal GET must still serve (permit recycled).
//! 2. post_body_never_waited_for: POST headers declaring Content-Length
//!    50000 with (almost) no body must get a reply/close in <3s instead of
//!    waiting for the declared body.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const TEST_IP: &str = "127.0.0.1";
const MULTICAST_IP: &str = "239.255.255.250";
const TCP_PORT: u16 = 8200;

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

async fn wait_for_tcp() {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match timeout(
            Duration::from_millis(300),
            TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT)),
        )
        .await
        {
            Ok(Ok(_)) => return,
            _ => {
                if tokio::time::Instant::now() > deadline {
                    panic!("server never became reachable");
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

async fn spawn_server(media: &std::path::Path) -> tokio::process::Child {
    let bin = env!("CARGO_BIN_EXE_RustyDLNA7");
    tokio::process::Command::new(bin)
        .arg(TEST_IP)
        .arg(media.to_str().unwrap())
        .arg(MULTICAST_IP)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn server")
}

fn media_dir(tag: &str) -> std::path::PathBuf {    std::env::temp_dir().join(format!(
        "rustydlna_loris_{}_{}_{}",
        std::process::id(),
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

// Serializes the two port-binding tests in this file (server hardcodes
// :8200/:1900, so two instances can never coexist).
static SERVER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[tokio::test]
async fn header_drip_reaped_despite_keepalives() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = media_dir("drip");
    std::fs::create_dir_all(&media).unwrap();
    let root_bytes: Vec<u8> = b"0123456789ABCDEF".repeat(64);
    std::fs::write(media.join("root.mp4"), &root_bytes).unwrap();
    let mut child = spawn_server(&media).await;
    wait_for_tcp().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drip: partial headers, then 1B/2s keepalives (each resets the OLD
    // per-read timeout; only the total deadline can reap this).
    let mut drip = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .expect("drip connect");
    drip
        .write_all(b"GET /root.mp4 HTTP/1.1\r\nHost: x\r\nX-P: ")
        .await
        .expect("drip partial");
    // Keepalive for 9s total (> 5s total deadline). Unfixed server holds.
    let mut closed_early = false;
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if drip.write_all(b"A").await.is_err() {
            closed_early = true;
            break;
        }
        // Non-blocking peek: server must send nothing before headers complete.
        let mut one = [0u8; 1];
        match timeout(Duration::from_millis(200), drip.read(&mut one)).await {
            Ok(Ok(0)) => {
                closed_early = true;
                break;
            }
            Ok(Ok(_)) => panic!("drip got a reply before completing headers"),
            _ => {} // timeout => still open, keep dripping
        }
    }
    // After ~8-9s the fixed server MUST have closed (deadline 5s). Drain to
    // EOF with a bounded wait; unfixed code blocks here (no EOF) => fail.
    let mut saw_eof = closed_early;
    if !saw_eof {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
        let mut buf = vec![0u8; 4096];
        while tokio::time::Instant::now() < deadline {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match timeout(left.min(Duration::from_secs(2)), drip.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    saw_eof = true;
                    break;
                }
                Ok(Ok(_)) => panic!("drip got reply bytes without completing headers"),
                _ => break, // timeout while open => unfixed
            }
        }
    }
    assert!(
        saw_eof,
        "header drip with keepalives must be reaped by the total header deadline"
    );

    // Permit recycled: server alive and serving.
    let mut c = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .expect("reconnect");
    c.write_all(format!("GET /root.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 32768];
    let _ = timeout(Duration::from_secs(5), async {
        loop {
            match c.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if find_double_crlf(&out).is_some() && out.len() > 512 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
    .await;
    assert!(out.starts_with(b"HTTP/1.1 206 Partial Content"), "alive after drip");
    assert!(out.ends_with(&root_bytes), "bytes after drip");

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
async fn post_body_never_waited_for() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = media_dir("body");
    std::fs::create_dir_all(&media).unwrap();
    std::fs::write(media.join("root.mp4"), b"0123456789ABCDEF").unwrap();
    let mut child = spawn_server(&media).await;
    wait_for_tcp().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Declare a 50000B body, send (almost) none of it. The server must answer
    // or close from headers alone in <3s — never wait for the declared body.
    let mut s = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .expect("connect");
    let partial =
        format!("POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: 50000\r\nContent-Type: text/xml\r\n\r\n<Body>", TEST_IP);
    s.write_all(partial.as_bytes()).await.unwrap();
    let t0 = tokio::time::Instant::now();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 32768];
    let _ = timeout(Duration::from_secs(3), async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if find_double_crlf(&out).is_some() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
    .await;
    let dt = t0.elapsed();
    // Either a Browse reply (unknown-id body still parses ObjectID-less =>
    // silent close) or a silent close: both prove no body wait, fast.
    assert!(
        dt < Duration::from_secs(3),
        "server waited for declared POST body ({:?})",
        dt
    );

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
    tokio::time::sleep(Duration::from_millis(500)).await;
}
