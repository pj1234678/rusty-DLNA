//! Regression for finding [E]: slow-read drip (no write timeout).
//!
//! Old code did unbounded `write_all(headers)` + `copy(file -> socket)` with
//! no timeout, so a client that finished headers then read nothing pinned one
//! Semaphore permit + task + file handle forever (1000 drips = DoS).
//! Fixed code (`WRITE_TIMEOUT` + chunked body send in `handle_get_request`)
//! must reap a stalled drip in ~5s and recycle its permit.
//!
//! Test: GET a big file, read headers only, read nothing for 9s, then drain:
//! the server must have closed (EOF) — unfixed code would still hold the
//! connection open (drain blocks, no EOF). A normal GET afterwards must still
//! serve (permit freed, server alive).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const TEST_IP: &str = "127.0.0.1";
const MULTICAST_IP: &str = "239.255.255.250";
const TCP_PORT: u16 = 8200;
// 8 MiB >> socket buffers, so copy() cannot finish without client reads.
const BIG_SIZE: usize = 8 * 1024 * 1024;

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

async fn send_raw(req: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .expect("connect");
    stream.write_all(req).await.expect("write");
    let mut out = Vec::new();
    let mut buf = vec![0u8; 32768];
    let _ = timeout(Duration::from_secs(10), async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if let Some(p) = find_double_crlf(&out) {
                        // File GETs carry Content-Length; read full body.
                        let hdr = &out[..p];
                        let lower: Vec<u8> =
                            hdr.iter().map(|b| b.to_ascii_lowercase()).collect();
                        let needle = b"content-length:";
                        if let Some(pos) =
                            lower.windows(needle.len()).position(|w| w == needle)
                        {
                            let mut i = pos + needle.len();
                            while i < hdr.len() && (hdr[i] == b' ' || hdr[i] == b'\t') {
                                i += 1;
                            }
                            let mut j = i;
                            while j < hdr.len() && hdr[j].is_ascii_digit() {
                                j += 1;
                            }
                            if let Ok(cl) = std::str::from_utf8(&hdr[i..j])
                                .unwrap_or("0")
                                .parse::<usize>()
                            {
                                if out.len() >= p + 4 + cl {
                                    break;
                                }
                            }
                        } else {
                            break;
                        }
                    }
                    if out.len() > 20_000_000 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
    .await;
    out
}

#[tokio::test]
async fn slow_drip_is_reaped_and_permits_freed() {
    if TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_slowread_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    let root_bytes: Vec<u8> = b"0123456789ABCDEF".repeat(64); // 1 KiB
    std::fs::write(media.join("root.mp4"), &root_bytes).unwrap();
    std::fs::write(media.join("big.bin"), vec![0xABu8; BIG_SIZE]).unwrap();

    let bin = env!("CARGO_BIN_EXE_RustyDLNA7");
    let mut child = tokio::process::Command::new(bin)
        .arg(TEST_IP)
        .arg(media.to_str().unwrap())
        .arg(MULTICAST_IP)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn server");
    wait_for_tcp().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 1. Fast path unaffected: small file streams exactly.
    let get_root = format!("GET /root.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes();
    let r = send_raw(&get_root).await;
    assert!(r.starts_with(b"HTTP/1.1 206 Partial Content"), "baseline 206");
    assert!(r.ends_with(&root_bytes), "baseline bytes");

    // 2. Drip: headers OK, then ZERO body reads for 9s (> WRITE_TIMEOUT 5s).
    let mut drip = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .expect("drip connect");
    drip
        .write_all(format!("GET /big.bin HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).as_bytes())
        .await
        .expect("drip write");
    let mut buf = vec![0u8; 65536];
    let mut head = Vec::new();
    timeout(Duration::from_secs(5), async {
        loop {
            match drip.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    head.extend_from_slice(&buf[..n]);
                    if find_double_crlf(&head).is_some() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
    .await
    .expect("headers must arrive");
    assert!(head.starts_with(b"HTTP/1.1 206 Partial Content"), "drip headers 206");
    // Hold: read nothing. A fixed server kills the stalled copy in ~5s.
    tokio::time::sleep(Duration::from_secs(9)).await;

    // Drain: fixed server has closed => buffered bytes then EOF within seconds.
    // Unfixed server still holds => drain blocks (no EOF) => timeout => fail.
    let mut saw_eof = false;
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < drain_deadline {
        let left = drain_deadline.saturating_duration_since(tokio::time::Instant::now());
        match timeout(left.min(Duration::from_secs(3)), drip.read(&mut buf)).await {
            Ok(Ok(0)) => {
                saw_eof = true;
                break;
            }
            Ok(Ok(_)) => continue, // buffered body bytes; keep draining to EOF
            _ => break,            // timeout/error: still open => unfixed
        }
    }
    assert!(
        saw_eof,
        "drip must be reaped (EOF) ~5s after stalling; still open => write-timeout missing"
    );

    // 3. Permit recycled: server alive and serving after reaping the drip.
    let r2 = send_raw(&get_root).await;
    assert!(r2.starts_with(b"HTTP/1.1 206 Partial Content"), "alive after drip");
    assert!(r2.ends_with(&root_bytes), "bytes after drip");

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
    tokio::time::sleep(Duration::from_millis(500)).await; // TIME_WAIT drain
}
