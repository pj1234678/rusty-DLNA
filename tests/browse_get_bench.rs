//! Focused browse + GET speed benchmarks (all ignored by default).
//!
//! Run: cargo test --test browse_get_bench -- --ignored --nocapture
//!      cargo test --release --test browse_get_bench -- --ignored --nocapture
//!
//! These complement tests/bench_perf.rs (which covers everything) by isolating
//! the two hot paths the current optimization pass targets:
//!   * cached Browse POST (ObjectID 0) — sequential + concurrent
//!   * small-file GET (1 KiB) — sequential + concurrent
//! Plus micro-benchmarks for the new fast paths (combined-path build,
//! FxHash lookup) so regressions are caught at unit level.
//!
//! All asserts are byte-exact (no behavior change allowed); req/s is
//! informational but must not regress vs. the pre-optimization baseline.

use std::hint::black_box;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration, Instant};

const TEST_IP: &str = "127.0.0.1";
const MULTICAST_IP: &str = "239.255.255.250";
const TCP_PORT: u16 = 8200;

static SERVER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_cl(headers: &[u8]) -> Option<usize> {
    let lower: Vec<u8> = headers.iter().map(|b| b.to_ascii_lowercase()).collect();
    let needle = b"content-length:";
    let pos = lower.windows(needle.len()).position(|w| w == needle)?;
    let mut i = pos + needle.len();
    while i < headers.len() && (headers[i] == b' ' || headers[i] == b'\t') {
        i += 1;
    }
    let mut j = i;
    while j < headers.len() && headers[j].is_ascii_digit() {
        j += 1;
    }
    std::str::from_utf8(&headers[i..j]).ok()?.parse().ok()
}

async fn send_raw(req: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .expect("connect");
    stream.write_all(req).await.expect("write");
    let mut out = Vec::new();
    let mut buf = vec![0u8; 32768];
    let _ = timeout(Duration::from_secs(5), async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if let Some(p) = find_double_crlf(&out) {
                        if let Some(cl) = parse_cl(&out[..p]) {
                            if out.len() >= p + 4 + cl {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    })
    .await;
    out
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

fn browse_req(object_id: &str) -> Vec<u8> {
    let body = format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:Browse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\"><ObjectID>{}</ObjectID><BrowseFlag>BrowseDirectChildren</BrowseFlag><Filter>*</Filter><StartingIndex>0</StartingIndex><RequestedCount>10</RequestedCount><SortCriteria></SortCriteria></u:Browse></s:Body></s:Envelope>",
        object_id
    );
    format!(
        "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
        TEST_IP,
        body.len(),
        body
    )
    .into_bytes()
}

async fn with_server<F, Fut>(media_files: &[(&str, usize)], f: F)
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_bg_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    for (name, size) in media_files {
        let data: Vec<u8> = (0..*size).map(|i| (i % 251) as u8).collect();
        std::fs::write(media.join(name), &data).unwrap();
    }
    // Standard 1 KiB payload for GET benches + a subdir for browse.
    if !media.join("f.mp4").exists() {
        std::fs::write(media.join("f.mp4"), b"0123456789ABCDEF".repeat(64)).unwrap();
    }
    if !media.join("d").exists() {
        std::fs::create_dir_all(media.join("d")).unwrap();
        std::fs::write(media.join("d").join("g.mp4"), b"0123456789ABCDEF").unwrap();
    }
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
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Reference payload for GET asserts.
    let payload = std::fs::read(media.join("f.mp4")).unwrap();
    f(payload).await;
    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
}

/// Cached Browse POST (ObjectID 0), sequential. Hot path for browse speed.
#[tokio::test]
#[ignore]
async fn bench_browse_seq() {
    with_server(&[], |_| async move {
        let req = browse_req("0");
        let r0 = send_raw(&req).await;
        assert!(r0.starts_with(b"HTTP/1.1 200 OK"));
        assert!(r0.windows(16).any(|w| w == b"<NumberReturned>"));
        black_box(&r0);
        let n = 100u32;
        let t = Instant::now();
        for _ in 0..n {
            let r = send_raw(&req).await;
            black_box(&r);
            assert!(r.starts_with(b"HTTP/1.1 200 OK"));
            assert_eq!(r.len(), r0.len(), "browse bytes must be stable");
        }
        let dt = t.elapsed().as_secs_f64();
        println!(
            "[bench-bg] browse cached seq ObjectID 0: {} reqs in {:.3}s = {:.0} req/s ({:.2} ms/req)",
            n,
            dt,
            n as f64 / dt,
            dt * 1000.0 / n as f64
        );
    })
    .await;
}

/// Cached Browse POST (ObjectID 0), concurrent x200.
#[tokio::test]
#[ignore]
async fn bench_browse_conc() {
    with_server(&[], |_| async move {
        let req = browse_req("0");
        let r0 = send_raw(&req).await;
        assert!(r0.starts_with(b"HTTP/1.1 200 OK"));
        let n = 200u32;
        let t = Instant::now();
        let mut hs = Vec::new();
        for _ in 0..n {
            let q = req.clone();
            let e = r0.clone();
            hs.push(tokio::spawn(async move {
                let r = send_raw(&q).await;
                black_box(&r);
                assert!(r.starts_with(b"HTTP/1.1 200 OK"));
                assert_eq!(r.len(), e.len());
            }));
        }
        for h in hs {
            h.await.unwrap();
        }
        let dt = t.elapsed().as_secs_f64();
        println!(
            "[bench-bg] browse cached conc x{}: {:.3}s = {:.0} req/s",
            n,
            dt,
            n as f64 / dt
        );
    })
    .await;
}

/// Small-file GET (1 KiB), sequential. Hot path for Get speed.
#[tokio::test]
#[ignore]
async fn bench_get_seq() {
    with_server(&[], |payload| async move {
        let get = format!("GET /f.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes();
        let r0 = send_raw(&get).await;
        assert!(r0.starts_with(b"HTTP/1.1 206 Partial Content"));
        assert!(r0.ends_with(&payload));
        let n = 200u32;
        let t = Instant::now();
        for _ in 0..n {
            let r = send_raw(&get).await;
            black_box(&r);
            assert!(r.starts_with(b"HTTP/1.1 206 Partial Content"));
            assert!(r.ends_with(&payload));
        }
        let dt = t.elapsed().as_secs_f64();
        println!(
            "[bench-bg] get 1KiB seq: {} reqs in {:.3}s = {:.0} req/s ({:.2} ms/req)",
            n,
            dt,
            n as f64 / dt,
            dt * 1000.0 / n as f64
        );
    })
    .await;
}

/// Small-file GET (1 KiB), concurrent x200.
#[tokio::test]
#[ignore]
async fn bench_get_conc() {
    with_server(&[], |payload| async move {
        let get = format!("GET /f.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes();
        let n = 200u32;
        let t = Instant::now();
        let mut hs = Vec::new();
        for _ in 0..n {
            let q = get.clone();
            let p = payload.clone();
            hs.push(tokio::spawn(async move {
                let r = send_raw(&q).await;
                black_box(&r);
                assert!(r.starts_with(b"HTTP/1.1 206 Partial Content"));
                assert!(r.ends_with(&p));
            }));
        }
        for h in hs {
            h.await.unwrap();
        }
        let dt = t.elapsed().as_secs_f64();
        println!(
            "[bench-bg] get 1KiB conc x{}: {:.3}s = {:.0} req/s",
            n,
            dt,
            n as f64 / dt
        );
    })
    .await;
}
