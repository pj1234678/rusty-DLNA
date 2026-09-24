//! Throughput benchmarks for RustyDLNA7 request handling (all ignored by
//! default so `cargo test` stays fast).
//!
//! Run:  cargo test --test bench_perf -- --ignored --nocapture
//!
//! No new dependencies, no unsafe. Asserts response *correctness* strictly;
//! throughput numbers are informational only (loopback timing is noisy).
//! Beyond the precached hot path: large-file chunked send (WRITE_TIMEOUT
//! loop), uncached dynamic fallback, and the traversal-tactic hot path.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration, Instant};

const TEST_IP: &str = "127.0.0.1";
const MULTICAST_IP: &str = "239.255.255.250";
const TCP_PORT: u16 = 8200;
// SSDP target: unicast 127.0.0.1:1900 is owned by the OS SSDP service, so the
// bench (like the exact suite) uses 127.0.0.2:1900, which only our 0.0.0.0:1900
// socket receives.
const SSDP_TARGET: &str = "127.0.0.2:1900";

// Serializes the port-binding benches in this file (the server hardcodes
// :8200/:1900, so two instances can never coexist).
static SERVER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
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
                        if let Some(cl) = parse_content_length(&out[..p]) {
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

#[tokio::test]
#[ignore]
async fn throughput_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_throughput_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    let payload: Vec<u8> = b"0123456789ABCDEF".repeat(64); // 1 KiB file
    std::fs::write(media.join("f.mp4"), &payload).unwrap();
    std::fs::create_dir_all(media.join("d")).unwrap();
    std::fs::write(media.join("d").join("g.mp4"), b"0123456789ABCDEF").unwrap();
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

    let get = format!("GET /f.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes();
    let body = "<s:Envelope><s:Body><ObjectID>0</ObjectID></s:Body></s:Envelope>";
    let post = format!(
        "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
        TEST_IP,
        body.len(),
        body
    )
    .into_bytes();

    // Warmup.
    for _ in 0..10 {
        let r = send_raw(&get).await;
        assert!(r.starts_with(b"HTTP/1.1 206 Partial Content"));
    }

    // Sequential file GETs.
    let n_get = 200u32;
    let t = Instant::now();
    for _ in 0..n_get {
        let r = send_raw(&get).await;
        assert!(r.starts_with(b"HTTP/1.1 206 Partial Content"));
        assert!(r.ends_with(&payload));
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "[throughput] sequential file GET (1 KiB): {} reqs in {:.3}s = {:.0} req/s ({:.2} ms/req)",
        n_get,
        dt,
        n_get as f64 / dt,
        dt * 1000.0 / n_get as f64
    );

    // Sequential Browse POSTs (precached root).
    let n_post = 60u32;
    let t = Instant::now();
    for _ in 0..n_post {
        let r = send_raw(&post).await;
        assert!(r.starts_with(b"HTTP/1.1 200 OK"));
        assert!(r.windows(16).any(|w| w == b"<NumberReturned>"));
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "[throughput] sequential Browse POST (cached): {} reqs in {:.3}s = {:.0} req/s ({:.2} ms/req)",
        n_post,
        dt,
        n_post as f64 / dt,
        dt * 1000.0 / n_post as f64
    );

    // Concurrent file GETs.
    let n_conc = 100u32;
    let t = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..n_conc {
        let g = get.clone();
        let p = payload.clone();
        handles.push(tokio::spawn(async move {
            let mut s = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
                .await
                .unwrap();
            s.write_all(&g).await.unwrap();
            let mut out = Vec::new();
            let mut buf = vec![0u8; 32768];
            let _ = timeout(Duration::from_secs(5), async {
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            out.extend_from_slice(&buf[..n]);
                            if let Some(pos) = find_double_crlf(&out) {
                                if let Some(cl) = parse_content_length(&out[..pos]) {
                                    if out.len() >= pos + 4 + cl {
                                        break;
                                    }
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
            .await;
            assert!(out.starts_with(b"HTTP/1.1 206 Partial Content"));
            assert!(out.ends_with(&p));
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "[throughput] concurrent file GET x{} (1 KiB): {:.3}s total = {:.0} req/s",
        n_conc,
        dt,
        n_conc as f64 / dt
    );

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
}

fn expected_ssdp_response() -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: http://{}:8200/rootDesc.xml\r\nSERVER: DLNA/1.0 DLNADOC/1.50 UPnP/1.0 RustyDLNA7/1.3.0\r\nST: urn:schemas-upnp-org:device:MediaServer:1\r\nUSN: uuid:4d696e6e-444c-164e-9d41-b827eb96c6c2::urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n",
        TEST_IP
    )
    .into_bytes()
}

#[tokio::test]
#[ignore]
async fn ssdp_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_ssdp_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    std::fs::write(media.join("f.mp4"), b"0123456789ABCDEF").unwrap();
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

    let expected = expected_ssdp_response();
    // The responder answers ANY datagram (even 1 byte / empty) from port 1900.
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    for probe in [b"M-SEARCH * HTTP/1.1\r\nST: MediaServer:1\r\n\r\n".to_vec(), b"X".to_vec(), b"".to_vec()] {
        sock.send_to(&probe, SSDP_TARGET).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, src) = timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .expect("ssdp warmup reply")
            .expect("ssdp recv");
        assert_eq!(src.port(), 1900, "ssdp source port");
        assert_eq!(&buf[..n], &expected[..], "ssdp template for {:?}", probe);
    }

    // Sequential ping-pong: strictly lossless, every reply byte-exact.
    let n_seq = 500u32;
    let mut lat = Vec::with_capacity(n_seq as usize);
    let t = Instant::now();
    for _ in 0..n_seq {
        let t0 = Instant::now();
        sock.send_to(b"M-SEARCH", SSDP_TARGET).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, _) = timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .expect("ssdp reply")
            .expect("ssdp recv");
        lat.push(t0.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(&buf[..n], &expected[..], "ssdp sequential reply bytes");
    }
    let dt = t.elapsed().as_secs_f64();
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "[throughput] SSDP sequential ping-pong: {} replies in {:.3}s = {:.0} replies/s (avg {:.3} ms, max {:.3} ms, {}B template)",
        n_seq,
        dt,
        n_seq as f64 / dt,
        lat.iter().sum::<f64>() / lat.len() as f64,
        lat[lat.len() - 1],
        expected.len()
    );

    // Burst: fire-and-collect with a deadline. UDP may drop under burst, so
    // the count is informational — but EVERY received datagram must be
    // byte-exact, and loopback should lose (almost) nothing.
    let n_burst = 300u32;
    for _ in 0..n_burst {
        sock.send_to(b"M-SEARCH", SSDP_TARGET).await.unwrap();
    }
    let mut got = 0u32;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while got < n_burst {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        let mut buf = vec![0u8; 4096];
        match timeout(left, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                assert_eq!(&buf[..n], &expected[..], "ssdp burst reply bytes");
                got += 1;
            }
            _ => break,
        }
    }
    println!(
        "[throughput] SSDP burst: {}/{ } replies collected (loss {:.1}%)",
        got,
        n_burst,
        100.0 * (n_burst - got) as f64 / n_burst as f64
    );
    assert!(
        got as f64 >= n_burst as f64 * 0.95,
        "SSDP burst loss too high on loopback: {}/{}",
        got,
        n_burst
    );

    // TCP path must be perfectly healthy after the SSDP storm.
    let r = send_raw(&format!("GET /f.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes()).await;
    assert!(r.starts_with(b"HTTP/1.1 206 Partial Content"));
    assert!(r.ends_with(b"0123456789ABCDEF"));

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
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

fn split_body(resp: &[u8]) -> &[u8] {
    match find_double_crlf(resp) {
        Some(p) => &resp[p + 4..],
        None => &[],
    }
}

/// Large-file streaming: exercises the bounded 16 KiB chunk send loop
/// (WRITE_TIMEOUT fix) with an 8 MiB file no socket buffer can swallow.
/// Correctness is strict (exact bytes, Range, lengths); MiB/s informational.
#[tokio::test]
#[ignore]
async fn large_file_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_large_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    let big: Vec<u8> = vec![0xABu8; 8 * 1024 * 1024];
    std::fs::write(media.join("big.bin"), &big).unwrap();
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

    // Full GET: exact status, Range, length, and all 8 MiB byte-exact.
    let get = format!("GET /big.bin HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes();
    let r = send_raw(&get).await;
    assert!(r.starts_with(b"HTTP/1.1 206 Partial Content"), "large full status");
    let p = find_double_crlf(&r).expect("large full headers");
    assert!(
        String::from_utf8_lossy(&r[..p]).contains("Content-Range: bytes 0-8388607/8388608"),
        "large full range"
    );
    assert_eq!(parse_content_length(&r[..p]), Some(big.len()), "large full CL");
    assert_eq!(split_body(&r), &big[..], "large full bytes");
    // Mid Range: 1 MiB offset serves to end.
    let range = format!(
        "GET /big.bin HTTP/1.1\r\nHost: {}\r\nRange: bytes=1048576-\r\n\r\n",
        TEST_IP
    )
    .into_bytes();
    let r2 = send_raw(&range).await;
    let p2 = find_double_crlf(&r2).expect("large range headers");
    assert!(
        String::from_utf8_lossy(&r2[..p2]).contains("Content-Range: bytes 1048576-8388607/8388608"),
        "large range header"
    );
    assert_eq!(parse_content_length(&r2[..p2]), Some(big.len() - 1_048_576));
    assert_eq!(split_body(&r2), &big[1_048_576..], "large range bytes");

    // Timing: repeated full 8 MiB GETs (chunk-loop throughput).
    let n = 5u32;
    let t = Instant::now();
    for _ in 0..n {
        let r = send_raw(&get).await;
        assert!(r.starts_with(b"HTTP/1.1 206 Partial Content"));
        assert_eq!(split_body(&r).len(), big.len());
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "[throughput] large file GET (8 MiB): {} reqs in {:.3}s = {:.1} MiB/s",
        n,
        dt,
        n as f64 * big.len() as f64 / dt / 1_048_576.0
    );

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
}

/// Uncached dynamic fallback: dirs/files created AFTER startup miss the
/// precache and pay read_dir + sort + render per request. Strict on counts,
/// ids, sort order, and follow-up streaming; req/s informational.
#[tokio::test]
#[ignore]
async fn dynamic_fallback_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_fallback_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    std::fs::write(media.join("root.mp4"), b"0123456789ABCDEF").unwrap();
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

    // Created after startup: invisible to precache, served via fallback.
    std::fs::create_dir_all(media.join("benchdir").join("sub")).unwrap();
    for i in 0..200u32 {
        let name = format!("f{:03}.mp4", i);
        std::fs::write(media.join("benchdir").join(&name), name.as_bytes()).unwrap();
    }
    std::fs::write(media.join("benchdir").join("sub").join("deep.mp4"), b"DEEP").unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Correctness: 1 subdir + 200 files, sorted, inside ids, then stream one.
    let req = browse_req("benchdir/");
    let r = send_raw(&req).await;
    assert!(r.starts_with(b"HTTP/1.1 200 OK"), "fallback status");
    let b = String::from_utf8_lossy(split_body(&r)).into_owned();
    assert!(b.contains("<NumberReturned>201</NumberReturned>"), "fallback count:\n{}", &b[..b.len().min(300)]);
    assert!(b.contains("<TotalMatches>201</TotalMatches>"), "fallback total");
    assert!(b.contains("benchdir/sub/"), "fallback container id");
    assert!(b.contains("benchdir/f000.mp4"), "fallback first file id");
    assert!(b.contains("benchdir/f199.mp4"), "fallback last file id");
    let p0 = b.find("benchdir/f000.mp4").unwrap();
    let p1 = b.find("benchdir/f001.mp4").unwrap();
    let p199 = b.find("benchdir/f199.mp4").unwrap();
    assert!(p0 < p1 && p1 < p199, "fallback files sorted");
    let g = send_raw(&format!("GET /benchdir/f042.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes()).await;
    assert_eq!(split_body(&g), b"f042.mp4", "fallback file streams");

    // Timing: repeated uncached browses (full read_dir + sort + render each).
    let n = 20u32;
    let t = Instant::now();
    for _ in 0..n {
        let r = send_raw(&req).await;
        assert!(r.starts_with(b"HTTP/1.1 200 OK"));
        assert!(String::from_utf8_lossy(split_body(&r)).contains("<NumberReturned>201</NumberReturned>"));
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "[throughput] dynamic fallback Browse (201 children): {} reqs in {:.3}s = {:.0} req/s ({:.2} ms/req)",
        n,
        dt,
        n as f64 / dt,
        dt * 1000.0 / n as f64
    );

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
}

/// Traversal-tactic hot path: every adversarial GET pays decode + hardened
/// sanitize. Inside-resolving tactics must serve the file; escaping tactics
/// (against a real outside sibling secret) must 404 with zero leaked bytes.
#[tokio::test]
#[ignore]
async fn traversal_paths_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_trav_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    let payload: Vec<u8> = b"0123456789ABCDEF".repeat(64); // 1 KiB
    std::fs::write(media.join("root.mp4"), &payload).unwrap();
    let outside = std::env::temp_dir().join(format!(
        "rustydlna_trav_outside_{}.txt",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&outside, b"SECRET-OUTSIDE").unwrap();
    let base = outside.file_name().unwrap().to_str().unwrap().to_string();
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

    // Inside-resolving tactics: byte-exact root.mp4.
    let inside = [
        "/../root.mp4",
        "/..%2Froot.mp4",
        "/..%5croot.mp4",
        "/..\\root.mp4",
        "/.../root.mp4",
        "/....//root.mp4",
        "/..%20/root.mp4",
        "/movies/../root.mp4",
    ];
    for path in inside {
        let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\n\r\n", path, TEST_IP).into_bytes();
        let r = send_raw(&req).await;
        assert!(r.starts_with(b"HTTP/1.1 206 Partial Content"), "inside {}", path);
        assert_eq!(split_body(&r), &payload[..], "inside bytes {}", path);
    }
    // Escaping tactics vs the real outside secret: exact 404, no leak.
    let escape: Vec<String> = [
        format!("/../{}", base),
        format!("/..%2F{}", base),
        format!("/..%5c{}", base),
        format!("/..\\{}", base),
        format!("/%2e%2e%5c{}", base),
        format!("/%2e%2e%5c..%5c{}", base),
        format!("/.../{}", base),
        format!("/....//{}", base),
        format!("/..%2e/{}", base),
        format!("/..%20/{}", base),
        format!("/%252e%252e%2f{}", base),
        format!("/C:/{}", base),
        format!("//server/share/{}", base),
        format!("/%c0%ae%c0%ae/{}", base),
        format!("/&amp;..%2f{}", base),
        format!("/{}%00.mp4", base),
    ]
    .into_iter()
    .collect();
    for path in &escape {
        let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\n\r\n", path, TEST_IP).into_bytes();
        let r = send_raw(&req).await;
        assert_eq!(r, b"HTTP/1.1 404 NOT FOUND\r\n\r\n".to_vec(), "escape {} 404", path);
        assert!(
            !r.windows(b"SECRET-OUTSIDE".len()).any(|w| w == b"SECRET-OUTSIDE"),
            "escape {} leaked",
            path
        );
    }

    // Timing: the full tactic set back to back (hardening overhead on GET).
    let all: Vec<String> = inside.iter().map(|s| s.to_string()).chain(escape.clone()).collect();
    let reqs: Vec<Vec<u8>> = all
        .iter()
        .map(|p| format!("GET {} HTTP/1.1\r\nHost: {}\r\n\r\n", p, TEST_IP).into_bytes())
        .collect();
    let n = 10u32;
    let t = Instant::now();
    for _ in 0..n {
        for q in &reqs {
            let r = send_raw(q).await;
            assert!(!r.is_empty(), "tactic answered");
        }
    }
    let dt = t.elapsed().as_secs_f64();
    let total = n as f64 * reqs.len() as f64;
    println!(
        "[throughput] traversal-tactic GETs ({} paths x{}): {:.0} reqs in {:.3}s = {:.0} req/s",
        reqs.len(),
        n,
        total,
        dt,
        total / dt
    );

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
    let _ = std::fs::remove_file(&outside);
}

/// Concurrent Browse POST storm: the gap in throughput_bench (which is
/// sequential POST only). All precached, byte-exact, connect-per-req.
#[tokio::test]
#[ignore]
async fn browse_post_storm_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_poststorm_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    std::fs::write(media.join("f.mp4"), b"0123456789ABCDEF").unwrap();
    std::fs::create_dir_all(media.join("d")).unwrap();
    std::fs::write(media.join("d").join("g.mp4"), b"0123456789ABCDEF").unwrap();
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

    let req = browse_req("0");
    let r = send_raw(&req).await;
    assert!(r.starts_with(b"HTTP/1.1 200 OK"));
    assert!(r.windows(16).any(|w| w == b"<NumberReturned>"));

    let n = 200u32;
    let t = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..n {
        let q = req.clone();
        handles.push(tokio::spawn(async move {
            let r = send_raw(&q).await;
            assert!(r.starts_with(b"HTTP/1.1 200 OK"));
            assert!(r.windows(16).any(|w| w == b"<NumberReturned>"));
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "[throughput] concurrent Browse POST x{} (cached): {:.3}s total = {:.0} req/s",
        n,
        dt,
        n as f64 / dt
    );

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
}

/// Mixed GET+POST load: measures interference (no blended metric existed).
#[tokio::test]
#[ignore]
async fn mixed_get_post_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_mixed_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    let payload: Vec<u8> = b"0123456789ABCDEF".repeat(64);
    std::fs::write(media.join("f.mp4"), &payload).unwrap();
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

    let get = format!("GET /f.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes();
    let post = browse_req("0");
    let n = 100u32;
    let t = Instant::now();
    let mut handles = Vec::new();
    for i in 0..n {
        if i % 2 == 0 {
            let g = get.clone();
            let p = payload.clone();
            handles.push(tokio::spawn(async move {
                let r = send_raw(&g).await;
                assert!(r.starts_with(b"HTTP/1.1 206 Partial Content"));
                assert!(r.ends_with(&p));
            }));
        } else {
            let q = post.clone();
            handles.push(tokio::spawn(async move {
                let r = send_raw(&q).await;
                assert!(r.starts_with(b"HTTP/1.1 200 OK"));
                assert!(r.windows(16).any(|w| w == b"<NumberReturned>"));
            }));
        }
    }
    for h in handles {
        h.await.unwrap();
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "[throughput] mixed GET+POST x{} (1:1): {:.3}s total = {:.0} req/s",
        n,
        dt,
        n as f64 / dt
    );

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
}

/// Large-dir (1000-file) uncached fallback: extends dynamic_fallback_bench
/// (201 children) with transient-memory pressure + sort-order locks.
#[tokio::test]
#[ignore]
async fn large_dir_fallback_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_bigdir_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    std::fs::write(media.join("root.mp4"), b"0123456789ABCDEF").unwrap();
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

    std::fs::create_dir_all(media.join("bigdir")).unwrap();
    for i in 0..1000u32 {
        let name = format!("f{:04}.mp4", i);
        std::fs::write(media.join("bigdir").join(&name), name.as_bytes()).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let req = browse_req("bigdir/");
    let r = send_raw(&req).await;
    assert!(r.starts_with(b"HTTP/1.1 200 OK"), "bigdir status");
    let b = String::from_utf8_lossy(split_body(&r)).into_owned();
    assert!(b.contains("<NumberReturned>1000</NumberReturned>"), "bigdir count");
    assert!(b.contains("bigdir/f0000.mp4"), "bigdir first");
    assert!(b.contains("bigdir/f0999.mp4"), "bigdir last");
    let p0 = b.find("bigdir/f0000.mp4").unwrap();
    let p1 = b.find("bigdir/f0001.mp4").unwrap();
    let p999 = b.find("bigdir/f0999.mp4").unwrap();
    assert!(p0 < p1 && p1 < p999, "bigdir sorted");
    let g = send_raw(&format!("GET /bigdir/f0042.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes()).await;
    assert_eq!(split_body(&g), b"f0042.mp4", "bigdir stream");

    let n = 10u32;
    let t = Instant::now();
    for _ in 0..n {
        let r = send_raw(&req).await;
        assert!(r.starts_with(b"HTTP/1.1 200 OK"));
        assert!(String::from_utf8_lossy(split_body(&r)).contains("<NumberReturned>1000</NumberReturned>"));
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "[throughput] large-dir fallback Browse (1000 children): {} reqs in {:.3}s = {:.0} req/s ({:.2} ms/req)",
        n,
        dt,
        n as f64 / dt,
        dt * 1000.0 / n as f64
    );

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
}

/// Permit drip recovery: hold 300 header-drips (below the 1000 permit cap),
/// prove a healthy GET still serves during the hold, then prove all drips
/// are reaped after the 5s header deadline and permits recycle.
#[tokio::test]
#[ignore]
async fn permit_drip_recovery_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_driprec_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    let payload: Vec<u8> = b"0123456789ABCDEF".repeat(64);
    std::fs::write(media.join("f.mp4"), &payload).unwrap();
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

    // Hold 300 drips: partial headers, never completed, never closed.
    let mut drips = Vec::new();
    for _ in 0..300u32 {
        let mut s = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
            .await
            .expect("drip connect");
        s.write_all(b"GET /f.mp4 HTTP/1.1\r\nHost: x\r\nX-P: ").await.ok();
        drips.push(s);
    }
    // Healthy traffic must still serve (300 < 1000 permits).
    let get = format!("GET /f.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes();
    let r = send_raw(&get).await;
    assert!(r.starts_with(b"HTTP/1.1 206 Partial Content"));
    assert!(r.ends_with(&payload));

    // Past the 5s header deadline every drip must EOF (reaped).
    tokio::time::sleep(Duration::from_secs(6)).await;
    let mut reaped = 0u32;
    let mut buf = vec![0u8; 64];
    for mut s in drips {
        let res = timeout(Duration::from_secs(3), s.read(&mut buf)).await;
        match res {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => reaped += 1,
            Ok(Ok(_)) => {}
        }
    }
    println!("[throughput] drip recovery: {}/300 drips reaped", reaped);
    assert_eq!(reaped, 300, "all drips must be reaped after header deadline");

    // Post-recovery throughput proves permit recycle.
    let n = 50u32;
    let t = Instant::now();
    for _ in 0..n {
        let r = send_raw(&get).await;
        assert!(r.starts_with(b"HTTP/1.1 206 Partial Content"));
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "[throughput] post-recovery GET: {} reqs in {:.3}s = {:.0} req/s",
        n,
        dt,
        n as f64 / dt
    );

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
}

/// Precache cold-start: 50 dirs x 20 files built BEFORE spawn; measures
/// spawn-to-ready (precache + bind + listen) and asserts the listing.
#[tokio::test]
#[ignore]
async fn precache_coldstart_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_coldstart_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    for d in 0..50u32 {
        let dir = media.join(format!("d{:02}", d));
        std::fs::create_dir_all(&dir).unwrap();
        for f in 0..20u32 {
            std::fs::write(dir.join(format!("f{:02}.mp4", f)), b"x").unwrap();
        }
    }
    let bin = env!("CARGO_BIN_EXE_RustyDLNA7");
    let t0 = Instant::now();
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
    let dt = t0.elapsed().as_secs_f64();
    println!(
        "[throughput] precache cold-start (51 dirs/1000 files) spawn-to-ready {:.0}ms = {:.0} dirs/s",
        dt * 1000.0,
        51.0 / dt
    );
    let r = send_raw(&browse_req("0")).await;
    assert!(r.starts_with(b"HTTP/1.1 200 OK"));
    assert!(String::from_utf8_lossy(split_body(&r)).contains("<NumberReturned>50</NumberReturned>"));

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
}

/// SSDP storm with drain-while-send: avoids the old fire-then-collect flake
/// (client rx buffer overflowed during the send burst) by interleaving
/// 50-send / 50-drain batches. Every datagram must be byte-exact; TCP must
/// stay healthy after the storm.
#[tokio::test]
#[ignore]
async fn ssdp_storm_drain_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_storm_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    std::fs::write(media.join("f.mp4"), b"0123456789ABCDEF").unwrap();
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

    let expected = expected_ssdp_response();
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    // Warmup: 3 probe shapes, all byte-exact.
    for probe in [b"M-SEARCH".to_vec(), b"X".to_vec(), b"".to_vec()] {
        sock.send_to(&probe, SSDP_TARGET).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, _) = timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .expect("ssdp warmup")
            .expect("recv");
        assert_eq!(&buf[..n], &expected[..]);
    }
    // 600-packet storm in 50-send / 50-drain batches.
    let n_storm = 600u32;
    let mut got = 0u32;
    let t = Instant::now();
    let mut left = n_storm;
    while left > 0 {
        let batch = left.min(50);
        for _ in 0..batch {
            sock.send_to(b"M-SEARCH", SSDP_TARGET).await.unwrap();
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        for _ in 0..batch {
            let left_t = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left_t.is_zero() {
                break;
            }
            let mut buf = vec![0u8; 4096];
            match timeout(left_t, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    assert_eq!(&buf[..n], &expected[..]);
                    got += 1;
                }
                _ => break,
            }
        }
        left -= batch;
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "[throughput] SSDP storm drain: {}/{} replies ({:.1}% loss) in {:.3}s = {:.0} replies/s",
        got,
        n_storm,
        100.0 * (n_storm - got) as f64 / n_storm as f64,
        dt,
        got as f64 / dt
    );
    assert!(got as f64 >= n_storm as f64 * 0.95, "storm loss too high: {}/{}", got, n_storm);

    let r = send_raw(&format!("GET /f.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes()).await;
    assert!(r.starts_with(b"HTTP/1.1 206 Partial Content"));
    assert!(r.ends_with(b"0123456789ABCDEF"));

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
}

fn tasklist_kb(pid: u32) -> f64 {
    let out = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
        .output();
    let out = match out {
        Ok(o) => o,
        Err(_) => return f64::NAN,
    };
    let s = String::from_utf8_lossy(&out.stdout).into_owned();
    // CSV: "name","PID","...","...","7,092 K" — last quoted field is mem.
    let last = s.split('"').nth_back(1).unwrap_or("");
    last.replace(',', "").replace('K', "").trim().parse::<f64>().unwrap_or(f64::NAN)
}

/// Per-conn memory via tasklist (std-only, Windows, informational):
/// holds 200 idle conns, reports delta. Asserts < 64 KiB/conn.
#[tokio::test]
#[ignore]
async fn rss_per_conn_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_rss_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    std::fs::write(media.join("f.mp4"), b"0123456789ABCDEF").unwrap();
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
    let pid = child.id().expect("child pid");
    let base = tasklist_kb(pid);
    let mut held = Vec::new();
    for _ in 0..200u32 {
        if let Ok(s) = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT)).await {
            held.push(s);
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let loaded = tasklist_kb(pid);
    let per = (loaded - base) / 200.0;
    println!("[mem] rss base {:.0}K loaded {:.0}K per-conn {:.1} KiB", base, loaded, per);
    assert!(per.is_finite(), "tasklist parse failed");
    assert!(per < 64.0, "per-conn blowout: {:.1} KiB", per);
    // Health during hold.
    let r = send_raw(&format!("GET /f.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes()).await;
    assert!(r.starts_with(b"HTTP/1.1 206 Partial Content"));
    drop(held);

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
}

/// 404/416 storm: sequential + concurrent cold-branch GETs. 404 pays
/// File::open miss only (26B write); 416 pays open+metadata (38B write).
#[tokio::test]
#[ignore]
async fn notfound_range_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_notfound_{}_{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    std::fs::write(media.join("f.mp4"), b"0123456789ABCDEF").unwrap();
    let outside = std::env::temp_dir().join(format!("rustydlna_notfound_out_{}.txt",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)));
    std::fs::write(&outside, b"SECRET-OUTSIDE").unwrap();
    let bin = env!("CARGO_BIN_EXE_RustyDLNA7");
    let mut child = tokio::process::Command::new(bin)
        .arg(TEST_IP).arg(media.to_str().unwrap()).arg(MULTICAST_IP)
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .kill_on_drop(true).spawn().expect("spawn server");
    wait_for_tcp().await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let req404 = format!("GET /nope-missing-xyz.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes();
    let req416 = format!("GET /f.mp4 HTTP/1.1\r\nHost: {}\r\nRange: bytes=99999-\r\n\r\n", TEST_IP).into_bytes();
    let exp404 = b"HTTP/1.1 404 NOT FOUND\r\n\r\n".to_vec();
    let exp416 = b"HTTP/1.1 416 Range Not Satisfiable\r\n\r\n".to_vec();
    for _ in 0..5 {
        let r = send_raw(&req404).await; std::hint::black_box(&r);
        assert_eq!(r, exp404);
        let r = send_raw(&req416).await; std::hint::black_box(&r);
        assert_eq!(r, exp416);
    }
    let n = 200u32;
    let t = Instant::now();
    for _ in 0..n {
        let r = send_raw(&req404).await; std::hint::black_box(&r);
        assert_eq!(r, exp404);
        assert!(!r.windows(b"SECRET-OUTSIDE".len()).any(|w| w == b"SECRET-OUTSIDE"));
    }
    let dt = t.elapsed().as_secs_f64();
    println!("[throughput] 404 miss GET (26B): {} reqs in {:.3}s = {:.0} req/s ({:.2} ms/req)", n, dt, n as f64 / dt, dt*1000.0/n as f64);
    let t = Instant::now();
    for _ in 0..n {
        let r = send_raw(&req416).await; std::hint::black_box(&r);
        assert_eq!(r, exp416);
    }
    let dt = t.elapsed().as_secs_f64();
    println!("[throughput] 416 range-beyond GET (38B): {} reqs in {:.3}s = {:.0} req/s ({:.2} ms/req)", n, dt, n as f64 / dt, dt*1000.0/n as f64);

    for (tag, req, exp) in [("404", req404.clone(), exp404.clone()), ("416", req416.clone(), exp416.clone())] {
        let m = 100u32; let t = Instant::now(); let mut hs = Vec::new();
        for _ in 0..m {
            let q = req.clone(); let e = exp.clone();
            hs.push(tokio::spawn(async move {
                let r = send_raw(&q).await; std::hint::black_box(&r);
                assert_eq!(r, e);
                assert!(!r.windows(b"SECRET-OUTSIDE".len()).any(|w| w == b"SECRET-OUTSIDE"));
            }));
        }
        for h in hs { h.await.unwrap(); }
        let dt = t.elapsed().as_secs_f64();
        println!("[throughput] concurrent {} x{}: {:.3}s total = {:.0} req/s", tag, m, dt, m as f64 / dt);
    }
    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
    let _ = std::fs::remove_file(&outside);
}

/// Empty-file quirk storm: 0-byte GET -> 206 + `bytes 0-0/0` + CL 0
/// (exercises the `remaining==0` early-return: no chunk alloc, no Take::read).
#[tokio::test]
#[ignore]
async fn empty_file_quirk_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_emptyq_{}_{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    std::fs::write(media.join("empty.mp4"), b"").unwrap();
    std::fs::write(media.join("s.mp4"), b"0123456789ABCDEF").unwrap();
    let bin = env!("CARGO_BIN_EXE_RustyDLNA7");
    let mut child = tokio::process::Command::new(bin)
        .arg(TEST_IP).arg(media.to_str().unwrap()).arg(MULTICAST_IP)
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .kill_on_drop(true).spawn().expect("spawn server");
    wait_for_tcp().await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let get = format!("GET /empty.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes();
    let exp = b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-0/0\r\nContent-Type: video/mp4\r\nContent-Length: 0\r\n\r\n".to_vec();
    for _ in 0..5 {
        let r = send_raw(&get).await; std::hint::black_box(&r);
        assert_eq!(r, exp, "empty quirk bytes");
    }
    // Single (untimed) inverted-quirk probe — shares the remaining==0 early-return.
    let inv = send_raw(&format!("GET /s.mp4 HTTP/1.1\r\nHost: {}\r\nRange: bytes=16-\r\n\r\n", TEST_IP).into_bytes()).await;
    let p = find_double_crlf(&inv).expect("inv headers");
    assert!(String::from_utf8_lossy(&inv[..p]).contains("Content-Range: bytes 16-15/16"));
    assert_eq!(parse_content_length(&inv[..p]), Some(0));
    assert!(split_body(&inv).is_empty());

    let n = 200u32; let t = Instant::now();
    for _ in 0..n {
        let r = send_raw(&get).await; std::hint::black_box(&r);
        assert_eq!(r, exp);
    }
    let dt = t.elapsed().as_secs_f64();
    println!("[throughput] empty-file quirk GET (104B hdr, 0B body): {} reqs in {:.3}s = {:.0} req/s ({:.2} ms/req)", n, dt, n as f64 / dt, dt*1000.0/n as f64);

    let m = 100u32; let t = Instant::now(); let mut hs = Vec::new();
    for _ in 0..m {
        let q = get.clone(); let e = exp.clone();
        hs.push(tokio::spawn(async move {
            let r = send_raw(&q).await; std::hint::black_box(&r);
            assert_eq!(r, e);
        }));
    }
    for h in hs { h.await.unwrap(); }
    let dt = t.elapsed().as_secs_f64();
    println!("[throughput] concurrent empty-file quirk x{}: {:.3}s total = {:.0} req/s", m, dt, m as f64 / dt);

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
}

/// SortCaps storm: POST GetSortCapabilities without ObjectID -> pre-baked
/// 480B response (no Server header). Exercises contains_sortcaps + early return.
#[tokio::test]
#[ignore]
async fn sortcaps_storm_bench() {
    let _guard = SERVER_LOCK.lock().unwrap();
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!("leftover server on {}:{} — kill RustyDLNA7 and re-run", TEST_IP, TCP_PORT);
    }
    let media = std::env::temp_dir().join(format!(
        "rustydlna_sortcaps_{}_{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    ));
    std::fs::create_dir_all(&media).unwrap();
    std::fs::write(media.join("f.mp4"), b"0123456789ABCDEF").unwrap();
    let bin = env!("CARGO_BIN_EXE_RustyDLNA7");
    let mut child = tokio::process::Command::new(bin)
        .arg(TEST_IP).arg(media.to_str().unwrap()).arg(MULTICAST_IP)
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .kill_on_drop(true).spawn().expect("spawn server");
    wait_for_tcp().await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let body = r#"<?xml version="1.0"?><s:Envelope><s:Body><u:GetSortCapabilities xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1"></u:GetSortCapabilities></s:Body></s:Envelope>"#;
    let req = format!("POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}", TEST_IP, body.len(), body).into_bytes();
    let first = send_raw(&req).await; // warmup + byte-exact template
    let p = find_double_crlf(&first).expect("sortcaps headers");
    let h = String::from_utf8_lossy(&first[..p]).into_owned();
    assert!(h.starts_with("HTTP/1.1 200 OK"), "sortcaps status");
    assert!(!h.contains("Server:"), "SortCaps must NOT send Server");
    assert!(h.contains("Content-Type: text/xml"));
    assert_eq!(parse_content_length(&first[..p]), Some(first.len() - p - 4));
    assert!(String::from_utf8_lossy(split_body(&first)).contains("<SortCaps>dc:title,dc:date,upnp:class,upnp:album,upnp:episodeNumber,upnp:originalTrackNumber</SortCaps>"));
    std::hint::black_box(&first);

    let n = 100u32; let t = Instant::now();
    for _ in 0..n {
        let r = send_raw(&req).await; std::hint::black_box(&r);
        assert_eq!(r, first, "sortcaps sequential byte-exact");
    }
    let dt = t.elapsed().as_secs_f64();
    println!("[throughput] SortCaps POST sequential (480B): {} reqs in {:.3}s = {:.0} req/s ({:.2} ms/req)", n, dt, n as f64 / dt, dt*1000.0/n as f64);

    let m = 100u32; let t = Instant::now(); let mut hs = Vec::new();
    for _ in 0..m {
        let q = req.clone(); let e = first.clone();
        hs.push(tokio::spawn(async move {
            let r = send_raw(&q).await; std::hint::black_box(&r);
            assert_eq!(r, e, "sortcaps concurrent byte-exact");
        }));
    }
    for h in hs { h.await.unwrap(); }
    let dt = t.elapsed().as_secs_f64();
    println!("[throughput] concurrent SortCaps POST x{}: {:.3}s total = {:.0} req/s", m, dt, m as f64 / dt);

    child.kill().await.ok();
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
    let _ = std::fs::remove_dir_all(&media);
}
