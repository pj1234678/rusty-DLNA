//! Exact-functionality regression suite for RustyDLNA7.
//!
//! Strategy: black-box. The binary crate exposes no library, so every
//! behavioural quirk is locked by spawning the real server binary and
//! speaking raw HTTP/TCP (and UDP for SSDP) to it, byte-for-byte.
//!
//! Covered (all verified against the reference binary before writing):
//! - CLI arg handling / usage / invalid LOCAL_IP / invalid MULTICAST_IP
//! - static XML routes: exact status line, headers, Content-Length, bodies
//! - file streaming: always 206, Content-Range/Content-Length, 404/416,
//!   case-sensitive Range, invalid-range fallback, range==size quirk,
//!   Range-end ignored, suffix-range fallback, empty-file quirk,
//!   non-mp4 Content-Type, percent/XML-entity decoding (+ stays literal,
//!   single-pass % decode), traversal sanitisation, query-string 404,
//!   double-slash collapse, raw '#' passthrough, HTTP version ignored
//! - request limits: >4096-byte headers silent, split-packet POST silent
//!   (server never waits for body), one request per connection
//! - Browse POST: cache keys "0"/"64$0", 64$ stripping (incl. "64$"->root
//!   fallback and double-prefix), first-ObjectID wins, ObjectID beats
//!   SortCaps, whitespace not trimmed, lenient closing tag,
//!   StartingIndex/RequestedCount ignored, unknown/file-id/empty => silent,
//!   GetSortCapabilities path, POST path ignored, empty POST silent,
//!   double-slash parentID bug, empty parentID for root items, sorting,
//!   encode() URLs, title escaping, no-slash fallback mangling,
//!   dynamic fallback for dirs created after startup, empty-media startup
//! - SSDP: exact 295-byte template via 127.0.0.2:1900 (unicast .1 hits the
//!   OS service, so tests use .2/.3 which only our 0.0.0.0:1900 socket gets)
//! - connection handling: unknown/lowercase methods silent, garbage survives,
//!   concurrent GET+POST load succeeds, outside-media escape blocked
//! - source invariants via include_str! so silent refactors are caught.

use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const TEST_IP: &str = "127.0.0.1";
const MULTICAST_IP: &str = "239.255.255.250";
const TCP_PORT: u16 = 8200;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn media_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "rustydlna_exact_{}_{}_{}",
        std::process::id(),
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

fn rm_rf(p: &Path) {
    let _ = std::fs::remove_dir_all(p);
}

fn write_file(p: &Path, bytes: &[u8]) {
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, bytes).unwrap();
}

/// Build the deterministic media tree used by every network test.
/// Returns (media_root, root_mp4_bytes).
fn setup_media(root: &Path) -> Vec<u8> {
    rm_rf(root);
    let root_mp4: Vec<u8> = b"0123456789ABCDEF".repeat(64); // 1024 bytes
    assert_eq!(root_mp4.len(), 1024);
    write_file(&root.join("root.mp4"), &root_mp4);
    write_file(&root.join("my movie.mp4"), &b"SPACE".repeat(20)); // 100
    write_file(&root.join("a&b.mp4"), &b"AMP".repeat(20)); // 60
    write_file(&root.join("paren(1).mp4"), &b"P".repeat(10));
    write_file(&root.join("quote'mp4.mp4"), &b"Q".repeat(10));
    write_file(&root.join("hash#tag.mp4"), &b"H".repeat(10));
    write_file(&root.join("comma,test.mp4"), &b"C".repeat(10));
    write_file(&root.join("empty.mp4"), &[]); // 0 bytes: locks bytes 0-0/0 quirk
    write_file(&root.join("note.txt"), b"HELLO TXT"); // 9 bytes: CT stays video/mp4
    write_file(&root.join("plus+file.mp4"), b"PLUS"); // 4 bytes: '+' is literal

    write_file(&root.join("movies").join("apple.mp4"), &b"A".repeat(10));
    write_file(&root.join("movies").join("film.mp4"), &b"HELLOFILM".repeat(100));
    write_file(&root.join("movies").join("zebra.mp4"), &b"Z".repeat(10));
    write_file(
        &root.join("movies").join("action").join("deep.mp4"),
        &b"DEEP".repeat(50),
    ); // 200
    write_file(&root.join("my dir").join("inner.mp4"), &b"X".repeat(50));
    write_file(&root.join("a&bdir").join("inner2.mp4"), &b"Y".repeat(60));
    std::fs::create_dir_all(root.join("empty")).unwrap();
    root_mp4
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    // case-insensitive search for "content-length:"
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

async fn wait_for_tcp(ip: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match timeout(
            Duration::from_millis(300),
            TcpStream::connect(format!("{}:{}", ip, TCP_PORT)),
        )
        .await
        {
            Ok(Ok(_)) => return,
            _ => {
                if tokio::time::Instant::now() > deadline {
                    panic!("server on {}:{} never became reachable", ip, TCP_PORT);
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

/// Send one raw request on a fresh connection, return raw response bytes.
/// Empty vec means the server closed the connection without replying
/// (the defined behaviour for unknown Browse IDs / bad POSTs).
async fn send_raw(ip: &str, req: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(format!("{}:{}", ip, TCP_PORT))
        .await
        .expect("connect for send_raw");
    stream.write_all(req).await.expect("write request");
    // signal end of POST body: server reads headers only (\r\n\r\n) then
    // parses the buffered bytes; no need to shutdown.
    let mut out = Vec::new();
    // Heap buffer: a 64 KiB stack array inside an async fn blows the
    // default test-thread stack once the mega-test future is built.
    let mut buf = vec![0u8; 32768];
    let _ = timeout(Duration::from_secs(4), async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if let Some(hdr_end) = find_double_crlf(&out) {
                        if let Some(cl) = parse_content_length(&out[..hdr_end]) {
                            if out.len() >= hdr_end + 4 + cl {
                                break;
                            }
                        } else {
                            // No Content-Length (404/416): give the server
                            // 300ms to close, then stop.
                            match timeout(
                                Duration::from_millis(300),
                                stream.read(&mut buf),
                            )
                            .await
                            {
                                Ok(Ok(0)) | Err(_) => break,
                                Ok(Ok(m)) => {
                                    out.extend_from_slice(&buf[..m]);
                                    break;
                                }
                                _ => break,
                            }
                        }
                    }
                    if out.len() > 10_000_000 {
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

fn split_response(resp: &[u8]) -> (Vec<u8>, Vec<u8>) {
    match find_double_crlf(resp) {
        Some(p) => (resp[..p].to_vec(), resp[p + 4..].to_vec()),
        None => (resp.to_vec(), Vec::new()),
    }
}

fn body_str(resp: &[u8]) -> String {
    String::from_utf8_lossy(&split_response(resp).1).into_owned()
}

fn browse_post(object_id: &str, starting_index: u32) -> Vec<u8> {
    let body = format!(
        "{}{}{}{}{}{}{}",
        r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>"#,
        r#"<u:Browse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">"#,
        format!("<ObjectID>{}</ObjectID>", object_id),
        "<BrowseFlag>BrowseDirectChildren</BrowseFlag><Filter>*</Filter>",
        format!(
            "<StartingIndex>{}</StartingIndex><RequestedCount>10</RequestedCount>",
            starting_index
        ),
        "<SortCriteria></SortCriteria></u:Browse></s:Body></s:Envelope>",
        ""
    );
    let req = format!(
        "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
        TEST_IP,
        body.len(),
        body
    );
    req.into_bytes()
}

fn get_req(path: &str, extra_headers: Option<&str>) -> Vec<u8> {
    let extra = extra_headers.map(|h| format!("\r\n{}", h)).unwrap_or_default();
    format!("GET {} HTTP/1.1\r\nHost: {}{}\r\n\r\n", path, TEST_IP, extra).into_bytes()
}

fn browse_post_custom(object_id: &str, starting_index: u32, requested_count: u32) -> Vec<u8> {
    let body = format!(
        "{}{}{}{}{}{}",
        r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>"#,
        r#"<u:Browse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">"#,
        format!("<ObjectID>{}</ObjectID>", object_id),
        "<BrowseFlag>BrowseDirectChildren</BrowseFlag><Filter>*</Filter>",
        format!(
            "<StartingIndex>{}</StartingIndex><RequestedCount>{}</RequestedCount>",
            starting_index, requested_count
        ),
        "<SortCriteria></SortCriteria></u:Browse></s:Body></s:Envelope>",
    );
    format!(
        "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
        TEST_IP,
        body.len(),
        body
    )
    .into_bytes()
}

/// POST to an arbitrary path. The server ignores the request-target for POST
/// (handle_post_request never looks at the URL), so /foo must behave like
/// /ctl/ContentDir. Locked by probe.
fn browse_post_to(path: &str, object_id: &str) -> Vec<u8> {
    let body = format!(
        "<?xml?><s:Envelope><s:Body><u:Browse><ObjectID>{}</ObjectID></u:Browse></s:Body></s:Envelope>",
        object_id
    );
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
        path,
        TEST_IP,
        body.len(),
        body
    )
    .into_bytes()
}

/// Send headers first, then the body on the SAME connection after a delay.
/// The server stops reading at \\r\\n\\r\\n and never waits for the body, so a
/// split-packet POST must get NO reply (and the late body write may RST).
/// Returns raw response bytes (expected empty).
async fn send_split_post(ip: &str, headers: &[u8], body: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(format!("{}:{}", ip, TCP_PORT))
        .await
        .expect("connect for split post");
    stream.write_all(headers).await.expect("write headers");
    tokio::time::sleep(Duration::from_millis(600)).await;
    // Body write may fail with RST since the server already closed; ignore.
    let _ = stream.write_all(body).await;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 8192];
    let _ = timeout(Duration::from_secs(3), async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if find_double_crlf(&out).is_some() {
                        // Any reply would be a regression; drain briefly then stop.
                        let _ = timeout(Duration::from_millis(300), stream.read(&mut buf)).await;
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

/// Probe SSDP. The server binds 0.0.0.0:1900 (coexisting with the OS SSDP
/// service which holds 127.0.0.1:1900 specifically), so unicast to 127.0.0.1
/// hits the OS and times out. Sending to 127.0.0.2/127.0.0.3 reaches ONLY our
/// socket. The server replies with the fixed template to ANY datagram.
async fn ssdp_probe(server_local_ip: &str) -> Vec<u8> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("bind udp for ssdp probe");
    // .2 first (proven to reach our socket), fall back to .3.
    for target in ["127.0.0.2", "127.0.0.3"] {
        let _ = sock
            .send_to(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: ns=01\r\nST: urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n", format!("{}:1900", target))
            .await;
        match timeout(Duration::from_secs(2), async {
            let mut buf = vec![0u8; 4096];
            let (n, _src) = sock.recv_from(&mut buf).await?;
            Ok::<Vec<u8>, std::io::Error>(buf[..n].to_vec())
        })
        .await
        {
            Ok(Ok(resp)) => {
                // Sanity: must be OUR server (LOCATION carries its LOCAL_IP),
                // not some other SSDP speaker.
                if resp
                    .windows(format!("LOCATION: http://{}:8200/rootDesc.xml", server_local_ip).len())
                    .any(|w| w == format!("LOCATION: http://{}:8200/rootDesc.xml", server_local_ip).as_bytes())
                {
                    return resp;
                }
                // Wrong speaker; keep trying.
            }
            _ => continue,
        }
    }
    panic!("no SSDP reply carrying LOCATION for {}", server_local_ip);
}

// ---------------------------------------------------------------------------
// source invariants (no server needed)
// ---------------------------------------------------------------------------

#[test]
fn source_static_routes_and_helpers_locked() {
    let src = include_str!("../src/main.rs");
    // 4 pre-baked static routes (direct byte-match arms, incl. rootDesc first)
    for route in [
        r#"b"/ContentDir.xml""#,
        r#"b"/X_MS_MediaReceiver_Registrar.xml""#,
        r#"b"/ConnectionMgr.xml""#,
        r#"b"/rootDesc.xml""#,
    ] {
        assert!(src.contains(route), "missing static route: {}", route);
    }
    // bake_static! exact header shape
    assert!(
        src.contains("Content-Length: {}") && src.contains("Content-Type: text/xml"),
        "bake_static! header shape changed"
    );
    // SSDP template pieces
    for piece in [
        "LOCATION: http://{}:8200/rootDesc.xml",
        "SERVER: DLNA/1.0 DLNADOC/1.50 UPnP/1.0 RustyDLNA7/1.3.0",
        "ST: urn:schemas-upnp-org:device:MediaServer:1",
        "USN: uuid:4d696e6e-444c-164e-9d41-b827eb96c6c2",
    ] {
        assert!(src.contains(piece), "SSDP template changed: {}", piece);
    }
    // Browse HTTP envelope quirks (note the ';' after text/xml; and Server value)
    for piece in [
        "Connection: Keep-Alive",
        "Content-Type: text/xml;",
        "Server: RustyDLNA DLNADOC/1.50 UPnP/1.0 RustyDLNA7/1.3.0",
    ] {
        assert!(src.contains(piece), "Browse header changed: {}", piece);
    }
    // File streaming quirks
    assert!(
        src.contains("206 Partial Content"),
        "file streaming must always answer 206"
    );
    assert!(
        src.contains("Content-Range: bytes {}-{}/{}"),
        "Content-Range template changed"
    );
    assert!(
        src.contains("Content-Type: video/mp4"),
        "stream Content-Type changed"
    );
    assert!(
        src.contains("HTTP/1.1 404 NOT FOUND"),
        "404 status line changed"
    );
    assert!(
        src.contains("HTTP/1.1 416 Range Not Satisfiable"),
        "416 status line changed"
    );
    // Cache keys / 64$ handling
    assert!(src.contains(r#""0""#), "root cache key 0 missing");
    assert!(src.contains(r#"b"64$0""#), "64$0 alias missing");
    assert!(
        src.contains(r#"starts_with(b"64$")"#),
        "64$ stripping logic changed"
    );
    // Range parsing is case-sensitive on purpose
    assert!(
        src.contains(r#"b"Range: bytes=""#),
        "Range header search changed (must stay case-sensitive)"
    );
    // SortCaps payload
    assert!(
        src.contains("dc:title,dc:date,upnp:class,upnp:album,upnp:episodeNumber,upnp:originalTrackNumber"),
        "SortCaps changed"
    );
    // TCP port + timeouts + concurrency limit
    assert!(src.contains(":8200"), "TCP port changed");
    assert!(src.contains("Semaphore::new(1000)"), "concurrency limit changed");
    assert!(
        src.contains("Duration::from_secs(5)"),
        "read timeout changed"
    );
    // Socket plumbing quirks
    assert!(
        src.contains("TcpListener::bind"),
        "TCP bind changed"
    );
    assert!(
        src.contains(r#"UdpSocket::bind("0.0.0.0:1900")"#),
        "SSDP UDP bind changed"
    );
    assert!(
        src.contains("join_multicast_v4"),
        "multicast join changed"
    );
    assert!(
        src.contains("set_nodelay(true)"),
        "TCP_NODELAY changed"
    );
    assert!(
        src.contains("recv_from") && src.contains("send_to"),
        "SSDP responder must recv_from then send_to same response"
    );
    // DIDL envelope constants (match unescaped fragments: main.rs embeds them
    // inside format! strings as \" so the file bytes contain backslashes).
    for piece in [
        "object.container.storageFolder",
        "object.item.videoItem",
        "http-get:*:video/mp4:*",
        "childCount",
        "storageUsed",
        "<NumberReturned>",
        "<TotalMatches>",
        "<UpdateID>0</UpdateID>",
        "DIDL-Lite",
        "restricted",
        "searchable",
    ] {
        assert!(src.contains(piece), "DIDL template changed: {}", piece);
    }
    // Streaming internals
    assert!(src.contains(".take("), "zero-copy take() changed");
    assert!(src.contains("SeekFrom::Start"), "range seek changed");
    assert!(src.contains("[0u8; 4096]"), "request buffer size changed");
    assert!(
        src.contains("saturating_sub(1)"),
        "Content-Range end calculation changed"
    );
    // POST dispatch is prefix-sensitive on purpose
    assert!(src.contains(r#"starts_with(b"GET ")"#), "GET dispatch changed");
    assert!(src.contains(r#"starts_with(b"POST ")"#), "POST dispatch changed");
    // Cache second-chance + encode fallback must stay.
    assert!(src.contains("or_else("), "cache or_else second-chance changed");
    // Non-special bytes pass through the encode/decode byte fast-paths untouched.
    assert!(
        src.split("mod perf_benches").next().unwrap().contains("out.push(b as char)"),
        "byte passthrough changed"
    );
    // Perf: the old identity copy `s.replace("é", "é")` was pure overhead
    // (it changed nothing). It must stay out of production code; "é" is
    // still handled by the match arm below (locked in the encode table test).
    assert!(!src.split("mod perf_benches").next().unwrap().contains(".replace(\"é\","), "identity replace must stay removed (perf)");
    // Request framing constants.
    assert!(src.contains(r#"b"\r\n\r\n""#), "header terminator changed");
    // Terminator scan is the tail-check + \r-hunt pair (no full rescan).
    assert!(src.contains("fn rhunt_complete"), "terminator scan changed");
    assert!(src.contains("fn headers_complete"), "terminator scan changed");
    // Incremental scan must keep the loop invariant documented in main.rs.
    assert!(src.contains("saturating_sub(3)"), "incremental header scan changed");
    // No UA sniffing: exact functionality serves every client identically.
    assert!(!src.contains("User-Agent"), "server must stay User-Agent-blind");
    assert!(!src.contains("user_agent"), "server must stay User-Agent-blind");
    // decode() must handle double-encoded "&amp;amp;" BEFORE single "&amp;",
    // otherwise "a&amp;amp;b" would decode wrong.
    {
        let i_double = src.find("\"&amp;amp;\"").expect("double-amp entity handling");
        let i_single = src.find("(\"&amp;\", \"&\")").expect("single-amp entity handling");
        assert!(i_double < i_single, "decode order: double-amp first");
    }
    // Both precache and fallback generate with (0, 5000): pagination params
    // from the wire are always ignored. (Scoped to production code: the
    // in-tree benches use 0, 5000 too.)
    assert_eq!(
        src.split("mod perf_benches").next().unwrap().matches(", 0, 5000,").count(),
        2,
        "both generate_browse_response call sites must use 0, 5000"
    );
}

#[test]
fn source_decode_encode_logic_locked() {
    let src = include_str!("../src/main.rs");
    // decode(): XML entities (double-amp first) then %XX via from_str_radix.
    // (Implementation is allocation-lean now: fast path + Cow + sliced hex,
    // but order and parsing semantics are locked.)
    for piece in [
        "\"&amp;amp;\"",
        "(\"&amp;\", \"&\")",
        "\"&apos;\"",
        "\"&eacute;\"",
        "from_str_radix",
    ] {
        assert!(src.contains(piece), "decode() changed: {}", piece);
    }
    // encode(): exact mapping table (match on push_str payloads so
    // char-quote style and scratch-variable names don't matter)
    for piece in [
        r#"push_str("%20")"#,
        r#"push_str("%27")"#,
        r#"push_str("%28")"#,
        r#"push_str("%29")"#,
        r#"push_str("%22")"#,
        r#"push_str("%23")"#,
        r#"push_str("%2C")"#,
        r#"push_str("&amp;amp;")"#,
        r#"push_str("&eacute;")"#,
    ] {
        assert!(src.contains(piece), "encode() changed: {}", piece);
    }
}

// ---------------------------------------------------------------------------
// CLI (no long-lived server needed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cli_wrong_arg_count_prints_usage_and_exits_1() {
    let bin = env!("CARGO_BIN_EXE_RustyDLNA7");
    for args in [
        Vec::<String>::new(),
        vec!["only-one".to_string()],
        vec!["a".to_string(), "b".to_string()],
        vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ],
    ] {
        let out = tokio::process::Command::new(bin)
            .args(&args)
            .output()
            .await
            .expect("run with wrong args");
        assert_eq!(
            out.status.code(),
            Some(1),
            "wrong arg count {:?} must exit 1",
            args
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("Usage:"),
            "stderr must contain Usage:, got: {}",
            stderr
        );
    }
}

#[tokio::test]
async fn cli_invalid_ip_fails() {
    let bin = env!("CARGO_BIN_EXE_RustyDLNA7");
    let dir = media_dir("cli");
    std::fs::create_dir_all(&dir).unwrap();
    let out = tokio::process::Command::new(bin)
        .arg("not-an-ip")
        .arg(dir.to_str().unwrap())
        .arg(MULTICAST_IP)
        .output()
        .await
        .expect("run with bad ip");
    assert!(
        !out.status.success(),
        "invalid LOCAL_IP must not exit 0"
    );
    rm_rf(&dir);
}

#[tokio::test]
async fn cli_invalid_multicast_ip_fails_before_binding() {
    // Parsing happens before precache/bind (main.rs parses both IPs up
    // front), so this fails fast without holding ports -- safe in parallel.
    let bin = env!("CARGO_BIN_EXE_RustyDLNA7");
    let dir = media_dir("cli-mcast");
    std::fs::create_dir_all(&dir).unwrap();
    let out = tokio::process::Command::new(bin)
        .arg(TEST_IP)
        .arg(dir.to_str().unwrap())
        .arg("not-an-ip")
        .output()
        .await
        .expect("run with bad multicast ip");
    assert!(
        !out.status.success(),
        "invalid MULTICAST_IP must not exit 0"
    );
    rm_rf(&dir);
}

// ---------------------------------------------------------------------------
// the one test that binds ports (runs everything sequentially)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exact_dlna_functionality() {
    let media = media_dir("mega");
    let root_mp4 = setup_media(&media);
    let media_s = media.to_str().unwrap().to_string();
    let bin = env!("CARGO_BIN_EXE_RustyDLNA7");

    // Fail fast on leftovers from a previous aborted run: if something already
    // answers on 8200, our new server could never have bound, and we would
    // otherwise talk to the stale instance and get confusing 404s.
    if tokio::net::TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
        .await
        .is_ok()
    {
        panic!(
            "leftover server still listening on {}:{} — kill RustyDLNA7 processes and re-run",
            TEST_IP, TCP_PORT
        );
    }

    let mut child = tokio::process::Command::new(bin)
        .arg(TEST_IP)
        .arg(&media_s)
        .arg(MULTICAST_IP)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn RustyDLNA7");
    wait_for_tcp(TEST_IP).await;
    // give the pre-cache a beat to finish printing (bind happens after it)
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ---- static routes ----------------------------------------------------
    for (path, marker) in [
        ("/rootDesc.xml", "urn:schemas-upnp-org:device:MediaServer:1"),
        ("/ContentDir.xml", "GetSearchCapabilities"),
        ("/ConnectionMgr.xml", "GetProtocolInfo"),
        (
            "/X_MS_MediaReceiver_Registrar.xml",
            "IsAuthorized",
        ),
    ] {
        let resp = send_raw(TEST_IP, &get_req(path, None)).await;
        let (hdr, body) = split_response(&resp);
        let hdr_s = String::from_utf8_lossy(&hdr);
        assert!(
            hdr_s.starts_with("HTTP/1.1 200 OK"),
            "{} must start with 200 OK, got {}",
            path,
            hdr_s.lines().next().unwrap_or("")
        );
        assert!(
            hdr_s.contains("Content-Type: text/xml"),
            "{} Content-Type",
            path
        );
        let cl = parse_content_length(&hdr).expect("static route needs CL");
        assert_eq!(cl, body.len(), "{} Content-Length must equal body", path);
        assert!(
            String::from_utf8_lossy(&body).contains(marker),
            "{} body must contain {}",
            path,
            marker
        );
    }
    // rootDesc specifics that DLNA clients depend on
    {
        let resp = send_raw(TEST_IP, &get_req("/rootDesc.xml", None)).await;
        let (_, body) = split_response(&resp);
        let b = String::from_utf8_lossy(&body);
        assert!(b.contains("<friendlyName>RustyDLNA7</friendlyName>"));
        assert!(b.contains("uuid:4d696e6e-444c-164e-9d41-b827eb96c6c2"));
        assert!(b.contains("<SCPDURL>/ContentDir.xml</SCPDURL>"));
    }
    // unknown / dir / case / query => exact 404
    for path in [
        "/foo.xml",
        "/",
        "/movies/",
        "/rootdesc.xml",
        "/root.mp4?x=1",
        "/nonexistent.mp4",
    ] {
        let resp = send_raw(TEST_IP, &get_req(path, None)).await;
        assert_eq!(
            resp,
            b"HTTP/1.1 404 NOT FOUND\r\n\r\n".to_vec(),
            "GET {} must be exact 404",
            path
        );
    }

    // ---- file streaming ---------------------------------------------------
    // no Range => STILL 206 (quirk), full file
    {
        let resp = send_raw(TEST_IP, &get_req("/root.mp4", None)).await;
        let (hdr, body) = split_response(&resp);
        let h = String::from_utf8_lossy(&hdr);
        assert!(h.starts_with("HTTP/1.1 206 Partial Content"), "no-range 206, got {}", h.lines().next().unwrap_or(""));
        assert!(h.contains("Content-Range: bytes 0-1023/1024"), "no-range Content-Range: {}", h);
        assert!(h.contains("Content-Type: video/mp4"), "stream CT");
        assert_eq!(parse_content_length(&hdr), Some(1024));
        assert_eq!(body, root_mp4, "no-range body must equal file");
    }
    // explicit 0
    {
        let resp = send_raw(TEST_IP, &get_req("/root.mp4", Some("Range: bytes=0-"))).await;
        let (hdr, body) = split_response(&resp);
        let h = String::from_utf8_lossy(&hdr);
        assert!(h.contains("Content-Range: bytes 0-1023/1024"));
        assert_eq!(body, root_mp4);
    }
    // mid range
    {
        let resp = send_raw(TEST_IP, &get_req("/root.mp4", Some("Range: bytes=10-"))).await;
        let (hdr, body) = split_response(&resp);
        let h = String::from_utf8_lossy(&hdr);
        assert!(h.contains("Content-Range: bytes 10-1023/1024"), "mid range hdr: {}", h);
        assert_eq!(parse_content_length(&hdr), Some(1014));
        assert_eq!(body, &root_mp4[10..]);
    }
    // last byte
    {
        let resp = send_raw(TEST_IP, &get_req("/root.mp4", Some("Range: bytes=1023-"))).await;
        let (hdr, body) = split_response(&resp);
        let h = String::from_utf8_lossy(&hdr);
        assert!(h.contains("Content-Range: bytes 1023-1023/1024"));
        assert_eq!(parse_content_length(&hdr), Some(1));
        assert_eq!(body, &root_mp4[1023..]);
    }
    // range == size => 206 with 0 bytes (NOT 416). Only `>` triggers 416.
    {
        let resp = send_raw(TEST_IP, &get_req("/root.mp4", Some("Range: bytes=1024-"))).await;
        let (hdr, body) = split_response(&resp);
        let h = String::from_utf8_lossy(&hdr);
        assert!(
            h.starts_with("HTTP/1.1 206 Partial Content"),
            "range==size must stay 206, got {}",
            h.lines().next().unwrap_or("")
        );
        assert!(h.contains("Content-Range: bytes 1024-1023/1024"), "inverted range quirk: {}", h);
        assert_eq!(parse_content_length(&hdr), Some(0));
        assert!(body.is_empty());
    }
    // range beyond => exact 416
    {
        let resp = send_raw(TEST_IP, &get_req("/root.mp4", Some("Range: bytes=99999-"))).await;
        assert_eq!(
            resp,
            b"HTTP/1.1 416 Range Not Satisfiable\r\n\r\n".to_vec(),
            "range beyond must be exact 416"
        );
    }
    // Range end is IGNORED: "bytes=5-10" serves 5..end, not 5..10.
    {
        let resp = send_raw(TEST_IP, &get_req("/root.mp4", Some("Range: bytes=5-10"))).await;
        let (hdr, body) = split_response(&resp);
        let h = String::from_utf8_lossy(&hdr);
        assert!(
            h.contains("Content-Range: bytes 5-1023/1024"),
            "range end must be ignored, got {}",
            h
        );
        assert_eq!(parse_content_length(&hdr), Some(1019));
        assert_eq!(body, &root_mp4[5..], "bytes=5-10 must serve to end");
    }
    // Suffix range "bytes=-10" has empty start -> parse fails -> 0 -> full file.
    {
        let resp = send_raw(TEST_IP, &get_req("/root.mp4", Some("Range: bytes=-10"))).await;
        let (hdr, body) = split_response(&resp);
        assert!(
            String::from_utf8_lossy(&hdr).contains("Content-Range: bytes 0-1023/1024"),
            "suffix range must fall back to 0"
        );
        assert_eq!(body, root_mp4);
    }
    // Empty file quirk: size 0 => "bytes 0-0/0", CL 0 (saturating_sub).
    {
        let resp = send_raw(TEST_IP, &get_req("/empty.mp4", None)).await;
        let (hdr, body) = split_response(&resp);
        let h = String::from_utf8_lossy(&hdr);
        assert!(h.starts_with("HTTP/1.1 206 Partial Content"), "empty file 206, got {}", h.lines().next().unwrap_or(""));
        assert!(h.contains("Content-Range: bytes 0-0/0"), "empty range: {}", h);
        assert_eq!(parse_content_length(&hdr), Some(0));
        assert!(body.is_empty());
    }
    // Empty file with range 1 (> 0) => 416.
    {
        let resp = send_raw(TEST_IP, &get_req("/empty.mp4", Some("Range: bytes=1-"))).await;
        assert_eq!(
            resp,
            b"HTTP/1.1 416 Range Not Satisfiable\r\n\r\n".to_vec(),
            "empty file range 1 must be 416"
        );
    }
    // Content-Type is ALWAYS video/mp4, even for .txt.
    {
        let resp = send_raw(TEST_IP, &get_req("/note.txt", None)).await;
        let (hdr, body) = split_response(&resp);
        let h = String::from_utf8_lossy(&hdr);
        assert!(h.contains("Content-Type: video/mp4"), "non-mp4 CT: {}", h);
        assert!(h.contains("Content-Range: bytes 0-8/9"), "note.txt range: {}", h);
        assert_eq!(body, b"HELLO TXT");
    }
    // HTTP version is ignored (1.0 behaves like 1.1).
    {
        let raw = format!("GET /root.mp4 HTTP/1.0\r\nHost: {}\r\n\r\n", TEST_IP).into_bytes();
        let resp = send_raw(TEST_IP, &raw).await;
        let (_, body) = split_response(&resp);
        assert_eq!(body, root_mp4, "HTTP/1.0 must serve same bytes");
    }
    // Malformed GET without version: path extraction yields empty -> 404.
    {
        let resp = send_raw(TEST_IP, b"GET /root.mp4\r\n\r\n").await;
        assert_eq!(
            resp,
            b"HTTP/1.1 404 NOT FOUND\r\n\r\n".to_vec(),
            "GET without version must be 404"
        );
    }
    // '+' stays literal: plus+file works, %2B decodes to '+', '+' never means space.
    {
        let resp = send_raw(TEST_IP, &get_req("/plus+file.mp4", None)).await;
        assert_eq!(split_response(&resp).1, b"PLUS", "raw plus must serve");
        let resp2 = send_raw(TEST_IP, &get_req("/plus%2Bfile.mp4", None)).await;
        assert_eq!(split_response(&resp2).1, b"PLUS", "%2B must decode to plus");
        let resp3 = send_raw(TEST_IP, &get_req("/my+movie.mp4", None)).await;
        assert_eq!(
            resp3,
            b"HTTP/1.1 404 NOT FOUND\r\n\r\n".to_vec(),
            "plus must NOT decode to space"
        );
    }
    // Percent decoding is single-pass: %2520 stays "%20", bare/invalid % stays literal -> 404.
    for path in ["/my%2520movie.mp4", "/root%.mp4", "/root%ZZ.mp4", "/root%2.mp4"] {
        let resp = send_raw(TEST_IP, &get_req(path, None)).await;
        assert_eq!(
            resp,
            b"HTTP/1.1 404 NOT FOUND\r\n\r\n".to_vec(),
            "GET {} must be 404 (single-pass/invalid %)",
            path
        );
    }
    // Double slash collapses (empty components skipped) and raw '#' passes through.
    {
        let resp = send_raw(TEST_IP, &get_req("//root.mp4", None)).await;
        assert_eq!(split_response(&resp).1, root_mp4, "// must collapse");
        let resp2 = send_raw(TEST_IP, &get_req("/hash#tag.mp4", None)).await;
        assert_eq!(split_response(&resp2).1, b"H".repeat(10), "raw # must serve");
    }
    // invalid / missing dash => fallback to 0
    for range_hdr in ["Range: bytes=abc-", "Range: bytes=10"] {
        let resp = send_raw(TEST_IP, &get_req("/root.mp4", Some(range_hdr))).await;
        let (hdr, body) = split_response(&resp);
        let h = String::from_utf8_lossy(&hdr);
        assert!(
            h.contains("Content-Range: bytes 0-1023/1024"),
            "{} must fall back to 0, got {}",
            range_hdr,
            h
        );
        assert_eq!(body, root_mp4);
    }
    // Range header name is case-sensitive
    {
        let resp = send_raw(TEST_IP, &get_req("/root.mp4", Some("range: bytes=5-"))).await;
        let (hdr, body) = split_response(&resp);
        assert!(
            String::from_utf8_lossy(&hdr).contains("Content-Range: bytes 0-1023/1024"),
            "lowercase range: must be ignored"
        );
        assert_eq!(body, root_mp4);
    }
    // percent / entity decoding for GET
    {
        let resp = send_raw(TEST_IP, &get_req("/my%20movie.mp4", None)).await;
        let (_, body) = split_response(&resp);
        assert_eq!(body, b"SPACE".repeat(20));
    }
    {
        let resp = send_raw(TEST_IP, &get_req("/paren%281%29.mp4", None)).await;
        let (_, body) = split_response(&resp);
        assert_eq!(body, b"P".repeat(10));
    }
    {
        let resp = send_raw(TEST_IP, &get_req("/quote%27mp4.mp4", None)).await;
        let (_, body) = split_response(&resp);
        assert_eq!(body, b"Q".repeat(10), "%27 decodes to apostrophe");
    }
    {
        // &apos; entity also decodes to apostrophe
        let resp = send_raw(TEST_IP, &get_req("/quote&apos;mp4.mp4", None)).await;
        let (_, body) = split_response(&resp);
        assert_eq!(body, b"Q".repeat(10), "&apos; must decode");
    }
    {
        let resp = send_raw(TEST_IP, &get_req("/hash%23tag.mp4", None)).await;
        let (_, body) = split_response(&resp);
        assert_eq!(body, b"H".repeat(10), "%23 decodes to #");
    }
    {
        let resp = send_raw(TEST_IP, &get_req("/comma%2Ctest.mp4", None)).await;
        let (_, body) = split_response(&resp);
        assert_eq!(body, b"C".repeat(10), "%2C decodes to comma");
    }
    {
        // double-encoded ampersand is THE way encode() emits '&'
        let resp = send_raw(TEST_IP, &get_req("/a&amp;amp;b.mp4", None)).await;
        let (_, body) = split_response(&resp);
        assert_eq!(body, b"AMP".repeat(20), "&amp;amp; must decode to &");
    }
    {
        // single-encoded also decodes
        let resp = send_raw(TEST_IP, &get_req("/a&amp;b.mp4", None)).await;
        let (_, body) = split_response(&resp);
        assert_eq!(body, b"AMP".repeat(20), "&amp; must decode to &");
    }
    // traversal is sanitised but stays inside the media dir
    for path in ["/../root.mp4", "/%2E%2E/root.mp4", "/movies/../root.mp4", "/./root.mp4",
        // extended tactics: all collapse inside media and serve root.mp4
        "/..%2froot.mp4", "/..\\root.mp4", "/.../root.mp4", "/....//root.mp4",
        "/..%20/root.mp4", "/..%2e/root.mp4", "/movies%2f..%2froot.mp4"] {
        let resp = send_raw(TEST_IP, &get_req(path, None)).await;
        let (_, body) = split_response(&resp);
        assert_eq!(body, root_mp4, "traversal {} must resolve inside media", path);
    }
    // subdir files
    {
        let resp = send_raw(TEST_IP, &get_req("/movies/film.mp4", None)).await;
        let (_, body) = split_response(&resp);
        assert_eq!(body, b"HELLOFILM".repeat(100));
    }
    {
        let resp = send_raw(TEST_IP, &get_req("/movies/action/deep.mp4", None)).await;
        let (_, body) = split_response(&resp);
        assert_eq!(body, b"DEEP".repeat(50));
    }

    // ---- Browse POST ------------------------------------------------------
    let root_resp = send_raw(TEST_IP, &browse_post("0", 0)).await;
    {
        let (hdr, body) = split_response(&root_resp);
        let h = String::from_utf8_lossy(&hdr);
        assert!(h.starts_with("HTTP/1.1 200 OK"), "browse 200, got {}", h.lines().next().unwrap_or(""));
        // Browse envelope quirks: Keep-Alive + 'text/xml;' WITH semicolon + Server
        assert!(h.contains("Connection: Keep-Alive"), "browse Keep-Alive: {}", h);
        assert!(h.contains("Content-Type: text/xml;"), "browse CT needs ';': {}", h);
        assert!(
            h.contains("Server: RustyDLNA DLNADOC/1.50 UPnP/1.0 RustyDLNA7/1.3.0"),
            "browse Server: {}",
            h
        );
        assert_eq!(parse_content_length(&hdr), Some(body.len()));
        let b = String::from_utf8_lossy(&body);
        // container first, then files sorted; root item parentID is EMPTY (quirk)
        assert!(b.contains(r#"&lt;container id="movies/" parentID="/""#), "root container:\n{}", b);
        assert!(b.contains(r#"&lt;item id="root.mp4" parentID="""#), "root item empty parent:\n{}", b);
        // Exact counts: 4 dirs (a&bdir, empty, movies, my dir) + 10 files = 14.
        assert!(b.contains("<NumberReturned>14</NumberReturned>"), "root counts:\n{}", b);
        assert!(b.contains("<TotalMatches>14</TotalMatches>"), "root totals:\n{}", b);
        // DIDL envelope constants never change.
        for attr in [
            "object.container.storageFolder",
            "object.item.videoItem",
            "http-get:*:video/mp4:*",
            "childCount=\"0\"",
            "storageUsed",
            "restricted=\"1\"",
            "searchable=\"1\"",
            "<UpdateID>0</UpdateID>",
        ] {
            assert!(b.contains(attr), "browse must contain {}", attr);
        }
        // dirs sorted, files sorted, dirs before files:
        // dirs: a&bdir, empty, movies, my dir; files: a&b, comma, empty, hash,
        // my movie, note, paren, plus, quote, root (ASCII sort).
        let pos_movies = b.find("movies/").expect("movies container");
        let pos_ab = b.find("a&amp;amp;b.mp4").expect("a&b item");
        let pos_my = b.find("my%20movie.mp4").expect("space item");
        let pos_root = b.find("root.mp4").expect("root item");
        assert!(pos_movies < pos_ab, "dirs before files");
        assert!(pos_ab < pos_my && pos_my < pos_root, "files sorted: {}", &b[b.find("NumberReturned").unwrap_or(0)..]);
        let pos_empty = b.find("empty.mp4").expect("empty file item");
        let pos_note = b.find("note.txt").expect("txt item");
        let pos_plus = b.find("plus+file.mp4").expect("plus item");
        assert!(pos_ab < pos_empty && pos_empty < pos_my, "new files sorted (a,empty,my)");
        assert!(pos_my < pos_note && pos_note < pos_root, "new files sorted (my,note,root)");
        assert!(pos_note < pos_plus || pos_plus < pos_root, "plus placed");
        // encode() URLs appear verbatim (incl. new files; '+' is literal, not %2B)
        for needle in [
            "http://127.0.0.1:8200/my%20movie.mp4",
            "http://127.0.0.1:8200/a&amp;amp;b.mp4",
            "http://127.0.0.1:8200/paren%281%29.mp4",
            "http://127.0.0.1:8200/quote%27mp4.mp4",
            "http://127.0.0.1:8200/hash%23tag.mp4",
            "http://127.0.0.1:8200/comma%2Ctest.mp4",
            "http://127.0.0.1:8200/empty.mp4",
            "http://127.0.0.1:8200/note.txt",
            "http://127.0.0.1:8200/plus+file.mp4",
        ] {
            assert!(b.contains(needle), "browse must contain res {}", needle);
        }
        // title escapes ONLY '&'
        assert!(b.contains("&lt;dc:title&gt;a&amp;amp;b.mp4&lt;/dc:title&gt;"), "amp title");
        assert!(b.contains("&lt;dc:title&gt;my movie.mp4&lt;/dc:title&gt;"), "space title raw");
        assert!(b.contains("&lt;dc:title&gt;paren(1).mp4&lt;/dc:title&gt;"), "paren title raw");
    }
    // 64$0 alias is byte-identical
    {
        let r64 = send_raw(TEST_IP, &browse_post("64$0", 0)).await;
        assert_eq!(r64, root_resp, "64$0 must be byte-identical to 0");
    }
    // subdir: double-slash parentID bug is locked
    let movies_resp = send_raw(TEST_IP, &browse_post("movies/", 0)).await;
    {
        let b = body_str(&movies_resp);
        assert!(
            b.contains(r#"&lt;container id="movies/action/" parentID="movies//""#),
            "double-slash parentID bug must be preserved:\n{}",
            b
        );
        assert!(b.contains(r#"parentID="movies/""#), "item parent");
        // sorted: action dir, then apple, film, zebra
        let pa = b.find("movies/action/").unwrap();
        let papple = b.find("movies/apple.mp4").unwrap();
        let pfilm = b.find("movies/film.mp4").unwrap();
        let pzebra = b.find("movies/zebra.mp4").unwrap();
        assert!(pa < papple && papple < pfilm && pfilm < pzebra, "subdir sorted");
        assert!(b.contains("<NumberReturned>4</NumberReturned>"));
        assert!(b.contains("<TotalMatches>4</TotalMatches>"));
    }
    // 64$ subdir alias identical
    {
        let r = send_raw(TEST_IP, &browse_post("64$movies/", 0)).await;
        assert_eq!(r, movies_resp, "64$movies/ identical");
    }
    // nested
    {
        let r = send_raw(TEST_IP, &browse_post("movies/action/", 0)).await;
        let b = body_str(&r);
        assert!(b.contains(r#"&lt;item id="movies/action/deep.mp4" parentID="movies/action/""#));
        assert!(b.contains("http://127.0.0.1:8200/movies/action/deep.mp4"));
        assert!(b.contains("<NumberReturned>1</NumberReturned>"));
    }
    // StartingIndex is IGNORED (pre-cached full response)
    {
        let r1 = send_raw(TEST_IP, &browse_post("0", 1)).await;
        assert_eq!(r1, root_resp, "StartingIndex must be ignored (cache)");
    }
    // unknown dir / file id / bad post => NO reply (empty)
    for oid in ["nosuchdir/", "root.mp4", "movies/nonexistent/"] {
        let r = send_raw(TEST_IP, &browse_post(oid, 0)).await;
        assert!(
            r.is_empty(),
            "Browse {} must return no bytes, got {}",
            oid,
            String::from_utf8_lossy(&r).chars().take(200).collect::<String>()
        );
    }
    {
        let body = "<s:Envelope><s:Body><u:Foo></u:Foo></s:Body></s:Envelope>";
        let req = format!(
            "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
            TEST_IP,
            body.len(),
            body
        );
        let r = send_raw(TEST_IP, req.as_bytes()).await;
        assert!(r.is_empty(), "POST without ObjectID/SortCaps must be silent");
    }
    // GetSortCapabilities path (different headers: NO Server/Keep-Alive)
    {
        let body = r#"<?xml version="1.0"?><s:Envelope><s:Body><u:GetSortCapabilities xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1"></u:GetSortCapabilities></s:Body></s:Envelope>"#;
        let req = format!(
            "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
            TEST_IP,
            body.len(),
            body
        );
        let r = send_raw(TEST_IP, req.as_bytes()).await;
        let (hdr, bdy) = split_response(&r);
        let h = String::from_utf8_lossy(&hdr);
        assert!(h.starts_with("HTTP/1.1 200 OK"));
        assert!(h.contains("Content-Type: text/xml"));
        assert!(!h.contains("Server:"), "SortCaps must NOT send Server, got {}", h);
        assert_eq!(parse_content_length(&hdr), Some(bdy.len()));
        let b = String::from_utf8_lossy(&bdy);
        assert!(b.contains("<SortCaps>dc:title,dc:date,upnp:class,upnp:album,upnp:episodeNumber,upnp:originalTrackNumber</SortCaps>"));
    }
    // first ObjectID wins (movies/ is non-empty here: 4 children)
    {
        let body = "<s:Envelope><s:Body><ObjectID>movies/</ObjectID><ObjectID>0</ObjectID></s:Body></s:Envelope>";
        let req = format!(
            "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
            TEST_IP,
            body.len(),
            body
        );
        let r = send_raw(TEST_IP, req.as_bytes()).await;
        assert_eq!(r, movies_resp, "first ObjectID must win");
    }
    // lenient closing tag still extracts 0
    {
        let body = "<?xml?><s:Envelope><s:Body><u:Browse><ObjectID>0</ObjectID_missing></u:Browse></s:Body></s:Envelope>";
        let req = format!(
            "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
            TEST_IP,
            body.len(),
            body
        );
        let r = send_raw(TEST_IP, req.as_bytes()).await;
        assert_eq!(r, root_resp, "lenient ObjectID extraction");
    }
    // encoded dir ids (cache-miss -> dynamic fallback, same bytes)
    for oid in ["my%20dir/", "my dir/", "64$my%20dir/"] {
        let r = send_raw(TEST_IP, &browse_post(oid, 0)).await;
        let b = body_str(&r);
        assert!(
            b.contains(r#"&lt;item id="my%20dir/inner.mp4" parentID="my%20dir/""#),
            "Browse {} must resolve space dir:\n{}",
            oid,
            b
        );
    }
    {
        let r = send_raw(TEST_IP, &browse_post("a&amp;amp;bdir/", 0)).await;
        let b = body_str(&r);
        assert!(b.contains("a&amp;amp;bdir/inner2.mp4"), "amp dir:\n{}", b);
    }
    // empty dir => valid envelope with 0 counts (not silent)
    {
        let r = send_raw(TEST_IP, &browse_post("empty/", 0)).await;
        let b = body_str(&r);
        assert!(b.contains("<NumberReturned>0</NumberReturned>"), "empty counts:\n{}", b);
        assert!(b.contains("<TotalMatches>0</TotalMatches>"));
    }
    // dynamic fallback: dir created AFTER startup is still browsable
    {
        std::fs::create_dir_all(media.join("newafter")).unwrap();
        std::fs::write(media.join("newafter").join("late.mp4"), b"L".repeat(33)).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let r = send_raw(TEST_IP, &browse_post("newafter/", 0)).await;
        let b = body_str(&r);
        assert!(b.contains("newafter/late.mp4"), "fallback browse:\n{}", b);
        assert!(b.contains("<NumberReturned>1</NumberReturned>"));
        // and directly streamable
        let g = send_raw(TEST_IP, &get_req("/newafter/late.mp4", None)).await;
        assert_eq!(split_response(&g).1, b"L".repeat(33));
    }
    // &eacute; entity round-trips through decode/encode
    {
        std::fs::create_dir_all(media.join("caf\u{00E9}")).unwrap();
        std::fs::write(media.join("caf\u{00E9}").join("song.mp4"), b"Z".repeat(7)).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let r = send_raw(TEST_IP, &browse_post("caf&eacute;/", 0)).await;
        let b = body_str(&r);
        assert!(b.contains("caf&eacute;/song.mp4"), "eacute browse:\n{}", b);
        let g = send_raw(TEST_IP, &get_req("/caf&eacute;/song.mp4", None)).await;
        assert_eq!(split_response(&g).1, b"Z".repeat(7), "eacute GET");
    }
    // ---- extended Browse quirks (same server) -------------------------------
    // POST path is IGNORED: /foo and / behave like /ctl/ContentDir.
    for path in ["/foo", "/"] {
        let r = send_raw(TEST_IP, &browse_post_to(path, "0")).await;
        assert_eq!(r, root_resp, "POST to {} must browse like control URL", path);
    }
    // "64$" strips to "" -> dynamic fallback listing the LIVE root dir
    // (NOT silent). Unlike the precached root_resp, the fallback reflects
    // dirs created after startup (newafter/, cafe/), so we assert containment
    // rather than byte equality. Verified by probe: same envelope, superset.
    {
        let r = send_raw(TEST_IP, &browse_post("64$", 0)).await;
        let b = body_str(&r);
        assert!(b.contains(r#"&lt;container id="movies/" parentID="/""#), "64$ fallback root:\n{}", b);
        assert!(b.contains(r#"&lt;item id="root.mp4" parentID="""#), "64$ has root item");
        // At least the 14 precached children must be present.
        assert!(b.contains("my%20movie.mp4") && b.contains("a&amp;amp;b.mp4"), "64$ has precached files");
        let r2 = send_raw(TEST_IP, &browse_post("64$64$0", 0)).await;
        assert_eq!(r2, root_resp, "double 64$ prefix strips once to cached 64$0");
    }
    // Explicitly empty <ObjectID></ObjectID> is silent (no SortCaps).
    {
        let r = send_raw(TEST_IP, &browse_post("", 0)).await;
        assert!(r.is_empty(), "empty ObjectID must be silent");
    }
    // Missing trailing slash falls to dynamic fallback with mangled ids:
    // path "movies" + name "apple.mp4" = "moviesapple.mp4" (no separator).
    {
        let r = send_raw(TEST_IP, &browse_post("movies", 0)).await;
        let b = body_str(&r);
        assert!(
            b.contains("moviesapple.mp4") && b.contains(r#"parentID="movies""#),
            "no-slash fallback must mangle ids:\n{}",
            b
        );
        assert_ne!(r, movies_resp, "movies without slash must differ from movies/");
    }
    // RequestedCount AND StartingIndex are both ignored (pre-cached).
    {
        let r_rc1 = send_raw(TEST_IP, &browse_post_custom("0", 0, 1)).await;
        assert_eq!(r_rc1, root_resp, "RequestedCount must be ignored");
        let r_si5 = send_raw(TEST_IP, &browse_post_custom("0", 5, 10)).await;
        assert_eq!(r_si5, root_resp, "StartingIndex 5 must be ignored");
    }
    // ObjectID beats GetSortCapabilities when both present.
    {
        let both = "<s:Envelope><s:Body><u:Browse><ObjectID>0</ObjectID></u:Browse><u:GetSortCapabilities/></s:Body></s:Envelope>";
        let req = format!(
            "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
            TEST_IP,
            both.len(),
            both
        );
        let r = send_raw(TEST_IP, req.as_bytes()).await;
        assert_eq!(r, root_resp, "ObjectID must win over SortCaps");
    }
    // Whitespace inside ObjectID is NOT trimmed -> cache miss + fs miss -> silent.
    {
        let body = "<s:Envelope><s:Body><ObjectID> 0 </ObjectID></s:Body></s:Envelope>";
        let req = format!(
            "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
            TEST_IP,
            body.len(),
            body
        );
        let r = send_raw(TEST_IP, req.as_bytes()).await;
        assert!(r.is_empty(), "' 0 ' with spaces must be silent");
    }
    // Method dispatch is case-sensitive: lowercase is silent.
    {
        let body = format!("<ObjectID>0</ObjectID>");
        let req = format!(
            "post /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n{}",
            TEST_IP,
            body.len(),
            body
        );
        let r = send_raw(TEST_IP, req.as_bytes()).await;
        assert!(r.is_empty(), "lowercase post must be silent");
    }

    // ---- SSDP / limits / connection quirks (same server) --------------------
    // SSDP exact template via 127.0.0.2 (unicast .1 hits the OS service).
    {
        let resp = ssdp_probe(TEST_IP).await;
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 200 OK"), "ssdp status: {}", s.lines().next().unwrap_or(""));
        for needle in [
            "CACHE-CONTROL: max-age=1800",
            "EXT:",
            &format!("LOCATION: http://{}:8200/rootDesc.xml", TEST_IP),
            "SERVER: DLNA/1.0 DLNADOC/1.50 UPnP/1.0 RustyDLNA7/1.3.0",
            "ST: urn:schemas-upnp-org:device:MediaServer:1",
            "USN: uuid:4d696e6e-444c-164e-9d41-b827eb96c6c2::urn:schemas-upnp-org:device:MediaServer:1",
        ] {
            assert!(s.contains(needle), "ssdp must contain {}", needle);
        }
        // Fixed size for 127.0.0.1 (LOCATION IP length determines total).
        assert_eq!(resp.len(), 295, "ssdp exact length for 127.0.0.1");
    }
    // >4096-byte headers overflow the stack buffer -> silent close (RST-safe).
    {
        let big = {
            let mut v = format!("GET /root.mp4 HTTP/1.1\r\nHost: {}\r\nX-Pad: ", TEST_IP).into_bytes();
            v.extend(std::iter::repeat(b'A').take(5000));
            v.extend_from_slice(b"\r\n\r\n");
            v
        };
        let r = send_raw(TEST_IP, &big).await;
        assert!(r.is_empty(), "5k headers must be silent, got {}b", r.len());
        // Server must still be alive afterwards.
        let r2 = send_raw(TEST_IP, &get_req("/root.mp4", None)).await;
        assert_eq!(split_response(&r2).1, root_mp4, "server must survive oversize");
    }
    // Split-packet POST (headers now, body later) gets NO reply: the server
    // never waits for the body past \r\n\r\n.
    {
        let body = b"<s:Envelope><s:Body><ObjectID>0</ObjectID></s:Body></s:Envelope>".to_vec();
        let headers = format!(
            "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n",
            TEST_IP,
            body.len()
        )
        .into_bytes();
        let r = send_split_post(TEST_IP, &headers, &body).await;
        assert!(r.is_empty(), "split POST must be silent, got {}b", r.len());
    }
    // Traversal can never escape: sibling file outside media stays hidden.
    {
        let outside = std::env::temp_dir().join(format!(
            "rustydlna_outside_{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&outside, b"SECRET-OUTSIDE").unwrap();
        let base = outside.file_name().unwrap().to_str().unwrap().to_string();
        // FIX #2: backslash / dot-variant climbs must also stay inside (404).
        // Extended: encoded/multi climbs, double-encoding, dot-variants,
        // drive/UNC absolutes, null/control/unicode, entity mixes.
        for path in [
            format!("/../{}", base),
            format!("/..%2F{}", base),
            format!("/..%5c{}", base),
            format!("/..\\{}", base),
            format!("/%2e%2e%5c{}", base),
            format!("/.../{}", base),
            format!("/..%2f..%2f{}", base),
            format!("/%2e%2e%2f{}", base),
            format!("/%2e%2e%5c..%5c{}", base),
            format!("/%252e%252e%2f{}", base),
            format!("/....//{}", base),
            format!("/..%2e/{}", base),
            format!("/.%2e/{}", base),
            format!("/..%20/{}", base),
            format!("/movies%2f..%2f..%2f{}", base),
            format!("/C:/{}", base),
            format!("/C%3a/{}", base),
            format!("//server/share/{}", base),
            format!("/%2fetc%2f{}", base),
            format!("/{}.mp4%00", base),
            format!("/{}%00/../{}", base, base),
            format!("/\u{FF0E}\u{FF0E}/{}", base),
            format!("/%c0%ae%c0%ae/{}", base),
            format!("/&amp;..%2f{}", base),
            format!("/{}%3f.mp4", base),
        ] {
            let r = send_raw(TEST_IP, &get_req(&path, None)).await;
            assert_eq!(
                r,
                b"HTTP/1.1 404 NOT FOUND\r\n\r\n".to_vec(),
                "escape {} must be 404",
                path
            );
            // And even if it ever returned 200, it must never contain the secret.
            assert!(
                !r.windows(b"SECRET-OUTSIDE".len())
                    .any(|w| w == b"SECRET-OUTSIDE"),
                "escape {} leaked bytes",
                path
            );
        }
        let _ = std::fs::remove_file(&outside);
    }
    // Large dynamic file (256 KiB, created after startup) streams exactly.
    {
        let big_bytes = vec![0xABu8; 262_144];
        std::fs::create_dir_all(media.join("bigafter")).unwrap();
        std::fs::write(media.join("bigafter").join("big.bin"), &big_bytes).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let r = send_raw(TEST_IP, &browse_post("bigafter/", 0)).await;
        assert!(body_str(&r).contains("bigafter/big.bin"), "big fallback browse");
        let g = send_raw(TEST_IP, &get_req("/bigafter/big.bin", None)).await;
        let (ghdr, gbody) = split_response(&g);
        assert_eq!(gbody, big_bytes, "256KiB must stream exactly");
        assert_eq!(parse_content_length(&ghdr), Some(262_144));
    }

    // ---- connection handling ----------------------------------------------
    // one request per connection (server closes; second request fails)
    {
        let mut s = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT))
            .await
            .unwrap();
        s.write_all(&get_req("/rootDesc.xml", None)).await.unwrap();
        let mut buf = vec![0u8; 8192];
        let mut total = Vec::new();
        let _ = timeout(Duration::from_secs(3), async {
            loop {
                match s.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        total.extend_from_slice(&buf[..n]);
                        if let Some(p) = find_double_crlf(&total) {
                            if let Some(cl) = parse_content_length(&total[..p]) {
                                if total.len() >= p + 4 + cl {
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
        assert!(!total.is_empty(), "first request must answer");
        // second request on the SAME socket must not be answered
        s.write_all(&get_req("/rootDesc.xml", None)).await.unwrap_or(());
        let second = timeout(Duration::from_secs(2), s.read(&mut buf)).await;
        match second {
            Err(_) => {} // timeout => no answer, good
            Ok(Ok(0)) => {} // clean close, good
            Ok(Ok(n)) => panic!("second request on same conn must not answer, got {} bytes", n),
            Ok(Err(_)) => {}
        }
    }
    // unknown method => silent close (PUT, HEAD, DELETE all silent: only GET/POST dispatch)
    for req in [
        b"PUT /root.mp4 HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        b"HEAD /root.mp4 HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        b"DELETE /root.mp4 HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
    ] {
        let r = send_raw(TEST_IP, &req).await;
        assert!(r.is_empty(), "{} must be silent", String::from_utf8_lossy(&req[..4]));
    }
    // garbage doesn't kill the server
    {
        let r = send_raw(TEST_IP, b"THIS IS NOT HTTP\r\n\r\n").await;
        assert!(r.is_empty(), "garbage should get no reply");
        let r2 = send_raw(TEST_IP, &get_req("/root.mp4", None)).await;
        assert_eq!(split_response(&r2).1, root_mp4, "server must survive garbage");
    }
    // concurrent load: 20 parallel GETs + 10 parallel POST browses all succeed
    {
        let mut handles = Vec::new();
        for _ in 0..20 {
            handles.push(tokio::spawn(send_raw_bytes(
                TEST_IP.to_string(),
                get_req("/root.mp4", None),
            )));
        }
        for h in handles {
            let resp = h.await.unwrap();
            assert_eq!(split_response(&resp).1, root_mp4, "concurrent GET mismatch");
        }
        let mut phandles = Vec::new();
        for _ in 0..10 {
            phandles.push(tokio::spawn(send_raw_bytes(
                TEST_IP.to_string(),
                browse_post("0", 0),
            )));
        }
        for h in phandles {
            let resp = h.await.unwrap();
            assert_eq!(resp, root_resp, "concurrent POST mismatch");
        }
    }

    // ---- second batch: POST fallback traversal, malformed IDs, static extras,
    //      range extras, pipelining, empty-conn, SSDP-any, SortCaps exact ------
    // FIX #1: POST fallback now sanitizes like GET. Browse "../" must stay
    // inside media (resolves to root) and must NEVER emit parent "../" ids.
    // Extended: encoded/multi climbs and dot-variants also resolve inside.
    for oid in ["../", "..%2F", "64$../", "%2e%2e/", "../../", "....//", ".../", "..%20/"] {
        let r = send_raw(TEST_IP, &browse_post(oid, 0)).await;
        let (hdr, body) = split_response(&r);
        assert!(
            String::from_utf8_lossy(&hdr).starts_with("HTTP/1.1 200 OK"),
            "Browse {} must stay inside (root), got no 200",
            oid
        );
        let b = String::from_utf8_lossy(&body);
        // Inside-media root listing: has precached markers, no parent escape.
        assert!(
            b.contains(r#"&lt;item id="root.mp4" parentID="""#),
            "Browse {} must resolve inside to root:\n{}",
            oid,
            b.chars().take(400).collect::<String>()
        );
        assert!(
            !b.contains("id=\"../") && !b.contains("..//"),
            "Browse {} must not leak parent ids:\n{}",
            oid,
            b.chars().take(400).collect::<String>()
        );
    }
    // Absolute-like "/etc/" stays inside media (media//etc/ missing) -> silent.
    {
        let r = send_raw(TEST_IP, &browse_post("/etc/", 0)).await;
        assert!(r.is_empty(), "/etc/ browse must be silent");
    }
    // Control/semicolon/drive/double-encoded ObjectIDs reference literal
    // missing dirs (never climb) -> silent.
    for oid in ["..%00/", "..;/", "C:/", "64$%252e%252e%2f", "%2e%2e%00/"] {
        let r = send_raw(TEST_IP, &browse_post(oid, 0)).await;
        assert!(r.is_empty(), "Browse {} must be silent (missing literal dir)", oid);
    }
    // FIX hardening: backslash / dot-variant / double-encoded ObjectIDs must
    // never leak parent. Backslash splits like '/' now; "..." collapses;
    // "%252e" double-decode is re-sanitized inside the fallback.
    {
        // Backslash climbs resolve inside (root) with no "../" or "\\" ids.
        for oid in ["..\\", "..%5c", "%2e%2e%5c", "..\\..\\", "%2e%2e%5c..%5c", "..%c0%af"] {
            let r = send_raw(TEST_IP, &browse_post(oid, 0)).await;
            // Either inside-root 200 or silent (if normalized to missing dir)
            // — but NEVER a parent listing with "../" or backslash ids.
            if r.is_empty() {
                continue;
            }
            let b = body_str(&r);
            assert!(!b.contains("id=\"../"), "backslash OID {} leaked parent", oid);
            assert!(!b.contains('\\'), "backslash OID {} leaked backslash", oid);
        }
        // Dot-variant "..." collapses inside, never parent.
        {
            let r = send_raw(TEST_IP, &browse_post(".../", 0)).await;
            if !r.is_empty() {
                let b = body_str(&r);
                assert!(!b.contains("id=\"../"), ".../ leaked parent");
            }
        }
        // Double-encoded "%252e%252e%2f" (-> "%2e%2e/" -> "../") must not escape:
        // either silent (missing "%2e%2e" dir) or inside-root, never parent.
        for oid in ["%252e%252e%2f", "%252e%252e%255c"] {
            let r = send_raw(TEST_IP, &browse_post(oid, 0)).await;
            if r.is_empty() {
                continue;
            }
            let b = body_str(&r);
            assert!(!b.contains("id=\"../"), "double-encoded {} leaked parent", oid);
        }
    }
    // ObjectID delimiters: need "ObjectID", then '>', then '<'. Missing '>'
    // is silent; missing proper close still extracts up to the NEXT '<'.
    {
        let no_gt = b"<s:Envelope><s:Body><ObjectID</s:Body></s:Envelope>".to_vec();
        let req = format!(
            "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
            TEST_IP,
            no_gt.len(),
            String::from_utf8_lossy(&no_gt)
        );
        assert!(send_raw(TEST_IP, req.as_bytes()).await.is_empty(), "ObjectID without '>' silent");
        // "<ObjectID>0" with no "</ObjectID>" still yields "0" (next '<' ends it).
        let no_close = b"<s:Envelope><s:Body><ObjectID>0</s:Body></s:Envelope>".to_vec();
        let req2 = format!(
            "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
            TEST_IP,
            no_close.len(),
            String::from_utf8_lossy(&no_close)
        );
        let r2 = send_raw(TEST_IP, req2.as_bytes()).await;
        // At this point dynamic dirs exist, so precached root_resp (14) may be
        // a subset; assert it contains the precached root markers instead.
        let b2 = body_str(&r2);
        assert!(b2.contains(r#"&lt;item id="root.mp4" parentID="""#), "unclosed OID still extracts 0");
        for oid in ["objectid", "getsortcapabilities"] {
            let lower = format!("<s:Envelope><s:Body><u:{}>x</u:{}></s:Body></s:Envelope>", oid, oid).into_bytes();
            let rq = format!(
                "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
                TEST_IP,
                lower.len(),
                String::from_utf8_lossy(&lower)
            );
            assert!(send_raw(TEST_IP, rq.as_bytes()).await.is_empty(), "lowercase {} silent", oid);
        }
    }
    // BrowseFlag/Filter/SortCriteria are ignored: BrowseMetadata == DirectChildren.
    {
        let meta_body = format!(
            "<?xml?><s:Envelope><s:Body><u:Browse><ObjectID>movies/</ObjectID><BrowseFlag>BrowseMetadata</BrowseFlag><Filter>*</Filter><StartingIndex>0</StartingIndex><RequestedCount>10</RequestedCount><SortCriteria></SortCriteria></u:Browse></s:Body></s:Envelope>"
        );
        let req = format!(
            "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
            TEST_IP,
            meta_body.len(),
            meta_body
        );
        assert_eq!(send_raw(TEST_IP, req.as_bytes()).await, movies_resp, "BrowseMetadata ignored");
    }
    // "64$nosuchdir/" strips then misses everywhere -> silent.
    {
        assert!(send_raw(TEST_IP, &browse_post("64$nosuchdir/", 0)).await.is_empty(), "64$ unknown silent");
    }
    // Static routes are exact raw-byte matches: query/slash/case/encoded all 404,
    // and Range is ignored (static path returns before range logic).
    for path in ["/rootDesc.xml?x=1", "/rootDesc.xml/", "/ROOTDESC.XML", "/%72ootDesc.xml"] {
        assert_eq!(
            send_raw(TEST_IP, &get_req(path, None)).await,
            b"HTTP/1.1 404 NOT FOUND\r\n\r\n".to_vec(),
            "static {} must be 404",
            path
        );
    }
    {
        let r = send_raw(TEST_IP, &get_req("/rootDesc.xml", Some("Range: bytes=5-"))).await;
        assert!(String::from_utf8_lossy(&split_response(&r).0).starts_with("HTTP/1.1 200 OK"), "static ignores Range");
    }
    // POST ignores path even for static-looking targets.
    {
        assert_eq!(
            send_raw(TEST_IP, &browse_post_to("/rootDesc.xml", "0")).await,
            root_resp,
            "POST to static path must still browse"
        );
    }
    // GET path edge: empty path, absolute URI, %00 all 404; %2F == '/'.
    for raw in [
        b"GET  HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        b"GET http://127.0.0.1:8200/root.mp4 HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        b"GET /root%00.mp4 HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
    ] {
        assert_eq!(send_raw(TEST_IP, &raw).await, b"HTTP/1.1 404 NOT FOUND\r\n\r\n".to_vec(), "GET edge 404: {:?}", &raw[..raw.len().min(30)]);
    }
    {
        assert_eq!(
            split_response(&send_raw(TEST_IP, &get_req("/movies%2Ffilm.mp4", None)).await).1,
            b"HELLOFILM".repeat(100),
            "%2F must act as slash"
        );
        // Lowercase hex works too.
        assert_eq!(
            split_response(&send_raw(TEST_IP, &get_req("/movies%2ffilm.mp4", None)).await).1,
            b"HELLOFILM".repeat(100),
            "lowercase %2f must work"
        );
    }
    // Range extras: space/overflow fall back to 0; multi-dash takes first;
    // uppercase/missing-space miss; first of two wins.
    for (hdr, expect_range) in [
        ("Range: bytes= 10-", "bytes 0-1023/1024"),
        ("Range: bytes=99999999999999999999-", "bytes 0-1023/1024"),
        ("Range: bytes=10-20-30", "bytes 10-1023/1024"),
        ("RANGE: bytes=5-", "bytes 0-1023/1024"),
        ("Range:bytes=5-", "bytes 0-1023/1024"),
    ] {
        let r = send_raw(TEST_IP, &get_req("/root.mp4", Some(hdr))).await;
        assert!(
            String::from_utf8_lossy(&split_response(&r).0).contains(&format!("Content-Range: {}", expect_range)),
            "{} -> {}, got {}",
            hdr,
            expect_range,
            String::from_utf8_lossy(&split_response(&r).0).lines().next().unwrap_or("")
        );
    }
    {
        let two = format!("GET /root.mp4 HTTP/1.1\r\nHost: {}\r\nRange: bytes=5-\r\nRange: bytes=900-\r\n\r\n", TEST_IP).into_bytes();
        let r = send_raw(TEST_IP, &two).await;
        assert!(String::from_utf8_lossy(&split_response(&r).0).contains("bytes 5-1023/1024"), "first Range wins");
    }
    // Pipelined second request on the SAME write is ignored (one req/conn).
    {
        let two = [get_req("/root.mp4", None), get_req("/movies/film.mp4", None)].concat();
        let r = send_raw(TEST_IP, &two).await;
        assert_eq!(split_response(&r).1, root_mp4, "pipelined must answer only first");
    }
    // Empty connection (connect+close, no bytes) must not kill the server.
    {
        let s = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT)).await.unwrap();
        drop(s);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(split_response(&send_raw(TEST_IP, &get_req("/root.mp4", None)).await).1, root_mp4, "alive after empty conn");
    }
    // 5s read timeout: partial headers with no terminator get closed with no reply.
    {
        let mut s = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT)).await.unwrap();
        s.write_all(b"GET /root.mp4 HTTP/1.1\r\nHost: x\r\nX-Wait: ").await.unwrap();
        // Server's timeout(Duration::from_secs(5), read) fires; allow margin.
        let mut buf = vec![0u8; 4096];
        let got = timeout(Duration::from_secs(8), s.read(&mut buf)).await;
        match got {
            Err(_) => panic!("slow-loris read never returned (server didn't time out)"),
            Ok(Ok(0)) => {} // clean close after timeout: expected
            Ok(Ok(n)) => panic!("slow-loris must get no bytes, got {}b", n),
            Ok(Err(_)) => {} // RST after timeout also acceptable
        }
        // And the server as a whole must still serve afterwards.
        assert_eq!(split_response(&send_raw(TEST_IP, &get_req("/root.mp4", None)).await).1, root_mp4, "alive after timeout");
    }
    // SSDP answers ANY datagram (even 1 byte / empty) from port 1900.
    {
        for payload in [vec![b'X'], vec![], b"M-SEARCH anything".to_vec()] {
            let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let target = "127.0.0.2:1900";
            let _ = sock.send_to(&payload, target).await;
            let mut buf = vec![0u8; 4096];
            let (n, src) = timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await.expect("ssdp any timeout").expect("ssdp recv");
            assert_eq!(src.port(), 1900, "ssdp src port");
            assert_eq!(&buf[..n], &ssdp_probe(TEST_IP).await[..], "ssdp any-payload same template");
        }
    }
    // SortCaps body is EXACTLY XML_CAPS from source (not just substring).
    {
        let src = include_str!("../src/main.rs");
        let marker = "const XML_CAPS: &str = r#\"";
        let start = src.find(marker).expect("XML_CAPS const") + marker.len();
        let end = src[start..].find("\"#;").expect("XML_CAPS end") + start;
        let expected = &src[start..end];
        let body = "<s:Envelope><s:Body><u:GetSortCapabilities xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\"></u:GetSortCapabilities></s:Body></s:Envelope>";
        let req = format!("POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}", TEST_IP, body.len(), body);
        let r = send_raw(TEST_IP, req.as_bytes()).await;
        assert_eq!(body_str(&r), expected, "SortCaps body must equal XML_CAPS const");
    }
    // Static bodies are EXACTLY the consts from source (bake_static adds only headers).
    {
        let src = include_str!("../src/main.rs");
        let pairs = [
            ("CONTENT_DIR_XML", "/ContentDir.xml"),
            ("CONNECTION_MGR_XML", "/ConnectionMgr.xml"),
            ("ROOT_DESC_XML", "/rootDesc.xml"),
            ("X_MS_MEDIA_RECEIVER_REGISTRAR_XML", "/X_MS_MediaReceiver_Registrar.xml"),
        ];
        for (name, path) in pairs {
            let marker = format!("const {}: &str = r#\"", name);
            let start = src.find(&marker).unwrap_or_else(|| panic!("{} const", name)) + marker.len();
            let end = src[start..].find("\"#;").unwrap_or_else(|| panic!("{} end", name)) + start;
            let expected = &src[start..end];
            let live = body_str(&send_raw(TEST_IP, &get_req(path, None)).await);
            assert_eq!(live, expected, "{} body must equal const", path);
        }
    }

    // ---- user-agent / ignored headers (same server) --------------------------
    // The server never sniffs User-Agent (no such code): DLNA TVs, consoles,
    // VLC, curl, empty and 2 KiB UAs must all be byte-identical to baseline.
    {
        let baseline_get = send_raw(TEST_IP, &get_req("/root.mp4", None)).await;
        for ua in [
            "VLC/3.0.20 LibVLC/3.0.20",
            "Linux/5.0 UPnP/1.0 DLNADOC/1.50 Samsung-TV/1.0",
            "Xbox-One/2.0",
            "curl/8.0",
            "PLAYSTATION 3; DLNADOC/1.50",
        ] {
            let req = format!(
                "GET /root.mp4 HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\n\r\n",
                TEST_IP, ua
            );
            assert_eq!(
                send_raw(TEST_IP, req.as_bytes()).await,
                baseline_get,
                "User-Agent {} must be ignored",
                ua
            );
        }
        // 2 KiB UA still fits the 4096 stack buffer -> identical.
        {
            let long_ua = "A".repeat(2000);
            let req = format!(
                "GET /root.mp4 HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\n\r\n",
                TEST_IP, long_ua
            );
            assert_eq!(send_raw(TEST_IP, req.as_bytes()).await, baseline_get, "2KiB UA ignored");
        }
        // Static route + POST browse are equally UA-blind.
        {
            let baseline_static = send_raw(TEST_IP, &get_req("/rootDesc.xml", None)).await;
            let req = format!("GET /rootDesc.xml HTTP/1.1\r\nHost: {}\r\nUser-Agent: Samsung-TV\r\n\r\n", TEST_IP);
            assert_eq!(send_raw(TEST_IP, req.as_bytes()).await, baseline_static, "static+UA identical");
            let body = "<s:Envelope><s:Body><ObjectID>0</ObjectID></s:Body></s:Envelope>";
            let with_ua = format!(
                "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nUser-Agent: VLC/3.0\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
                TEST_IP,
                body.len(),
                body
            );
            let without_ua = format!(
                "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
                TEST_IP,
                body.len(),
                body
            );
            assert_eq!(
                send_raw(TEST_IP, with_ua.as_bytes()).await,
                send_raw(TEST_IP, without_ua.as_bytes()).await,
                "POST+UA identical"
            );
        }
    }
    // Host is never validated: missing or lowercase Host still serves.
    {
        let baseline = send_raw(TEST_IP, &get_req("/root.mp4", None)).await;
        assert_eq!(
            send_raw(TEST_IP, b"GET /root.mp4 HTTP/1.1\r\n\r\n").await,
            baseline,
            "missing Host must still serve"
        );
        let lower = format!("GET /root.mp4 HTTP/1.1\r\nhost: {}\r\n\r\n", TEST_IP).into_bytes();
        assert_eq!(send_raw(TEST_IP, &lower).await, baseline, "lowercase host ignored");
    }
    // POST ignores Content-Type and Content-Length (reads only to \\r\\n\\r\\n).
    {
        let body = "<s:Envelope><s:Body><ObjectID>0</ObjectID></s:Body></s:Envelope>";
        let baseline = send_raw(
            TEST_IP,
            format!(
                "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
                TEST_IP,
                body.len(),
                body
            )
            .as_bytes(),
        )
        .await;
        for (label, req) in [
            ("no-CT", format!("POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n{}", TEST_IP, body.len(), body)),
            ("text/plain", format!("POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}", TEST_IP, body.len(), body)),
            ("lying-0", format!("POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nContent-Type: text/xml\r\n\r\n{}", TEST_IP, body)),
            ("lying-99999", format!("POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: 99999\r\nContent-Type: text/xml\r\n\r\n{}", TEST_IP, body)),
        ] {
            assert_eq!(send_raw(TEST_IP, req.as_bytes()).await, baseline, "POST {} ignored", label);
        }
    }
    // Only GET/POST dispatch: UPnP/HTTP extras are silent.
    for method in ["OPTIONS", "SUBSCRIBE", "NOTIFY", "UNSUBSCRIBE", "PATCH"] {
        let req = format!("{} /root.mp4 HTTP/1.1\r\nHost: {}\r\n\r\n", method, TEST_IP);
        assert!(
            send_raw(TEST_IP, req.as_bytes()).await.is_empty(),
            "{} must be silent",
            method
        );
    }
    // HTTP version is never checked.
    {
        let baseline = send_raw(TEST_IP, &get_req("/root.mp4", None)).await;
        for version in ["HTTP/2", "HTTP/2.0", "HTTP/0.9", "HTTP/9.9"] {
            let req = format!("GET /root.mp4 {}\r\nHost: {}\r\n\r\n", version, TEST_IP);
            assert_eq!(send_raw(TEST_IP, req.as_bytes()).await, baseline, "{} ignored", version);
        }
    }
    // Header order / extras never matter (byte-scan for Range, Host unchecked).
    {
        let baseline = send_raw(TEST_IP, &get_req("/root.mp4", Some("Range: bytes=10-"))).await;
        let swapped = format!("GET /root.mp4 HTTP/1.1\r\nRange: bytes=10-\r\nHost: {}\r\n\r\n", TEST_IP);
        assert_eq!(send_raw(TEST_IP, swapped.as_bytes()).await, baseline, "Range-before-Host same");
        let extra = format!(
            "GET /root.mp4 HTTP/1.1\r\nHost: {}\r\nX-Custom: foo\r\nAccept: */*\r\nAccept-Language: en\r\nConnection: close\r\n\r\n",
            TEST_IP
        );
        assert_eq!(
            send_raw(TEST_IP, extra.as_bytes()).await,
            send_raw(TEST_IP, &get_req("/root.mp4", None)).await,
            "extra headers ignored"
        );
    }

    // ---- request framing / path / range / OID extras (same server) ------------
    // Split GET across packets still accumulates (pos += n) and serves.
    {
        let mut s = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT)).await.unwrap();
        s.write_all(b"GET /root.mp4 HTTP/1.1\r\nHost: x\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        s.write_all(b"X-A: b\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 32768];
        let mut out = Vec::new();
        let _ = timeout(Duration::from_secs(4), async {
            loop {
                match s.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        out.extend_from_slice(&buf[..n]);
                        if let Some(p) = find_double_crlf(&out) {
                            if let Some(cl) = parse_content_length(&out[..p]) {
                                if out.len() >= p + 4 + cl {
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
        assert_eq!(split_response(&out).1, root_mp4, "split GET must serve full");
    }
    // Split terminator (\r\n + \n across packets) still matches windows(4).
    {
        let mut s = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT)).await.unwrap();
        s.write_all(b"GET /root.mp4 HTTP/1.1\r\nHost: x\r\n\r").await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        s.write_all(b"\n").await.unwrap();
        let mut buf = vec![0u8; 32768];
        let mut out = Vec::new();
        let _ = timeout(Duration::from_secs(4), async {
            loop {
                match s.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        out.extend_from_slice(&buf[..n]);
                        if let Some(p) = find_double_crlf(&out) {
                            if let Some(cl) = parse_content_length(&out[..p]) {
                                if out.len() >= p + 4 + cl {
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
        assert_eq!(split_response(&out).1, root_mp4, "split terminator must serve");
    }
    // Partial headers completed well under 5s must still serve (positive timeout).
    {
        let mut s = TcpStream::connect(format!("{}:{}", TEST_IP, TCP_PORT)).await.unwrap();
        s.write_all(b"GET /root.mp4 HTTP/1.1\r\nHost: x\r\nX-Wait: ").await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        s.write_all(b"done\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 32768];
        let mut out = Vec::new();
        let _ = timeout(Duration::from_secs(4), async {
            loop {
                match s.read(&mut buf).await {
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
        assert_eq!(split_response(&out).1, root_mp4, "1s-delayed rest must serve");
    }
    // Exact-4096 request WITH terminator at the end succeeds (terminator wins
    // over the pos==len guard); 4096 bytes with NO terminator is silent.
    {
        let base = format!("GET /root.mp4 HTTP/1.1\r\nHost: {}\r\nX-Pad: ", TEST_IP).into_bytes();
        let mut exact = base.clone();
        exact.extend(std::iter::repeat(b'C').take(4096 - base.len() - 4));
        exact.extend_from_slice(b"\r\n\r\n");
        assert_eq!(exact.len(), 4096);
        assert_eq!(split_response(&send_raw(TEST_IP, &exact).await).1, root_mp4, "exact-4096 with terminator serves");
        let mut no_term = base.clone();
        no_term.extend(std::iter::repeat(b'D').take(4096 - base.len()));
        assert_eq!(no_term.len(), 4096);
        assert!(send_raw(TEST_IP, &no_term).await.is_empty(), "4096 without terminator silent");
    }
    // Path quirks: trailing slash on a FILE still serves ("" component skipped),
    // over-pop beyond root cannot panic (pop on empty is a no-op), dots and
    // multi-slashes collapse, %2E acts as '.', %66 hex letters decode.
    {
        assert_eq!(split_response(&send_raw(TEST_IP, &get_req("/root.mp4/", None)).await).1, root_mp4, "trailing slash on file serves");
        assert_eq!(split_response(&send_raw(TEST_IP, &get_req("/../../root.mp4", None)).await).1, root_mp4, "over-pop serves");
        assert_eq!(
            split_response(&send_raw(TEST_IP, &get_req("/./movies/./film.mp4", None)).await).1,
            b"HELLOFILM".repeat(100),
            "embedded dots serve"
        );
        assert_eq!(
            split_response(&send_raw(TEST_IP, &get_req("//movies///film.mp4", None)).await).1,
            b"HELLOFILM".repeat(100),
            "multi-slash serves"
        );
        assert_eq!(
            split_response(&send_raw(TEST_IP, &get_req("/movies/film%2Emp4", None)).await).1,
            b"HELLOFILM".repeat(100),
            "%2E must decode to dot"
        );
        assert_eq!(
            split_response(&send_raw(TEST_IP, &get_req("/movies/%66ilm.mp4", None)).await).1,
            b"HELLOFILM".repeat(100),
            "%66 must decode to 'f'"
        );
    }
    // Range number quirks: leading zeros ok, Rust u64 accepts '+', trailing
    // space fails the parse and falls back to 0.
    for (hdr, expect_range, expect_len) in [
        ("Range: bytes=00010-", "bytes 10-1023/1024", 1014),
        ("Range: bytes=+10-", "bytes 10-1023/1024", 1014),
        ("Range: bytes=10 -", "bytes 0-1023/1024", 1024),
    ] {
        let r = send_raw(TEST_IP, &get_req("/root.mp4", Some(hdr))).await;
        let (h, b) = split_response(&r);
        assert!(
            String::from_utf8_lossy(&h).contains(&format!("Content-Range: {}", expect_range)),
            "{} -> {}",
            hdr,
            expect_range
        );
        assert_eq!(b.len(), expect_len, "{} body len", hdr);
    }
    // ObjectID tolerates attributes: <ObjectID foo="bar"> still extracts.
    {
        let body = "<s:Envelope><s:Body><ObjectID foo=\"bar\">movies/</ObjectID></s:Body></s:Envelope>";
        let req = format!(
            "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
            TEST_IP,
            body.len(),
            body
        );
        assert_eq!(send_raw(TEST_IP, req.as_bytes()).await, movies_resp, "OID attributes ignored");
    }
    // ObjectID value "GetSortCapabilities" is just an unknown ID -> silent
    // (non-empty object_id beats the SortCaps branch).
    {
        let body = "<s:Envelope><s:Body><ObjectID>GetSortCapabilities</ObjectID></s:Body></s:Envelope>";
        let req = format!(
            "POST /ctl/ContentDir HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
            TEST_IP,
            body.len(),
            body
        );
        assert!(send_raw(TEST_IP, req.as_bytes()).await.is_empty(), "OID=SortCaps silent");
    }
    // Nested no-slash fallback mangles by concatenation (suite media HAS action/).
    {
        let r = send_raw(TEST_IP, &browse_post("movies/action", 0)).await;
        let b = body_str(&r);
        assert!(b.contains("movies/actiondeep.mp4"), "nested no-slash mangling:\n{}", b.chars().take(300).collect::<String>());
        assert!(b.contains("<NumberReturned>1</NumberReturned>"), "nested no-slash count");
    }
    // Double slash is normalized to single slash in fallback ids (fix: sanitize).
    {
        let b = body_str(&send_raw(TEST_IP, &browse_post("movies//", 0)).await);
        assert!(b.contains("movies/film.mp4"), "double-slash normalized:\n{}", b.chars().take(300).collect::<String>());
        assert!(!b.contains("movies//film.mp4"), "must not preserve double slash:\n{}", b.chars().take(300).collect::<String>());
    }
    // HEAD to a static path is silent too (only GET serves statics).
    {
        let req = format!("HEAD /rootDesc.xml HTTP/1.1\r\nHost: {}\r\n\r\n", TEST_IP);
        assert!(send_raw(TEST_IP, req.as_bytes()).await.is_empty(), "HEAD static silent");
    }
    // Server binds exactly local_ip:8200, not 0.0.0.0 (sibling IP refuses).
    {
        let refused = timeout(Duration::from_secs(2), TcpStream::connect("127.0.0.2:8200")).await;
        assert!(
            !matches!(refused, Ok(Ok(_))),
            "127.0.0.2:8200 must refuse while bound to 127.0.0.1"
        );
    }

    // ---- shutdown phase 1 + startup logs -------------------------------------
    // kill and collect output to verify pre-cache messages.
    // Phase-1 media has exactly 6 dirs: root, movies, movies/action,
    // my dir, a&bdir, empty.
    child.kill().await.expect("kill server");
    let out = timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("wait server exit")
        .expect("output");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Pre-cache complete."),
        "stdout must log pre-cache, got: {}",
        stdout.chars().take(500).collect::<String>()
    );
    assert!(
        stdout.contains("6 directories loaded into memory."),
        "phase-1 must precache 6 dirs, got: {}",
        stdout.chars().take(500).collect::<String>()
    );

    // ---- phase 2: empty media server (sequential, same ports) ----------------
    // Proves a fresh/empty library still binds and serves an empty DIDL.
    tokio::time::sleep(Duration::from_millis(800)).await; // let 1900/8200 release
    {
        let empty_media = media_dir("empty-phase2");
        std::fs::create_dir_all(&empty_media).unwrap();
        let empty_s = empty_media.to_str().unwrap().to_string();
        let mut child2 = tokio::process::Command::new(bin)
            .arg(TEST_IP)
            .arg(&empty_s)
            .arg(MULTICAST_IP)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn empty-media server");
        wait_for_tcp(TEST_IP).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        let r = send_raw(TEST_IP, &browse_post("0", 0)).await;
        let b = body_str(&r);
        assert!(b.contains("<NumberReturned>0</NumberReturned>"), "empty media root 0:\n{}", b);
        assert!(b.contains("<TotalMatches>0</TotalMatches>"));
        let g = send_raw(TEST_IP, &get_req("/anything.mp4", None)).await;
        assert_eq!(g, b"HTTP/1.1 404 NOT FOUND\r\n\r\n".to_vec(), "empty media GET 404");
        // SSDP still advertises the same IP while empty.
        let ssdp = ssdp_probe(TEST_IP).await;
        assert!(String::from_utf8_lossy(&ssdp).contains(&format!("LOCATION: http://{}:8200/rootDesc.xml", TEST_IP)));
        child2.kill().await.expect("kill empty server");
        let out2 = timeout(Duration::from_secs(5), child2.wait_with_output())
            .await
            .expect("wait empty server")
            .expect("output");
        let stdout2 = String::from_utf8_lossy(&out2.stdout);
        assert!(
            stdout2.contains("1 directories loaded into memory."),
            "empty media must precache 1 dir, got: {}",
            stdout2.chars().take(500).collect::<String>()
        );
        rm_rf(&empty_media);
    }

    rm_rf(&media);
    // let TIME_WAIT drain before any later bind in this process
    tokio::time::sleep(Duration::from_millis(500)).await;
}

async fn send_raw_bytes(ip: String, req: Vec<u8>) -> Vec<u8> {
    send_raw(&ip, &req).await
}
