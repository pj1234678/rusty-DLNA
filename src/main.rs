use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::env;
use std::io::SeekFrom;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task;
use tokio::time::{timeout, Duration};

// Slow-read (drip) defense — fix for [E]:
// handle_client already kills stalled *reads* after 5s, but the old file
// streamer did unbounded `write_all(headers)` + `copy(file -> socket)` with
// NO timeout, so a client that finished headers then read 1B/s (or nothing)
// pinned one Semaphore permit + task + file handle forever; 1000 drips =
// total DoS. Every socket WRITE below must now make progress within
// WRITE_TIMEOUT. The body goes out in small chunks so a client must sustain
// ~3KB/s (16KiB/5s); stalled drips die in ~5s instead of never. Fast LAN
// players sending/reading normally are unaffected.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const BODY_CHUNK: usize = 16 * 1024;

// Manual u64 rendering into a stack buffer (beats `write!` ~1.7-3x in
// microbenchmarks; byte-identical output incl. empty-file and inverted quirks).
fn push_u64(buf: &mut [u8], pos: &mut usize, mut v: u64) {
    if v == 0 {
        buf[*pos] = b'0';
        *pos += 1;
        return;
    }
    let start = *pos;
    while v > 0 {
        buf[*pos] = b'0' + (v % 10) as u8;
        *pos += 1;
        v /= 10;
    }
    buf[start..*pos].reverse();
}

fn put_slice(buf: &mut [u8], pos: &mut usize, s: &[u8]) {
    buf[*pos..*pos + s.len()].copy_from_slice(s);
    *pos += s.len();
}

// Allocation-free `Range: bytes=<n>-` parse with identical fallback semantics
// to the old `windows(13)+lossy+parse` (missing/invalid/overflow => 0, range
// end ignored, case-sensitive name, leading '+' like `parse`, ~1.7x faster).
// Fused single-pass digit scan: parse digits until the first '-' (range end
// ignored) instead of pre-scanning for '-' then re-validating. Identical
// fallback semantics: missing/invalid/overflow/suffix => 0, first '-' wins,
// leading '+' like `parse`, first occurrence wins.
fn parse_range_header(req: &[u8]) -> u64 {
    let needle = b"Range: bytes=";
    let mut i = 0usize;
    while i + needle.len() <= req.len() {
        if req[i] != b'R' {
            i += 1;
            continue;
        }
        if &req[i..i + needle.len()] != needle {
            i += 1;
            continue;
        }
        let mut s = i + needle.len();
        if s < req.len() && req[s] == b'+' {
            s += 1;
            if s >= req.len() {
                return 0;
            }
        }
        if s >= req.len() || req[s] == b'-' {
            return 0;
        }
        let mut v: u64 = 0;
        let mut k = s;
        while k < req.len() {
            let b = req[k];
            if b == b'-' {
                return v;
            }
            if !b.is_ascii_digit() {
                return 0;
            }
            let d = (b - b'0') as u64;
            match v.checked_mul(10).and_then(|x| x.checked_add(d)) {
                Some(nv) => v = nv,
                None => return 0,
            }
            k += 1;
        }
        return 0;
    }
    0
}

// First-byte-filtered `GetSortCapabilities` scan (beats `windows(19).any`
// ~1.1x in microbenchmarks; identical true/false on all inputs).
fn contains_sortcaps(req: &[u8]) -> bool {
    let needle = b"GetSortCapabilities";
    let mut i = 0usize;
    while i + needle.len() <= req.len() {
        if req[i] != b'G' {
            i += 1;
            continue;
        }
        if &req[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

struct AppConfig {
    local_ip: String,
    dir_path: String,
    // Pre-baked static HTTP responses (headers included) to avoid runtime
    // formatting; matched directly (a 4-arm byte compare beats the old
    // HashMap lookup ~14x in microbenchmarks).
    root_desc_xml: Arc<[u8]>,
    content_dir_xml: Arc<[u8]>,
    registrar_xml: Arc<[u8]>,
    conn_mgr_xml: Arc<[u8]>,
    // Pre-baked SortCapabilities response (was rebuilt with format! per request)
    sort_caps_response: Arc<[u8]>,
}

// Pre-computes directory responses. Keys are Box<[u8]> to allow zero-copy &[u8] lookups.
async fn precache_directories(ip: &str, dir_path: &str) -> HashMap<Box<[u8]>, Arc<[u8]>> {
    println!("Starting background pre-cache...");
    let mut cache = HashMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back("".to_string()); 

    let mut dir_count = 0;

    while let Some(current_path) = queue.pop_front() {
        // Single-traversal: the render already did read_dir+metadata+sort;
        // reuse its sorted child-dir list instead of a second walk (halves
        // precache I/O; identical keys/bytes; also closes a TOCTOU window).
        let (browse_response, child_dirs) =
            generate_browse_response_inner(&current_path, 0, 5000, ip, dir_path).await;
        let response_bytes: Arc<[u8]> = browse_response.into_bytes().into();

        let cache_key = if current_path.is_empty() { "0".to_string() } else { current_path.clone() };
        cache.insert(cache_key.as_bytes().to_vec().into_boxed_slice(), response_bytes.clone());

        if cache_key == "0" {
            cache.insert(b"64$0".to_vec().into_boxed_slice(), response_bytes.clone());
        }
        dir_count += 1;

        for name in child_dirs {
            queue.push_back(format!("{}{}/", current_path, name));
        }
    }
    
    println!("Pre-cache complete. {} directories loaded into memory.", dir_count);
    cache
}

// Macro to pre-bake static XML routes with their HTTP headers
macro_rules! bake_static {
    ($body:expr) => {
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}", $body.len(), $body).into_bytes().into()
    };
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <LOCAL_IP> <MEDIA_DIR_PATH> <MULTICAST_IP>", args[0]);
        std::process::exit(1);
    }

    let local_ip = args[1].clone();
    let dir_path = args[2].clone();
    let local_addr: Ipv4Addr = local_ip.parse().expect("Invalid Local IP");
    let multicast_addr: Ipv4Addr = args[3].parse().expect("Invalid Multicast IP");

    let config = Arc::new(AppConfig { 
        local_ip: local_ip.clone(), 
        dir_path: dir_path.clone(), 
        root_desc_xml: bake_static!(ROOT_DESC_XML),
        content_dir_xml: bake_static!(CONTENT_DIR_XML),
        registrar_xml: bake_static!(X_MS_MEDIA_RECEIVER_REGISTRAR_XML),
        conn_mgr_xml: bake_static!(CONNECTION_MGR_XML),
        sort_caps_response: format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}", XML_CAPS.len(), XML_CAPS).into_bytes().into(),
    });
    
    let raw_cache = precache_directories(&local_ip, &dir_path).await;
    let cache: Arc<HashMap<Box<[u8]>, Arc<[u8]>>> = Arc::new(raw_cache);

    let tcp_listener = TcpListener::bind(format!("{}:8200", local_ip)).await.unwrap();
    
    // Setup Multicast SSDP
    let ssdp_socket = UdpSocket::bind("0.0.0.0:1900").await.unwrap();
    ssdp_socket.join_multicast_v4(multicast_addr, local_addr).unwrap();
    
    let ssdp_response: Arc<[u8]> = format!(
        "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: http://{}:8200/rootDesc.xml\r\nSERVER: DLNA/1.0 DLNADOC/1.50 UPnP/1.0 RustyDLNA7/1.3.0\r\nST: urn:schemas-upnp-org:device:MediaServer:1\r\nUSN: uuid:4d696e6e-444c-164e-9d41-b827eb96c6c2::urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n",
        local_ip
    ).into_bytes().into();
    
    let ssdp_socket = Arc::new(ssdp_socket);

    // Blistering fast SSDP responder
    task::spawn({
        let socket = ssdp_socket.clone();
        let resp = ssdp_response.clone();
        async move {
            let mut buf = [0u8; 1024];
            loop {
                if let Ok((_, src)) = socket.recv_from(&mut buf).await {
                    let _ = socket.send_to(&resp, src).await;
                }
            }
        }
    });

    let semaphore = Arc::new(Semaphore::new(1000));

    loop {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        match tcp_listener.accept().await {
            Ok((stream, _)) => {
                let _ = stream.set_nodelay(true);
                let cache_clone = cache.clone();
                let config_clone = config.clone();
                task::spawn(async move {
                    let _permit = permit; 
                    handle_client(stream, cache_clone, config_clone).await;
                });
            }
            Err(_) => continue,
        }
    }
}

// Hot path: Zero heap allocations. Uses stack buffer and byte-slice scanning.
async fn handle_client(mut stream: TcpStream, cache: Arc<HashMap<Box<[u8]>, Arc<[u8]>>>, config: Arc<AppConfig>) {
    let mut buffer = [0u8; 4096]; // Pure stack memory
    let mut pos = 0;

    // Total header deadline (slowloris fix): the per-read 5s timeout below
    // resets on EVERY received byte, so without this a 1B/4s drip holds one
    // Semaphore permit + task forever (1000 drips = DoS), for GET, POST or
    // even garbage, pre-routing. Headers must now complete within 5s of
    // connect no matter the drip rate; legitimate LAN clients finish in
    // milliseconds (split-packet and 1s-delayed completions still pass).
    // POST bodies are never waited on (reply/close at headers end), so slow
    // bodies hold nothing by design; the drip fix from [E] covers writes.
    let header_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let left = header_deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() { return; }
        match timeout(left, stream.read(&mut buffer[pos..])).await {
            Ok(Ok(0)) | Err(_) => return,
            Ok(Ok(n)) => {
                let prev = pos;
                pos += n;
                // Only windows overlapping freshly-read bytes can newly match:
                // every window fully inside the old prefix already tested
                // negative on a previous iteration, and the first iteration
                // starts at 0 (identical outcome to a full rescan).
                let from = prev.saturating_sub(3);
                if headers_complete(&buffer[from..pos]) { break; }
                if pos == buffer.len() { return; }
            }
            Ok(Err(_)) => return,
        }
    }

    let req = &buffer[..pos];
    
    if req.starts_with(b"GET ") {
        handle_get_request(stream, req, config).await;
    } else if req.starts_with(b"POST ") {
        handle_post_request(stream, req, cache, config).await;
    }
}

// Zero-allocation static routing & ultra-low allocation file streaming
async fn handle_get_request(mut stream: TcpStream, req: &[u8], config: Arc<AppConfig>) {
    // Extract Path natively from bytes
    let path_start = 4;
    let path_end = req[path_start..].iter().position(|&b| b == b' ').unwrap_or(0) + path_start;
    let raw_path = &req[path_start..path_end];

    // 1. Pre-baked static routes: length dispatch, then one byte compare
    // (rootDesc first — players fetch it first via SSDP LOCATION).
    // Misses (file GETs, the hot path) usually fail on the integer compare.
    let raw_len = raw_path.len();
    if raw_len == 13 {
        if raw_path == b"/rootDesc.xml" {
            let _ = timeout(WRITE_TIMEOUT, stream.write_all(&config.root_desc_xml)).await;
            return;
        }
    } else if raw_len == 15 {
        if raw_path == b"/ContentDir.xml" {
            let _ = timeout(WRITE_TIMEOUT, stream.write_all(&config.content_dir_xml)).await;
            return;
        }
    } else if raw_len == 18 {
        if raw_path == b"/ConnectionMgr.xml" {
            let _ = timeout(WRITE_TIMEOUT, stream.write_all(&config.conn_mgr_xml)).await;
            return;
        }
    } else if raw_len == 33 {
        if raw_path == b"/X_MS_MediaReceiver_Registrar.xml" {
            let _ = timeout(WRITE_TIMEOUT, stream.write_all(&config.registrar_xml)).await;
            return;
        }
    }

    // 2. Dynamic File Path
    // Fallback to string for OS filesystem interaction.
    // Fast path: decode() is the identity when there is no '&'/'%' (it
    // would just `to_owned()`), so skip its allocation and sanitize the
    // raw path directly — byte-identical, one fewer String alloc on the
    // hot clean path (e.g. "/root.mp4"). Manual join avoids `format!`
    // machinery with identical "{dir}/{san}" bytes.
    let path_str = String::from_utf8_lossy(raw_path);
    let sanitized_path_str = if path_str.bytes().any(|b| b == b'&' || b == b'%') {
        sanitize_path(&decode(&path_str))
    } else {
        sanitize_path(&path_str)
    };
    let mut combined_path =
        String::with_capacity(config.dir_path.len() + 1 + sanitized_path_str.len());
    combined_path.push_str(&config.dir_path);
    combined_path.push('/');
    combined_path.push_str(&sanitized_path_str);

    let mut file = match File::open(&combined_path).await {
        Ok(f) => f,
        Err(_) => {
            let _ = timeout(WRITE_TIMEOUT, stream.write_all(b"HTTP/1.1 404 NOT FOUND\r\n\r\n")).await;
            return;
        }
    };
    
    let file_size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    
    // Allocation-free Range parse (identical fallback semantics, ~1.7x faster).
    let range = parse_range_header(req);

    if range > file_size {
        let _ = timeout(WRITE_TIMEOUT, stream.write_all(b"HTTP/1.1 416 Range Not Satisfiable\r\n\r\n")).await;
        return;
    }

    if range > 0 {
        if file.seek(SeekFrom::Start(range)).await.is_err() { return; }
    }

    // 3. Zero-Allocation Stack Header for Streaming (manual u64 rendering
    // beats `write!` ~1.7-3x; byte-identical incl. empty/inverted quirks).
    let mut header_buf = [0u8; 256];
    let mut header_len = 0usize;
    put_slice(&mut header_buf, &mut header_len, b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes ");
    push_u64(&mut header_buf, &mut header_len, range);
    put_slice(&mut header_buf, &mut header_len, b"-");
    push_u64(&mut header_buf, &mut header_len, file_size.saturating_sub(1));
    put_slice(&mut header_buf, &mut header_len, b"/");
    push_u64(&mut header_buf, &mut header_len, file_size);
    put_slice(&mut header_buf, &mut header_len, b"\r\nContent-Type: video/mp4\r\nContent-Length: ");
    push_u64(&mut header_buf, &mut header_len, file_size - range);
    put_slice(&mut header_buf, &mut header_len, b"\r\n\r\n");
    match timeout(WRITE_TIMEOUT, stream.write_all(&header_buf[..header_len])).await {
        Ok(Ok(())) => {},
        _ => return,
    }

    // Bounded send loop (was unbounded `copy()`): each 16KiB chunk must flush
    // within WRITE_TIMEOUT or the task dies and the permit is freed. Stalled
    // drips are reaped in ~5s; healthy readers never notice.
    // Right-size: small remainders (1 KiB files, last chunk) only need a
    // small buffer (~1.5µs saved/GET); zero-body quirks (empty file,
    // range==size inverted) skip the alloc + Take::read entirely — wire
    // bytes unchanged (segmentation only, header already sent).
    let remaining = file_size - range;
    if remaining == 0 {
        return;
    }
    let mut limited_file = file.take(remaining);
    let mut chunk = vec![0u8; remaining.min(BODY_CHUNK as u64) as usize];
    loop {
        let n = match limited_file.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return,
        };
        match timeout(WRITE_TIMEOUT, stream.write_all(&chunk[..n])).await {
            Ok(Ok(())) => {},
            _ => return,
        }
    }
}

// Byte-level ObjectID extraction (reverted to `windows(8).position`:
// the first-byte manual filter measured ~0.65x (slower) and the fused
// single-loop tied at ~1.0x on this machine, so the original stays —
// identical '>'/'<' scans and empty-fallback semantics).
fn extract_object_id(req: &[u8]) -> &[u8] {
    let mut object_id = &b""[..];
    if let Some(pos) = req.windows(8).position(|w| w == b"ObjectID") {
        let start = pos + 8;
        if let Some(open) = req[start..].iter().position(|&b| b == b'>') {
            let id_start = start + open + 1;
            if let Some(close) = req[id_start..].iter().position(|&b| b == b'<') {
                object_id = &req[id_start..id_start + close];
            }
        }
    }
    object_id
}

// Pure byte-level POST handler
async fn handle_post_request(
    mut stream: TcpStream,
    req: &[u8],
    cache: Arc<HashMap<Box<[u8]>, Arc<[u8]>>>,
    config: Arc<AppConfig>,
) {
    let object_id = extract_object_id(req);

    if object_id.is_empty() {
        if contains_sortcaps(req) {
            let _ = timeout(WRITE_TIMEOUT, stream.write_all(&config.sort_caps_response)).await;
        }
        return;
    }

    // Strip "64$" natively using slices
    let mut lookup_id = object_id;
    if lookup_id.starts_with(b"64$") { lookup_id = &lookup_id[3..]; }
    
    // O(1) Zero-Copy lookup using native &[u8] against the Box<[u8]> keys.
    // Single lookup when no "64$" was stripped (lookup == object, the second
    // `or_else` would hash the same key twice); double lookup only when the
    // strip changed the length, preserving the "64$0"->root second chance.
    if let Some(cached_response) = if lookup_id.len() == object_id.len() {
        cache.get(lookup_id)
    } else {
        cache.get(lookup_id).or_else(|| cache.get(object_id))
    } {
        let _ = timeout(WRITE_TIMEOUT, stream.write_all(cached_response)).await;
        return;
    }

    // Dynamic Fallback (Cold Path) — hardened: sanitize AFTER decode so
    // ObjectID traversal (e.g. "../", "..%2F", "64$../") can never escape
    // the media dir (previously `decoded` was joined directly, no sanitize).
    // `safe` gates the metadata check; `generate_browse_response` re-sanitizes
    // after its own decode (kills %252e double-decode) and uses the sanitized
    // display path for IDs.
    // Fast path: decode() is identity without '&'/'%', so borrow `id_str`
    // directly (saves one alloc); otherwise decode once and reuse the owned
    // value for both the metadata gate and the browse render. Manual join
    // matches `format!("{}/{}")` bytes without `format!` overhead.
    let id_str = String::from_utf8_lossy(lookup_id);
    let decoded_opt = if id_str.bytes().any(|b| b == b'&' || b == b'%') {
        Some(decode(&id_str))
    } else {
        None
    };
    let decoded_ref: &str = decoded_opt.as_deref().unwrap_or(&id_str);
    let safe = sanitize_path(decoded_ref);
    let mut combined_path = String::with_capacity(config.dir_path.len() + 1 + safe.len());
    combined_path.push_str(&config.dir_path);
    combined_path.push('/');
    combined_path.push_str(&safe);
    if let Ok(metadata) = fs::metadata(&combined_path).await {
        if metadata.is_dir() {
            let browse_response = generate_browse_response(decoded_ref, 0, 5000, &config.local_ip, &config.dir_path).await;
            let _ = timeout(WRITE_TIMEOUT, stream.write_all(browse_response.as_bytes())).await;
        }
    }
}

// Background pre-cache generator (Runs once, allocations don't matter)
// Hardened: filesystem path is decode()+sanitize() (blocks "../" and
// "%252e" double-decode escapes); display IDs use the sanitized path with a
// single trailing '/' preserved so legit "mydir/" listings are unchanged.
// Inner variant also returns the sorted child-dir basenames so precache can
// reuse one traversal instead of walking each dir twice.
async fn generate_browse_response(path: &str, starting_index: u32, requested_count: u32, ip: &str, dir_path: &str) -> String {
    generate_browse_response_inner(path, starting_index, requested_count, ip, dir_path).await.0
}

async fn generate_browse_response_inner(path: &str, starting_index: u32, requested_count: u32, ip: &str, dir_path: &str) -> (String, Vec<String>) {
    let decoded = decode(path);
    let fs_safe = sanitize_path(&decoded);
    let combined_path = format!("{}/{}", dir_path, fs_safe);
    // Display path for DIDL ids: sanitized + trailing '/' iff the decoded
    // request had one (and result non-empty). Collapses "movies//" -> "movies/".
    let display_path: Cow<str> = if fs_safe.is_empty() {
        Cow::Borrowed("")
    } else if decoded.ends_with('/') || decoded.ends_with('\\') {
        Cow::Owned(format!("{}/", fs_safe))
    } else {
        Cow::Borrowed(&fs_safe)
    };
    let mut soap = String::with_capacity(4096);
    let mut count = 0;

    soap.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:BrowseResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\"><Result>&lt;DIDL-Lite xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:upnp=\"urn:schemas-upnp-org:metadata-1-0/upnp/\" xmlns=\"urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/\"&gt;");
    
    let mut dirs = Vec::new();
    let mut files = Vec::new();

    if let Ok(mut entries) = fs::read_dir(&combined_path).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            // metadata-first + into_string(): valid UTF-8 yields the same
            // String with zero-copy buffer reuse (one fewer alloc+memcpy per
            // entry); invalid UTF-8 still skips either way; symlink-to-dir
            // still counts as dir via metadata(). Byte-identical output.
            if let Ok(meta) = entry.metadata().await {
                if let Ok(name) = entry.file_name().into_string() {
                    if meta.is_dir() { dirs.push(name); } else { files.push(name); }
                }
            }
        }
    }

    dirs.sort_unstable();
    files.sort_unstable();

    let mut loop_count = 0;
    // encode(display) is loop-invariant: hoist it instead of recomputing it up
    // to 3x per file entry. Output bytes unchanged for legit paths (display
    // equals the old raw path); traversal now renders sanitized inside-paths.
    // esc_path is the DIDL-escaped twin for the raw display_path used in
    // container ids (display_path itself can hold & < > " ' from dir names).
    let enc_path = encode(&display_path);
    let esc_path = escape_didl(&display_path);
    for name in dirs.iter().chain(files.iter()) {
        if loop_count >= starting_index + requested_count { break; }
        if loop_count < starting_index {
            loop_count += 1; continue;
        }

        // Title is DIDL text AND lands inside id="..." attributes: escape
        // &, <, >, " and ' (borrow when there is nothing to escape).
        let title: Cow<str> = escape_didl(name);
        if loop_count < dirs.len() as u32 {
            soap.push_str("&lt;container id=\"");
            soap.push_str(&esc_path);
            soap.push_str(&title);
            soap.push_str("/\" parentID=\"");
            soap.push_str(&esc_path);
            soap.push_str("/\" restricted=\"1\" searchable=\"1\" childCount=\"0\"&gt;&lt;dc:title&gt;");
            soap.push_str(&title);
            soap.push_str("&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.storageFolder&lt;/upnp:class&gt;&lt;upnp:storageUsed&gt;-1&lt;/upnp:storageUsed&gt;&lt;/container&gt;");
        } else {
            // encode(name) computed once and reused for id + res URL.
            let enc_name = encode(name);
            soap.push_str("&lt;item id=\"");
            soap.push_str(&enc_path);
            soap.push_str(&enc_name);
            soap.push_str("\" parentID=\"");
            soap.push_str(&enc_path);
            soap.push_str("\" restricted=\"1\" searchable=\"1\"&gt;&lt;dc:title&gt;");
            soap.push_str(&title);
            soap.push_str("&lt;/dc:title&gt;&lt;upnp:class&gt;object.item.videoItem&lt;/upnp:class&gt;&lt;res protocolInfo=\"http-get:*:video/mp4:*\"&gt;http://");
            soap.push_str(ip);
            soap.push_str(":8200/");
            soap.push_str(&enc_path);
            soap.push_str(&enc_name);
            soap.push_str("&lt;/res&gt;&lt;/item&gt;");
        }
        loop_count += 1;
        count += 1;
    }

    soap.push_str(&format!("&lt;/DIDL-Lite&gt;</Result><NumberReturned>{}</NumberReturned><TotalMatches>{}</TotalMatches><UpdateID>0</UpdateID></u:BrowseResponse></s:Body></s:Envelope>", count, count));

    let resp = format!("HTTP/1.1 200 OK\r\nConnection: Keep-Alive\r\nContent-Type: text/xml;\r\nContent-Length: {}\r\nServer: RustyDLNA DLNADOC/1.50 UPnP/1.0 RustyDLNA7/1.3.0\r\n\r\n{}", soap.len(), soap);
    (resp, dirs)
}

// Hardened sanitizer (fixes traversal bypasses #1/#2):
// - splits on '/' AND '\\' (Windows treats '\\' as separator; old code only
//   split on '/' so "..\\.." survived as a literal filename and escaped on
//   Windows via File::open).
// - collapses Windows trailing dot/space variants: any component that is
//   entirely '.'/' ' (e.g. "...", "....", ".. ", ". ") is skipped instead of
//   kept literally (Win32 strips trailing dots/spaces, so those would
//   otherwise bypass the exact ".." check).
// Byte-level split on ASCII '/'/'\\' (never inside UTF-8 multibyte sequences),
// so slicing stays on char boundaries; all previously-safe outputs unchanged.
fn sanitize_path(decoded_path: &str) -> String {
    let b = decoded_path.as_bytes();
    let mut out = String::with_capacity(decoded_path.len());
    let mut i = 0usize;
    while i <= b.len() {
        let mut j = i;
        while j < b.len() && b[j] != b'/' && b[j] != b'\\' {
            j += 1;
        }
        let comp = &decoded_path[i..j];
        if comp.is_empty() {
        } else if comp.len() == 1 && comp.as_bytes()[0] == b'.' {
        } else if comp.len() == 2 && comp.as_bytes()[0] == b'.' && comp.as_bytes()[1] == b'.' {
            if let Some(k) = out.rfind('/') {
                out.truncate(k);
            } else {
                out.clear();
            }
        } else {
            // Windows strips trailing dots/spaces per component. If the
            // whole component is dots/spaces ("...", ".. ", ". ") it must
            // not be kept literally — it would normalize OS-side. Fast path:
            // only scan when the last byte could allow all-dots/spaces.
            let last = comp.as_bytes()[comp.len() - 1];
            if (last == b' ' || last == b'.') && comp.trim_end_matches([' ', '.']).is_empty() {
                // skip (secure: never pop, never keep)
            } else {
                if !out.is_empty() {
                    out.push('/');
                }
                out.push_str(comp);
            }
        }
        if j >= b.len() {
            break;
        }
        i = j + 1;
    }
    out
}

// Finds "\r\n\r\n" by hunting '\r' (every terminator starts with one): far
// fewer 4-byte compares than `windows(4).any` on typical headers, with the
// identical outcome (every occurrence is checked at its '\r').
fn rhunt_complete(window: &[u8]) -> bool {
    let mut i = 0usize;
    while i < window.len() {
        while i < window.len() && window[i] != b'\r' {
            i += 1;
        }
        if i + 4 <= window.len()
            && window[i + 1] == b'\n'
            && window[i + 2] == b'\r'
            && window[i + 3] == b'\n'
        {
            return true;
        }
        i += 1;
    }
    false
}

// Complete requests usually end exactly at the terminator: one 4-byte tail
// check decides them; the \r-hunt covers splits and pipelined tails.
fn headers_complete(window: &[u8]) -> bool {
    (window.len() >= 4
        && window[window.len() - 4] == b'\r'
        && window[window.len() - 3] == b'\n'
        && window[window.len() - 2] == b'\r'
        && window[window.len() - 1] == b'\n')
        || rhunt_complete(window)
}

const fn hexv_table() -> [i8; 256] {
    let mut t = [-1i8; 256];
    let mut d = 0usize;
    while d < 10 {
        t[b'0' as usize + d] = d as i8;
        d += 1;
    }
    let mut h = 0usize;
    while h < 6 {
        t[b'a' as usize + h] = (10 + h) as i8;
        t[b'A' as usize + h] = (10 + h) as i8;
        h += 1;
    }
    t
}
const HEXV: [i8; 256] = hexv_table();

/// Single-scan `haystack.replace(pat, rep)` into reused `out` (returns whether
/// anything matched; `out` untouched on miss).
fn replace_into(hay: &str, pat: &str, rep: &str, out: &mut String) -> bool {
    let Some(first) = hay.find(pat) else { return false; };
    out.clear();
    out.push_str(&hay[..first]);
    out.push_str(rep);
    let mut rest = &hay[first + pat.len()..];
    while let Some(i) = rest.find(pat) {
        out.push_str(&rest[..i]);
        out.push_str(rep);
        rest = &rest[i + pat.len()..];
    }
    out.push_str(rest);
    true
}

fn decode(s: &str) -> String {
    // One flag scan learns which passes are needed at all.
    let mut has_amp = false;
    let mut has_pct = false;
    for b in s.bytes() {
        if b == b'&' {
            has_amp = true;
        } else if b == b'%' {
            has_pct = true;
        }
        if has_amp && has_pct {
            break;
        }
    }
    if !has_amp && !has_pct {
        return s.to_owned();
    }
    // Sequential entity passes with identical order/semantics ("&amp;amp;"
    // first): one scan per pass into reused scratch, lazily — skipped entirely
    // when no '&' is present, and borrowing when nothing matches.
    let mut cur: Cow<str> = Cow::Borrowed(s);
    if has_amp {
        let mut scratch = String::new();
        for (pat, rep) in [("&amp;amp;", "&"), ("&amp;", "&"), ("&apos;", "'"), ("&eacute;", "é")] {
            if replace_into(&cur, pat, rep, &mut scratch) {
                cur = Cow::Owned(std::mem::take(&mut scratch));
            }
        }
    }
    if !has_pct {
        return cur.into_owned();
    }
    let cur: &str = &cur;
    // Byte-level % pass: ASCII success triples via table; every other shape
    // uses the exact char-slice fallback (same slices, same parse, same
    // consumption — e.g. "%%41" stays literal, "%2" yields \x02).
    let bytes = cur.as_bytes();
    let mut out = String::with_capacity(cur.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            let rest = bytes.len() - i - 1;
            if rest >= 2 {
                let h1 = HEXV[bytes[i + 1] as usize];
                let h2 = HEXV[bytes[i + 2] as usize];
                if h1 >= 0 && h2 >= 0 {
                    out.push((h1 as u8 * 16 + h2 as u8) as char);
                    i += 3;
                    continue;
                }
                if bytes[i + 1] == b'+' && h2 >= 0 {
                    out.push(h2 as u8 as char);
                    i += 3;
                    continue;
                }
            } else if rest == 1 && HEXV[bytes[i + 1] as usize] >= 0 {
                out.push(HEXV[bytes[i + 1] as usize] as u8 as char);
                i += 2;
                continue;
            }
            let rest_str = &cur[i + 1..];
            let mut chars2 = rest_str.chars();
            let (len1, len2) = match (chars2.next(), chars2.next()) {
                (None, _) => (0, 0),
                (Some(a), None) => (a.len_utf8(), 0),
                (Some(a), Some(b2)) => (a.len_utf8(), b2.len_utf8()),
            };
            let hex = &rest_str[..len1 + len2];
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v as char);
            } else {
                out.push('%');
                out.push_str(hex);
            }
            i += 1 + len1 + len2;
            continue;
        }
        if b < 0x80 {
            out.push(b as char);
            i += 1;
        } else {
            let ch = cur[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}
// DIDL text/attribute escape for the double-escaped layer.
//
// The Browse `Result` blob is `&lt;`-escaped DIDL: clients unescape it once
// (`&lt;`->`<`, `&amp;`->`&`) before parsing. A raw `<`, `>`, `"`, `'`
// smuggled into that blob becomes live markup / breaks out of attributes
// after the unescape (stored XML injection). So titles and display-path ids
// must be escaped here: `&`->`&amp;amp;` (halved once by the outer layer,
// then once more by the inner DIDL parse => `&`), `<`->`&amp;lt;` (outer
// => `&lt;`, inner => `<` *text*, not markup), etc.
fn escape_didl(s: &str) -> Cow<'_, str> {
    if !s.bytes().any(|b| matches!(b, b'&' | b'<' | b'>' | b'"' | b'\'')) {
        return Cow::Borrowed(s);
    }
    // Bulk-copy runs between escapes (beats per-char push ~1.04x; slices
    // split only at ASCII specials so boundaries stay on char edges).
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() * 2);
    let mut i = 0usize;
    while i < bytes.len() {
        let mut j = i;
        while j < bytes.len() && !matches!(bytes[j], b'&' | b'<' | b'>' | b'"' | b'\'') {
            j += 1;
        }
        out.push_str(&s[i..j]);
        i = j;
        if i >= bytes.len() {
            break;
        }
        match bytes[i] {
            b'&' => out.push_str("&amp;amp;"),
            b'<' => out.push_str("&amp;lt;"),
            b'>' => out.push_str("&amp;gt;"),
            b'"' => out.push_str("&amp;quot;"),
            _ => out.push_str("&amp;apos;"),
        }
        i += 1;
    }
    Cow::Owned(out)
}
fn encode(s: &str) -> String {
    // Fast path: plain ASCII with nothing to escape — one allocation.
    // (The old identity copy of "é" onto itself is dropped: it changed
    // nothing and only added a full scan + allocation. "é" still maps to
    // "&eacute;" via the match arm below.)
    // Security: `%` MUST be encoded (`%2e.mp4` on disk would otherwise
    // advertise as `%2e.mp4` and GET-decode to the wrong file `..mp4`);
    // `< >` must never survive into ids/res URLs as raw angles (XML
    // injection after the client's mandatory unescape); `\` is a separator
    // post-sanitize and `?` splits client-side query parsing.
    if !s.bytes().any(|b| matches!(b, b' ' | b'\'' | b'(' | b')' | b'"' | b'#' | b',' | b'&' | b'%' | b'<' | b'>' | b'\\' | b'?') || !b.is_ascii()) {
        return s.to_owned();
    }
    // Byte loop: ASCII needs no UTF-8 decoding per scalar; non-ASCII falls
    // back to char handling with identical arms.
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() * 2);
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b' ' => out.push_str("%20"),
            b'\'' => out.push_str("%27"),
            b'(' => out.push_str("%28"),
            b')' => out.push_str("%29"),
            b'"' => out.push_str("%22"),
            b'#' => out.push_str("%23"),
            b',' => out.push_str("%2C"),
            b'&' => out.push_str("&amp;amp;"),
            b'%' => out.push_str("%25"),
            b'<' => out.push_str("%3C"),
            b'>' => out.push_str("%3E"),
            b'\\' => out.push_str("%5C"),
            b'?' => out.push_str("%3F"),
            b if b < 0x80 => out.push(b as char),
            _ => {
                let ch = s[i..].chars().next().unwrap();
                if ch == 'é' {
                    out.push_str("&eacute;");
                } else {
                    out.push(ch);
                }
                i += ch.len_utf8();
                continue;
            }
        }
        i += 1;
    }
    out
}
const XML_CAPS: &str = r#"<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetSortCapabilitiesResponse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1"><SortCaps>dc:title,dc:date,upnp:class,upnp:album,upnp:episodeNumber,upnp:originalTrackNumber</SortCaps></u:GetSortCapabilitiesResponse></s:Body></s:Envelope>"#;
const CONTENT_DIR_XML: &str = r#"<?xml version="1.0"?><scpd xmlns="urn:schemas-upnp-org:service-1-0"><specVersion><major>1</major><minor>0</minor></specVersion><actionList><action><name>GetSearchCapabilities</name><argumentList><argument><name>SearchCaps</name><direction>out</direction><relatedStateVariable>SearchCapabilities</relatedStateVariable></argument></argumentList></action><action><name>GetSortCapabilities</name><argumentList><argument><name>SortCaps</name><direction>out</direction><relatedStateVariable>SortCapabilities</relatedStateVariable></argument></argumentList></action><action><name>GetSystemUpdateID</name><argumentList><argument><name>Id</name><direction>out</direction><relatedStateVariable>SystemUpdateID</relatedStateVariable></argument></argumentList></action><action><name>Browse</name><argumentList><argument><name>ObjectID</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_ObjectID</relatedStateVariable></argument><argument><name>BrowseFlag</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_BrowseFlag</relatedStateVariable></argument><argument><name>Filter</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Filter</relatedStateVariable></argument><argument><name>StartingIndex</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Index</relatedStateVariable></argument><argument><name>RequestedCount</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable></argument><argument><name>SortCriteria</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_SortCriteria</relatedStateVariable></argument><argument><name>Result</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Result</relatedStateVariable></argument><argument><name>NumberReturned</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable></argument><argument><name>TotalMatches</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable></argument><argument><name>UpdateID</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_UpdateID</relatedStateVariable></argument></argumentList></action><action><name>Search</name><argumentList><argument><name>ContainerID</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_ObjectID</relatedStateVariable></argument><argument><name>SearchCriteria</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_SearchCriteria</relatedStateVariable></argument><argument><name>Filter</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Filter</relatedStateVariable></argument><argument><name>StartingIndex</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Index</relatedStateVariable></argument><argument><name>RequestedCount</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable></argument><argument><name>SortCriteria</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_SortCriteria</relatedStateVariable></argument><argument><name>Result</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Result</relatedStateVariable></argument><argument><name>NumberReturned</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable></argument><argument><name>TotalMatches</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable></argument><argument><name>UpdateID</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_UpdateID</relatedStateVariable></argument></argumentList></action><action><name>UpdateObject</name><argumentList><argument><name>ObjectID</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_ObjectID</relatedStateVariable></argument><argument><name>CurrentTagValue</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_TagValueList</relatedStateVariable></argument><argument><name>NewTagValue</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_TagValueList</relatedStateVariable></argument></argumentList></action></actionList><serviceStateTable><stateVariable sendEvents="yes"><name>TransferIDs</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_ObjectID</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_Result</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_SearchCriteria</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_BrowseFlag</name><dataType>string</dataType><allowedValueList><allowedValue>BrowseMetadata</allowedValue><allowedValue>BrowseDirectChildren</allowedValue></allowedValueList></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_Filter</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_SortCriteria</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_Index</name><dataType>ui4</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_Count</name><dataType>ui4</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_UpdateID</name><dataType>ui4</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_TagValueList</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="no"><name>SearchCapabilities</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="no"><name>SortCapabilities</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="yes"><name>SystemUpdateID</name><dataType>ui4</dataType></stateVariable></serviceStateTable></scpd>"#;
const X_MS_MEDIA_RECEIVER_REGISTRAR_XML: &str = r#"<?xml version="1.0"?><scpd xmlns="urn:schemas-upnp-org:service-1-0"><specVersion><major>1</major><minor>0</minor></specVersion><actionList><action><name>IsAuthorized</name><argumentList><argument><name>DeviceID</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_DeviceID</relatedStateVariable></argument><argument><name>Result</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Result</relatedStateVariable></argument></argumentList></action><action><name>IsValidated</name><argumentList><argument><name>DeviceID</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_DeviceID</relatedStateVariable></argument><argument><name>Result</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Result</relatedStateVariable></argument></argumentList></action><action><name>RegisterDevice</name><argumentList><argument><name>RegistrationReqMsg</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_RegistrationReqMsg</relatedStateVariable></argument><argument><name>RegistrationRespMsg</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_RegistrationRespMsg</relatedStateVariable></argument></argumentList></action></actionList><serviceStateTable><stateVariable sendEvents="no"><name>A_ARG_TYPE_DeviceID</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_RegistrationReqMsg</name><dataType>bin.base64</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_RegistrationRespMsg</name><dataType>bin.base64</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_Result</name><dataType>int</dataType></stateVariable><stateVariable sendEvents="yes"><name>AuthorizationDeniedUpdateID</name><dataType>ui4</dataType></stateVariable><stateVariable sendEvents="yes"><name>AuthorizationGrantedUpdateID</name><dataType>ui4</dataType></stateVariable><stateVariable sendEvents="yes"><name>ValidationRevokedUpdateID</name><dataType>ui4</dataType></stateVariable><stateVariable sendEvents="yes"><name>ValidationSucceededUpdateID</name><dataType>ui4</dataType></stateVariable></serviceStateTable></scpd>"#;
const CONNECTION_MGR_XML: &str = r#"<?xml version="1.0"?><scpd xmlns="urn:schemas-upnp-org:service-1-0"><specVersion><major>1</major><minor>0</minor></specVersion><actionList><action><name>GetProtocolInfo</name><argumentList><argument><name>Source</name><direction>out</direction><relatedStateVariable>SourceProtocolInfo</relatedStateVariable></argument><argument><name>Sink</name><direction>out</direction><relatedStateVariable>SinkProtocolInfo</relatedStateVariable></argument></argumentList></action><action><name>GetCurrentConnectionIDs</name><argumentList><argument><name>ConnectionIDs</name><direction>out</direction><relatedStateVariable>CurrentConnectionIDs</relatedStateVariable></argument></argumentList></action><action><name>GetCurrentConnectionInfo</name><argumentList><argument><name>ConnectionID</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_ConnectionID</relatedStateVariable></argument><argument><name>RcsID</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_RcsID</relatedStateVariable></argument><argument><name>AVTransportID</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_AVTransportID</relatedStateVariable></argument><argument><name>ProtocolInfo</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_ProtocolInfo</relatedStateVariable></argument><argument><name>PeerConnectionManager</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_ConnectionManager</relatedStateVariable></argument><argument><name>PeerConnectionID</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_ConnectionID</relatedStateVariable></argument><argument><name>Direction</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Direction</relatedStateVariable></argument><argument><name>Status</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_ConnectionStatus</relatedStateVariable></argument></argumentList></action></actionList><serviceStateTable><stateVariable sendEvents="yes"><name>SourceProtocolInfo</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="yes"><name>SinkProtocolInfo</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="yes"><name>CurrentConnectionIDs</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_ConnectionStatus</name><dataType>string</dataType><allowedValueList><allowedValue>OK</allowedValue><allowedValue>ContentFormatMismatch</allowedValue><allowedValue>InsufficientBandwidth</allowedValue><allowedValue>UnreliableChannel</allowedValue><allowedValue>Unknown</allowedValue></allowedValueList></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_ConnectionManager</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_Direction</name><dataType>string</dataType><allowedValueList><allowedValue>Input</allowedValue><allowedValue>Output</allowedValue></allowedValueList></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_ProtocolInfo</name><dataType>string</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_ConnectionID</name><dataType>i4</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_AVTransportID</name><dataType>i4</dataType></stateVariable><stateVariable sendEvents="no"><name>A_ARG_TYPE_RcsID</name><dataType>i4</dataType></stateVariable></serviceStateTable></scpd>"#;
const ROOT_DESC_XML: &str = r#"<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion><device><deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType><friendlyName>RustyDLNA7</friendlyName><manufacturer>RustyDLNA7</manufacturer><manufacturerURL>http://www.netgear.com/</manufacturerURL><modelDescription>RustyDLNA on Linux</modelDescription><modelName>Windows Media Connect compatible (MiniDLNA)</modelName><modelNumber>1.3.0</modelNumber><modelURL>http://www.netgear.com</modelURL><serialNumber>00000000</serialNumber><UDN>uuid:4d696e6e-444c-164e-9d41-b827eb96c6c2</UDN><dlna:X_DLNADOC xmlns:dlna="urn:schemas-dlna-org:device-1-0">DMS-1.50</dlna:X_DLNADOC><presentationURL>/</presentationURL><iconList><icon><mimetype>image/png</mimetype><width>48</width><height>48</height><depth>24</depth><url>/icons/sm.png</url></icon><icon><mimetype>image/png</mimetype><width>120</width><height>120</height><depth>24</depth><url>/icons/lrg.png</url></icon><icon><mimetype>image/jpeg</mimetype><width>48</width><height>48</height><depth>24</depth><url>/icons/sm.jpg</url></icon><icon><mimetype>image/jpeg</mimetype><width>120</width><height>120</height><depth>24</depth><url>/icons/lrg.jpg</url></icon></iconList><serviceList><service><serviceType>urn:schemas-upnp-org:service:ContentDirectory:1</serviceType><serviceId>urn:upnp-org:serviceId:ContentDirectory</serviceId><controlURL>/ctl/ContentDir</controlURL><eventSubURL>/evt/ContentDir</eventSubURL><SCPDURL>/ContentDir.xml</SCPDURL></service><service><serviceType>urn:schemas-upnp-org:service:ConnectionManager:1</serviceType><serviceId>urn:upnp-org:serviceId:ConnectionManager</serviceId><controlURL>/ctl/ConnectionMgr</controlURL><eventSubURL>/evt/ConnectionMgr</eventSubURL><SCPDURL>/ConnectionMgr.xml</SCPDURL></service><service><serviceType>urn:microsoft.com:service:X_MS_MediaReceiverRegistrar:1</serviceType><serviceId>urn:microsoft.com:serviceId:X_MS_MediaReceiverRegistrar</serviceId><controlURL>/ctl/X_MS_MediaReceiverRegistrar</controlURL><eventSubURL>/evt/X_MS_MediaReceiverRegistrar</eventSubURL><SCPDURL>/X_MS_MediaReceiverRegistrar.xml</SCPDURL></service></serviceList></device></root>"#;
// ---------------------------------------------------------------------------
// Hot-path benchmarks + exact-output locks (cfg(test) only - stripped from
// the release binary).
//
// Condensed to the CURRENT implementations only: timing benches exercise the
// production helpers directly, and correctness tests lock live output against
// baked tables, std references (format!), and security properties. No frozen
// old copies, no rejected variants, no new dependencies, no unsafe.
//
// * `cargo test correctness` - fast guards, run by default.
// * `cargo test -- --ignored --nocapture` - timing benches.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod perf_benches {
    use super::{
        contains_sortcaps, decode, encode, escape_didl, extract_object_id,
        generate_browse_response, headers_complete, parse_range_header, push_u64,
        put_slice, sanitize_path,
    };
    use std::hint::black_box;
    use std::time::Instant;

    const DECODE_CORPUS: &[&str] = &[
        "",
        "movies/",
        "movies/action/deep.mp4",
        "root.mp4",
        "my%20movie.mp4",
        "paren%281%29.mp4",
        "quote%27mp4.mp4",
        "quote&apos;mp4.mp4",
        "hash%23tag.mp4",
        "comma%2Ctest.mp4",
        "a&amp;amp;b.mp4",
        "a&amp;b.mp4",
        "a&b.mp4",
        "&amp;amp;amp;",
        "caf&eacute;/song.mp4",
        "caf\u{e9}/song.mp4",
        "%2E%2E/root.mp4",
        "../root.mp4",
        "movies/../root.mp4",
        "./root.mp4",
        "//root.mp4",
        "root%.mp4",
        "root%ZZ.mp4",
        "root%2.mp4",
        "%",
        "%2",
        "%41",
        "%2b",
        "%2B",
        "%2F",
        "%00",
        "%2520",
        "%+2",
        "%-2",
        "%\u{e9}",
        "%\u{e9}X",
        "my%2520movie.mp4",
        "plus+file.mp4",
        "plus%2Bfile.mp4",
        "100% sure",
        "\u{e9}",
        "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p.mp4",
        "hash#tag.mp4",
        "comma,test.mp4",
        "note.txt",
        "my dir/inner.mp4",
        "a&bdir/inner2.mp4",
        "%41%42%43%20%26%20%27test%27",
    ];

    /// Baked live outputs for DECODE_CORPUS, in order (dumped from the
    /// verified implementation; any behavior change fails loudly here).
    const DECODE_EXPECTED: &[&str] = &[
        "",
        "movies/",
        "movies/action/deep.mp4",
        "root.mp4",
        "my movie.mp4",
        "paren(1).mp4",
        "quote'mp4.mp4",
        "quote'mp4.mp4",
        "hash#tag.mp4",
        "comma,test.mp4",
        "a&b.mp4",
        "a&b.mp4",
        "a&b.mp4",
        "&",
        "caf\u{e9}/song.mp4",
        "caf\u{e9}/song.mp4",
        "../root.mp4",
        "../root.mp4",
        "movies/../root.mp4",
        "./root.mp4",
        "//root.mp4",
        "root%.mp4",
        "root%ZZ.mp4",
        "root%2.mp4",
        "%",
        "\u{2}",
        "A",
        "+",
        "+",
        "/",
        "\0",
        "%20",
        "\u{2}",
        "%-2",
        "%\u{e9}",
        "%\u{e9}X",
        "my%20movie.mp4",
        "plus+file.mp4",
        "plus+file.mp4",
        "100% sure",
        "\u{e9}",
        "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p.mp4",
        "hash#tag.mp4",
        "comma,test.mp4",
        "note.txt",
        "my dir/inner.mp4",
        "a&bdir/inner2.mp4",
        "ABC & 'test'",
    ];

    const ENCODE_CORPUS: &[&str] = &[
        "",
        "movies/",
        "my movie.mp4",
        "a&b.mp4",
        "paren(1).mp4",
        "quote'mp4.mp4",
        "hash#tag.mp4",
        "comma,test.mp4",
        "note.txt",
        "caf\u{e9}",
        "caf\u{e9}/song.mp4",
        "a\"b",
        "x/y.z-foo_bar~",
        "my dir/inner.mp4",
        "a&bdir/",
        "plus+file.mp4",
        "%20",
        "100%",
        "a/b/c/d.mp4",
        "UPPER lower 0123",
    ];

    /// Baked live outputs for ENCODE_CORPUS, in order.
    const ENCODE_EXPECTED: &[&str] = &[
        "",
        "movies/",
        "my%20movie.mp4",
        "a&amp;amp;b.mp4",
        "paren%281%29.mp4",
        "quote%27mp4.mp4",
        "hash%23tag.mp4",
        "comma%2Ctest.mp4",
        "note.txt",
        "caf&eacute;",
        "caf&eacute;/song.mp4",
        "a%22b",
        "x/y.z-foo_bar~",
        "my%20dir/inner.mp4",
        "a&amp;amp;bdir/",
        "plus+file.mp4",
        "%2520",
        "100%25",
        "a/b/c/d.mp4",
        "UPPER%20lower%200123",
    ];

    const SANITIZE_CORPUS: &[&str] = &[
        "",
        "root.mp4",
        "movies/film.mp4",
        "movies/action/deep.mp4",
        "../root.mp4",
        "../../root.mp4",
        "../../etc/passwd",
        "./root.mp4",
        "/",
        "a//b///c",
        "./x/./y",
        "a&b/../c",
        "..",
        ".",
        "...",
        "my dir/inner.mp4",
        "a/b/c/d/e/f/g/h/i/j/k.mp4",
        "movies/../root.mp4",
        "a/../../b",
        "caf\u{e9}/song.mp4",
        "trailing/",
        "/leading/slash",
    ];

    /// Baked live outputs for SANITIZE_CORPUS, in order. Note "..." collapses
    /// (Windows strips trailing dots/spaces, so all-dots components are
    /// skipped rather than kept literally).
    const SANITIZE_EXPECTED: &[&str] = &[
        "",
        "root.mp4",
        "movies/film.mp4",
        "movies/action/deep.mp4",
        "root.mp4",
        "root.mp4",
        "etc/passwd",
        "root.mp4",
        "",
        "a/b/c",
        "x/y",
        "c",
        "",
        "",
        "",
        "my dir/inner.mp4",
        "a/b/c/d/e/f/g/h/i/j/k.mp4",
        "root.mp4",
        "b",
        "caf\u{e9}/song.mp4",
        "trailing",
        "leading/slash",
    ];

    const SANITIZE_ADV_CORPUS: &[&str] = &[
        "",
        "root.mp4",
        "movies/film.mp4",
        "../root.mp4",
        "..\\secret.txt",
        "a\\b\\c",
        ".../secret.txt",
        "....",
        ".. /secret.txt",
        "...\\secret.txt",
        "a/.../b",
        "movies/../root.mp4",
        "my dir/inner.mp4",
        "a/b/c/d/e/f/g/h/i/j/k.mp4",
        "trailing/",
        "/leading/slash",
        "a//b///c",
        "normal/long/path/with/many/components/file.mp4",
        "caf\u{e9}/song.mp4",
    ];

    /// Baked live outputs for SANITIZE_ADV_CORPUS, in order (backslash is a
    /// separator; dot/space-only components collapse).
    const SANITIZE_ADV_EXPECTED: &[&str] = &[
        "",
        "root.mp4",
        "movies/film.mp4",
        "root.mp4",
        "secret.txt",
        "a/b/c",
        "secret.txt",
        "",
        "secret.txt",
        "secret.txt",
        "a/b",
        "root.mp4",
        "my dir/inner.mp4",
        "a/b/c/d/e/f/g/h/i/j/k.mp4",
        "trailing",
        "leading/slash",
        "a/b/c",
        "normal/long/path/with/many/components/file.mp4",
        "caf\u{e9}/song.mp4",
    ];

    // GET hot-path pipeline cases: (raw wire input, sanitized output).
    const PIPELINE_CORPUS: &[(&str, &str)] = &[
        ("../root.mp4", "root.mp4"),
        ("..%2Froot.mp4", "root.mp4"),
        ("%2e%2e%2froot.mp4", "root.mp4"),
        ("..%5croot.mp4", "root.mp4"),
        ("..\\root.mp4", "root.mp4"),
        ("%252e%252e%2froot.mp4", "%2e%2e/root.mp4"), // single-pass stays
        (".../root.mp4", "root.mp4"),
        ("..%20/root.mp4", "root.mp4"),
        ("movies/../root.mp4", "root.mp4"),
        ("movies%2f..%2f..%2fetc/passwd", "etc/passwd"),
        ("my%20movie.mp4", "my movie.mp4"),
        ("movies%2Ffilm.mp4", "movies/film.mp4"),
        ("a&amp;amp;b.mp4", "a&b.mp4"),
        ("quote&apos;x.mp4", "quote'x.mp4"),
        ("caf&eacute;/song.mp4", "caf\u{e9}/song.mp4"),
        ("C:/Windows/win.ini", "C:/Windows/win.ini"),
        ("%c0%ae%c0%ae/x.mp4", "\u{c0}\u{ae}\u{c0}\u{ae}/x.mp4"),
        ("\u{FF0E}\u{FF0E}/x.mp4", "\u{FF0E}\u{FF0E}/x.mp4"),
        ("file%4", "file\u{4}"), // lone trailing "%H" -> control char
        ("%+2F", "\u{2}F"),      // "%+H" quirk -> low nibble, not '/'
        ("100%.mp4", "100%.mp4"),
        ("%2520.mp4", "%20.mp4"),
        ("a//b///c.mp4", "a/b/c.mp4"),
        ("./x/./y.mp4", "x/y.mp4"),
        ("&amp;../x.mp4", "&../x.mp4"), // entity -> "&", literal "&.." dir
        ("..;/x.mp4", "..;/x.mp4"),     // semicolon: literal dir, no climb
    ];

    const ESCAPE_CORPUS: &[&str] = &[
        "",
        "plain.mp4",
        "my movie.mp4",
        "a&b.mp4",
        "q'x.mp4",
        "a\"b.mp4",
        "a<b>.mp4",
        "a>b.mp4",
        "a&b<c>d\"e'f.mp4",
        "&&&&",
        "''''",
        "<<>>",
        "my movie part 2 final cut remastered edition directors cut.mp4",
        "aaaaaaaaaa&bbbbbbbbbb cccccccccc,dddddddddd#eeeeeeeeee",
        "a&bdir/",
        "movies/",
        "caf\u{e9}/song.mp4",
        "\u{e9}\u{e9}\u{e9}\u{e9}",
        "x\u{301}y",
        "long plain run without any escapable characters 0123456789 abcdefghijklmnopqrstuvwxyz",
        "mixed & and plain text with spaces and (parens) and, commas #hash",
    ];

    /// Baked live outputs for ESCAPE_CORPUS, in order.
    const ESCAPE_EXPECTED: &[&str] = &[
        "",
        "plain.mp4",
        "my movie.mp4",
        "a&amp;amp;b.mp4",
        "q&amp;apos;x.mp4",
        "a&amp;quot;b.mp4",
        "a&amp;lt;b&amp;gt;.mp4",
        "a&amp;gt;b.mp4",
        "a&amp;amp;b&amp;lt;c&amp;gt;d&amp;quot;e&amp;apos;f.mp4",
        "&amp;amp;&amp;amp;&amp;amp;&amp;amp;",
        "&amp;apos;&amp;apos;&amp;apos;&amp;apos;",
        "&amp;lt;&amp;lt;&amp;gt;&amp;gt;",
        "my movie part 2 final cut remastered edition directors cut.mp4",
        "aaaaaaaaaa&amp;amp;bbbbbbbbbb cccccccccc,dddddddddd#eeeeeeeeee",
        "a&amp;amp;bdir/",
        "movies/",
        "caf\u{e9}/song.mp4",
        "\u{e9}\u{e9}\u{e9}\u{e9}",
        "x\u{301}y",
        "long plain run without any escapable characters 0123456789 abcdefghijklmnopqrstuvwxyz",
        "mixed &amp;amp; and plain text with spaces and (parens) and, commas #hash",
    ];

    const RANGE_CORPUS: &[&str] = &[
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=0-\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=10-\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=1023-\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=99999-\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=5-10\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=-10\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=abc-\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=10\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nrange: bytes=5-\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=+5-\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=007-\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=18446744073709551615-\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=18446744073709551616-\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes= 5-\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=5a-\r\n\r\n",
        "GET /root.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=-\r\n\r\n",
        "GET /a.mp4 HTTP/1.1\r\nHost: 127.0.0.1\r\nRange: bytes=10-\r\nX-Client: VLC/3.0\r\n\r\n",
    ];

    /// Baked live outputs for RANGE_CORPUS, in order (missing/invalid/
    /// overflow/suffix ranges all fall back to 0; the range end is ignored).
    const RANGE_EXPECTED: &[u64] = &[
        0, 0, 10, 1023, 99999, 5, 0, 0, 0, 0, 5, 7, 18446744073709551615, 0, 0,
        0, 0, 10,
    ];

    const SORTCAPS_CORPUS: &[&[u8]] = &[
        b"POST /ctl/ContentDir HTTP/1.1\r\nHost: x\r\n\r\n<s:Envelope><s:Body><ObjectID>0</ObjectID></s:Body></s:Envelope>",
        b"POST /ctl/ContentDir HTTP/1.1\r\nHost: x\r\n\r\n<s:Envelope><s:Body><u:GetSortCapabilities></u:GetSortCapabilities></s:Body></s:Envelope>",
        b"POST /ctl/ContentDir HTTP/1.1\r\nHost: x\r\n\r\n<s:Envelope><s:Body><u:Foo>no oid here, padding padding padding</u:Foo></s:Body></s:Envelope>",
        b"POST /ctl/ContentDir HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET /root.mp4 HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GetSortCapabilities",
        b"GetSortCapabilitie",
        b"XGetSortCapabilities",
        b"GetSortCapabilitiesGetSortCapabilities",
    ];

    /// Baked live outputs for SORTCAPS_CORPUS, in order.
    const SORTCAPS_EXPECTED: &[bool] =
        &[false, true, false, false, false, true, false, true, true];

    const OID_CORPUS: &[&[u8]] = &[
        b"<ObjectID>0</ObjectID>",
        b"<ObjectID>movies/</ObjectID>",
        b"<ObjectID>64$movies/</ObjectID>",
        b"<ObjectID></ObjectID>",
        b"<ObjectID>0</ObjectID_missing>",
        b"<ObjectID>0",
        b"<ObjectID",
        b"<objectid>0</objectid>",
        b"<ObjectID foo=\"bar\">movies/</ObjectID>",
        b"<ObjectID>GetSortCapabilities</ObjectID>",
        b"<ObjectID> 0 </ObjectID>",
        b"<ObjectID>movies/</ObjectID><ObjectID>0</ObjectID>",
        b"no oid here, but GetSortCapabilities is present",
        b"no oid here",
        b"",
        b"ObjectID",
        b"ObjectID>",
        b"ObjectID><",
        b"xxObjectID>y<",
        b"OObjectID>q</ObjectID>",
        b"<ObjectID>a>b</ObjectID>",
        b"<ObjectID><</ObjectID>",
        b"<ObjectID>>",
    ];

    /// Baked live outputs for OID_CORPUS, in order (first ObjectID wins;
    /// malformed/empty/absent yields empty; matching is case-sensitive).
    const OID_EXPECTED: &[&str] = &[
        "0",
        "movies/",
        "64$movies/",
        "",
        "0",
        "",
        "",
        "",
        "movies/",
        "GetSortCapabilities",
        " 0 ",
        "movies/",
        "",
        "",
        "",
        "",
        "",
        "",
        "y",
        "q",
        "a>b",
        "",
        "",
    ];

    fn chunked(req: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        req.chunks(chunk).map(|c| c.to_vec()).collect()
    }

    fn time_it(iters: u64, mut f: impl FnMut()) -> f64 {
        for _ in 0..10 {
            f();
        }
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        t.elapsed().as_secs_f64()
    }

    /// Incremental framing harness: mirrors handle_client's read loop exactly
    /// (only windows overlapping fresh bytes are re-checked; the 4096 cap
    /// goes silent). Returns the buffer position at first detection.
    fn feed_live(chunks: &[&[u8]]) -> Option<usize> {
        let mut buf = vec![0u8; 4096];
        let mut pos = 0usize;
        for c in chunks {
            let prev = pos;
            buf[pos..pos + c.len()].copy_from_slice(c);
            pos += c.len();
            let from = prev.saturating_sub(3);
            if headers_complete(&buf[from..pos]) {
                return Some(pos);
            }
            if pos == buf.len() {
                return None;
            }
        }
        None
    }

    /// GET hot-path composition: decode then sanitize, as handle_get_request
    /// does after a static-route miss.
    fn get_pipeline(raw: &str) -> String {
        sanitize_path(&decode(raw))
    }

    #[test]
    fn correctness_decode() {
        assert_eq!(DECODE_CORPUS.len(), DECODE_EXPECTED.len(), "table drift");
        for (s, expected) in DECODE_CORPUS.iter().zip(DECODE_EXPECTED.iter()) {
            assert_eq!(&decode(s), expected, "decode {:?}", s);
        }
        // Triple-encoded entity collapses; '%%' stays literal.
        assert_eq!(decode("&amp;amp;amp;"), "&");
        assert_eq!(decode("%%41"), "%%41");
    }

    #[test]
    fn correctness_encode() {
        assert_eq!(ENCODE_CORPUS.len(), ENCODE_EXPECTED.len(), "table drift");
        for (s, expected) in ENCODE_CORPUS.iter().zip(ENCODE_EXPECTED.iter()) {
            assert_eq!(&encode(s), expected, "encode {:?}", s);
        }
    }

    #[test]
    fn correctness_sanitize() {
        assert_eq!(SANITIZE_CORPUS.len(), SANITIZE_EXPECTED.len(), "table drift");
        assert_eq!(
            SANITIZE_ADV_CORPUS.len(),
            SANITIZE_ADV_EXPECTED.len(),
            "table drift"
        );
        for (p, expected) in SANITIZE_CORPUS
            .iter()
            .zip(SANITIZE_EXPECTED.iter())
            .chain(SANITIZE_ADV_CORPUS.iter().zip(SANITIZE_ADV_EXPECTED.iter()))
        {
            let got = sanitize_path(p);
            assert_eq!(&got, expected, "sanitize {:?}", p);
            assert!(
                !got.split('/').any(|c| c == ".."),
                "sanitize climbs for {:?} -> {:?}",
                p,
                got
            );
            assert!(!got.contains('\\'), "backslash survives for {:?} -> {:?}", p, got);
        }
    }

    #[test]
    fn correctness_escape() {
        assert_eq!(ESCAPE_CORPUS.len(), ESCAPE_EXPECTED.len(), "table drift");
        for (s, expected) in ESCAPE_CORPUS.iter().zip(ESCAPE_EXPECTED.iter()) {
            assert_eq!(&escape_didl(s).into_owned(), expected, "escape {:?}", s);
        }
    }

    #[test]
    fn correctness_range() {
        assert_eq!(RANGE_CORPUS.len(), RANGE_EXPECTED.len(), "table drift");
        for (r, expected) in RANGE_CORPUS.iter().zip(RANGE_EXPECTED.iter()) {
            assert_eq!(&parse_range_header(r.as_bytes()), expected, "range {:?}", r);
        }
        // Non-UTF8 range values fall back to 0 like the lossy+parse path.
        let bad1 = b"GET /r.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=\xFF-".to_vec();
        let bad2 = b"GET /r.mp4 HTTP/1.1\r\nHost: x\r\nRange: bytes=1\xFF2-".to_vec();
        assert_eq!(parse_range_header(&bad1), 0, "range non-utf8");
        assert_eq!(parse_range_header(&bad2), 0, "range non-utf8 mid");
    }

    #[test]
    fn correctness_sortcaps_scan() {
        assert_eq!(SORTCAPS_CORPUS.len(), SORTCAPS_EXPECTED.len(), "table drift");
        for (r, expected) in SORTCAPS_CORPUS.iter().zip(SORTCAPS_EXPECTED.iter()) {
            assert_eq!(&contains_sortcaps(r), expected, "sortcaps {:?}", r);
        }
    }

    #[test]
    fn correctness_object_id() {
        assert_eq!(OID_CORPUS.len(), OID_EXPECTED.len(), "table drift");
        for (body, expected) in OID_CORPUS.iter().zip(OID_EXPECTED.iter()) {
            let mut req = b"POST /ctl/ContentDir HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
            req.extend_from_slice(body);
            assert_eq!(extract_object_id(&req), expected.as_bytes(), "oid {:?}", body);
        }
    }

    #[test]
    fn correctness_header_build() {
        // push_u64 renders exactly like format!("{}", v) for all u64.
        for v in [
            0u64,
            1,
            9,
            10,
            99,
            100,
            1023,
            1024,
            65535,
            1_000_000,
            u32::MAX as u64,
            u64::MAX / 10,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let mut buf = [0u8; 32];
            let mut p = 0usize;
            push_u64(&mut buf, &mut p, v);
            assert_eq!(&buf[..p], format!("{}", v).as_bytes(), "push_u64 {}", v);
        }
        // 206 headers byte-identical to the format! reference, incl. the
        // empty-file (0-0/0) and range==size inverted quirks.
        for (range, size) in [
            (0u64, 1024u64),
            (10, 1024),
            (1023, 1024),
            (1024, 1024),
            (0, 0),
            (0, 1),
            (0, 9),
            (5, 200),
            (1023, 262_144),
            (0, u64::MAX),
            (7, u64::MAX),
            (u64::MAX, u64::MAX),
        ] {
            let expected = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {}-{}/{}\r\nContent-Type: video/mp4\r\nContent-Length: {}\r\n\r\n",
                range,
                size.saturating_sub(1),
                size,
                size - range
            );
            let mut buf = [0u8; 256];
            let mut p = 0usize;
            put_slice(&mut buf, &mut p, b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes ");
            push_u64(&mut buf, &mut p, range);
            put_slice(&mut buf, &mut p, b"-");
            push_u64(&mut buf, &mut p, size.saturating_sub(1));
            put_slice(&mut buf, &mut p, b"/");
            push_u64(&mut buf, &mut p, size);
            put_slice(&mut buf, &mut p, b"\r\nContent-Type: video/mp4\r\nContent-Length: ");
            push_u64(&mut buf, &mut p, size - range);
            put_slice(&mut buf, &mut p, b"\r\n\r\n");
            assert_eq!(&buf[..p], expected.as_bytes(), "header {:?}/{:?}", range, size);
        }
    }

    /// Exact-output + never-escapes lock for the composed GET pipeline over
    /// adversarial wire inputs (runs by default).
    #[test]
    fn correctness_pipeline() {
        for &(raw, expected) in PIPELINE_CORPUS {
            let got = get_pipeline(raw);
            assert_eq!(got, expected, "pipeline {:?}", raw);
            assert!(
                !got.split('/').any(|c| c == ".."),
                "pipeline climbs for {:?} -> {:?}",
                raw,
                got
            );
            assert!(!got.contains('\\'), "pipeline backslash for {:?} -> {:?}", raw, got);
            // POST double-decode stage (generate_browse_response decodes again).
            let twice = sanitize_path(&decode(&decode(raw)));
            assert!(
                !twice.split('/').any(|c| c == ".."),
                "pipeline 2x climbs for {:?} -> {:?}",
                raw,
                twice
            );
            assert!(!twice.contains('\\'), "pipeline 2x backslash for {:?} -> {:?}", raw, twice);
        }
    }

    /// Regression: decode()+sanitize() pipeline must never yield an escaping
    /// path (no ".." component, no backslash, no drive escape). Covers FIX #1
    /// (POST unsanitized) and FIX #2 (backslash + Win32 dot-variants).
    #[test]
    fn traversal_never_escapes() {
        use super::{decode as live_decode, sanitize_path as live_sanitize};
        // (raw wire input, must-not-contain-outside-marker)
        let attacks = [
            "../",
            "..%2F",
            "..%2f",
            "%2e%2e/",
            "%2E%2E%5C",
            "..%5c",
            "..%5C",
            "..\\",
            "..\\..\\",
            "%252e%252e%2f", // double-encode: 1st -> "%2e%2e/", 2nd -> "../"
            "%252e%252e%255c",
            ".../",
            "....",
            ".. /",
            "a/..%20/b",
            "C:/Windows/",
            "/etc/",
            "movies/../../etc/passwd",
            // --- extended tactics: mixed/long climbs, encodings, OS angles ---
            "..%2f..%2f..%2fetc/passwd", // triple encoded climb
            "%2e%2e%2f",                 // fully-encoded dots + slash
            "..%5c..%5c",                // double backslash climb
            "%255c..%255c",              // double-encoded backslash (stays literal)
            "%25252e",                   // triple-encoded dot (stays literal)
            "..%00/",                    // null byte component (open fails, never climbs)
            "..%0d%0a/",                 // CRLF decodes into filename, not headers
            "%+2f",                      // "%+H" quirk -> low nibble, NOT '/'
            "file%4",                    // lone trailing "%H" -> control char
            "%c0%ae%c0%ae/",             // overlong UTF-8 -> latin1 chars, not ".."
            "..%c0%af",                  // overlong slash -> latin1, not separator
            "\u{FF0E}\u{FF0E}/",         // fullwidth dots: literal file, not ".."
            "\u{FF0F}etc\u{FF0F}",       // fullwidth slashes: not separators
            "&amp;../",                  // entity -> "&", then literal "&.."
            "&amp;amp;..%2f",            // double entity + encoded slash
            "C:/",                       // drive root (format! join keeps inside)
            "C%3a/Windows/win.ini",      // encoded colon drive
            "//server/share/",           // UNC collapses to inside path
            "%2fetc%2fpasswd",           // encoded absolute
            "....//",                    // quad dot collapses
            "..%2e/",                    // dotdot-dot: all dots, skipped
            ".%2e/",                     // dot-encoded-dot
            "..%20/",                    // dotdot-space: stripped, skipped
            ".. /",                      // raw dotdot-space
            ". /",                       // dot-space
            "a/.../b",                   // ellipsis component skipped
            "...\\secret.txt",           // triple-dot + backslash
            "..;/",                      // semicolon: literal "..;" dir
            "http://127.0.0.1:8200/root.mp4", // absolute URI form
        ];
        for raw in attacks {
            // GET pipeline: single decode then sanitize (as in handle_get).
            let once = live_sanitize(&live_decode(raw));
            assert!(
                !once.split('/').any(|c| c == ".."),
                "GET pipeline escapes for {:?} -> {:?}",
                raw,
                once
            );
            assert!(!once.contains('\\'), "backslash survives for {:?} -> {:?}", raw, once);
            // POST pipeline: double decode (fallback decodes again) then sanitize,
            // as generate_browse_response does. Must still not escape.
            let twice = live_sanitize(&live_decode(&live_decode(raw)));
            assert!(
                !twice.split('/').any(|c| c == ".."),
                "POST double-decode escapes for {:?} -> {:?}",
                raw,
                twice
            );
            assert!(!twice.contains('\\'), "backslash survives 2x for {:?} -> {:?}", raw, twice);
        }
        // Legit paths unchanged (no over-blocking).
        for (input, expected) in [
            ("root.mp4", "root.mp4"),
            ("movies/film.mp4", "movies/film.mp4"),
            ("a//b///c", "a/b/c"),
            ("movies/../root.mp4", "root.mp4"),
            ("my dir/inner.mp4", "my dir/inner.mp4"),
            ("%252e.mp4", "%2e.mp4"), // single-pass: literal %2e file, not ".."
            ("%2520.mp4", "%20.mp4"), // literal %20 file, not space
            ("a<b>.mp4", "a<b>.mp4"), // angles are literal post-encode (%3C)
            ("a?b.mp4", "a?b.mp4"),   // '?' literal (encoded %3F on the wire)
            ("100%.mp4", "100%.mp4"), // '%' literal (encoded %25 on the wire)
        ] {
            assert_eq!(live_sanitize(&live_decode(input)), expected, "legit {:?}", input);
        }
    }

    #[tokio::test]
    async fn correctness_browse_build() {
        let dir = std::env::temp_dir().join(format!(
            "rustydlna_condensed_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        for n in ["a&b.mp4", "my movie.mp4", "plain.mp4"] {
            std::fs::write(dir.join(n), b"data").unwrap();
        }
        std::fs::write(dir.join("sub").join("deep.mp4"), b"deep").unwrap();
        let d = dir.to_str().unwrap();
        let resp = generate_browse_response("", 0, 5000, "127.0.0.1", d).await;
        let (head, body) = resp.split_once("\r\n\r\n").expect("browse headers");
        assert!(head.starts_with("HTTP/1.1 200 OK"), "browse status");
        assert!(head.contains("Connection: Keep-Alive"), "browse keep-alive");
        assert!(head.contains(&format!("Content-Length: {}", body.len())), "browse length");
        assert!(body.contains("&lt;container id=\"sub/\""), "sub container");
        assert!(body.contains("<NumberReturned>4</NumberReturned>"), "root count");
        assert!(body.contains("<TotalMatches>4</TotalMatches>"), "root total");
        let pa = body.find("a&amp;amp;b.mp4").expect("amp item");
        let pm = body.find("my%20movie.mp4").expect("space item");
        let pp = body.find("plain.mp4").expect("plain item");
        assert!(pa < pm && pm < pp, "files sorted");
        let sub = generate_browse_response("sub/", 0, 5000, "127.0.0.1", d).await;
        let sbody = sub.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(sbody.contains("sub/deep.mp4"), "nested item");
        assert!(sbody.contains("<NumberReturned>1</NumberReturned>"), "nested count");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn correctness_header_framing() {
        // Detection position must not depend on packet chunking: the first
        // completed prefix wins no matter how reads split the stream.
        let bodies: &[&[u8]] = &[
            b"GET /root.mp4 HTTP/1.1\r\nHost: x\r\n\r\n",
            b"POST /ctl/ContentDir HTTP/1.1\r\nHost: x\r\nContent-Length: 70\r\nContent-Type: text/xml\r\n\r\n<body>hello world, this is a longer request body for scanning</body>",
            b"GET /a.mp4 HTTP/1.1\r\nHost: x\r\nX-Pad: AAAA\r\n\r\n",
            b"\r\n\r\n",
            b"xxx\r\n\r\nyyy",
        ];
        for body in bodies {
            let end_of_headers = body
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .expect("corpus has a terminator");
            for chunk in [1usize, 2, 3, 7, 64, 511, 512, 1024, 4096] {
                // Detection fires at the first read boundary at/after the
                // terminator end (a terminator split across reads is still
                // caught thanks to the 3-byte overlap).
                let mut end = 0usize;
                let mut expect = None;
                while end < body.len() {
                    end = (end + chunk).min(body.len());
                    if end >= end_of_headers {
                        expect = Some(end);
                        break;
                    }
                }
                let owned = chunked(body, chunk);
                let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
                assert_eq!(feed_live(&refs), expect, "framing chunk={}", chunk);
            }
        }
        // ~3.5KB header block without terminator until the very end.
        let mut big = b"GET /root.mp4 HTTP/1.1\r\nHost: x\r\nX-Pad: ".to_vec();
        big.extend(std::iter::repeat(b'Q').take(3500));
        big.extend_from_slice(b"\r\n\r\n");
        for chunk in [64usize, 511, 512, 1000] {
            let owned = chunked(&big, chunk);
            let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
            assert_eq!(feed_live(&refs), Some(big.len()), "big framing chunk={}", chunk);
        }
        // No terminator in 4096 bytes stays silent at every chunking.
        let bare = vec![b'Z'; 4096];
        for chunk in [1usize, 512, 4096] {
            let owned = chunked(&bare, chunk);
            let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
            assert_eq!(feed_live(&refs), None, "unterminated chunk={}", chunk);
        }
    }

    #[test]
    #[ignore]
    fn bench_decode() {
        let iters = 15_000u64;
        let dt = time_it(iters, || {
            for s in DECODE_CORPUS {
                black_box(decode(black_box(s)));
            }
        });
        println!(
            "[bench] decode (live): {:.3}s total, {:.1} ns/input ({} iters x {} inputs)",
            dt,
            dt * 1e9 / (iters as f64 * DECODE_CORPUS.len() as f64),
            iters,
            DECODE_CORPUS.len()
        );
    }

    #[test]
    #[ignore]
    fn bench_encode() {
        let iters = 20_000u64;
        let dt = time_it(iters, || {
            for s in ENCODE_CORPUS {
                black_box(encode(black_box(s)));
            }
        });
        println!(
            "[bench] encode (live): {:.3}s total, {:.1} ns/input ({} iters x {} inputs)",
            dt,
            dt * 1e9 / (iters as f64 * ENCODE_CORPUS.len() as f64),
            iters,
            ENCODE_CORPUS.len()
        );
    }

    #[test]
    #[ignore]
    fn bench_header_scan() {
        // ~3.5KB headers fed in 512B chunks through the live framing harness.
        let mut big = b"GET /root.mp4 HTTP/1.1\r\nHost: x\r\nX-Pad: ".to_vec();
        big.extend(std::iter::repeat(b'Q').take(3500));
        big.extend_from_slice(b"\r\n\r\n");
        let owned = chunked(&big, 512);
        let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
        let iters = 3_000u64;
        let dt = time_it(iters, || {
            black_box(feed_live(black_box(&refs)));
        });
        println!(
            "[bench] header-scan (live, {}B in 512B chunks): {:.3}s total ({:.1} us/feed, {} iters)",
            big.len(),
            dt,
            dt * 1e6 / iters as f64,
            iters
        );
    }

    #[test]
    #[ignore]
    fn bench_scan_single_packet() {
        // The common real case: small requests arriving whole (one read).
        let reqs: Vec<Vec<u8>> = vec![
            b"GET /root.mp4 HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
            b"GET /movies/action/deep.mp4 HTTP/1.1\r\nHost: 127.0.0.1\r\nRange: bytes=10-\r\nX-Client: VLC/3.0\r\n\r\n".to_vec(),
            b"POST /ctl/ContentDir HTTP/1.1\r\nHost: x\r\nContent-Length: 70\r\nContent-Type: text/xml\r\n\r\n<s:Envelope><s:Body><ObjectID>0</ObjectID></s:Body></s:Envelope>".to_vec(),
        ];
        let iters = 50_000u64;
        let dt = time_it(iters, || {
            for r in &reqs {
                let one: &[&[u8]] = &[r.as_slice()];
                black_box(feed_live(black_box(one)));
            }
        });
        println!(
            "[bench] scan-single-packet (live): {:.3}s total ({} iters x {} reqs)",
            dt,
            iters,
            reqs.len()
        );
    }

    #[tokio::test]
    #[ignore]
    async fn bench_browse_build() {
        let dir = std::env::temp_dir().join(format!(
            "rustydlna_bench_big_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        for i in 0..200 {
            let name = match i % 10 {
                0 => format!("a&b_{}.mp4", i),
                1 => format!("my movie {}.mp4", i),
                2 => format!("comma,{}.mp4", i),
                3 => format!("hash#{}.mp4", i),
                4 => format!("quote'{}.mp4", i),
                5 => format!("paren({}).mp4", i),
                _ => format!("file{:03}.mp4", i),
            };
            std::fs::write(dir.join(name), b"data").unwrap();
        }
        let d = dir.to_str().unwrap().to_string();
        // Warmup.
        black_box(generate_browse_response("", 0, 5000, "127.0.0.1", &d).await);
        let iters = 20u64;
        let t = Instant::now();
        for _ in 0..iters {
            black_box(generate_browse_response("", 0, 5000, "127.0.0.1", &d).await);
        }
        let dt = t.elapsed().as_secs_f64();
        println!(
            "[bench] browse-build (200 files, live): {:.3}s total, {:.2} ms/req ({} iters)",
            dt,
            dt * 1000.0 / iters as f64,
            iters
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore]
    fn bench_sanitize() {
        let iters = 20_000u64;
        let dt = time_it(iters, || {
            for p in SANITIZE_CORPUS {
                black_box(sanitize_path(black_box(p)));
            }
        });
        println!(
            "[bench] sanitize (live): {:.3}s total, {:.1} ns/input ({} iters x {} paths)",
            dt,
            dt * 1e9 / (iters as f64 * SANITIZE_CORPUS.len() as f64),
            iters,
            SANITIZE_CORPUS.len()
        );
    }

    #[test]
    #[ignore]
    fn bench_sanitize_hardened() {
        let iters = 20_000u64;
        let dt = time_it(iters, || {
            for p in SANITIZE_ADV_CORPUS {
                black_box(sanitize_path(black_box(p)));
            }
        });
        println!(
            "[bench] sanitize-hardened (live): {:.3}s total, {:.1} ns/input ({} iters x {} paths)",
            dt,
            dt * 1e9 / (iters as f64 * SANITIZE_ADV_CORPUS.len() as f64),
            iters,
            SANITIZE_ADV_CORPUS.len()
        );
    }

    #[test]
    #[ignore]
    fn bench_pipeline() {
        // Composed GET hot path: decode + sanitize over adversarial inputs.
        let iters = 20_000u64;
        let dt = time_it(iters, || {
            for (raw, _) in PIPELINE_CORPUS {
                black_box(get_pipeline(black_box(raw)));
            }
        });
        println!(
            "[bench] pipeline decode+sanitize (live, adversarial): {:.3}s total ({} iters x {} inputs)",
            dt,
            iters,
            PIPELINE_CORPUS.len()
        );
    }

    #[test]
    #[ignore]
    fn bench_objectid() {
        let bodies: Vec<Vec<u8>> = [
            "<s:Envelope><s:Body><ObjectID>movies/action/deep.mp4</ObjectID></s:Body></s:Envelope>",
            "<s:Envelope><s:Body><ObjectID>0</ObjectID></s:Body></s:Envelope>",
            "<s:Envelope><s:Body><u:Foo>no oid here, padding padding padding padding</u:Foo></s:Body></s:Envelope>",
        ]
        .iter()
        .map(|b| format!("POST /ctl/ContentDir HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{}", b.len(), b).into_bytes())
        .collect();
        let iters = 50_000u64;
        let dt = time_it(iters, || {
            for r in &bodies {
                black_box(extract_object_id(black_box(r)));
            }
        });
        println!(
            "[bench] objectid-extract (live): {:.3}s total ({} iters x {} reqs)",
            dt,
            iters,
            bodies.len()
        );
    }

    #[test]
    #[ignore]
    fn bench_header_build() {
        // Manual 206-header assembly (push_u64 + put_slice), as production does.
        // Browse counts use format! like production (manual measured slower).
        let cases = [(0u64, 1024u64), (10, 1024), (0, 200), (1023, 262_144)];
        let iters = 50_000u64;
        let dt = time_it(iters, || {
            for (r, s) in &cases {
                let mut buf = [0u8; 256];
                let mut p = 0usize;
                put_slice(&mut buf, &mut p, b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes ");
                push_u64(&mut buf, &mut p, *r);
                put_slice(&mut buf, &mut p, b"-");
                push_u64(&mut buf, &mut p, s.saturating_sub(1));
                put_slice(&mut buf, &mut p, b"/");
                push_u64(&mut buf, &mut p, *s);
                put_slice(&mut buf, &mut p, b"\r\nContent-Type: video/mp4\r\nContent-Length: ");
                push_u64(&mut buf, &mut p, s - r);
                put_slice(&mut buf, &mut p, b"\r\n\r\n");
                black_box((buf, p));
            }
        });
        println!(
            "[bench] header206-build (live): {:.3}s total ({} iters x {} cases)",
            dt,
            iters,
            cases.len()
        );
    }

    #[test]
    #[ignore]
    fn bench_escape() {
        let iters = 20_000u64;
        let dt = time_it(iters, || {
            for s in ESCAPE_CORPUS {
                black_box(escape_didl(black_box(s)));
            }
        });
        println!(
            "[bench] escape-didl (live): {:.3}s total, {:.1} ns/input ({} iters x {} inputs)",
            dt,
            dt * 1e9 / (iters as f64 * ESCAPE_CORPUS.len() as f64),
            iters,
            ESCAPE_CORPUS.len()
        );
    }

    #[test]
    #[ignore]
    fn bench_range() {
        let reqs: Vec<Vec<u8>> = RANGE_CORPUS.iter().map(|s| s.as_bytes().to_vec()).collect();
        let iters = 50_000u64;
        let dt = time_it(iters, || {
            for r in &reqs {
                black_box(parse_range_header(black_box(r)));
            }
        });
        println!(
            "[bench] range-parse (live): {:.3}s total ({} iters x {} reqs)",
            dt,
            iters,
            reqs.len()
        );
    }

    #[test]
    #[ignore]
    fn bench_sortcaps_scan() {
        let iters = 100_000u64;
        let dt = time_it(iters, || {
            for r in SORTCAPS_CORPUS {
                black_box(contains_sortcaps(black_box(r)));
            }
        });
        println!(
            "[bench] sortcaps-scan (live): {:.3}s total ({} iters x {} reqs)",
            dt,
            iters,
            SORTCAPS_CORPUS.len()
        );
    }
}

// ---------------------------------------------------------------------------
// XSS/DIDL-injection regression tests (issue #2).
//
// The Browse `Result` payload is `&lt;`-escaped DIDL: every client MUST
// unescape it once (`&lt;`->`<`) before parsing. Anything emitted raw into
// that blob that looks like markup (`<`, `>`, `"`) or re-introduces entities
// becomes live markup / breaks attributes after the unescape.
// These tests use only Windows-legal filenames (no FS port tricks) plus pure
// `encode()` unit checks for `< > % \ ?` (illegal on NTFS, legal on the
// MiniDLNA-on-Linux target), so they run on any OS with no sockets.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod xss_escape_tests {
    use super::{decode, encode, generate_browse_response, sanitize_path};

    fn tmp_media(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "rustydlna_xss_{}_{}_{}",
            std::process::id(),
            tag,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn encode_escapes_markup_and_percent() {
        // `< >` must never survive into ids/res URLs as raw angles.
        assert_eq!(encode("<"), "%3C", "encode(<) must percent-encode");
        assert_eq!(encode(">"), "%3E", "encode(>) must percent-encode");
        // `%` must be encoded or advertised URLs mis-decode (`%2e.mp4` -> `..mp4`).
        assert_eq!(encode("%"), "%25", "encode(%) must percent-encode");
        assert_eq!(encode("%2e.mp4"), "%252e.mp4", "literal %2e must round-trip");
        // `\` (separator after sanitize) and `?` (client query-split) too.
        assert_eq!(encode("\\"), "%5C", "encode(backslash)");
        assert_eq!(encode("?"), "%3F", "encode(?)");
    }

    #[test]
    fn encode_keeps_existing_mapping() {
        // Guards: the long-locked mapping from tests/dlna_exact.rs must not move.
        assert_eq!(encode("my movie.mp4"), "my%20movie.mp4");
        assert_eq!(encode("a&b.mp4"), "a&amp;amp;b.mp4");
        assert_eq!(encode("paren(1).mp4"), "paren%281%29.mp4");
        assert_eq!(encode("quote'mp4.mp4"), "quote%27mp4.mp4");
        assert_eq!(encode("hash#tag.mp4"), "hash%23tag.mp4");
        assert_eq!(encode("comma,test.mp4"), "comma%2Ctest.mp4");
        assert_eq!(encode("plus+file.mp4"), "plus+file.mp4");
    }

    #[tokio::test]
    async fn browse_title_escapes_apos() {
        // `'` is Windows-legal and today passes raw through the title.
        let dir = tmp_media("apos");
        std::fs::write(dir.join("q'x.mp4"), b"X").unwrap();
        let resp = generate_browse_response("", 0, 5000, "127.0.0.1", dir.to_str().unwrap()).await;
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(
            body.contains("q&amp;apos;x.mp4"),
            "title must DIDL-escape apostrophe, got:\n{}",
            &body[..body.len().min(600)]
        );
        assert!(
            !body.contains("q'x.mp4"),
            "raw apostrophe must not survive in titles/ids, got:\n{}",
            &body[..body.len().min(600)]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn browse_container_id_escapes_apos() {
        // Dir ids use the raw title with NO encode() at all (worst spot).
        let dir = tmp_media("dir apos");
        std::fs::create_dir_all(dir.join("d'x")).unwrap();
        let resp = generate_browse_response("", 0, 5000, "127.0.0.1", dir.to_str().unwrap()).await;
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(
            body.contains("d&amp;apos;x/"),
            "container id must escape apostrophe, got:\n{}",
            &body[..body.len().min(600)]
        );
        assert!(
            !body.contains("d'x/"),
            "raw apostrophe must not survive in container ids, got:\n{}",
            &body[..body.len().min(600)]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn browse_percent_file_roundtrips() {
        // Disk file `%2e.mp4` (Windows-legal): advertised URL must GET back
        // to the same file. Today encode() leaves `%` raw so the URL
        // re-decodes to `..mp4` (wrong file / 404).
        let dir = tmp_media("pct");
        std::fs::write(dir.join("%2e.mp4"), b"PCT").unwrap();
        let resp = generate_browse_response("", 0, 5000, "127.0.0.1", dir.to_str().unwrap()).await;
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(
            body.contains("%252e.mp4"),
            "advertised id must double the %, got:\n{}",
            &body[..body.len().min(600)]
        );
        // Simulate what handle_get_request does with the advertised URL.
        let advertised = "/%252e.mp4";
        let opened = sanitize_path(&decode(advertised));
        assert_eq!(opened, "%2e.mp4", "GET of advertised URL must reopen the same file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn browse_amp_stays_escaped() {
        // Regression guard: `&` handling (the only char escaped today) keeps
        // its exact double-escaped form.
        let dir = tmp_media("amp");
        std::fs::write(dir.join("a&b.mp4"), b"A").unwrap();
        let resp = generate_browse_response("", 0, 5000, "127.0.0.1", dir.to_str().unwrap()).await;
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(body.contains("a&amp;amp;b.mp4"), "amp escaping changed:\n{}", &body[..body.len().min(600)]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn browse_wire_has_no_raw_markup() {
        // Belt-and-braces on Windows-legal names: no raw `<>"` may appear in
        // the escaped blob for these files (would become markup post-unescape).
        let dir = tmp_media("nomarkup");
        std::fs::write(dir.join("q'x.mp4"), b"X").unwrap();
        std::fs::write(dir.join("a&b.mp4"), b"A").unwrap();
        let resp = generate_browse_response("", 0, 5000, "127.0.0.1", dir.to_str().unwrap()).await;
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        // Titles/ids live between &lt;...&gt;; a raw `"` or `'` there breaks out.
        for needle in ["q'x.mp4", "q\"x"] {
            assert!(!body.contains(needle), "raw {} in wire: {}", needle, &body[..body.len().min(400)]);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
