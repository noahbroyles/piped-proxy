mod resolver;
mod sabr;
mod ump_stream;
mod utils;

use actix_web::http::StatusCode;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpResponseBuilder, HttpServer};
use listenfd::ListenFd;
use once_cell::sync::Lazy;
use qstring::QString;
use regex::Regex;
use reqwest::{Body, Client, Request, Url};
use std::error::Error;
use std::io::ErrorKind;
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, io};

#[cfg(not(any(feature = "reqwest-native-tls", feature = "reqwest-rustls")))]
compile_error!("feature \"reqwest-native-tls\" or \"reqwest-rustls\" must be set for proxy to have TLS support");

use futures_util::TryStreamExt;
use http::{HeaderName, Method};
use reqwest::header::HeaderValue;
use reqwest::redirect::Policy;
#[cfg(any(feature = "webp", feature = "avif", feature = "qhash"))]
use tokio::task::spawn_blocking;
use ump_stream::UmpTransformStream;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn try_get_fd_listeners() -> (Option<UnixListener>, Option<TcpListener>) {
    let mut fd = ListenFd::from_env();

    let unix_listener = env::var("FD_UNIX").ok().map(|fd_unix| {
        let fd_pos = fd_unix.parse().expect("FD_UNIX is not a number");
        println!("Trying to take Unix socket at position {}", fd_pos);
        fd.take_unix_listener(fd_pos)
            .expect(format!("fd {} is not a Unix socket", fd_pos).as_str())
            .expect(format!("fd {} has already been used", fd_pos).as_str())
    });

    let tcp_listener = env::var("FD_TCP").ok().map(|fd_tcp| {
        let fd_pos = fd_tcp.parse().expect("FD_TCP is not a number");
        println!("Trying to take TCP listener at position {}", fd_pos);
        fd.take_tcp_listener(fd_pos)
            .expect(format!("fd {} is not a TCP listener", fd_pos).as_str())
            .expect(format!("fd {} has already been used", fd_pos).as_str())
    });

    (unix_listener, tcp_listener)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Running server!");

    let mut server = HttpServer::new(|| {
        // match all requests
        App::new().default_service(web::to(index))
    });

    let fd_listeners = try_get_fd_listeners();

    if let Some(unix_listener) = fd_listeners.0 {
        server = server
            .listen_uds(unix_listener)
            .expect("Error while trying to listen on Unix socket passed by fd");
        println!("Listening on Unix socket passed by fd.");
    }

    if let Some(tcp_listener) = fd_listeners.1 {
        server = server
            .listen(tcp_listener)
            .expect("Error while trying to listen on TCP listener passed by fd");
        println!("Listening on TCP listener passed by fd.");
    }

    // Only bind manually if there is not already a listener
    if server.addrs().is_empty() {
        // get socket/port from env
        // backwards compat when only UDS is set
        server = if utils::get_env_bool("UDS") {
            let socket_path =
                env::var("BIND_UNIX").unwrap_or_else(|_| "./socket/actix.sock".to_string());
            server.bind_uds(socket_path)?
        } else {
            let bind = env::var("BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
            server.bind(bind)?
        };
    }

    server.run().await
}

static RE_DOMAIN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?:[a-z\d.-]*\.)?([a-z\d-]*\.[a-z\d-]*)$").unwrap());
static RE_MANIFEST: Lazy<Regex> = Lazy::new(|| Regex::new("(?m)URI=\"([^\"]+)\"").unwrap());
static RE_DASH_MANIFEST: Lazy<Regex> =
    Lazy::new(|| Regex::new("BaseURL>(https://[^<]+)</BaseURL").unwrap());

static CLIENT: Lazy<Client> = Lazy::new(|| {
    let builder = Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0")
        // reqwest follows redirects to any http(s) URL by default, so a redirect from an allowed
        // domain could point the proxy at internal services (e.g. cloud metadata at
        // 169.254.169.254) and their responses would be returned to the client. Only follow
        // redirects that stay on allowed domains.
        .redirect(Policy::custom(|attempt| {
            // same limit as reqwest's default policy, the first URL is the original request
            if attempt.previous().len() > 10 {
                return attempt.error("too many redirects");
            }

            if is_redirect_allowed(attempt.url()) {
                attempt.follow()
            } else {
                let url = attempt.url().to_string();
                attempt.error(format!("redirect to disallowed URL {}", url))
            }
        }))
        // refuse to connect allowed domains to loopback, private, link-local, ... addresses
        .dns_resolver(resolver::PublicOnlyResolver);

    let proxy = if let Ok(proxy) = env::var("PROXY") {
        reqwest::Proxy::all(proxy).ok()
    } else {
        None
    };

    let builder = if let Some(proxy) = proxy {
        // proxy basic auth
        if let Ok(proxy_auth_user) = env::var("PROXY_USER") {
            let proxy_auth_pass = env::var("PROXY_PASS").unwrap_or_default();
            builder.proxy(proxy.basic_auth(&proxy_auth_user, &proxy_auth_pass))
        } else {
            builder.proxy(proxy)
        }
    } else {
        builder
    };

    if utils::get_env_bool("IPV4_ONLY") {
        builder.local_address("0.0.0.0".parse().ok())
    } else {
        builder
    }
    .build()
    .unwrap()
});

const ANDROID_USER_AGENT: &str = "com.google.android.youtube/1537338816 (Linux; U; Android 13; en_US; ; Build/TQ2A.230505.002; Cronet/113.0.5672.24)";
const ALLOWED_DOMAINS: [&str; 8] = [
    "youtube.com",
    "googlevideo.com",
    "ytimg.com",
    "ggpht.com",
    "googleusercontent.com",
    "lbryplayer.xyz",
    "odycdn.com",
    "ajay.app",
];

/// Whether `host` is googlevideo.com or a subdomain of it, the only hosts that serve SABR.
fn is_googlevideo_host(host: &str) -> bool {
    host == "googlevideo.com" || host.ends_with(".googlevideo.com")
}

/// Whether the proxy may fetch from `host` (one of the allowed domains or a subdomain of one).
fn is_host_allowed(host: &str) -> bool {
    RE_DOMAIN
        .captures(host)
        .and_then(|domain| domain.get(1))
        .is_some_and(|domain| ALLOWED_DOMAINS.contains(&domain.as_str()))
}

// Whether the upstream client may follow a redirect to this URL. Like the original request it must
// be https on the default port, and its host must be on an allowed domain. IP literals never pass
// the domain check.
fn is_redirect_allowed(url: &Url) -> bool {
    url.scheme() == "https" && url.port().is_none() && url.host_str().is_some_and(is_host_allowed)
}

fn add_headers(response: &mut HttpResponseBuilder) {
    response
        .append_header(("Access-Control-Allow-Origin", "*"))
        .append_header(("Access-Control-Allow-Headers", "*"))
        .append_header(("Access-Control-Allow-Methods", "*"))
        .append_header(("Access-Control-Max-Age", "1728000"));
}

// Headers from the client that may be forwarded upstream. This is an allowlist rather than a
// blocklist so that anything identifying the user (client IP headers added by reverse proxies and
// CDNs, cookies, client hints, accept-language, ...) is dropped by default instead of leaking to
// Google whenever a new header appears.
//
// 'accept-encoding' is deliberately not forwarded: reqwest then advertises only the encodings it
// can decompress itself (gzip, br). Forwarding the client's value could let Google answer with an
// encoding reqwest passes through still compressed (e.g. zstd), which breaks the manifest rewriting,
// image transcoding and SABR redirect rewriting below.
// 'range' is not forwarded either, it is moved into the query string for videoplayback.
fn is_request_header_allowed(header: &str) -> bool {
    matches!(
        header,
        "accept"
            // the type of the SABR request body, see proxy_sabr
            | "content-type"
            // conditional requests, so the browser can revalidate cached images
            | "if-none-match"
            | "if-modified-since"
    )
}

// Headers from the upstream response that may be passed back to the client
fn is_response_header_allowed(header: &str) -> bool {
    if header.starts_with("access-control") {
        return false;
    }

    !matches!(
        header,
        "host"
            | "content-length"
            | "set-cookie"
            | "alt-svc"
            | "accept-ch"
            | "report-to"
            | "strict-transport-security"
            | "user-agent"
            | "range"
            | "transfer-encoding"
            | "x-real-ip"
            | "origin"
            | "referer"
            // the 'x-title' header contains non-ascii characters which is not allowed on some HTTP clients
            | "x-title"
    )
}

/// Parses "start-end" or "start-" (optionally prefixed with "bytes="), as used by the Range header
/// and the range query parameter. Returns None for anything else instead of panicking.
fn parse_byte_range(range: &str) -> Option<(u64, Option<u64>)> {
    let range = range.trim();
    let range = range.strip_prefix("bytes=").unwrap_or(range);
    let (start, end) = range.split_once('-')?;
    let start = start.trim().parse::<u64>().ok()?;
    let end = match end.trim() {
        "" => None,
        end => Some(end.parse::<u64>().ok()?),
    };
    Some((start, end))
}

struct RangeRequest {
    start: u64,
    end: u64,
    total_size: u64,
}

fn parse_range(range_str: &str, total_size: u64) -> Option<RangeRequest> {
    let range_parts: Vec<&str> = range_str.split('-').collect();

    if range_parts.len() != 2 {
        return None;
    }

    let start_result = range_parts[0].parse::<u64>();
    let start = start_result.unwrap_or(0);

    // Parse end position - if empty, use total_size-1 (open-ended range)
    let end = if range_parts[1].is_empty() {
        total_size.saturating_sub(1) // Avoid underflow
    } else {
        let end_result = range_parts[1].parse::<u64>();
        let parsed_end = end_result.unwrap_or(total_size.saturating_sub(1));
        parsed_end.min(total_size.saturating_sub(1))
    };

    Some(RangeRequest {
        start,
        end,
        total_size,
    })
}

fn handle_range_response_correction(
    response: &mut HttpResponseBuilder,
    range_str: Option<&String>,
    clen: Option<u64>,
    resp: &reqwest::Response,
) -> Option<()> {
    // Check if this is a range request (either in headers or query string)
    let has_range_request = resp.headers().contains_key("range") || range_str.is_some();

    // Only apply correction if we have a range request and response is 200 (should be 206)
    if !has_range_request
        || !resp.status().is_success()
        || resp.status() == reqwest::StatusCode::PARTIAL_CONTENT
    {
        return None;
    }

    // total_size is the full file size from the videoplayback URL's `clen`. The
    // upstream Content-Length is only the current chunk; using it as the total
    // produced malformed Content-Range that broke itag-18 seek in Chromium.
    let total_size = match clen {
        Some(c) if c > 0 => c,
        _ => resp
            .headers()
            .get("content-length")?
            .to_str()
            .ok()?
            .parse::<u64>()
            .ok()?,
    };

    if total_size == 0 {
        return None;
    }

    // Parse the range request into start/end positions
    let range_request = parse_range(range_str?, total_size)?;

    // Apply proper HTTP range headers
    apply_range_headers(response, &range_request);

    Some(())
}

fn apply_range_headers(response: &mut HttpResponseBuilder, range_request: &RangeRequest) {
    let content_range_value = format!(
        "bytes {}-{}/{}",
        range_request.start, range_request.end, range_request.total_size
    );

    // Use total_size when range was truncated by YouTube (start > end)
    // Otherwise calculate normally
    let actual_length = if range_request.start > range_request.end {
        range_request.total_size
    } else {
        range_request.end - range_request.start + 1
    };

    // Set proper partial content response
    response.status(actix_web::http::StatusCode::PARTIAL_CONTENT);
    // Set required headers for partial content responses
    response.insert_header(("Content-Range", content_range_value));
    response.insert_header(("Content-Length", actual_length.to_string()));
}

async fn index(req: HttpRequest, body: web::Bytes) -> Result<HttpResponse, Box<dyn Error>> {
    // SABR clients POST their requests to /videoplayback, nothing else takes a body
    let is_sabr_post =
        req.method() == actix_web::http::Method::POST && req.path() == "/videoplayback";

    if req.method() == actix_web::http::Method::OPTIONS {
        let mut response = HttpResponse::Ok();
        add_headers(&mut response);
        return Ok(response.finish());
    } else if req.method() != actix_web::http::Method::GET
        && req.method() != actix_web::http::Method::HEAD
        && !is_sabr_post
    {
        let mut response = HttpResponse::MethodNotAllowed();
        add_headers(&mut response);
        return Ok(response.finish());
    }

    // parse query string
    let mut query = QString::from(req.query_string());

    #[cfg(feature = "qhash")]
    {
        use std::collections::BTreeSet;

        let secret = env::var("HASH_SECRET");
        if let Ok(secret) = secret {
            let Some(qhash) = query.get("qhash") else {
                return Err("No qhash provided".into());
            };

            if qhash.len() != 8 {
                return Err("Invalid qhash provided".into());
            }

            let path = req.path().as_bytes().to_owned();

            // Store sorted key-value pairs
            let mut set = BTreeSet::new();
            {
                let pairs = query.to_pairs();
                for (key, value) in &pairs {
                    if matches!(*key, "qhash" | "range" | "rewrite" | "rn") {
                        continue;
                    }
                    set.insert((key.as_bytes().to_owned(), value.as_bytes().to_owned()));
                }
            }

            let hash = spawn_blocking(move || {
                let mut hasher = blake3::Hasher::new();

                for (key, value) in set {
                    hasher.update(&key);
                    hasher.update(&value);
                }

                let range_marker = b"/range/";

                // Find the slice before "/range/"
                if let Some(position) = path
                    .windows(range_marker.len())
                    .position(|window| window == range_marker)
                {
                    // Update the hasher with the part of the path before "/range/"
                    // We add +1 to include the "/" in the hash
                    // This is done for DASH streams for the manifests provided by YouTube
                    hasher.update(&path[..(position + 1)]);
                } else {
                    hasher.update(&path);
                }

                hasher.update(secret.as_bytes());

                let hash = hasher.finalize().to_hex();

                hash[..8].to_owned()
            })
            .await
            .unwrap();

            if hash != qhash {
                return Err("Invalid qhash provided".into());
            }
        }
    }

    let Some(host) = query.get("host").map(|s| s.to_string()) else {
        return Err("No host provided".into());
    };

    #[cfg(any(feature = "webp", feature = "avif"))]
    let disallow_image_transcoding = utils::get_env_bool("DISALLOW_IMAGE_TRANSCODING");

    let rewrite = query.get("rewrite") != Some("false");

    #[cfg(feature = "avif")]
    let avif = query.get("avif") == Some("true");

    if !RE_DOMAIN.is_match(host.as_str()) {
        return Err("Invalid host provided".into());
    }

    if !is_host_allowed(host.as_str()) {
        return Err("Domain not allowed".into());
    }

    let video_playback = req.path().eq("/videoplayback");

    if video_playback {
        if let Some(expiry) = query.get("expire") {
            let expiry = expiry.parse::<i64>()?;
            let now = SystemTime::now();
            let now = now
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs() as i64;
            if now > expiry {
                return Err("Expire time in past".into());
            }
        }
    }

    let is_android = video_playback && query.get("c").unwrap_or("").eq("ANDROID");

    if is_sabr_post {
        // Only googlevideo speaks SABR; anything else would make this an open POST relay
        if !is_googlevideo_host(&host) {
            return Err("Domain not allowed".into());
        }
        return proxy_sabr(&req, query, &host, body, is_android).await;
    }

    let is_web = video_playback && query.get("c").unwrap_or("").eq("WEB");

    let is_ump = video_playback && query.get("ump").is_some();

    let mime_type = query.get("mime").map(|s| s.to_string());

    // A content length of 0 would make every "clen - 1" below underflow, so treat it as unknown
    let clen = query
        .get("clen")
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&clen| clen > 0);

    if video_playback && !query.has("range") {
        if let Some(range) = req.headers().get("range") {
            // A Range header we can't make sense of is ignored, like servers do
            if let Some((start, end)) = range.to_str().ok().and_then(parse_byte_range) {
                let end = end.or(clen.map(|clen| clen - 1)).unwrap_or(0);
                if end != 0 {
                    let range = format!("{}-{}", start, end);
                    query.add_pair(("range", range));
                }
            }
        } else if let Some(clen) = clen {
            let range = format!("0-{}", clen - 1);
            query.add_pair(("range", range));
        }
    }

    let range = query.get("range").map(|s| s.to_string());

    let qs = {
        let collected = query
            .into_pairs()
            .into_iter()
            .filter(|(key, _)| !matches!(key.as_str(), "host" | "rewrite" | "qhash"))
            .collect::<Vec<_>>();
        QString::new(collected)
    };

    let mut url = Url::parse(&format!("https://{}{}", host, req.path()))?;
    url.set_query(Some(qs.to_string().as_str()));

    let method = {
        if is_web && video_playback {
            Method::POST
        } else {
            Method::from_str(req.method().as_str())?
        }
    };

    let mut request = Request::new(method, url);

    if is_web && video_playback {
        request.body_mut().replace(Body::from("x\0"));
    }

    let request_headers = request.headers_mut();

    for (key, value) in req.headers() {
        let key = key.as_str();
        if is_request_header_allowed(key) {
            request_headers.insert(
                HeaderName::from_str(key)?,
                HeaderValue::from_bytes(value.as_bytes())?,
            );
        }
    }

    if is_android {
        request_headers.insert("User-Agent", ANDROID_USER_AGENT.parse()?);
    }

    let resp = CLIENT.execute(request).await?;

    let mut response = HttpResponse::build(StatusCode::from_u16(resp.status().as_u16())?);

    add_headers(&mut response);

    for (key, value) in resp.headers() {
        if is_response_header_allowed(key.as_str()) {
            response.append_header((key.as_str(), value.as_bytes()));
        }
    }

    // Fix range request handling - convert 200 to 206 if we have a range request
    // and ensure Content-Range header is present
    handle_range_response_correction(&mut response, range.as_ref(), clen, &resp);

    if rewrite {
        if let Some(content_type) = resp.headers().get("content-type") {
            #[cfg(feature = "avif")]
            if !disallow_image_transcoding
                && (content_type == "image/webp" || content_type == "image/jpeg" && avif)
            {
                let resp_bytes = resp.bytes().await?;
                let (body, content_type) = spawn_blocking(|| {
                    use ravif::{Encoder, Img};
                    use rgb::FromSlice;

                    // Send anything that doesn't decode as it is
                    let Ok(image) = image::load_from_memory(&resp_bytes) else {
                        return (resp_bytes.into(), "image/jpeg");
                    };

                    let width = image.width() as usize;
                    let height = image.height() as usize;

                    let buf = image.into_rgb8();
                    let buf = buf.as_raw().as_rgb();

                    let buffer = Img::new(buf, width, height);

                    let res = Encoder::new()
                        .with_quality(80f32)
                        .with_speed(7)
                        .encode_rgb(buffer);

                    if let Ok(res) = res {
                        (res.avif_file.to_vec(), "image/avif")
                    } else {
                        (resp_bytes.into(), "image/jpeg")
                    }
                })
                .await
                .unwrap();
                response.content_type(content_type);
                return Ok(response.body(body));
            }

            #[cfg(feature = "webp")]
            if !disallow_image_transcoding && content_type == "image/jpeg" {
                let resp_bytes = resp.bytes().await?;
                let (body, content_type) = spawn_blocking(|| {
                    use libwebp_sys::{WebPEncodeRGB, WebPFree};

                    // Send anything that doesn't decode as it is
                    let Ok(image) = image::load_from_memory(&resp_bytes) else {
                        return (resp_bytes.into(), "image/jpeg");
                    };
                    let width = image.width();
                    let height = image.height();

                    let quality = 85;

                    // as_rgb8() is None for grayscale or CMYK JPEGs, so convert instead
                    let image = image.into_rgb8();
                    let data = image.as_raw();

                    let bytes: Vec<u8> = unsafe {
                        let mut out_buf = std::ptr::null_mut();
                        let stride = width as i32 * 3;
                        let len: usize = WebPEncodeRGB(
                            data.as_ptr(),
                            width as i32,
                            height as i32,
                            stride,
                            quality as f32,
                            &mut out_buf,
                        );
                        let vec = std::slice::from_raw_parts(out_buf, len).into();
                        WebPFree(out_buf as *mut _);
                        vec
                    };

                    if bytes.len() < resp_bytes.len() {
                        (bytes, "image/webp")
                    } else {
                        (resp_bytes.into(), "image/jpeg")
                    }
                })
                .await
                .unwrap();
                response.content_type(content_type);
                return Ok(response.body(body));
            }

            if content_type == "application/x-mpegurl"
                || content_type == "application/vnd.apple.mpegurl"
            {
                let resp_str = resp.text().await?;

                let modified = resp_str
                    .lines()
                    .map(|line| {
                        let captures = RE_MANIFEST.captures(line);
                        if let Some(captures) = captures {
                            let url = captures.get(1).unwrap().as_str();
                            if url.starts_with("https://") {
                                return line.replace(
                                    url,
                                    utils::localize_url(url, host.as_str()).as_str(),
                                );
                            }
                        }
                        utils::localize_url(line, host.as_str())
                    })
                    .collect::<Vec<String>>()
                    .join("\n");

                return Ok(response.body(modified));
            }
            if content_type == "video/vnd.mpeg.dash.mpd" || content_type == "application/dash+xml" {
                let resp_str = resp.text().await?;
                let mut new_resp = resp_str.clone();
                let captures = RE_DASH_MANIFEST.captures_iter(&resp_str);
                for capture in captures {
                    let url = capture.get(1).unwrap().as_str();
                    let new_url = utils::localize_url(url, host.as_str());
                    let new_url = utils::escape_xml(new_url.as_str());
                    new_resp = new_resp.replace(url, new_url.as_ref());
                }
                return Ok(response.body(new_resp));
            }
        }
    }

    if let Some(content_length) = resp
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    {
        response.no_chunking(content_length);
    }

    if is_ump && resp.status().is_success() {
        if let Some(mime_type) = mime_type {
            response.content_type(mime_type);
        }
        if req.headers().contains_key("range") {
            // check if it's not the whole stream
            if let Some(ref range) = range {
                if let Some(clen) = clen {
                    if range != &format!("0-{}", clen - 1) {
                        response.status(StatusCode::PARTIAL_CONTENT);

                        // Add proper Content-Range header for UMP streams
                        let content_range_value = format!("bytes {}/{}", range, clen);
                        response.insert_header(("Content-Range", content_range_value.clone()));
                    }
                }
            }
        }
        let resp = resp.bytes_stream();
        let resp = resp.map_err(|e| io::Error::new(ErrorKind::Other, e));
        let transformed_stream = UmpTransformStream::new(resp);
        // print errors
        let transformed_stream = transformed_stream.map_err(|e| {
            eprintln!("UMP Transforming Error: {}", e);
            e
        });

        // calculate content length from clen and range
        if let Some(clen) = clen {
            let length = match range.as_deref() {
                Some(range) => parse_byte_range(range).and_then(|(start, end)| {
                    let end = end.unwrap_or(clen - 1);
                    // An inverted range has no sensible length; leave it chunked
                    end.checked_sub(start).map(|len| len + 1)
                }),
                None => Some(clen),
            };
            if let Some(length) = length {
                response.no_chunking(length);
            }
        }

        return Ok(response.streaming(transformed_stream));
    }

    // Stream response
    Ok(response.streaming(resp.bytes_stream()))
}

/// Forwards a SABR (or plain UMP) POST from a client that speaks the protocol itself,
/// such as googlevideo's `SabrStreamingAdapter`. The body goes up as-is and the UMP
/// response comes back as-is, except that redirects are pointed back at this proxy.
async fn proxy_sabr(
    req: &HttpRequest,
    query: QString,
    host: &str,
    body: web::Bytes,
    is_android: bool,
) -> Result<HttpResponse, Box<dyn Error>> {
    let qs = QString::new(
        query
            .into_pairs()
            .into_iter()
            .filter(|(key, _)| !matches!(key.as_str(), "host" | "rewrite" | "qhash"))
            .collect::<Vec<_>>(),
    );

    let mut url = Url::parse(&format!("https://{}{}", host, req.path()))?;
    url.set_query(Some(qs.to_string().as_str()));

    let mut request = Request::new(Method::POST, url);
    request.body_mut().replace(Body::from(body));

    let request_headers = request.headers_mut();
    for (key, value) in req.headers() {
        let key = key.as_str();
        // 'accept-encoding' is not on the allowlist, so compression is left to reqwest, which then
        // hands us decoded bytes the redirect rewriter can read
        if is_request_header_allowed(key) {
            request_headers.insert(
                HeaderName::from_str(key)?,
                HeaderValue::from_bytes(value.as_bytes())?,
            );
        }
    }

    if is_android {
        request_headers.insert("User-Agent", ANDROID_USER_AGENT.parse()?);
    }

    let resp = CLIENT.execute(request).await?;

    let mut response = HttpResponse::build(StatusCode::from_u16(resp.status().as_u16())?);
    add_headers(&mut response);

    for (key, value) in resp.headers() {
        if is_response_header_allowed(key.as_str()) {
            response.append_header((key.as_str(), value.as_bytes()));
        }
    }

    let is_ump = resp
        .headers()
        .get("content-type")
        .is_some_and(|content_type| {
            content_type
                .as_bytes()
                .starts_with(b"application/vnd.yt-ump")
        });

    let stream = resp.bytes_stream().map_err(io::Error::other);

    if is_ump {
        if let Some(origin) = sabr::public_origin(req) {
            // The rewritten redirects change the length, so this is always chunked
            return Ok(response.streaming(sabr::UmpRedirectRewriter::new(stream, origin)));
        }
        eprintln!("Cannot work out this proxy's public URL, so SABR redirects will bypass it. Set PROXY_PUBLIC_URL.");
    }

    Ok(response.streaming(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_byte_ranges_without_panicking() {
        assert_eq!(parse_byte_range("bytes=0-499"), Some((0, Some(499))));
        assert_eq!(parse_byte_range("100-"), Some((100, None)));
        assert_eq!(parse_byte_range(" bytes=5-10 "), Some((5, Some(10))));
        for bad in ["", "5", "bytes=5", "a-b", "-5", "5-x", "bytes=-", "1-2-3"] {
            assert_eq!(parse_byte_range(bad), None, "{:?}", bad);
        }
    }

    #[test]
    fn never_forwards_identifying_headers() {
        for header in [
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "forwarded",
            "via",
            "cf-connecting-ip",
            "true-client-ip",
            "x-client-ip",
            "x-real-ip",
            "cookie",
            "authorization",
            "proxy-authorization",
            "origin",
            "referer",
            "accept-language",
            "accept-encoding",
            "range",
        ] {
            assert!(!is_request_header_allowed(header), "{} is forwarded", header);
        }
        // What SABR and image revalidation need still goes through
        for header in ["content-type", "accept", "if-none-match", "if-modified-since"] {
            assert!(is_request_header_allowed(header), "{} is dropped", header);
        }
    }

    #[test]
    fn sabr_is_limited_to_googlevideo() {
        assert!(is_googlevideo_host("rr1---sn-abc.googlevideo.com"));
        assert!(is_googlevideo_host("googlevideo.com"));
        for host in [
            "evilgooglevideo.com",
            "x.googleusercontent.com",
            "googlevideo.com.evil.example",
            "www.youtube.com",
        ] {
            assert!(!is_googlevideo_host(host), "{}", host);
        }
    }
}
