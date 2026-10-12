//! SABR (Server ABR) passthrough.
//!
//! With SABR, the player POSTs a `VideoPlaybackAbrRequest` protobuf to the
//! `serverAbrStreamingUrl` and gets back a UMP stream of numbered parts. The
//! client (e.g. googlevideo's `SabrStreamingAdapter`) builds the request and
//! parses the response itself, so the proxy only has to forward the body and
//! stream the answer back. The one thing it can't pass through untouched is a
//! `SABR_REDIRECT` part: that tells the client to send its next requests to a
//! different googlevideo host, so we point it back at this proxy instead.

use crate::utils;
use actix_web::HttpRequest;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::Stream;
use reqwest::Url;
use std::env;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// UMP part type of a `SabrRedirect` message (see googlevideo's `UMPPartId`).
const PART_SABR_REDIRECT: u32 = 43;

/// A redirect is a single URL, so anything bigger than this isn't one we want to buffer.
const MAX_REDIRECT_PART_SIZE: usize = 64 * 1024;

/// Reads a UMP variable-length integer. Returns `(value, bytes used)`, or `None` if `buf` is too short.
///
/// UMP integers are not protobuf varints: the number of leading 1 bits in the
/// first byte says how many more bytes follow (up to 4).
fn read_ump_varint(buf: &[u8]) -> Option<(u32, usize)> {
    let first = *buf.first()?;
    let size = match first {
        0x00..=0x7f => 1,
        0x80..=0xbf => 2,
        0xc0..=0xdf => 3,
        0xe0..=0xef => 4,
        _ => 5,
    };
    if buf.len() < size {
        return None;
    }

    let b = |i: usize| buf[i] as u32;
    let value = match size {
        1 => first as u32,
        2 => (first as u32 & 0x3f) | (b(1) << 6),
        3 => (first as u32 & 0x1f) | ((b(1) | (b(2) << 8)) << 5),
        4 => (first as u32 & 0x0f) | ((b(1) | (b(2) << 8) | (b(3) << 16)) << 4),
        // 5 bytes: the prefix byte carries no data, the value is a little-endian u32
        _ => u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
    };

    Some((value, size))
}

/// Writes a UMP variable-length integer (the inverse of [`read_ump_varint`]).
fn write_ump_varint(out: &mut BytesMut, value: u32) {
    if value < 0x80 {
        out.put_u8(value as u8);
    } else if value < 0x4000 {
        out.put_u8(((value & 0x3f) | 0x80) as u8);
        out.put_u8((value >> 6) as u8);
    } else if value < 0x20_0000 {
        out.put_u8(((value & 0x1f) | 0xc0) as u8);
        out.put_u16_le((value >> 5) as u16);
    } else if value < 0x1000_0000 {
        out.put_u8(((value & 0x0f) | 0xe0) as u8);
        out.put_u8((value >> 4) as u8);
        out.put_u16_le((value >> 12) as u16);
    } else {
        out.put_u8(0xf0);
        out.put_u32_le(value);
    }
}

/// Reads a protobuf (LEB128) varint, advancing `buf`.
fn read_proto_varint(buf: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *buf.first()?;
        buf.advance(1);
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None // more than 10 bytes, not a varint we trust
}

/// Writes a protobuf (LEB128) varint.
fn write_proto_varint(out: &mut BytesMut, mut value: u64) {
    while value >= 0x80 {
        out.put_u8((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.put_u8(value as u8);
}

/// Rewrites field 1 (`url`) of a `SabrRedirect` protobuf with `rewrite`, keeping every other field.
/// Returns `None` if the message doesn't parse, so the caller can pass the original through.
fn rewrite_sabr_redirect(
    message: &[u8],
    rewrite: impl Fn(&str) -> Option<String>,
) -> Option<Bytes> {
    let mut input = message;
    let mut out = BytesMut::with_capacity(message.len() + 128);

    while !input.is_empty() {
        let field_start = input;
        let tag = read_proto_varint(&mut input)?;
        let (field, wire_type) = (tag >> 3, tag & 7);

        // Work out how long this field's value is, so unknown fields can be copied verbatim
        let value_len = match wire_type {
            0 => {
                let mut probe = input;
                read_proto_varint(&mut probe)?;
                input.len() - probe.len()
            }
            1 => 8,
            2 => {
                let len = read_proto_varint(&mut input)? as usize;
                if field == 1 {
                    let url = std::str::from_utf8(input.get(..len)?).ok()?;
                    let new_url = rewrite(url).unwrap_or_else(|| url.to_string());
                    write_proto_varint(&mut out, tag);
                    write_proto_varint(&mut out, new_url.len() as u64);
                    out.put_slice(new_url.as_bytes());
                    input.advance(len);
                    continue;
                }
                len
            }
            5 => 4,
            _ => return None, // groups are long gone; anything else means we misparsed
        };

        input.get(..value_len)?;
        input.advance(value_len);
        // Copy the whole field (tag, length prefix and value) as it was
        out.put_slice(&field_start[..field_start.len() - input.len()]);
    }

    Some(out.freeze())
}

/// Works out the public base URL of this proxy (e.g. `https://pipedproxy.example.com`),
/// which redirect URLs must be absolute against.
///
/// `PROXY_PUBLIC_URL` wins if set. Otherwise it is guessed from the headers the
/// reverse proxy in front of us passes on, assuming HTTPS if it doesn't say.
pub fn public_origin(req: &HttpRequest) -> Option<String> {
    if let Ok(url) = env::var("PROXY_PUBLIC_URL") {
        let url = url.trim().trim_end_matches('/');
        if !url.is_empty() {
            return Some(url.to_string());
        }
    }

    // Only the first value counts when a header was appended to by several proxies
    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };

    let host = header("x-forwarded-host").or_else(|| header("host"))?;
    let scheme = header("x-forwarded-proto").unwrap_or_else(|| "https".to_string());

    // Don't let a weird header smuggle a path or credentials into the redirect
    if !matches!(scheme.as_str(), "http" | "https")
        || host.contains(|c: char| matches!(c, '/' | '@' | '?' | '#' | '\\') || c.is_whitespace())
    {
        return None;
    }

    Some(format!("{}://{}", scheme, host))
}

/// Turns a googlevideo redirect URL into the same URL going through this proxy.
/// URLs for hosts the proxy wouldn't serve are left alone.
pub fn localize_redirect_url(url: &str, origin: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    if parsed.scheme() != "https" || !crate::is_host_allowed(parsed.host_str()?) {
        return None;
    }

    // localize_url adds the `host` parameter (and the qhash, if one is configured)
    Some(format!("{}{}", origin, utils::localize_url(url, "")))
}

/// Passes a UMP response through unchanged, except that the URL in every
/// `SABR_REDIRECT` part is pointed back at this proxy.
///
/// Media parts are forwarded as they arrive, so this never buffers more than a
/// part header (or a small redirect part).
pub struct UmpRedirectRewriter<S> {
    inner: S,
    origin: String,
    buffer: BytesMut,
    /// Bytes of the current (non-redirect) part that can be forwarded without looking at them
    passthrough: usize,
    done: bool,
}

impl<S> UmpRedirectRewriter<S>
where
    S: Stream<Item = Result<Bytes, io::Error>> + Unpin,
{
    pub fn new(inner: S, origin: String) -> Self {
        UmpRedirectRewriter {
            inner,
            origin,
            buffer: BytesMut::new(),
            passthrough: 0,
            done: false,
        }
    }

    /// Takes the next chunk to send out of the buffer, if there is one ready.
    fn next_output(&mut self) -> Option<Bytes> {
        if self.buffer.is_empty() {
            return None;
        }

        // Middle of a media part: just shovel bytes along
        if self.passthrough > 0 {
            let len = self.passthrough.min(self.buffer.len());
            self.passthrough -= len;
            return Some(self.buffer.split_to(len).freeze());
        }

        // Start of a part: we need its full header first
        let (part_type, type_len) = read_ump_varint(&self.buffer)?;
        let (part_size, size_len) = read_ump_varint(&self.buffer[type_len..])?;
        let header_len = type_len + size_len;
        let part_size = part_size as usize;

        if part_type != PART_SABR_REDIRECT || part_size > MAX_REDIRECT_PART_SIZE {
            // Not ours to touch: send the header and stream the payload through
            self.passthrough = part_size;
            return Some(self.buffer.split_to(header_len).freeze());
        }

        // A redirect: wait until the whole (small) part is here, then rewrite it
        if self.buffer.len() < header_len + part_size {
            return None;
        }
        let part = self.buffer.split_to(header_len + part_size).freeze();
        let payload = &part[header_len..];

        let origin = self.origin.as_str();
        let Some(new_payload) =
            rewrite_sabr_redirect(payload, |url| localize_redirect_url(url, origin))
        else {
            eprintln!("Could not parse a SABR redirect, passing it through unchanged");
            return Some(part);
        };

        let mut out = BytesMut::with_capacity(new_payload.len() + 10);
        write_ump_varint(&mut out, PART_SABR_REDIRECT);
        write_ump_varint(&mut out, new_payload.len() as u32);
        out.put_slice(&new_payload);
        Some(out.freeze())
    }
}

impl<S> Stream for UmpRedirectRewriter<S>
where
    S: Stream<Item = Result<Bytes, io::Error>> + Unpin,
{
    type Item = Result<Bytes, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if let Some(chunk) = this.next_output() {
                return Poll::Ready(Some(Ok(chunk)));
            }

            if this.done {
                // Upstream ended mid-part: hand over whatever is left as it was
                if this.buffer.is_empty() {
                    return Poll::Ready(None);
                }
                return Poll::Ready(Some(Ok(this.buffer.split().freeze())));
            }

            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(bytes))) => {
                    // Fast path: the whole chunk belongs to the media part being streamed
                    if this.buffer.is_empty() && this.passthrough >= bytes.len() {
                        this.passthrough -= bytes.len();
                        return Poll::Ready(Some(Ok(bytes)));
                    }
                    this.buffer.extend_from_slice(&bytes);
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => this.done = true,
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{stream, StreamExt};

    fn ump_part(part_type: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = BytesMut::new();
        write_ump_varint(&mut out, part_type);
        write_ump_varint(&mut out, payload.len() as u32);
        out.put_slice(payload);
        out.to_vec()
    }

    fn redirect_message(url: &str) -> Vec<u8> {
        let mut out = BytesMut::new();
        write_proto_varint(&mut out, (1 << 3) | 2);
        write_proto_varint(&mut out, url.len() as u64);
        out.put_slice(url.as_bytes());
        out.to_vec()
    }

    /// Pulls field 1 back out of a `SabrRedirect` message.
    fn redirect_url(message: &[u8]) -> String {
        let mut input = message;
        assert_eq!(read_proto_varint(&mut input), Some((1 << 3) | 2));
        let len = read_proto_varint(&mut input).unwrap() as usize;
        assert_eq!(input.len(), len);
        String::from_utf8(input.to_vec()).unwrap()
    }

    /// Splits a UMP body back into (type, payload) parts.
    fn parse_parts(mut buf: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut parts = Vec::new();
        while !buf.is_empty() {
            let (t, a) = read_ump_varint(buf).unwrap();
            let (s, b) = read_ump_varint(&buf[a..]).unwrap();
            let start = a + b;
            parts.push((t, buf[start..start + s as usize].to_vec()));
            buf = &buf[start + s as usize..];
        }
        parts
    }

    /// Feeds `input` through the rewriter in chunks of `chunk_size` bytes.
    async fn run(input: &[u8], chunk_size: usize) -> Vec<u8> {
        let chunks: Vec<Result<Bytes, io::Error>> = input
            .chunks(chunk_size)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        let rewriter =
            UmpRedirectRewriter::new(stream::iter(chunks), "https://proxy.example".to_string());
        rewriter.map(|r| r.unwrap().to_vec()).concat().await
    }

    #[test]
    fn ump_varints_round_trip() {
        for value in [
            0,
            1,
            127,
            128,
            16383,
            16384,
            2097151,
            2097152,
            268435455,
            268435456,
            u32::MAX,
        ] {
            let mut out = BytesMut::new();
            write_ump_varint(&mut out, value);
            assert_eq!(
                read_ump_varint(&out),
                Some((value, out.len())),
                "value {}",
                value
            );
            // A truncated integer must ask for more data, not panic
            assert_eq!(read_ump_varint(&out[..out.len() - 1]), None);
        }
    }

    #[tokio::test]
    async fn rewrites_redirects_and_keeps_everything_else() {
        let url = "https://rr5---sn-abc.googlevideo.com/videoplayback?expire=1&sabr=1&id=x";
        let media = vec![7u8; 100_000];
        let mut input = ump_part(20, b"header");
        input.extend(ump_part(21, &media));
        input.extend(ump_part(PART_SABR_REDIRECT, &redirect_message(url)));
        input.extend(ump_part(35, b"policy"));

        // Chunk sizes that split headers, media and the redirect at awkward places
        for chunk_size in [1, 3, 7, 1000, 65536, input.len()] {
            let parts = parse_parts(&run(&input, chunk_size).await);
            assert_eq!(parts.len(), 4, "chunk size {}", chunk_size);
            assert_eq!(parts[0], (20, b"header".to_vec()));
            assert_eq!(parts[1], (21, media.clone()));
            assert_eq!(parts[3], (35, b"policy".to_vec()));

            let (part_type, payload) = &parts[2];
            assert_eq!(*part_type, PART_SABR_REDIRECT);
            let new_url = Url::parse(&redirect_url(payload)).unwrap();
            assert_eq!(new_url.host_str(), Some("proxy.example"));
            assert_eq!(new_url.path(), "/videoplayback");
            let query: Vec<_> = new_url.query_pairs().into_owned().collect();
            assert!(query.contains(&("host".into(), "rr5---sn-abc.googlevideo.com".into())));
            assert!(query.contains(&("sabr".into(), "1".into())));
        }
    }

    #[test]
    fn leaves_foreign_redirects_alone() {
        let message = redirect_message("https://evil.example/videoplayback");
        let rewritten = rewrite_sabr_redirect(&message, |url| {
            localize_redirect_url(url, "https://proxy.example")
        })
        .unwrap();
        assert_eq!(rewritten.as_ref(), message.as_slice());
    }

    #[test]
    fn keeps_unknown_redirect_fields() {
        let mut message = BytesMut::new();
        write_proto_varint(&mut message, 2 << 3); // field 2, wire type 0 (varint)
        write_proto_varint(&mut message, 300);
        message.put_slice(&redirect_message(
            "https://rr1---sn-x.googlevideo.com/videoplayback?a=b",
        ));

        let rewritten = rewrite_sabr_redirect(&message, |_| Some("https://p/x".into())).unwrap();
        let mut expected = BytesMut::new();
        write_proto_varint(&mut expected, 2 << 3);
        write_proto_varint(&mut expected, 300);
        expected.put_slice(&redirect_message("https://p/x"));
        assert_eq!(rewritten, expected.freeze());
    }

    #[test]
    fn rejects_garbage_redirects() {
        assert!(rewrite_sabr_redirect(&[0x0a, 0x50, b'h'], |_| None).is_none());
        assert!(rewrite_sabr_redirect(&[0x0b], |_| None).is_none());
    }
}
