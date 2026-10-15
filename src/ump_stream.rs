use bytes::{Bytes, BytesMut};
use futures_util::Stream;
use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Reads a UMP variable-length integer at `offset`, or fails if the buffer doesn't hold all of it yet.
fn read_variable_integer(buf: &[u8], offset: usize) -> io::Result<(u32, usize)> {
    buf.get(offset..)
        .and_then(crate::sabr::read_ump_varint)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "Incomplete UMP integer"))
}

pub struct UmpTransformStream<S>
where
    S: Stream<Item = Result<Bytes, io::Error>> + Unpin,
{
    inner: S,
    buffer: BytesMut,
    found_stream: bool,
    remaining: usize,
}

impl<S> UmpTransformStream<S>
where
    S: Stream<Item = Result<Bytes, io::Error>> + Unpin,
{
    pub fn new(stream: S) -> Self {
        UmpTransformStream {
            inner: stream,
            buffer: BytesMut::new(),
            found_stream: false,
            remaining: 0,
        }
    }
}

impl<S> Stream for UmpTransformStream<S>
where
    S: Stream<Item = Result<Bytes, io::Error>> + Unpin,
{
    type Item = Result<Bytes, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        while let Poll::Ready(item) = Pin::new(&mut this.inner).poll_next(cx) {
            match item {
                Some(Ok(bytes)) => {
                    if this.found_stream {
                        if this.remaining > 0 {
                            let len = std::cmp::min(this.remaining, bytes.len());
                            this.remaining -= len;
                            if this.remaining == 0 {
                                this.buffer.clear();
                                this.buffer.extend_from_slice(&bytes[len..]);
                                this.found_stream = false;
                            }
                            return Poll::Ready(Some(Ok(bytes.slice(0..len))));
                        } else {
                            this.found_stream = false;
                            this.buffer.clear();
                            this.buffer.extend_from_slice(&bytes);
                        };
                    } else {
                        this.buffer.extend_from_slice(&bytes);
                    }
                }
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                None => {
                    return Poll::Ready(None);
                }
            }
        }

        if !this.found_stream && !this.buffer.is_empty() {
            let (segment_type, s1) = match read_variable_integer(&this.buffer, 0) {
                Ok(result) => result,
                Err(_) => return Poll::Pending,
            };
            let (segment_length, s2) = match read_variable_integer(&this.buffer, s1) {
                Ok(result) => result,
                Err(_) => return Poll::Pending,
            };
            if segment_type != 21 {
                // Not the stream
                if this.buffer.len() > s1 + s2 + segment_length as usize {
                    let _ = this.buffer.split_to(s1 + s2 + segment_length as usize);
                }
            } else {
                // A zero-length part (no header byte to skip) is not worth underflowing over
                this.remaining = (segment_length as usize).saturating_sub(1);

                // The header byte after the part header must be here before it can be skipped
                if this.buffer.len() < s1 + s2 + 1 {
                    return Poll::Pending;
                }
                let _ = this.buffer.split_to(s1 + s2 + 1);

                if this.buffer.len() > segment_length as usize {
                    let len = std::cmp::min(this.remaining, this.buffer.len());
                    this.remaining -= len;

                    return Poll::Ready(Some(Ok(this.buffer.split_to(len).into())));
                } else {
                    this.remaining = this.remaining.saturating_sub(this.buffer.len());
                    this.found_stream = true;

                    return Poll::Ready(Some(Ok(this.buffer.to_vec().into())));
                }
            }
        }

        Poll::Pending
    }
}
