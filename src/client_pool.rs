//! Spreads upstream requests over several reqwest clients so that no HTTP/2 connection carries
//! more requests at once than the server allows.
//!
//! reqwest (through hyper-util) keeps a single HTTP/2 connection per host and sends every request
//! for that host over it. googlevideo allows 100 concurrent streams on a connection, and h2 queues
//! any request past that until another one finishes, so a busy proxy would make the 101st request
//! wait. Each reqwest client has its own connection pool, so sending the overflow through another
//! client opens another connection instead.
//!
//! Requests are counted under the host they were sent to. One that reqwest follows through a
//! redirect to another host still occupies a stream on that host's connection without being
//! counted there, which can only make a request queue, never fail.

use std::sync::Mutex;
use std::sync::PoisonError;
use futures_util::StreamExt;
use std::collections::HashMap;
use http::Response as HttpResponse;
use reqwest::{Body, Client, Request, Response};

/// The most requests to send over one connection at once. googlevideo advertises
/// SETTINGS_MAX_CONCURRENT_STREAMS = 100.
const MAX_STREAMS_PER_CONNECTION: usize = 100;

pub struct ClientPool {
    build: fn() -> Client,
    state: Mutex<State>,
}

struct State {
    /// `clients[i]` carries the i-th connection to every host
    clients: Vec<Client>,
    slots: StreamSlots,
}

impl ClientPool {
    /// `build` makes a new client whenever every existing one has a full connection to a host.
    pub fn new(build: fn() -> Client) -> Self {
        ClientPool {
            build,
            state: Mutex::new(State {
                clients: Vec::new(),
                slots: StreamSlots::default(),
            }),
        }
    }

    /// Sends `request` through the first client whose connection to the host has room for
    /// another stream. The request keeps its slot until its response body has been read to the
    /// end or dropped.
    pub async fn execute(&'static self, request: Request) -> reqwest::Result<Response> {
        let host = request.url().host_str().unwrap_or_default().to_owned();
        let (client, slot) = self.acquire(host);

        // on an error the slot is dropped, and so released, here
        let resp = client.execute(request).await?;

        let status = resp.status();
        let version = resp.version();
        let headers = resp.headers().clone();

        // Move the slot into the body stream so that it lives exactly as long as the body
        let body = Body::wrap_stream(resp.bytes_stream().map(move |chunk| {
            let _slot = &slot;
            chunk
        }));

        let mut response = HttpResponse::new(body);
        *response.status_mut() = status;
        *response.version_mut() = version;
        *response.headers_mut() = headers;

        Ok(Response::from(response))
    }

    fn acquire(&'static self, host: String) -> (Client, Slot) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);

        let index = state.slots.acquire(&host);
        // A host never has more connections than there are clients, so at most one is missing
        if index == state.clients.len() {
            state.clients.push((self.build)());
        }

        let client = state.clients[index].clone();
        let slot = Slot {
            pool: self,
            host,
            index,
        };
        (client, slot)
    }
}

/// A request's place on a connection, given back when dropped
struct Slot {
    pool: &'static ClientPool,
    host: String,
    index: usize,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut state = self
            .pool
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.slots.release(&self.host, self.index);
    }
}

/// How many requests are in flight to each host over each client's connection
#[derive(Default)]
struct StreamSlots {
    in_flight: HashMap<String, Vec<usize>>,
}

impl StreamSlots {
    /// Takes a slot on the first connection to `host` that has room and returns its index,
    /// adding a connection when all of them are full.
    fn acquire(&mut self, host: &str) -> usize {
        let counts = self.in_flight.entry(host.to_owned()).or_default();

        let index = counts
            .iter()
            .position(|&count| count < MAX_STREAMS_PER_CONNECTION)
            .unwrap_or(counts.len());
        if index == counts.len() {
            counts.push(0);
        }

        counts[index] += 1;
        index
    }

    fn release(&mut self, host: &str, index: usize) {
        if let Some(counts) = self.in_flight.get_mut(host) {
            counts[index] -= 1;

            // Nearly every video is on a different googlevideo host, so forget hosts with nothing
            // in flight instead of keeping an entry for each one forever
            if counts.iter().all(|&count| count == 0) {
                self.in_flight.remove(host);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflows_onto_a_new_connection() {
        let mut slots = StreamSlots::default();

        for _ in 0..MAX_STREAMS_PER_CONNECTION {
            assert_eq!(slots.acquire("a.googlevideo.com"), 0);
        }
        assert_eq!(slots.acquire("a.googlevideo.com"), 1);
        assert_eq!(slots.acquire("a.googlevideo.com"), 1);

        // other hosts have connections of their own
        assert_eq!(slots.acquire("b.googlevideo.com"), 0);
    }

    #[test]
    fn reuses_freed_slots_first() {
        let mut slots = StreamSlots::default();

        for _ in 0..=MAX_STREAMS_PER_CONNECTION {
            slots.acquire("a.googlevideo.com");
        }
        slots.release("a.googlevideo.com", 0);

        assert_eq!(slots.acquire("a.googlevideo.com"), 0);
        assert_eq!(slots.acquire("a.googlevideo.com"), 1);
    }

    #[test]
    fn forgets_idle_hosts() {
        let mut slots = StreamSlots::default();

        for _ in 0..=MAX_STREAMS_PER_CONNECTION {
            slots.acquire("a.googlevideo.com");
        }
        for _ in 0..MAX_STREAMS_PER_CONNECTION {
            slots.release("a.googlevideo.com", 0);
        }
        assert!(slots.in_flight.contains_key("a.googlevideo.com"));

        slots.release("a.googlevideo.com", 1);
        assert!(slots.in_flight.is_empty());
    }
}
