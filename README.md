# piped-proxy

A proxy for Piped written in Rust, meant to superseed [http3-ytproxy](https://github.com/TeamPiped/http3-ytproxy).

## SABR

YouTube's web player streams with SABR: it POSTs a protobuf request to `/videoplayback` and gets back a UMP stream. This fork forwards those POSTs as they are and streams the answer back, so a client that speaks SABR itself (such as [googlevideo](https://github.com/LuanRT/googlevideo)'s `SabrStreamingAdapter`) can play through the proxy. The only part it changes is a `SABR_REDIRECT`, whose URL it points back at the proxy so that the client never contacts Google directly.

Redirect URLs have to be absolute, so the proxy needs to know its public URL. Set it with `PROXY_PUBLIC_URL`, such as `PROXY_PUBLIC_URL=https://pipedproxy.example.com`. Without it, the proxy uses the `X-Forwarded-Host` (or `Host`) and `X-Forwarded-Proto` headers from the reverse proxy in front of it, and assumes HTTPS when there is no `X-Forwarded-Proto`.

With `HASH_SECRET` set, the `rn` parameter (a request counter that the SABR client changes on every request) is left out of the `qhash`, like `range`.
