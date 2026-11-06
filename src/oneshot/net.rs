//! Pooled blocking HTTP transport shared by the one-shot exports.
//!
//! One [`Transport`] owns one `ureq::Agent`, i.e. one keep-alive connection pool (and optionally a
//! proxy and a private CA). Build it once and reuse it: a new agent per request throws away the
//! warm connection, which is where most of the one-shot latency win comes from.

use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;
/// How long an idle pooled connection is kept before being dropped. Keep this at or below the
/// venue/proxy's own idle timeout, otherwise the next order lands on a dead socket and pays a
/// reconnect (see the July 2026 leg-miss RCA).
pub const DEFAULT_IDLE_MS: u64 = 30_000;

pub struct Transport {
    agent: ureq::Agent,
}

#[derive(Debug)]
pub struct HttpOut {
    pub status: u16,
    pub body: Vec<u8>,
    pub retry_after: Option<String>,
}

impl Transport {
    /// * `proxy`: e.g. `socks5h://127.0.0.1:25344` (wireproxy). Use the `socks5h` scheme so the
    ///   proxy resolves the hostname, as Argus's `requests` setup does.
    /// * `ca_pem_path`: extra trust root (PEM) used INSTEAD of the bundled web roots; for private CAs/tests.
    /// * `timeout_ms` / `idle_ms`: `0` selects the default.
    pub fn new(
        proxy: Option<&str>,
        ca_pem_path: Option<&str>,
        timeout_ms: u64,
        idle_ms: u64,
    ) -> Result<Self, String> {
        let timeout = Duration::from_millis(if timeout_ms == 0 { DEFAULT_TIMEOUT_MS } else { timeout_ms });
        let idle = Duration::from_millis(if idle_ms == 0 { DEFAULT_IDLE_MS } else { idle_ms });
        let mut b = ureq::Agent::config_builder()
            // 4xx/5xx are data for the caller (429 + Retry-After, venue rejections), not errors.
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .max_idle_age(idle);
        if let Some(p) = proxy.filter(|p| !p.is_empty()) {
            b = b.proxy(Some(ureq::Proxy::new(p).map_err(|e| format!("invalid proxy {p:?}: {e}"))?));
        }
        if let Some(path) = ca_pem_path.filter(|p| !p.is_empty()) {
            let pem = std::fs::read(path).map_err(|e| format!("cannot read CA file {path:?}: {e}"))?;
            let cert = ureq::tls::Certificate::from_pem(&pem).map_err(|e| format!("invalid CA PEM {path:?}: {e}"))?;
            b = b.tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::new_with_certs(&[cert]))
                    .build(),
            );
        }
        Ok(Self { agent: b.build().into() })
    }

    pub fn shared(
        proxy: Option<&str>,
        ca_pem_path: Option<&str>,
        timeout_ms: u64,
        idle_ms: u64,
    ) -> Result<Arc<Self>, String> {
        Self::new(proxy, ca_pem_path, timeout_ms, idle_ms).map(Arc::new)
    }

    /// POST `body`. `Err` means a transport failure (the request's fate is unknown); any HTTP
    /// status, including 4xx/5xx, is an `Ok`.
    pub fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<HttpOut, String> {
        let mut resp = self
            .agent
            .post(url)
            .header("Content-Type", content_type)
            .send(body)
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = resp.body_mut().read_to_vec().map_err(|e| format!("reading response body: {e}"))?;
        Ok(HttpOut { status, body, retry_after })
    }
}
