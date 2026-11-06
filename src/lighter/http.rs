//! ureq-backed implementation of `lighters::http::HttpClient`.
//!
//! Only `CheckClient` and nonce-fetching (`nonce == -1`) need HTTP. The endpoint
//! paths and JSON shapes mirror the Go reference (`lighter-go/client/http`) and
//! `lighters`' own reqwest implementation.

use lighters::error::{Error, Result};
use lighters::http::HttpClient;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct ResultCode {
    #[serde(default)]
    code: i32,
    #[serde(default)]
    message: String,
}

#[derive(Debug, Deserialize)]
struct NextNonce {
    #[serde(flatten)]
    status: ResultCode,
    nonce: i64,
}

#[derive(Debug, Deserialize)]
struct ApiKeyEntry {
    api_key_index: u8,
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct AccountApiKeys {
    #[serde(flatten)]
    status: ResultCode,
    #[serde(default)]
    api_keys: Vec<ApiKeyEntry>,
}

const CODE_OK: i32 = 200;

/// Blocking HTTP client pointed at a Lighter base URL.
pub struct UreqClient {
    endpoint: String,
    agent: ureq::Agent,
}

/// ureq has no default timeout; without one a stalled server would hang the
/// calling Python process inside `CheckClient` / nonce fetches.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

impl UreqClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            .build()
            .into();
        Self {
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            agent,
        }
    }

    fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T> {
        let url = format!("{}/{}", self.endpoint, path);
        let mut req = self.agent.get(&url);
        for (k, v) in query {
            req = req.query(*k, v);
        }
        let mut resp = req.call().map_err(|e| Error::Http(e.to_string()))?;
        let body = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| Error::Http(e.to_string()))?;
        Ok(serde_json::from_str::<T>(&body)?)
    }
}

impl HttpClient for UreqClient {
    fn get_next_nonce(&self, account_index: i64, api_key_index: u8) -> Result<i64> {
        let parsed: NextNonce = self.get_json(
            "api/v1/nextNonce",
            &[
                ("account_index", account_index.to_string()),
                ("api_key_index", api_key_index.to_string()),
            ],
        )?;
        if parsed.status.code != CODE_OK {
            return Err(Error::Http(parsed.status.message));
        }
        Ok(parsed.nonce)
    }

    fn get_api_key(&self, account_index: i64, api_key_index: u8) -> Result<String> {
        let parsed: AccountApiKeys =
            self.get_json("api/v1/apikeys", &[("account_index", account_index.to_string())])?;
        if parsed.status.code != CODE_OK {
            return Err(Error::Http(parsed.status.message));
        }
        parsed
            .api_keys
            .into_iter()
            .find(|k| k.api_key_index == api_key_index)
            .map(|k| k.public_key)
            .ok_or_else(|| Error::Http(format!("no api key returned for index {api_key_index}")))
    }
}
