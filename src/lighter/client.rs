//! Stateful client registry, mirroring `lighter-go/client`'s
//! `SharedClientManager`.
//!
//! `CreateClient` binds a private key to an `(api_key_index, account_index)`
//! pair; `sign_*` then look the client up. The most recently created client is
//! also the global default (`api_key_index == 255, account_index == -1`), and a
//! per-account default is kept (`api_key_index == 255, account_index != -1`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use lighters::TxClient;

use crate::lighter::http::UreqClient;

pub struct Entry {
    pub client: Arc<TxClient>,
    pub endpoint: String,
}

struct Registry {
    /// (api_key_index, account_index) -> client
    clients: HashMap<(u8, i64), Arc<Entry>>,
    default_by_account: HashMap<i64, Arc<Entry>>,
    default: Option<Arc<Entry>>,
}

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| {
        Mutex::new(Registry {
            clients: HashMap::new(),
            default_by_account: HashMap::new(),
            default: None,
        })
    })
}

fn client_not_created() -> String {
    "client is not created, call CreateClient() first".to_string()
}

/// Registers a client for `(api_key_index, account_index)`.
pub fn create_client(
    url: &str,
    private_key: &str,
    chain_id: u32,
    api_key_index: u8,
    account_index: i64,
) -> Result<(), String> {
    // Mirrors Go's `CreateClient`: account index must be positive.
    if account_index <= 0 {
        return Err("invalid account index".to_string());
    }

    let client = TxClient::new(private_key, account_index, api_key_index, chain_id)
        .map_err(|e| e.to_string())?
        .with_http(Box::new(UreqClient::new(url)));

    let entry = Arc::new(Entry {
        client: Arc::new(client),
        endpoint: url.trim_end_matches('/').to_string(),
    });

    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.clients
        .insert((api_key_index, account_index), entry.clone());
    reg.default_by_account.insert(account_index, entry.clone());
    reg.default = Some(entry);
    Ok(())
}

/// Looks up a registered client, mirroring Go's `GetClient`.
pub fn get_client(api_key_index: u8, account_index: i64) -> Result<Arc<Entry>, String> {
    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    if api_key_index == 255 {
        if account_index == -1 {
            return reg.default.clone().ok_or_else(client_not_created);
        }
        return reg
            .default_by_account
            .get(&account_index)
            .cloned()
            .ok_or_else(client_not_created);
    }
    reg.clients
        .get(&(api_key_index, account_index))
        .cloned()
        .ok_or_else(client_not_created)
}
