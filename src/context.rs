use blueprint_sdk::clients::BlueprintServicesClient;
use blueprint_sdk::contexts::tangle::TangleClientContext;
use blueprint_sdk::crypto::k256::K256Ecdsa;
use blueprint_sdk::networking::service_handle::NetworkServiceHandle;
use blueprint_sdk::runner::config::BlueprintEnvironment;
use blueprint_sdk::stores::local_database::LocalDatabase;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::{IncompleteKeyShare, KeyShare};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// The network protocol version for the DFNS service
pub(crate) const NETWORK_PROTOCOL: &str = "dfns/cggmp24/1.0.0";

/// Global DFNS context, initialized once at startup.
static DFNS_CTX: OnceLock<DfnsContext> = OnceLock::new();

/// Get the global DFNS context. Panics if not initialized.
pub fn dfns_ctx() -> &'static DfnsContext {
    DFNS_CTX.get().expect("DfnsContext not initialized")
}

/// Storage structure for DFNS-related data
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct DfnsStore {
    /// The incomplete key share from keygen (before aux info)
    pub incomplete_key_share: Option<IncompleteKeyShare<Secp256k1>>,
    /// The full key share (after aux info generation)
    pub key_share: Option<KeyShare<Secp256k1, SecurityLevel128>>,
}

/// DFNS-CGGMP24 Service Context
#[derive(Clone)]
pub struct DfnsContext {
    pub env: BlueprintEnvironment,
    pub network_backend: NetworkServiceHandle<K256Ecdsa>,
    pub store: Arc<LocalDatabase<DfnsStore>>,
}

impl DfnsContext {
    /// Creates and globally initializes the DFNS context.
    pub async fn init(env: &BlueprintEnvironment) -> Result<(), String> {
        let tangle_client = env.tangle_client().await.map_err(|e| e.to_string())?;

        let operators = tangle_client
            .get_operators()
            .await
            .map_err(|e| e.to_string())?;

        let operator_keys =
            blueprint_sdk::networking::service::AllowedKeys::<K256Ecdsa>::EvmAddresses(
                operators.keys().cloned().collect(),
            );

        let (_allowed_keys_tx, allowed_keys_rx) = crossbeam_channel::unbounded();

        let network_config = env
            .libp2p_network_config::<K256Ecdsa>(NETWORK_PROTOCOL, false)
            .map_err(|e| e.to_string())?;

        let network_backend = env
            .libp2p_start_network(network_config, operator_keys, allowed_keys_rx)
            .map_err(|e| e.to_string())?;

        let keystore_dir = PathBuf::from(&env.keystore_uri).join("dfns.json");
        let store = Arc::new(
            LocalDatabase::open(keystore_dir).map_err(|e| format!("Failed to open store: {e}"))?,
        );

        let ctx = DfnsContext {
            env: env.clone(),
            network_backend,
            store,
        };

        DFNS_CTX
            .set(ctx)
            .map_err(|_| "DfnsContext already initialized".to_string())
    }

    /// Returns the blueprint ID
    pub fn blueprint_id(&self) -> Result<u64, String> {
        self.env
            .protocol_settings
            .tangle()
            .map(|c| c.blueprint_id)
            .map_err(|err| format!("Blueprint ID not found: {err}"))
    }
}
