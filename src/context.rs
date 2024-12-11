use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::{KeyShare, PregeneratedPrimes};
use color_eyre::eyre;
use gadget_sdk as sdk;
use gadget_sdk::contexts::{KeystoreContext, MPCContext, ServicesContext, TangleClientContext};
use gadget_sdk::ext::subxt::tx::Signer;
use gadget_sdk::network::NetworkMultiplexer;
use gadget_sdk::store::LocalDatabase;
use gadget_sdk::subxt_core::ext::sp_core::ecdsa;
use key_share::CoreKeyShare;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

/// The network protocol version for the DFNS service
const NETWORK_PROTOCOL: &str = "/dfns/cggmp21/1.0.0";

/// Storage structure for DFNS-related data
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct DfnsStore {
    /// The core key share for the current session
    pub inner: Option<KeygenOutput>,
    /// Refreshed key share after a refresh operation
    pub refreshed_key: Option<KeyShare<Secp256k1, SecurityLevel128>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeygenOutput {
    pub pregenerated_primes: PregeneratedPrimes,
    pub keyshare: KeyShare<Secp256k1>,
    pub public_key: CoreKeyShare<Secp256k1>,
}

/// DFNS-CGGMP21 Service Context that holds all the necessary context for the service
/// to run. This structure implements various traits for keystore, client, and service
/// functionality.
#[derive(Clone, KeystoreContext, TangleClientContext, ServicesContext, MPCContext)]
pub struct DfnsContext {
    #[config]
    pub config: sdk::config::StdGadgetConfiguration,
    pub network_backend: Arc<NetworkMultiplexer>,
    pub store: Arc<LocalDatabase<DfnsStore>>,
    pub identity: ecdsa::Pair,
    #[call_id]
    pub call_id: Option<u64>,
}

// Core context management implementation
impl DfnsContext {
    /// Creates a new service context with the provided configuration
    ///
    /// # Errors
    /// Returns an error if:
    /// - Network initialization fails
    /// - Configuration is invalid
    pub fn new(config: sdk::config::StdGadgetConfiguration) -> eyre::Result<Self> {
        let network_config = config
            .libp2p_network_config(NETWORK_PROTOCOL)
            .map_err(|err| eyre::eyre!("Failed to create network configuration: {err}"))?;

        let identity = network_config.ecdsa_key.clone();
        let gossip_handle = sdk::network::setup::start_p2p_network(network_config)
            .map_err(|err| eyre::eyre!("Failed to start the P2P network: {err}"))?;

        let keystore_dir = PathBuf::from(config.keystore_uri.clone()).join("dfns.json");
        let store = Arc::new(LocalDatabase::open(keystore_dir));

        Ok(Self {
            store,
            identity,
            config,
            network_backend: Arc::new(NetworkMultiplexer::new(gossip_handle)),
            call_id: None,
        })
    }
}
