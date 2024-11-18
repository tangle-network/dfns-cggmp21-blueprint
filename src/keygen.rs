use crate::context::{DfnsContext, DfnsStore};
use cggmp21::{
    keygen::{KeygenBuilder, NonThresholdMsg},
    security_level::SecurityLevel128,
    supported_curves::Secp256k1,
    ExecutionId,
};
use gadget_sdk::{
    compute_sha256_hash,
    event_listener::tangle::{
        jobs::{services_post_processor, services_pre_processor},
        TangleEventListener,
    },
    job,
    network::round_based_compat::NetworkDeliveryWrapper,
    tangle_subxt::tangle_testnet_runtime::api::services::events::JobCalled,
    Error as GadgetError,
};
use k256::sha2::Sha256;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use round_based::party::MpcParty;
use sp_core::ecdsa::Public;
use std::collections::BTreeMap;

#[job(
    id = 0,
    params(n),
    event_listener(
        listener = TangleEventListener<DfnsContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
/// Runs a distributed key generation (DKG) process using DFNS-CGGMP21 protocol
///
/// # Arguments
/// * `n` - Number of parties participating in the DKG
/// * `context` - The DFNS context containing network and storage configuration
///
/// # Returns
/// Returns the generated public key as a byte vector on success
///
/// # Errors
/// Returns an error if:
/// - Failed to retrieve blueprint ID or call ID
/// - Failed to get party information
/// - MPC protocol execution failed
/// - Serialization of results failed
pub async fn keygen(n: u16, context: DfnsContext) -> Result<Vec<u8>, GadgetError> {
    // Get configuration and compute deterministic values
    let blueprint_id = context
        .blueprint_id()
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;
    let call_id = context
        .current_call_id()
        .await
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;

    let (meta_hash, deterministic_hash) = compute_deterministic_hashes(n, blueprint_id, call_id);
    let execution_id = ExecutionId::new(&deterministic_hash);

    // Setup party information
    let (party_index, operators) = context
        .get_party_index_and_operators()
        .await
        .map_err(|e| KeygenError::ContextError(e.to_string()))?;

    let parties: BTreeMap<u16, Public> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as u16, ecdsa))
        .collect();

    gadget_sdk::info!(
        "Starting DFNS-CGGMP21 Keygen for party {party_index}, n={n}, eid={}",
        hex::encode(execution_id.as_bytes())
    );

    // Initialize RNG and network
    let mut rng = ChaCha20Rng::from_seed(deterministic_hash);
    let delivery = setup_network_party(&context, party_index, deterministic_hash, parties).await;
    let party = MpcParty::connected(delivery);
    // Execute the MPC protocol
    let result = KeygenBuilder::<Secp256k1, SecurityLevel128, Sha256>::new(
        execution_id,
        party_index as u16,
        n,
    )
    .start(&mut rng, party)
    .await
    .map_err(|e| KeygenError::MpcError(e.to_string()))?;

    gadget_sdk::info!(
        "Ending DFNS-CGGMP21 Keygen for party {party_index}, n={n}, eid={}",
        hex::encode(execution_id.as_bytes())
    );

    // Store the results
    let store_key = hex::encode(meta_hash);
    context.store.set(
        &store_key,
        DfnsStore {
            inner: Some(result.clone()),
            refreshed_key: None,
        },
    );

    // Serialize the results
    let public_key = bincode::serialize(&result.shared_public_key)
        .map_err(|e| KeygenError::SerializationError(e.to_string()))?;

    // Serialize the share (currently unused but kept for potential future use)
    let _serializable_share = bincode::serialize(&result.into_inner())
        .map_err(|e| KeygenError::SerializationError(e.to_string()))?;

    Ok(public_key)
}

/// Configuration constants for the DFNS keygen process
const KEYGEN_SALT: &str = "dfns-keygen";
const META_SALT: &str = "dfns";

/// Error type for keygen-specific operations
#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    #[error("Failed to serialize data: {0}")]
    SerializationError(String),

    #[error("MPC protocol error: {0}")]
    MpcError(String),

    #[error("Context error: {0}")]
    ContextError(String),
}

impl From<KeygenError> for GadgetError {
    fn from(err: KeygenError) -> Self {
        GadgetError::Other(err.to_string())
    }
}

/// Helper function to compute deterministic hashes for the keygen process
fn compute_deterministic_hashes(n: u16, blueprint_id: u64, call_id: u64) -> ([u8; 32], [u8; 32]) {
    let meta_hash = compute_sha256_hash!(
        n.to_be_bytes(),
        blueprint_id.to_be_bytes(),
        call_id.to_be_bytes(),
        META_SALT
    );

    let deterministic_hash = compute_sha256_hash!(meta_hash.as_ref(), KEYGEN_SALT);

    (meta_hash, deterministic_hash)
}

type NetworkMessage = NonThresholdMsg<Secp256k1, SecurityLevel128, Sha256>;

/// Helper function to setup the network party for MPC
async fn setup_network_party(
    context: &DfnsContext,
    party_index: usize,
    deterministic_hash: [u8; 32],
    parties: BTreeMap<u16, Public>,
) -> NetworkDeliveryWrapper<NetworkMessage> {
    NetworkDeliveryWrapper::new(
        context.network_backend.clone(),
        party_index as _,
        deterministic_hash,
        parties,
    )
}
