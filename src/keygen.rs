use crate::context::{DfnsContext, DfnsStore, KeygenOutput};
use blueprint_sdk::contexts::tangle::TangleClientContext;
use blueprint_sdk::crypto::tangle_pair_signer::sp_core::ecdsa::Public;
use blueprint_sdk::event_listeners::tangle::events::TangleEventListener;
use blueprint_sdk::event_listeners::tangle::services::{
    services_post_processor, services_pre_processor,
};
use blueprint_sdk::logging::info;
use blueprint_sdk::networking::round_based_compat::{NetworkDeliveryWrapper, NetworkWrapper};
use blueprint_sdk::std::rand::{rngs::OsRng, RngCore};
use blueprint_sdk::tangle_subxt::tangle_testnet_runtime::api::services::events::JobCalled;
use blueprint_sdk::Error;
use cggmp21::keygen::{KeygenBuilder, ThresholdMsg};
use cggmp21::{
    security_level::SecurityLevel128, supported_curves::Secp256k1, ExecutionId, PregeneratedPrimes,
};
use futures::StreamExt;
use k256::sha2::Sha256;
use round_based::party::MpcParty;
use round_based::Delivery;
use std::collections::BTreeMap;

#[blueprint_sdk::job(
    id = 0,
    params(t),
    event_listener(
        listener = TangleEventListener<DfnsContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
/// Runs a distributed key generation (DKG) process using DFNS-CGGMP21 protocol
///
/// # Arguments
/// * `t` - Threshold
/// * `context` - The DFNS context containing network and storage configuration
///
/// # Returns
/// The generated public key as a byte vector on success
///
/// # Errors
/// Returns an error if:
/// - Failed to retrieve blueprint ID or call ID
/// - Failed to get party information
/// - MPC protocol execution failed
/// - Serialization of results failed
pub async fn keygen(t: u16, context: DfnsContext) -> Result<Vec<u8>, Error> {
    // Setup party information
    let (party_index, operators) = context
        .tangle_client()
        .await?
        .get_party_index_and_operators()
        .await
        .map_err(|e| Error::Other(format!("Context error: {e}")))?;

    let parties: BTreeMap<u16, Public> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as u16, ecdsa))
        .collect();
    // Get configuration and compute deterministic values
    let blueprint_id = context
        .tangle_client()
        .await?
        .blueprint_id()
        .await
        .map_err(|e| Error::Other(format!("Context error: {e}")))?;
    let call_id = context.call_id.expect("Call ID not found");
    let n = parties.len();

    let (meta_hash, deterministic_hash) =
        compute_deterministic_hashes(n as u16, blueprint_id, call_id);
    let execution_id = ExecutionId::new(&deterministic_hash);

    info!(
        "Starting DFNS-CGGMP21 Keygen #{call_id} for party {party_index}, n={n}, eid={}",
        hex::encode(execution_id.as_bytes())
    );

    // Initialize RNG and network
    let mut rng = OsRng;
    let delivery = NetworkDeliveryWrapper::new(
        context.network_mux().clone(),
        party_index as u16,
        deterministic_hash,
        parties.clone(),
    );
    let party = MpcParty::connected(delivery);
    // Execute the MPC protocol
    let result = KeygenBuilder::<Secp256k1, SecurityLevel128, Sha256>::new(
        execution_id,
        party_index as u16,
        n as u16,
    )
    .set_threshold(t)
    .enforce_reliable_broadcast(false)
    .start(&mut rng, party)
    .await
    .map_err(|e| Error::Custom(format!("MPC protocol error: {e}")))?;

    info!("[Long task] Running pregenerated primes for party {party_index}");

    let pregenerated_primes = generate_pregenerated_primes(rng).await?;

    info!(
        "Ending DFNS-CGGMP21 Keygen for party {party_index}, n={n}, eid={}",
        hex::encode(execution_id.as_bytes())
    );

    // Store the results
    let store_key = hex::encode(meta_hash);
    context.store.set(
        &store_key,
        DfnsStore {
            inner: Some(KeygenOutput {
                pregenerated_primes,
                public_key: result.clone(),
            }),
            refreshed_key: None,
            keyshare: None,
        },
    );

    // Serialize the results
    let public_key = serde_json::to_vec(&result.shared_public_key)
        .map_err(|e| Error::Custom(format!("Failed to serialize data: {e}")))?;

    // Serialize the share (currently unused but kept for potential future use)
    let _serializable_share = serde_json::to_vec(&result.into_inner())
        .map_err(|e| Error::Custom(format!("Failed to serialize data: {e}")))?;

    Ok(public_key)
}

/// Configuration constants for the DFNS keygen process
const KEYGEN_SALT: &str = "dfns-keygen";
const META_SALT: &str = "dfns";

/// Helper function to compute deterministic hashes for the keygen process
pub(crate) fn compute_deterministic_hashes(
    n: u16,
    blueprint_id: u64,
    call_id: u64,
) -> ([u8; 32], [u8; 32]) {
    let meta_hash = compute_sha256_hash!(
        n.to_be_bytes(),
        blueprint_id.to_be_bytes(),
        call_id.to_be_bytes(),
        META_SALT
    );

    let deterministic_hash = compute_sha256_hash!(meta_hash.as_ref(), KEYGEN_SALT);

    (meta_hash, deterministic_hash)
}

type NetworkMessage = ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>;

/// Helper function to set up the network party for MPC
pub async fn setup_network_party(
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

async fn generate_pregenerated_primes<R: RngCore + Send + 'static>(
    mut rng: R,
) -> Result<PregeneratedPrimes, Error> {
    let pregenerated_primes = tokio::task::spawn_blocking(move || {
        cggmp21::PregeneratedPrimes::<SecurityLevel128>::generate(&mut rng)
    })
    .await
    .map_err(|err| Error::Other(format!("Failed to generate pregenerated primes: {err:?}")))?;
    Ok(pregenerated_primes)
}
