use crate::context::DfnsContext;
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
use cggmp21::key_refresh::{AuxOnlyMsg, KeyRefreshBuilder};
use cggmp21::{
    security_level::SecurityLevel128, supported_curves::Secp256k1, ExecutionId, KeyShare,
};
use futures::StreamExt;
use k256::sha2::Sha256;
use round_based::party::MpcParty;
use round_based::Delivery;
use std::collections::BTreeMap;

#[blueprint_sdk::job(
    id = 1,
    params(keygen_call_id),
    event_listener(
        listener = TangleEventListener<DfnsContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
/// Runs a [t; n] keygen using DFNS-CGGMP21. Returns the public key
pub async fn key_refresh(keygen_call_id: u64, context: DfnsContext) -> Result<Vec<u8>, Error> {
    let (i, operators) = context
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
    let tangle_client = context
        .tangle_client()
        .await
        .map_err(|e| Error::Other(e.to_string()))?;
    let blueprint_id = tangle_client
        .await?
        .blueprint_id()
        .await
        .map_err(|e| Error::Other(e.to_string()))?;
    let call_id = context.call_id.expect("Call ID not found");
    let n = parties.len();
    let (meta_hash, deterministic_hash) =
        crate::keygen::compute_deterministic_hashes(n as u16, blueprint_id, keygen_call_id);
    let store_key = hex::encode(meta_hash);
    info!("DFNS-Refresh: Store key for {i}: {store_key}");
    let state = context
        .store
        .get(&store_key)
        .ok_or_else(|| Error::Other("[key refresh] Keygen output not found in DB".to_string()))?;

    let mut rng = OsRng;
    let deterministic_hash = Sha256::digest(deterministic_hash).to_vec();
    let execution_id = ExecutionId::new(&deterministic_hash);

    let delivery = NetworkDeliveryWrapper::new(
        context.network_mux().clone(),
        i as u16,
        deterministic_hash,
        parties.clone(),
    );

    let party = round_based::party::MpcParty::connected(delivery).set_runtime(TokioRuntime);

    info!(
        "Starting DFNS-CGGMP21 AUX/Key Refresh #{call_id} for party {i}, n={n}, eid={}",
        hex::encode(execution_id.as_bytes())
    );

    let keygen_output = state
        .inner
        .as_ref()
        .ok_or_else(|| Error::Other("Keygen output not found".to_string()))?;

    let aux_info = cggmp21::key_refresh::AuxInfoGenerationBuilder::new_aux_gen(
        execution_id,
        i as _,
        n as _,
        keygen_output.pregenerated_primes.clone(),
    )
    .start(&mut rng, party)
    .await
    .map_err(|e| Error::Other(format!("Failed to generate aux info: {}", e)))?;

    let keyshare = KeyShare::from_parts((keygen_output.public_key.clone(), aux_info))
        .map_err(|e| Error::Other(format!("Failed to create keyshare: {}", e)))?;
    state.keyshare = Some(keyshare.clone());

    context.store.set(&store_key, state.clone());

    // Even though we are using the keygen hash function (in order to get the store key for the meta_hash value), we need to ensure
    // uniqueness of the EID by adding in more elements to the hash
    let deterministic_hash = Sha256::digest(deterministic_hash)
        .chain(call_id.to_be_bytes())
        .chain(b"dfns-key-refresh")
        .finalize()
        .to_vec();

    let eid = ExecutionId::new(&deterministic_hash);

    info!(
        "Starting DFNS-CGGMP21 Key Refresh #{call_id} for party {i}, n={n}, eid={}",
        hex::encode(eid.as_bytes())
    );

    let delivery =
        NetworkDeliveryWrapper::new(context.network_mux().clone(), i as u16, eid, parties);
    let party = round_based::party::MpcParty::connected(delivery).set_runtime(TokioRuntime);

    let store_key = hex::encode(meta_hash);

    let pregenerated_primes = keygen_output.pregenerated_primes.clone();

    let t = keygen_output.public_key.min_signers();

    // TODO: parameterize this
    let result = KeyRefreshBuilder::<Secp256k1, SecurityLevel128, Sha256>::new(
        eid,
        &keyshare,
        pregenerated_primes,
    )
    .start(&mut rng, party)
    .await
    .map_err(|err| Error::Other(err.to_string()))?;

    // Refreshed key needs to be saved, that way we can begin signing
    state.refreshed_key = Some(result.clone());

    context.store.set(&store_key, state);

    let public_key =
        serde_json::to_vec(&result.shared_public_key).expect("Failed to serialize public key");
    let serializable_share =
        serde_json::to_vec(&result.into_inner()).expect("Failed to serialize share");

    Ok(public_key)
}
