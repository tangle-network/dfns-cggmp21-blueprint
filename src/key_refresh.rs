use crate::context::DfnsContext;
use crate::keygen::KeygenError;
use cggmp21::key_refresh::{AuxOnlyMsg, KeyRefreshBuilder};
use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::{ExecutionId, KeyShare};
use color_eyre::eyre::OptionExt;
use gadget_sdk::contexts::MPCContext;
use gadget_sdk::event_listener::tangle::jobs::{services_post_processor, services_pre_processor};
use gadget_sdk::event_listener::tangle::TangleEventListener;
use gadget_sdk::network::round_based_compat::NetworkDeliveryWrapper;
use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::services::events::JobCalled;
use gadget_sdk::{compute_sha256_hash, job};
use k256::sha2::Sha256;
use rand_chacha::rand_core::OsRng;
use round_based::runtime::TokioRuntime;
use round_based::MpcParty;
use sp_core::ecdsa::Public;
use std::collections::BTreeMap;

#[job(
    id = 1,
    params(keygen_call_id),
    event_listener(
        listener = TangleEventListener<DfnsContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
/// Runs a [t; n] keygen using DFNS-CGGMP21. Returns the public key
pub async fn key_refresh(
    keygen_call_id: u64,
    context: DfnsContext,
) -> Result<Vec<u8>, gadget_sdk::Error> {
    let (i, operators) = context.get_party_index_and_operators().await?;
    let parties: BTreeMap<u16, Public> = operators
        .into_iter()
        .enumerate()
        .map(|(j, (_, ecdsa))| (j as u16, ecdsa))
        .collect();
    let blueprint_id = context.blueprint_id()?;
    let call_id = context.call_id.expect("Call ID not found");
    let n = parties.len();
    let (meta_hash, deterministic_hash) =
        crate::keygen::compute_deterministic_hashes(n as u16, blueprint_id, keygen_call_id);
    let store_key = hex::encode(meta_hash);
    gadget_sdk::info!("DFNS-Refresh: Store key for {i}: {store_key}");
    let mut state = context
        .store
        .get(&store_key)
        .ok_or_eyre("[key refresh] Keygen output not found in DB")?;

    let mut rng = OsRng;
    let deterministic_hash = compute_sha256_hash!(deterministic_hash, "aux-info");
    let execution_id = ExecutionId::new(&deterministic_hash);
    let delivery = NetworkDeliveryWrapper::<AuxOnlyMsg<k256::sha2::Sha256, SecurityLevel128>>::new(
        context.network_backend.clone(),
        i as _,
        deterministic_hash,
        parties.clone(),
    );

    let keygen_output = state.inner.as_ref().ok_or_eyre("Keygen output not found")?;
    let pregenerated_primes = keygen_output.pregenerated_primes.clone();
    let keygen_result = keygen_output.public_key.clone();
    let party = MpcParty::connected(delivery);

    gadget_sdk::info!(
        "Starting DFNS-CGGMP21 AUX/Key Refresh #{call_id} for party {i}, n={n}, eid={}",
        hex::encode(execution_id.as_bytes())
    );

    let aux_info = cggmp21::key_refresh::AuxInfoGenerationBuilder::new_aux_gen(
        execution_id,
        i as _,
        n as _,
        pregenerated_primes,
    )
    .start(&mut rng, party)
    .await
    .map_err(|e| KeygenError::MpcError(e.to_string()))?;

    let keyshare = KeyShare::from_parts((keygen_result, aux_info))
        .map_err(|e| KeygenError::AuxInfoError(e.to_string()))?;
    state.keyshare = Some(keyshare.clone());

    context.store.set(&store_key, state.clone());

    // Even though we are using the keygen hash function (in order to get the store key for the meta_hash value), we need to ensure
    // uniqueness of the EID by adding in more elements to the hash
    let deterministic_hash = compute_sha256_hash!(
        deterministic_hash,
        call_id.to_be_bytes(),
        "dfns-key-refresh"
    );

    let eid = ExecutionId::new(&deterministic_hash);

    gadget_sdk::info!(
        "Starting DFNS-CGGMP21 Key Refresh #{call_id} for party {i}, n={n}, eid={}",
        hex::encode(eid.as_bytes())
    );

    let delivery = NetworkDeliveryWrapper::new(
        context.network_backend.clone(),
        i as _,
        deterministic_hash,
        parties,
    );
    let party = round_based::party::MpcParty::connected(delivery).set_runtime(TokioRuntime);

    let store_key = hex::encode(meta_hash);

    let keygen_output = state
        .inner
        .as_ref()
        .ok_or_eyre("[key-refresh] Keygen output not found")?;

    // This generate_pregenerated_orimes function can take awhile to run
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
    .map_err(|err| gadget_sdk::Error::Other(err.to_string()))?;

    // Refreshed key needs to be saved, that way we can begin signing
    state.refreshed_key = Some(result.clone());

    context.store.set(&store_key, state);

    let public_key =
        serde_json::to_vec(&result.shared_public_key).expect("Failed to serialize public key");
    let serializable_share =
        serde_json::to_vec(&result.into_inner()).expect("Failed to serialize share");

    Ok(public_key)
}
