use crate::context::dfns_ctx;
use crate::{KeyRefreshRequest, KeyRefreshResult};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::{ExecutionId, KeyShare, PregeneratedPrimes};
use blueprint_sdk::crypto::k256::K256Ecdsa;
use blueprint_sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use blueprint_sdk::tangle::extract::{Caller, TangleArg, TangleResult};
use blueprint_sdk::info;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use round_based::PartyIndex;
use sha2::Sha256;
use std::collections::HashMap;

const KEY_REFRESH_SALT: &str = "dfns-key-refresh";

/// Generates auxiliary info and combines with the incomplete key share to
/// produce a full key share ready for signing.
pub async fn key_refresh(
    Caller(_caller): Caller,
    TangleArg(request): TangleArg<KeyRefreshRequest>,
) -> Result<TangleResult<KeyRefreshResult>, String> {
    let ctx = dfns_ctx();
    let n = request.n;

    // Get party info from connected peers
    let mut all_peers = ctx.network_backend.peers();
    let local_peer_id = ctx.network_backend.local_peer_id;
    if !all_peers.contains(&local_peer_id) {
        all_peers.push(local_peer_id);
    }
    all_peers.sort();

    let party_count = all_peers.len() as u16;
    let i = all_peers
        .iter()
        .position(|p| *p == local_peer_id)
        .ok_or_else(|| "Local peer not found in peer list".to_string())? as u16;

    let parties: HashMap<PartyIndex, libp2p::PeerId> = all_peers
        .into_iter()
        .enumerate()
        .map(|(idx, peer_id)| (idx as PartyIndex, peer_id))
        .collect();

    let blueprint_id = ctx.blueprint_id()?;
    let call_id = 0u64;

    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, call_id, KEY_REFRESH_SALT);
    let execution_id = ExecutionId::new(&deterministic_hash);

    info!(
        "Starting DFNS-CGGMP24 Aux Info Gen for party {i}, n={party_count}, eid={}",
        hex::encode(execution_id.as_bytes())
    );

    let mut rng = rand_chacha::ChaChaRng::from_seed(deterministic_hash);

    // Look up incomplete key share from keygen
    let key = hex::encode(meta_hash);
    let mut store_state = ctx
        .store
        .get(&key)
        .map_err(|e| format!("Store error: {e}"))?
        .ok_or_else(|| "Keygen output not found in DB".to_string())?;
    let incomplete_key_share = store_state
        .incomplete_key_share
        .clone()
        .ok_or_else(|| "Incomplete key share not found".to_string())?;

    // Generate pregenerated primes (computationally expensive)
    let pregenerated_primes = generate_pregenerated_primes(rng.clone()).await?;

    type AuxMsg = cggmp24::key_refresh::msg::Msg<Sha256, SecurityLevel128>;

    let network = RoundBasedNetworkAdapter::<AuxMsg, K256Ecdsa>::new(
        ctx.network_backend.clone(),
        i,
        &parties,
        crate::context::NETWORK_PROTOCOL,
    );

    let party = round_based::party::MpcParty::connected(network);

    // Run aux info generation protocol
    let aux_info = cggmp24::aux_info_gen(execution_id, i, party_count, pregenerated_primes)
        .start(&mut rng, party)
        .await
        .map_err(|err| format!("Aux info gen MPC error: {err}"))?;

    // Combine incomplete key share with aux info to get full key share
    let full_key_share = KeyShare::from_parts((incomplete_key_share, aux_info))
        .map_err(|err| format!("Failed to combine key share: {err}"))?;

    store_state.key_share = Some(full_key_share.clone());
    let _ = ctx.store.set(&key, store_state);

    let public_key =
        serde_json::to_vec(&full_key_share.shared_public_key).map_err(|e| e.to_string())?;

    Ok(TangleResult(KeyRefreshResult {
        public_key: public_key.into(),
    }))
}

async fn generate_pregenerated_primes<R: RngCore + Send + 'static>(
    mut rng: R,
) -> Result<PregeneratedPrimes<SecurityLevel128>, String> {
    tokio::task::spawn_blocking(move || {
        cggmp24::PregeneratedPrimes::<SecurityLevel128>::generate(&mut rng)
    })
    .await
    .map_err(|err| format!("Failed to generate pregenerated primes: {err:?}"))
}
