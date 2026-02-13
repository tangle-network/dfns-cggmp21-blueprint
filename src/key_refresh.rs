use crate::context::dfns_ctx;
use crate::{KeyRefreshRequest, KeyRefreshResult};
use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::{ExecutionId, PregeneratedPrimes};
use blueprint_sdk::crypto::k256::K256Ecdsa;
use blueprint_sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use blueprint_sdk::tangle::extract::{Caller, TangleArg, TangleResult};
use blueprint_sdk::info;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use round_based::PartyIndex;
use sha2::Sha256;
use std::collections::HashMap;

const KEY_REFRESH_SALT: &str = "dfns-key-refresh";

/// Runs a key refresh using DFNS-CGGMP21. Returns the refreshed public key.
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
        "Starting DFNS-CGGMP21 Key Refresh for party {i}, n={party_count}, eid={}",
        hex::encode(execution_id.as_bytes())
    );

    let mut rng = rand_chacha::ChaChaRng::from_seed(deterministic_hash);

    // Look up keygen output
    let key = hex::encode(meta_hash);
    let mut cggmp21_state = ctx
        .store
        .get(&key)
        .map_err(|e| format!("Store error: {e}"))?
        .ok_or_else(|| "Keygen output not found in DB".to_string())?;
    let keygen_output = cggmp21_state
        .inner
        .as_ref()
        .ok_or_else(|| "Keygen output not found".to_string())?;

    // Generate pregenerated primes (computationally expensive)
    let pregenerated_primes = generate_pregenerated_primes(rng.clone()).await?;

    type RefreshMsg = cggmp21::key_refresh::msg::non_threshold::Msg<Secp256k1, Sha256, SecurityLevel128>;

    let network = RoundBasedNetworkAdapter::<RefreshMsg, K256Ecdsa>::new(
        ctx.network_backend.clone(),
        i,
        &parties,
        crate::context::NETWORK_PROTOCOL,
    );

    let party = round_based::party::MpcParty::connected(network);

    let result = cggmp21::key_refresh(execution_id, keygen_output, pregenerated_primes)
        .start(&mut rng, party)
        .await
        .map_err(|err| format!("Key refresh MPC error: {err}"))?;

    cggmp21_state.refreshed_key = Some(result.clone());
    let _ = ctx.store.set(&key, cggmp21_state);

    let public_key =
        serde_json::to_vec(&result.shared_public_key).map_err(|e| e.to_string())?;

    Ok(TangleResult(KeyRefreshResult {
        public_key: public_key.into(),
    }))
}

async fn generate_pregenerated_primes<R: RngCore + Send + 'static>(
    mut rng: R,
) -> Result<PregeneratedPrimes<SecurityLevel128>, String> {
    tokio::task::spawn_blocking(move || {
        cggmp21::PregeneratedPrimes::<SecurityLevel128>::generate(&mut rng)
    })
    .await
    .map_err(|err| format!("Failed to generate pregenerated primes: {err:?}"))
}
