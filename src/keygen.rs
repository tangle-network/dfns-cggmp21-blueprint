use crate::context::{dfns_ctx, DfnsStore};
use crate::{KeygenRequest, KeygenResult};
use cggmp24::keygen::NonThresholdMsg;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use blueprint_sdk::crypto::k256::K256Ecdsa;
use blueprint_sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use blueprint_sdk::tangle::extract::{Caller, TangleArg, TangleResult};
use blueprint_sdk::info;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use round_based::party::MpcParty;
use round_based::PartyIndex;
use sha2::Sha256;
use std::collections::HashMap;

const KEYGEN_SALT: &str = "dfns-keygen";

/// Runs a distributed key generation (DKG) process using DFNS-CGGMP24 protocol.
/// Returns an incomplete key share. Run key_refresh (aux info gen) to complete it.
pub async fn keygen(
    Caller(_caller): Caller,
    TangleArg(request): TangleArg<KeygenRequest>,
) -> Result<TangleResult<KeygenResult>, String> {
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
    let call_id = 0u64; // Deterministic from on-chain context

    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, call_id, KEYGEN_SALT);
    let execution_id = ExecutionId::new(&deterministic_hash);

    info!(
        "Starting DFNS-CGGMP24 Keygen for party {i}, n={party_count}, eid={}",
        hex::encode(execution_id.as_bytes())
    );

    let mut rng = ChaCha20Rng::from_seed(deterministic_hash);

    type KeygenMsg = NonThresholdMsg<Secp256k1, SecurityLevel128, Sha256>;

    let network = RoundBasedNetworkAdapter::<KeygenMsg, K256Ecdsa>::new(
        ctx.network_backend.clone(),
        i,
        &parties,
        crate::context::NETWORK_PROTOCOL,
    );

    let party = MpcParty::connected(network);

    let incomplete_key_share = cggmp24::keygen::<Secp256k1>(execution_id, i, party_count)
        .start(&mut rng, party)
        .await
        .map_err(|e| format!("Keygen MPC error: {e}"))?;

    info!(
        "Ending DFNS-CGGMP24 Keygen for party {i}, n={party_count}, eid={}",
        hex::encode(execution_id.as_bytes())
    );

    // Store the incomplete key share
    let store_key = hex::encode(meta_hash);
    let _ = ctx.store.set(
        &store_key,
        DfnsStore {
            incomplete_key_share: Some(incomplete_key_share.clone()),
            key_share: None,
        },
    );

    let public_key =
        serde_json::to_vec(&incomplete_key_share.shared_public_key).map_err(|e| e.to_string())?;

    Ok(TangleResult(KeygenResult {
        public_key: public_key.into(),
    }))
}
