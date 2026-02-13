use crate::context::dfns_ctx;
use crate::{SignRequest, SignResult};
use blueprint_sdk::crypto::k256::K256Ecdsa;
use blueprint_sdk::info;
use blueprint_sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use blueprint_sdk::tangle::extract::{Caller, TangleArg, TangleResult};
use cggmp24::supported_curves::Secp256k1;
use cggmp24::{DataToSign, ExecutionId};
use rand_chacha::rand_core::SeedableRng;
use round_based::PartyIndex;
use sha2::Sha256;
use std::collections::HashMap;

const SIGNING_SALT: &str = "dfns-signing";

/// Runs a signing protocol using DFNS-CGGMP24. Returns the signature.
pub async fn signing(
    Caller(_caller): Caller,
    TangleArg(request): TangleArg<SignRequest>,
) -> Result<TangleResult<SignResult>, String> {
    let ctx = dfns_ctx();
    let n = request.n;
    let message_to_sign = request.message_to_sign.to_vec();

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
        crate::compute_deterministic_hashes(n, blueprint_id, call_id, SIGNING_SALT);
    let execution_id = ExecutionId::new(&deterministic_hash);

    info!(
        "Starting DFNS-CGGMP24 Signing for party {i}, n={party_count}, eid={}",
        hex::encode(execution_id.as_bytes())
    );

    let mut rng = rand_chacha::ChaChaRng::from_seed(deterministic_hash);

    // Look up full key share
    let key = hex::encode(meta_hash);
    let key_share = ctx
        .store
        .get(&key)
        .map_err(|e| format!("Store error: {e}"))?
        .ok_or_else(|| "Key store entry not found in DB".to_string())?
        .key_share
        .ok_or_else(|| "Full key share not found (run key_refresh first)".to_string())?;

    // Use all parties for signing
    let participants: Vec<u16> = (0..party_count).collect();

    type SignMsg = cggmp24::signing::msg::Msg<Secp256k1, Sha256>;

    let network = RoundBasedNetworkAdapter::<SignMsg, K256Ecdsa>::new(
        ctx.network_backend.clone(),
        i,
        &parties,
        crate::context::NETWORK_PROTOCOL,
    );

    let party = round_based::party::MpcParty::connected(network);

    let message = DataToSign::<Secp256k1>::digest::<Sha256>(&message_to_sign);

    let signature = cggmp24::signing(execution_id, i as _, &participants, &key_share)
        .sign(&mut rng, party, &message)
        .await
        .map_err(|err| format!("Signing MPC error: {err}"))?;

    // Verify the signature
    let public_key = &key_share.shared_public_key;
    signature
        .verify(public_key, &message)
        .map_err(|err| format!("Signature verification failed: {err}"))?;

    let serialized_signature = serde_json::to_vec(&signature).map_err(|e| e.to_string())?;

    Ok(TangleResult(SignResult {
        signature: serialized_signature.into(),
    }))
}
