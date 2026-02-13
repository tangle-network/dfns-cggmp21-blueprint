use crate::context::dfns_ctx;
use crate::{SignRequest, SignResult};
use cggmp21::supported_curves::Secp256k1;
use cggmp21::{DataToSign, ExecutionId};
use blueprint_sdk::crypto::k256::K256Ecdsa;
use blueprint_sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use blueprint_sdk::tangle::extract::{Caller, TangleArg, TangleResult};
use blueprint_sdk::info;
use rand_chacha::rand_core::SeedableRng;
use round_based::PartyIndex;
use sha2::Sha256;
use std::collections::HashMap;

const SIGNING_SALT: &str = "dfns-signing";

/// Runs a signing protocol using DFNS-CGGMP21. Returns the signature.
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
    let blueprint_id = context.blueprint_id()?;
    let call_id = context.call_id.expect("Call ID not found");
    let n = parties.len();

    let (meta_hash, deterministic_hash) =
        crate::keygen::compute_deterministic_hashes(n as u16, blueprint_id, keygen_call_id);
    let store_key = hex::encode(meta_hash);

    let state = context
        .store
        .get(&store_key)
        .ok_or_eyre("[signing] Keygen output not found in DB")?;

    // Even though we are using the keygen hash function (in order to get the store key for the meta_hash value), we need to ensure
    // uniqueness of the EID by adding in more elements to the hash
    let deterministic_hash =
        compute_sha256_hash!(deterministic_hash, call_id.to_be_bytes(), "dfns-signing");
    let eid = ExecutionId::new(&deterministic_hash);

    let blueprint_id = ctx.blueprint_id()?;
    let call_id = 0u64;

    let (meta_hash, deterministic_hash) =
        crate::compute_deterministic_hashes(n, blueprint_id, call_id, SIGNING_SALT);
    let execution_id = ExecutionId::new(&deterministic_hash);

    info!(
        "Starting DFNS-CGGMP21 Signing for party {i}, n={party_count}, eid={}",
        hex::encode(execution_id.as_bytes())
    );

    let mut rng = rand_chacha::ChaChaRng::from_seed(deterministic_hash);

    // Look up refreshed key
    let key = hex::encode(meta_hash);
    let keygen_output = ctx
        .store
        .get(&key)
        .map_err(|e| format!("Store error: {e}"))?
        .ok_or_else(|| "Keygen output not found in DB".to_string())?
        .refreshed_key
        .ok_or_else(|| "Refreshed key not found".to_string())?;

    // Use all parties for signing
    let participants: Vec<u16> = (0..party_count).collect();

    type SignMsg = cggmp21::signing::msg::Msg<Secp256k1, Sha256>;

    let network = RoundBasedNetworkAdapter::<SignMsg, K256Ecdsa>::new(
        ctx.network_backend.clone(),
        i,
        &parties,
        crate::context::NETWORK_PROTOCOL,
    );

    let party = round_based::party::MpcParty::connected(network);

    let message = DataToSign::<Secp256k1>::digest::<Sha256>(&message_to_sign);

    let signature = cggmp21::signing(execution_id, i as _, &participants, &keygen_output)
        .sign(&mut rng, party, message)
        .await
        .map_err(|err| format!("Signing MPC error: {err}"))?;

    // Verify the signature
    let public_key = &keygen_output.shared_public_key;
    signature
        .verify(public_key, &message)
        .map_err(|err| format!("Signature verification failed: {err}"))?;

    let serialized_signature =
        serde_json::to_vec(&signature).map_err(|e| e.to_string())?;

    Ok(TangleResult(SignResult {
        signature: serialized_signature.into(),
    }))
}
