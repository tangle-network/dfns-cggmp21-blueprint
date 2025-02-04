use crate::context::DfnsContext;
use blueprint_sdk::contexts::tangle::TangleClientContext;
use blueprint_sdk::crypto::tangle_pair_signer::sp_core::ecdsa::Public;
use blueprint_sdk::event_listeners::tangle::events::TangleEventListener;
use blueprint_sdk::event_listeners::tangle::services::{
    services_post_processor, services_pre_processor,
};
use blueprint_sdk::logging::info;
use blueprint_sdk::networking::round_based_compat::{NetworkDeliveryWrapper, NetworkWrapper};
use blueprint_sdk::std::rand::{prelude::SliceRandom, rngs::OsRng, RngCore};
use blueprint_sdk::tangle_subxt::tangle_testnet_runtime::api::services::events::JobCalled;
use blueprint_sdk::Error;
use cggmp21::key_share::AnyKeyShare;
use cggmp21::signing::SigningBuilder;
use cggmp21::{
    security_level::SecurityLevel128, supported_curves::Secp256k1, DataToSign, ExecutionId,
};
use futures::StreamExt;
use k256::sha2::Sha256;
use round_based::party::MpcParty;
use round_based::Delivery;
use std::collections::BTreeMap;

#[blueprint_sdk::job(
    id = 2,
    params(keygen_call_id, message_to_sign),
    event_listener(
        listener = TangleEventListener<DfnsContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    ),
)]
/// Runs a [t; n] keygen using DFNS-CGGMP21. Returns the public key
pub async fn sign(
    keygen_call_id: u64,
    message_to_sign: Vec<u8>,
    context: DfnsContext,
) -> Result<Vec<u8>, Error> {
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
    let blueprint_id = context
        .tangle_client()
        .await?
        .blueprint_id()
        .await
        .map_err(|e| Error::Other(format!("Context error: {e}")))?;
    let call_id = context.call_id.expect("Call ID not found");
    let n = parties.len();

    let (meta_hash, deterministic_hash) =
        crate::keygen::compute_deterministic_hashes(n as u16, blueprint_id, keygen_call_id);
    let store_key = hex::encode(meta_hash);

    let state = context
        .store
        .get(&store_key)
        .ok_or_else(|| Error::Other("[signing] Keygen output not found in DB".to_string()))?;

    // Even though we are using the keygen hash function (in order to get the store key for the meta_hash value), we need to ensure
    // uniqueness of the EID by adding in more elements to the hash
    let deterministic_hash =
        compute_sha256_hash!(deterministic_hash, call_id.to_be_bytes(), "dfns-signing");
    let eid = ExecutionId::new(&deterministic_hash);

    info!(
        "Starting DFNS-CGGMP21 Signing #{call_id} for party {i}, n={n}, eid={}",
        hex::encode(eid.as_bytes())
    );

    let mut rng = OsRng;
    let delivery = NetworkDeliveryWrapper::new(
        context.network_backend.clone(),
        i as _,
        deterministic_hash,
        parties,
    );
    let party = MpcParty::connected(delivery);

    let key_refresh_output = state
        .refreshed_key
        .ok_or_else(|| Error::Other("[signing] Keygen output not found".to_string()))?;
    // Choose `t` signers to perform signing
    let t = key_refresh_output.min_signers();
    let shares = &key_refresh_output.public_shares;
    let mut participants = (0..n).collect::<Vec<_>>();
    participants.shuffle(&mut rng);
    let participants = &participants[..usize::from(t)];
    info!("Signers: {participants:?}");
    let participants_shares = participants.iter().map(|i| &shares[*i]);
    let participants = participants.iter().map(|r| *r as u16).collect::<Vec<u16>>();

    // TODO: Parameterize the Curve type
    let signing = SigningBuilder::<Secp256k1, SecurityLevel128, Sha256>::new(
        eid,
        i as _,
        &participants,
        &key_refresh_output,
    );
    let message_to_sign = DataToSign::<Secp256k1>::digest::<Sha256>(&message_to_sign);
    let signature = signing
        .sign(&mut rng, party, message_to_sign)
        .await
        .map_err(|err| Error::Other(err.to_string()))?;

    let public_key = &key_refresh_output.shared_public_key;

    signature
        .verify(public_key, &message_to_sign)
        .map_err(|err| Error::Other(err.to_string()))?;

    let serialized_signature =
        serde_json::to_vec(&signature).expect("Failed to serialize signature");

    Ok(serialized_signature)
}
