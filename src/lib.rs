pub mod context;
pub mod key_refresh;
pub mod keygen;
pub mod signing;

use blueprint_sdk::alloy::sol;
use blueprint_sdk::crypto::hashing::sha2_256;
use blueprint_sdk::tangle::TangleLayer;
use blueprint_sdk::{Job, Router};

pub const JOB_KEYGEN: u8 = 0;
pub const JOB_KEY_REFRESH: u8 = 1;
pub const JOB_SIGN: u8 = 2;

const META_SALT: &str = "dfns";

sol! {
    struct KeygenRequest { uint16 n; }
    struct KeygenResult { bytes public_key; }
    struct KeyRefreshRequest { uint16 n; }
    struct KeyRefreshResult { bytes public_key; }
    struct SignRequest { uint16 n; bytes message_to_sign; }
    struct SignResult { bytes signature; }
}

/// Compute deterministic hashes for protocol execution IDs.
pub fn compute_deterministic_hashes(
    n: u16,
    blueprint_id: u64,
    call_id: u64,
    salt: &str,
) -> ([u8; 32], [u8; 32]) {
    let mut meta_input = Vec::new();
    meta_input.extend_from_slice(&n.to_be_bytes());
    meta_input.extend_from_slice(&blueprint_id.to_be_bytes());
    meta_input.extend_from_slice(&call_id.to_be_bytes());
    meta_input.extend_from_slice(META_SALT.as_bytes());
    let meta_hash = sha2_256(&meta_input);

    let mut det_input = Vec::new();
    det_input.extend_from_slice(&meta_hash);
    det_input.extend_from_slice(salt.as_bytes());
    let deterministic_hash = sha2_256(&det_input);

    (meta_hash, deterministic_hash)
}

pub fn router() -> Router {
    Router::new()
        .route(JOB_KEYGEN, keygen::keygen.layer(TangleLayer))
        .route(JOB_KEY_REFRESH, key_refresh::key_refresh.layer(TangleLayer))
        .route(JOB_SIGN, signing::signing.layer(TangleLayer))
}
