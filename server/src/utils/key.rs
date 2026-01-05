use base64::Engine;
use rand::{Rng, distr::Alphanumeric};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn generate_key() -> String {
    let random_part: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX_EPOCH")
        .as_secs()
        .to_string();

    let ts_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ts.as_bytes());

    format!("{}.{}", random_part, ts_b64)
}
