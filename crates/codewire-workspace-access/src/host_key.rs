use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use ssh_key::PrivateKey;
use ssh_key::private::Ed25519Keypair;

/// A fresh Ed25519 SSH host key. The daemon generates one per binding
/// generation and records only its public half.
pub fn generate_ed25519_key() -> PrivateKey {
    let signing_key = SigningKey::generate(&mut OsRng);
    PrivateKey::from(Ed25519Keypair::from_seed(&signing_key.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_distinct_ed25519_keys() {
        let first = generate_ed25519_key();
        let second = generate_ed25519_key();
        assert_eq!(first.algorithm(), ssh_key::Algorithm::Ed25519);
        assert_ne!(
            first.public_key().to_openssh().unwrap(),
            second.public_key().to_openssh().unwrap()
        );
    }
}
