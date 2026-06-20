use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    ACCOUNT_SIGNATURE_SCHEME, CHAIN_ID, RECOVERY_SIGNATURE_SCHEME,
};

const CRYPTO_POLICY_ID: &str = "nebula-pq-devnet-policy-v1";
const CRYPTO_POLICY_VERSION: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoPolicySuite {
    pub role: &'static str,
    pub scheme: &'static str,
    pub standard: &'static str,
    pub devnet_domain: &'static str,
    pub status: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CryptoRole {
    AccountSignature,
    ValidatorSignature,
    ProverSignature,
    WatchtowerSignature,
    NetworkSignature,
    RecoverySignature,
    KeyEstablishment,
}

impl CryptoRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccountSignature => "account_signature",
            Self::ValidatorSignature => "validator_signature",
            Self::ProverSignature => "prover_signature",
            Self::WatchtowerSignature => "watchtower_signature",
            Self::NetworkSignature => "network_signature",
            Self::RecoverySignature => "recovery_signature",
            Self::KeyEstablishment => "key_establishment",
        }
    }

    pub fn scheme(&self) -> &'static str {
        match self {
            Self::AccountSignature
            | Self::ValidatorSignature
            | Self::ProverSignature
            | Self::WatchtowerSignature
            | Self::NetworkSignature => ACCOUNT_SIGNATURE_SCHEME,
            Self::RecoverySignature => RECOVERY_SIGNATURE_SCHEME,
            Self::KeyEstablishment => "ML-KEM-768",
        }
    }

    fn signing_domain(&self) -> &'static str {
        match self {
            Self::AccountSignature
            | Self::ValidatorSignature
            | Self::ProverSignature
            | Self::WatchtowerSignature
            | Self::NetworkSignature => "DEVNET-ML-DSA-65-SIGNATURE",
            Self::RecoverySignature => "DEVNET-SLH-DSA-SHAKE-128S-SIGNATURE",
            Self::KeyEstablishment => "MEMPOOL-ML-KEM-CIPHERTEXT",
        }
    }
}

const CRYPTO_POLICY_SUITES: &[CryptoPolicySuite] = &[
    CryptoPolicySuite {
        role: "account_signature",
        scheme: "ML-DSA-65",
        standard: "NIST FIPS 204",
        devnet_domain: "DEVNET-ML-DSA-65-SIGNATURE",
        status: "required",
    },
    CryptoPolicySuite {
        role: "validator_signature",
        scheme: "ML-DSA-65",
        standard: "NIST FIPS 204",
        devnet_domain: "DEVNET-ML-DSA-65-SIGNATURE",
        status: "required",
    },
    CryptoPolicySuite {
        role: "prover_signature",
        scheme: "ML-DSA-65",
        standard: "NIST FIPS 204",
        devnet_domain: "DEVNET-ML-DSA-65-SIGNATURE",
        status: "required",
    },
    CryptoPolicySuite {
        role: "watchtower_signature",
        scheme: "ML-DSA-65",
        standard: "NIST FIPS 204",
        devnet_domain: "DEVNET-ML-DSA-65-SIGNATURE",
        status: "required",
    },
    CryptoPolicySuite {
        role: "network_signature",
        scheme: "ML-DSA-65",
        standard: "NIST FIPS 204",
        devnet_domain: "DEVNET-ML-DSA-65-SIGNATURE",
        status: "required",
    },
    CryptoPolicySuite {
        role: "recovery_signature",
        scheme: "SLH-DSA-SHAKE-128s",
        standard: "NIST FIPS 205",
        devnet_domain: "DEVNET-SLH-DSA-SHAKE-128S-SIGNATURE",
        status: "required",
    },
    CryptoPolicySuite {
        role: "key_establishment",
        scheme: "ML-KEM-768",
        standard: "NIST FIPS 203",
        devnet_domain: "MEMPOOL-ML-KEM-CIPHERTEXT",
        status: "required",
    },
    CryptoPolicySuite {
        role: "transcript_hash",
        scheme: "SHAKE256-devnet-domain-hash",
        standard: "FIPS 202 / cSHAKE-compatible domain separation target",
        devnet_domain: "NEBULA-L2-DEVNET",
        status: "required",
    },
    CryptoPolicySuite {
        role: "privacy_proof",
        scheme: "devnet-mock-private-transfer-proof",
        standard: "placeholder until audited PQ-safe proof stack",
        devnet_domain: "PRIVACY-PROOF",
        status: "devnet-placeholder",
    },
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecord {
    pub label: String,
    pub account_id: String,
    pub spend_public_key: String,
    pub recovery_public_key: String,
    pub network_public_key: String,
    pub auth_scheme: String,
    pub auth_implementation: String,
    pub crypto_policy_root: String,
    pub crypto_policy_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    pub signer_label: String,
    pub auth_scheme: String,
    pub auth_public_key: String,
    pub auth_transcript_hash: String,
    pub auth_signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyRecord {
    pub role: CryptoRole,
    pub scheme: String,
    pub label: String,
    pub key_id: String,
    pub public_key: String,
    pub crypto_policy_root: String,
}

impl PublicKeyRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "role": self.role.as_str(),
            "scheme": self.scheme,
            "label": self.label,
            "key_id": self.key_id,
            "public_key": self.public_key,
            "crypto_policy_root": self.crypto_policy_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemEnvelope {
    pub role: CryptoRole,
    pub scheme: String,
    pub recipient_key_id: String,
    pub recipient_public_key_root: String,
    pub ciphertext_hash: String,
    pub transcript_hash: String,
    pub crypto_policy_root: String,
}

impl KemEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "role": self.role.as_str(),
            "scheme": self.scheme,
            "recipient_key_id": self.recipient_key_id,
            "recipient_public_key_root": self.recipient_public_key_root,
            "ciphertext_hash": self.ciphertext_hash,
            "transcript_hash": self.transcript_hash,
            "crypto_policy_root": self.crypto_policy_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryAuthorization {
    pub recovery_label: String,
    pub recovery_scheme: String,
    pub recovery_public_key: String,
    pub recovery_transcript_hash: String,
    pub recovery_signature: String,
}

pub fn crypto_policy_suites() -> Vec<CryptoPolicySuite> {
    CRYPTO_POLICY_SUITES.to_vec()
}

pub fn crypto_policy_root() -> String {
    let leaves = CRYPTO_POLICY_SUITES
        .iter()
        .map(|suite| {
            json!({
                "policy_id": CRYPTO_POLICY_ID,
                "policy_version": CRYPTO_POLICY_VERSION,
                "suite": suite,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("CRYPTO-POLICY", &leaves)
}

fn account_secret(label: &str) -> String {
    domain_hash("ACCOUNT-SECRET-SEED", &[HashPart::Str(label)], 64)
}

pub fn public_key_for_label(role: CryptoRole, label: &str) -> PublicKeyRecord {
    let account = account_record(label);
    let public_key = match role {
        CryptoRole::AccountSignature => account.spend_public_key,
        CryptoRole::ValidatorSignature => domain_hash(
            "VALIDATOR-CONSENSUS-PUBLIC",
            &[HashPart::Str(&account.spend_public_key)],
            64,
        ),
        CryptoRole::ProverSignature => domain_hash(
            "PROVER-PUBLIC",
            &[HashPart::Str(&account.spend_public_key)],
            64,
        ),
        CryptoRole::WatchtowerSignature => domain_hash(
            "WATCHTOWER-PUBLIC",
            &[HashPart::Str(&account.spend_public_key)],
            64,
        ),
        CryptoRole::NetworkSignature => domain_hash(
            "NETWORK-SIGNING-PUBLIC",
            &[HashPart::Str(&account.spend_public_key)],
            64,
        ),
        CryptoRole::RecoverySignature => account.recovery_public_key,
        CryptoRole::KeyEstablishment => account.network_public_key,
    };
    PublicKeyRecord {
        key_id: domain_hash(
            "CRYPTO-PUBLIC-KEY-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(role.as_str()),
                HashPart::Str(label),
                HashPart::Str(&public_key),
                HashPart::Str(&crypto_policy_root()),
            ],
            32,
        ),
        scheme: role.scheme().to_string(),
        label: label.to_string(),
        role,
        public_key,
        crypto_policy_root: crypto_policy_root(),
    }
}

pub fn account_record(label: &str) -> AccountRecord {
    let secret_seed = account_secret(label);
    AccountRecord {
        label: label.to_string(),
        account_id: domain_hash("ACCOUNT-ID", &[HashPart::Str(label)], 32),
        spend_public_key: domain_hash("ACCOUNT-SPEND-PUBLIC", &[HashPart::Str(&secret_seed)], 64),
        recovery_public_key: domain_hash(
            "ACCOUNT-RECOVERY-PUBLIC",
            &[HashPart::Str(&secret_seed)],
            64,
        ),
        network_public_key: domain_hash(
            "ACCOUNT-NETWORK-PUBLIC",
            &[HashPart::Str(&secret_seed)],
            64,
        ),
        auth_scheme: ACCOUNT_SIGNATURE_SCHEME.to_string(),
        auth_implementation: "devnet-mock-not-production-crypto".to_string(),
        crypto_policy_root: crypto_policy_root(),
        crypto_policy_version: CRYPTO_POLICY_VERSION.to_string(),
    }
}

pub fn auth_transcript_hash(domain: &str, payload: &Value) -> String {
    domain_hash(
        "AUTH-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn role_auth_transcript_hash(role: CryptoRole, domain: &str, payload: &Value) -> String {
    domain_hash(
        "AUTH-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(role.as_str()),
            HashPart::Str(role.scheme()),
            HashPart::Str(&crypto_policy_root()),
            HashPart::Str(domain),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn sign_authorization(label: &str, domain: &str, payload: &Value) -> Authorization {
    let transcript_hash = auth_transcript_hash(domain, payload);
    let secret = account_secret(label);
    let signature = domain_hash(
        "DEVNET-ML-DSA-65-SIGNATURE",
        &[HashPart::Str(&secret), HashPart::Str(&transcript_hash)],
        64,
    );
    Authorization {
        signer_label: label.to_string(),
        auth_scheme: ACCOUNT_SIGNATURE_SCHEME.to_string(),
        auth_public_key: account_record(label).spend_public_key,
        auth_transcript_hash: transcript_hash,
        auth_signature: signature,
    }
}

pub fn sign_authorization_for_role(
    role: CryptoRole,
    label: &str,
    domain: &str,
    payload: &Value,
) -> Authorization {
    let transcript_hash = role_auth_transcript_hash(role.clone(), domain, payload);
    let secret = account_secret(label);
    let signature = domain_hash(
        role.signing_domain(),
        &[
            HashPart::Str(role.as_str()),
            HashPart::Str(&crypto_policy_root()),
            HashPart::Str(&secret),
            HashPart::Str(&transcript_hash),
        ],
        64,
    );
    let public_key = public_key_for_label(role.clone(), label);
    Authorization {
        signer_label: label.to_string(),
        auth_scheme: role.scheme().to_string(),
        auth_public_key: public_key.public_key,
        auth_transcript_hash: transcript_hash,
        auth_signature: signature,
    }
}

pub fn verify_authorization_for_role(
    role: CryptoRole,
    expected_public_key: &str,
    domain: &str,
    payload: &Value,
    authorization: &Authorization,
) -> bool {
    let expected = sign_authorization_for_role(role, &authorization.signer_label, domain, payload);
    expected == *authorization && authorization.auth_public_key == expected_public_key
}

pub fn sign_validator_authorization(label: &str, domain: &str, payload: &Value) -> Authorization {
    sign_authorization_for_role(CryptoRole::ValidatorSignature, label, domain, payload)
}

pub fn verify_validator_authorization(
    expected_public_key: &str,
    domain: &str,
    payload: &Value,
    authorization: &Authorization,
) -> bool {
    verify_authorization_for_role(
        CryptoRole::ValidatorSignature,
        expected_public_key,
        domain,
        payload,
        authorization,
    )
}

pub fn sign_prover_authorization(label: &str, domain: &str, payload: &Value) -> Authorization {
    sign_authorization_for_role(CryptoRole::ProverSignature, label, domain, payload)
}

pub fn verify_prover_authorization(
    expected_public_key: &str,
    domain: &str,
    payload: &Value,
    authorization: &Authorization,
) -> bool {
    verify_authorization_for_role(
        CryptoRole::ProverSignature,
        expected_public_key,
        domain,
        payload,
        authorization,
    )
}

pub fn sign_watchtower_authorization(label: &str, domain: &str, payload: &Value) -> Authorization {
    sign_authorization_for_role(CryptoRole::WatchtowerSignature, label, domain, payload)
}

pub fn verify_watchtower_authorization(
    expected_public_key: &str,
    domain: &str,
    payload: &Value,
    authorization: &Authorization,
) -> bool {
    verify_authorization_for_role(
        CryptoRole::WatchtowerSignature,
        expected_public_key,
        domain,
        payload,
        authorization,
    )
}

pub fn sign_network_authorization(label: &str, domain: &str, payload: &Value) -> Authorization {
    sign_authorization_for_role(CryptoRole::NetworkSignature, label, domain, payload)
}

pub fn verify_network_authorization(
    expected_public_key: &str,
    domain: &str,
    payload: &Value,
    authorization: &Authorization,
) -> bool {
    verify_authorization_for_role(
        CryptoRole::NetworkSignature,
        expected_public_key,
        domain,
        payload,
        authorization,
    )
}

pub fn verify_authorization(
    label: &str,
    domain: &str,
    payload: &Value,
    authorization: &Authorization,
) -> bool {
    sign_authorization(label, domain, payload) == *authorization
}

pub fn sign_recovery_authorization(
    label: &str,
    domain: &str,
    payload: &Value,
) -> RecoveryAuthorization {
    let transcript_hash = auth_transcript_hash(domain, payload);
    let secret = account_secret(label);
    let signature = domain_hash(
        "DEVNET-SLH-DSA-SHAKE-128S-SIGNATURE",
        &[HashPart::Str(&secret), HashPart::Str(&transcript_hash)],
        64,
    );
    RecoveryAuthorization {
        recovery_label: label.to_string(),
        recovery_scheme: RECOVERY_SIGNATURE_SCHEME.to_string(),
        recovery_public_key: account_record(label).recovery_public_key,
        recovery_transcript_hash: transcript_hash,
        recovery_signature: signature,
    }
}

pub fn build_kem_envelope(
    role: CryptoRole,
    recipient_key_id: &str,
    recipient_public_key_root: &str,
    transcript: &Value,
) -> KemEnvelope {
    let transcript_hash = domain_hash(
        "KEM-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(role.as_str()),
            HashPart::Str(role.scheme()),
            HashPart::Str(&crypto_policy_root()),
            HashPart::Str(recipient_key_id),
            HashPart::Str(recipient_public_key_root),
            HashPart::Json(transcript),
        ],
        32,
    );
    let ciphertext_hash = domain_hash(
        role.signing_domain(),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(role.as_str()),
            HashPart::Str(recipient_key_id),
            HashPart::Str(recipient_public_key_root),
            HashPart::Str(&transcript_hash),
        ],
        32,
    );
    KemEnvelope {
        role: role.clone(),
        scheme: role.scheme().to_string(),
        recipient_key_id: recipient_key_id.to_string(),
        recipient_public_key_root: recipient_public_key_root.to_string(),
        ciphertext_hash,
        transcript_hash,
        crypto_policy_root: crypto_policy_root(),
    }
}

pub fn verify_kem_envelope(
    envelope: &KemEnvelope,
    expected_role: CryptoRole,
    expected_recipient_public_key_root: &str,
    transcript: &Value,
) -> bool {
    if envelope.role != expected_role
        || envelope.scheme != expected_role.scheme()
        || envelope.recipient_public_key_root != expected_recipient_public_key_root
        || envelope.crypto_policy_root != crypto_policy_root()
    {
        return false;
    }
    build_kem_envelope(
        expected_role,
        &envelope.recipient_key_id,
        expected_recipient_public_key_root,
        transcript,
    ) == *envelope
}

pub fn verify_recovery_authorization(
    label: &str,
    domain: &str,
    payload: &Value,
    authorization: &RecoveryAuthorization,
) -> bool {
    sign_recovery_authorization(label, domain, payload) == *authorization
}

pub fn crypto_suite() -> Value {
    json!({
        "account_signature": ACCOUNT_SIGNATURE_SCHEME,
        "validator_signature": ACCOUNT_SIGNATURE_SCHEME,
        "recovery_signature": RECOVERY_SIGNATURE_SCHEME,
        "key_establishment": "ML-KEM-768",
        "transcript_hash": "SHAKE256-devnet-domain-hash",
        "privacy_proof": "devnet-mock-private-transfer-proof",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn crypto_policy_root_matches_python_reference() {
        assert_eq!(
            crypto_policy_root(),
            "8933149e25477f81d66a5fafe4f9364046cb108d8fff94b58299ecafe397dd35"
        );
    }

    #[test]
    fn account_record_matches_python_reference() {
        let account = account_record("vector-account");
        assert_eq!(
            account.account_id,
            "8e05acf8aae1d01495b5c5c5521a0384ac86b7d6ad5170f9c5c6a8f14dd7feed"
        );
        assert_eq!(
            account.spend_public_key,
            "c650024740cfc44d9b04558acc6f5cc17d0a76772de4b76b802e048a1e13570a51ccab7d6b6e1ab32e924c284ee50f346494fc3d2c938f01f64c879e0d8a9ea9"
        );
        assert_eq!(
            account.recovery_public_key,
            "34efb89cca3094fcad170acc69af584b0c1e25860121d325a43f4925e4c3f46b2144ac611eccdcf3c19c043888b9d42ebe050e2f03d6ec4fb1b7d80fa186de79"
        );
        assert_eq!(
            account.network_public_key,
            "55382ae836fe938029f6b5da583a410bba86bf69efb1d34b42131ffa85ed7ab17843fa55c594d31f087bcb7283eefde64f7ea920dee0e3c5030db4ed76839faa"
        );
    }

    #[test]
    fn authorization_matches_python_reference() {
        let payload = json!({"chain_id": CHAIN_ID, "purpose": "go parity", "nonce": 7});
        let auth = sign_authorization("vector-account", "go_parity", &payload);
        assert_eq!(
            auth.auth_transcript_hash,
            "913f95629e0d5d3c62c2a734769e957ed0b5aa0522f0c71d3d1b5a799e329666"
        );
        assert_eq!(
            auth.auth_signature,
            "9234e9ffb38c49326b2f3d4caae9e2963b3226e09c7a707d753c44d0a04a24eb7c04bb715c21af1d2a6b66e86cdfc2ab43b5b190a441b5958e01a0a7eba0d930"
        );
        assert!(verify_authorization(
            "vector-account",
            "go_parity",
            &payload,
            &auth
        ));
    }

    #[test]
    fn recovery_authorization_uses_slh_dsa_policy() {
        let payload = json!({"account_id": "account", "rotation_nonce": 1});
        let recovery = sign_recovery_authorization("vector-account", "account_rotation", &payload);

        assert_eq!(recovery.recovery_scheme, RECOVERY_SIGNATURE_SCHEME);
        assert_eq!(
            recovery.recovery_public_key,
            account_record("vector-account").recovery_public_key
        );
        assert!(verify_recovery_authorization(
            "vector-account",
            "account_rotation",
            &payload,
            &recovery
        ));
    }
}
