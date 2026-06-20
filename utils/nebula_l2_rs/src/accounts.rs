use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{
        account_record, build_kem_envelope, sign_authorization, sign_recovery_authorization,
        verify_authorization, verify_recovery_authorization, Authorization, CryptoRole,
        KemEnvelope, RecoveryAuthorization,
    },
    hash::{domain_hash, merkle_root, HashPart},
    mempool::relay_path_public_metadata,
    ACCOUNT_SIGNATURE_SCHEME, CHAIN_ID, RECOVERY_SIGNATURE_SCHEME,
};

pub type AccountResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountState {
    pub account_id: String,
    pub current_label: String,
    pub spend_public_key: String,
    pub recovery_public_key: String,
    pub network_public_key: String,
    pub rotation_nonce: u64,
    pub status: String,
}

impl AccountState {
    pub fn from_label(label: impl Into<String>) -> Self {
        let label = label.into();
        let record = account_record(&label);
        Self {
            account_id: record.account_id,
            current_label: label,
            spend_public_key: record.spend_public_key,
            recovery_public_key: record.recovery_public_key,
            network_public_key: record.network_public_key,
            rotation_nonce: 0,
            status: "active".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "spend_public_key": self.spend_public_key,
            "recovery_public_key": self.recovery_public_key,
            "network_public_key": self.network_public_key,
            "rotation_nonce": self.rotation_nonce,
            "status": self.status,
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("account state record object")
            .insert(
                "current_label".to_string(),
                Value::String(self.current_label.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRotation {
    pub account_id: String,
    pub previous_label: String,
    pub new_label: String,
    pub previous_spend_public_key: String,
    pub new_spend_public_key: String,
    pub new_recovery_public_key: String,
    pub new_network_public_key: String,
    pub rotation_nonce: u64,
    pub recovery_label: String,
    pub recovery_scheme: String,
    pub recovery_public_key: String,
    pub recovery_transcript_hash: String,
    pub recovery_signature: String,
    pub proof_system: String,
}

impl AccountRotation {
    pub fn build(
        account: &AccountState,
        new_label: impl Into<String>,
        recovery_label: impl Into<String>,
    ) -> AccountResult<Self> {
        let new_label = new_label.into();
        let recovery_label = recovery_label.into();
        let new_account = account_record(&new_label);
        let mut rotation = Self {
            account_id: account.account_id.clone(),
            previous_label: account.current_label.clone(),
            new_label,
            previous_spend_public_key: account.spend_public_key.clone(),
            new_spend_public_key: new_account.spend_public_key,
            new_recovery_public_key: new_account.recovery_public_key,
            new_network_public_key: new_account.network_public_key,
            rotation_nonce: account
                .rotation_nonce
                .checked_add(1)
                .ok_or_else(|| "account rotation nonce overflow".to_string())?,
            recovery_label: String::new(),
            recovery_scheme: RECOVERY_SIGNATURE_SCHEME.to_string(),
            recovery_public_key: String::new(),
            recovery_transcript_hash: String::new(),
            recovery_signature: String::new(),
            proof_system: "devnet-slh-dsa-account-rotation".to_string(),
        };
        let recovery = sign_recovery_authorization(
            &recovery_label,
            "account_rotation",
            &rotation.unsigned_record(),
        );
        rotation.recovery_label = recovery.recovery_label;
        rotation.recovery_scheme = recovery.recovery_scheme;
        rotation.recovery_public_key = recovery.recovery_public_key;
        rotation.recovery_transcript_hash = recovery.recovery_transcript_hash;
        rotation.recovery_signature = recovery.recovery_signature;
        Ok(rotation)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "account_rotation",
            "account_id": self.account_id,
            "previous_spend_public_key": self.previous_spend_public_key,
            "new_spend_public_key": self.new_spend_public_key,
            "new_recovery_public_key": self.new_recovery_public_key,
            "new_network_public_key": self.new_network_public_key,
            "rotation_nonce": self.rotation_nonce,
            "proof_system": self.proof_system,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("account rotation public record object");
        object.insert(
            "recovery_scheme".to_string(),
            Value::String(self.recovery_scheme.clone()),
        );
        object.insert(
            "recovery_public_key".to_string(),
            Value::String(self.recovery_public_key.clone()),
        );
        object.insert(
            "recovery_transcript_hash".to_string(),
            Value::String(self.recovery_transcript_hash.clone()),
        );
        object.insert(
            "recovery_signature".to_string(),
            Value::String(self.recovery_signature.clone()),
        );
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record
            .as_object_mut()
            .expect("account rotation state record object");
        object.insert(
            "previous_label".to_string(),
            Value::String(self.previous_label.clone()),
        );
        object.insert(
            "new_label".to_string(),
            Value::String(self.new_label.clone()),
        );
        object.insert(
            "recovery_label".to_string(),
            Value::String(self.recovery_label.clone()),
        );
        record
    }

    pub fn recovery_authorization(&self) -> RecoveryAuthorization {
        RecoveryAuthorization {
            recovery_label: self.recovery_label.clone(),
            recovery_scheme: self.recovery_scheme.clone(),
            recovery_public_key: self.recovery_public_key.clone(),
            recovery_transcript_hash: self.recovery_transcript_hash.clone(),
            recovery_signature: self.recovery_signature.clone(),
        }
    }

    pub fn verify_recovery_authorization(&self) -> bool {
        verify_recovery_authorization(
            &self.recovery_label,
            "account_rotation",
            &self.unsigned_record(),
            &self.recovery_authorization(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSessionOpenRequest {
    pub signer_label: String,
    pub relay_path: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub node_committee_key_id: String,
    pub node_network_root: String,
    pub session_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSession {
    pub session_id: String,
    pub account_id: String,
    pub wallet_network_public_key: String,
    pub node_committee_key_id: String,
    pub node_network_root: String,
    pub relay_path: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub account_rotation_nonce: u64,
    pub kem_ciphertext_hash: String,
    pub kem_envelope: KemEnvelope,
    pub session_transcript_hash: String,
    pub status: String,
    pub signer_label: String,
    pub auth_scheme: String,
    pub auth_public_key: String,
    pub auth_transcript_hash: String,
    pub auth_signature: String,
}

impl WalletSession {
    pub fn build(account: &AccountState, request: WalletSessionOpenRequest) -> AccountResult<Self> {
        let signer_label = request.signer_label;
        let relay_path = request.relay_path;
        let node_committee_key_id = request.node_committee_key_id;
        let node_network_root = request.node_network_root;
        if relay_path.is_empty() {
            return Err("relay_path is required".to_string());
        }
        if request.expires_at_height <= request.opened_at_height {
            return Err("wallet session expiry must be after open height".to_string());
        }
        if account.status != "active" {
            return Err("wallet session account must be active".to_string());
        }
        if account.current_label != signer_label {
            return Err("wallet session signer must match current account label".to_string());
        }

        let kem_envelope = wallet_session_kem_envelope(
            &account.account_id,
            &account.network_public_key,
            &node_committee_key_id,
            &node_network_root,
            &relay_path,
            request.opened_at_height,
            request.expires_at_height,
            account.rotation_nonce,
        );
        let kem_ciphertext_hash = kem_envelope.ciphertext_hash.clone();
        let session_transcript_hash = domain_hash(
            "WALLET-SESSION-TRANSCRIPT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&account.account_id),
                HashPart::Str(&account.network_public_key),
                HashPart::Str(&node_committee_key_id),
                HashPart::Str(&kem_ciphertext_hash),
                HashPart::Str(&relay_path),
                HashPart::Int(request.opened_at_height as i128),
                HashPart::Int(request.expires_at_height as i128),
            ],
            32,
        );
        let session_id = domain_hash(
            "WALLET-SESSION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&account.account_id),
                HashPart::Str(&session_transcript_hash),
                HashPart::Int(request.session_sequence as i128),
            ],
            32,
        );

        let mut session = Self {
            session_id,
            account_id: account.account_id.clone(),
            wallet_network_public_key: account.network_public_key.clone(),
            node_committee_key_id,
            node_network_root,
            relay_path,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.expires_at_height,
            account_rotation_nonce: account.rotation_nonce,
            kem_ciphertext_hash,
            kem_envelope,
            session_transcript_hash,
            status: "active".to_string(),
            signer_label,
            auth_scheme: ACCOUNT_SIGNATURE_SCHEME.to_string(),
            auth_public_key: String::new(),
            auth_transcript_hash: String::new(),
            auth_signature: String::new(),
        };
        let authorization = sign_authorization(
            &session.signer_label,
            "wallet_session_open",
            &session.unsigned_record(),
        );
        session.auth_scheme = authorization.auth_scheme;
        session.auth_public_key = authorization.auth_public_key;
        session.auth_transcript_hash = authorization.auth_transcript_hash;
        session.auth_signature = authorization.auth_signature;
        Ok(session)
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = json!({
            "session_id": self.session_id,
            "account_id": self.account_id,
            "wallet_network_public_key": self.wallet_network_public_key,
            "node_committee_key_id": self.node_committee_key_id,
            "node_network_root": self.node_network_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "account_rotation_nonce": self.account_rotation_nonce,
            "kem_ciphertext_hash": self.kem_ciphertext_hash,
            "kem_envelope": self.kem_envelope.public_record(),
            "session_transcript_hash": self.session_transcript_hash,
        });
        record
            .as_object_mut()
            .expect("wallet session unsigned record object")
            .extend(relay_path_public_metadata(&self.relay_path));
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("wallet session public record object");
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.auth_signature.clone()),
        );
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record
            .as_object_mut()
            .expect("wallet session state record object");
        object.insert(
            "relay_path".to_string(),
            Value::String(self.relay_path.clone()),
        );
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        record
    }

    pub fn authorization(&self) -> Authorization {
        Authorization {
            signer_label: self.signer_label.clone(),
            auth_scheme: self.auth_scheme.clone(),
            auth_public_key: self.auth_public_key.clone(),
            auth_transcript_hash: self.auth_transcript_hash.clone(),
            auth_signature: self.auth_signature.clone(),
        }
    }

    pub fn verify_authorization(&self) -> bool {
        verify_authorization(
            &self.signer_label,
            "wallet_session_open",
            &self.unsigned_record(),
            &self.authorization(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRegistry {
    pub accounts: BTreeMap<String, AccountState>,
    pub account_rotations: BTreeMap<String, AccountRotation>,
    pub wallet_sessions: BTreeMap<String, WalletSession>,
    pub retired_account_labels: BTreeSet<String>,
    pub height: u64,
    pub node_committee_key_id: String,
    pub node_network_root: String,
}

impl Default for AccountRegistry {
    fn default() -> Self {
        Self::new(
            domain_hash(
                "MEMPOOL-COMMITTEE-KEY-ID",
                &[HashPart::Str(CHAIN_ID), HashPart::Str("account-registry")],
                32,
            ),
            merkle_root("NODE-NETWORK-KEYS", &[]),
        )
    }
}

impl AccountRegistry {
    pub fn new(
        node_committee_key_id: impl Into<String>,
        node_network_root: impl Into<String>,
    ) -> Self {
        Self {
            accounts: BTreeMap::new(),
            account_rotations: BTreeMap::new(),
            wallet_sessions: BTreeMap::new(),
            retired_account_labels: BTreeSet::new(),
            height: 0,
            node_committee_key_id: node_committee_key_id.into(),
            node_network_root: node_network_root.into(),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn advance_height(&mut self, blocks: u64) -> AccountResult<u64> {
        self.height = self
            .height
            .checked_add(blocks)
            .ok_or_else(|| "account registry height overflow".to_string())?;
        Ok(self.height)
    }

    pub fn set_node_network_root(&mut self, node_network_root: impl Into<String>) {
        self.node_network_root = node_network_root.into();
    }

    pub fn register_account(&mut self, label: impl Into<String>) -> AccountResult<AccountState> {
        let label = label.into();
        if self.retired_account_labels.contains(&label) {
            return Err("account label has been retired".to_string());
        }
        let account = AccountState::from_label(label);
        if self.accounts.contains_key(&account.account_id) {
            return Err("account already registered".to_string());
        }
        self.accounts
            .insert(account.account_id.clone(), account.clone());
        Ok(account)
    }

    pub fn submit_account_rotation(
        &mut self,
        account_id: &str,
        new_label: impl Into<String>,
        recovery_label: impl Into<String>,
    ) -> AccountResult<AccountRotation> {
        let account = self
            .accounts
            .get(account_id)
            .ok_or_else(|| "unknown account".to_string())?;
        let rotation = AccountRotation::build(account, new_label, recovery_label)?;
        self.verify_account_rotation(&rotation)?;
        let rotation_id = account_rotation_id(&rotation);
        self.apply_account_rotation(&rotation)?;
        self.account_rotations.insert(rotation_id, rotation.clone());
        Ok(rotation)
    }

    pub fn verify_account_rotation(&self, rotation: &AccountRotation) -> AccountResult<()> {
        let account = self
            .accounts
            .get(&rotation.account_id)
            .ok_or_else(|| "unknown account".to_string())?;
        if account.status != "active" {
            return Err("account is not active".to_string());
        }
        if rotation.previous_label != account.current_label {
            return Err("account rotation previous label mismatch".to_string());
        }
        if rotation.previous_spend_public_key != account.spend_public_key {
            return Err("account rotation previous spend key mismatch".to_string());
        }
        if rotation.rotation_nonce != account.rotation_nonce + 1 {
            return Err("account rotation nonce mismatch".to_string());
        }
        if self.retired_account_labels.contains(&rotation.new_label) {
            return Err("new account label has been retired".to_string());
        }
        if rotation.recovery_public_key != account.recovery_public_key {
            return Err("account rotation recovery key mismatch".to_string());
        }
        let expected_new = account_record(&rotation.new_label);
        if rotation.new_spend_public_key != expected_new.spend_public_key {
            return Err("account rotation new spend key mismatch".to_string());
        }
        if rotation.new_recovery_public_key != expected_new.recovery_public_key {
            return Err("account rotation new recovery key mismatch".to_string());
        }
        if rotation.new_network_public_key != expected_new.network_public_key {
            return Err("account rotation new network key mismatch".to_string());
        }
        if !rotation.verify_recovery_authorization() {
            return Err("invalid account recovery authorization".to_string());
        }
        Ok(())
    }

    pub fn open_wallet_session(
        &mut self,
        account_id: &str,
        signer_label: impl Into<String>,
        relay_path: impl Into<String>,
        expires_in_blocks: u64,
    ) -> AccountResult<WalletSession> {
        if expires_in_blocks == 0 {
            return Err("expires_in_blocks must be positive".to_string());
        }
        let account = self
            .accounts
            .get(account_id)
            .ok_or_else(|| "unknown account".to_string())?;
        let expires_at_height = self
            .height
            .checked_add(expires_in_blocks)
            .ok_or_else(|| "wallet session expiry height overflow".to_string())?;
        let session = WalletSession::build(
            account,
            WalletSessionOpenRequest {
                signer_label: signer_label.into(),
                relay_path: relay_path.into(),
                opened_at_height: self.height,
                expires_at_height,
                node_committee_key_id: self.node_committee_key_id.clone(),
                node_network_root: self.node_network_root.clone(),
                session_sequence: self.wallet_sessions.len() as u64,
            },
        )?;
        self.verify_wallet_session(&session)?;
        self.wallet_sessions
            .insert(session.session_id.clone(), session.clone());
        Ok(session)
    }

    pub fn verify_wallet_session(&self, session: &WalletSession) -> AccountResult<()> {
        if session.status != "active" && session.status != "revoked" {
            return Err("invalid wallet session status".to_string());
        }
        if session.expires_at_height <= session.opened_at_height {
            return Err("wallet session expiry must be after open height".to_string());
        }
        let account = self
            .accounts
            .get(&session.account_id)
            .ok_or_else(|| "wallet session references unknown account".to_string())?;
        if session.signer_label.is_empty() {
            return Err("wallet session signer label is required in state".to_string());
        }
        let expected_account = account_record(&session.signer_label);
        if expected_account.account_id != session.account_id {
            return Err("wallet session signer account mismatch".to_string());
        }
        if expected_account.network_public_key != session.wallet_network_public_key {
            return Err("wallet session network key mismatch".to_string());
        }
        if session.status == "active" {
            if account.current_label != session.signer_label {
                return Err("active wallet session signer is not current".to_string());
            }
            if account.rotation_nonce != session.account_rotation_nonce {
                return Err("active wallet session rotation nonce mismatch".to_string());
            }
            if account.network_public_key != session.wallet_network_public_key {
                return Err("active wallet session network key mismatch".to_string());
            }
        }
        let expected_kem = wallet_session_kem_envelope(
            &session.account_id,
            &session.wallet_network_public_key,
            &session.node_committee_key_id,
            &session.node_network_root,
            &session.relay_path,
            session.opened_at_height,
            session.expires_at_height,
            session.account_rotation_nonce,
        );
        if session.kem_ciphertext_hash != expected_kem.ciphertext_hash
            || session.kem_envelope != expected_kem
        {
            return Err("wallet session KEM ciphertext mismatch".to_string());
        }
        let expected_transcript = domain_hash(
            "WALLET-SESSION-TRANSCRIPT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&session.account_id),
                HashPart::Str(&session.wallet_network_public_key),
                HashPart::Str(&session.node_committee_key_id),
                HashPart::Str(&session.kem_ciphertext_hash),
                HashPart::Str(&session.relay_path),
                HashPart::Int(session.opened_at_height as i128),
                HashPart::Int(session.expires_at_height as i128),
            ],
            32,
        );
        if session.session_transcript_hash != expected_transcript {
            return Err("wallet session transcript mismatch".to_string());
        }
        if !session.verify_authorization() {
            return Err("invalid wallet session authorization".to_string());
        }
        Ok(())
    }

    pub fn wallet_session_status(&self, session_id: &str) -> AccountResult<Value> {
        let session = self
            .wallet_sessions
            .get(session_id)
            .ok_or_else(|| "unknown wallet session".to_string())?;
        let expired = self.height > session.expires_at_height;
        let stale_network = session.status == "active"
            && !expired
            && session.node_network_root != self.node_network_root;
        let active = session.status == "active" && !expired && !stale_network;
        let status = if active {
            "active"
        } else if expired {
            "expired"
        } else if stale_network {
            "stale_network"
        } else {
            &session.status
        };
        Ok(json!({
            "status": status,
            "current_height": self.height,
            "blocks_until_expiry": session.expires_at_height.saturating_sub(self.height) + u64::from(self.height <= session.expires_at_height),
            "session": session.public_record(),
            "wallet_session_root": self.wallet_session_root(),
            "account_root": self.account_root(),
            "node_network_root": self.node_network_root,
        }))
    }

    pub fn account_root(&self) -> String {
        let accounts = self
            .accounts
            .values()
            .map(AccountState::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "ACCOUNT",
            &[json!({
                "accounts": accounts,
                "wallet_session_count": self.wallet_sessions.len(),
                "wallet_session_root": self.wallet_session_root(),
            })],
        )
    }

    pub fn account_rotation_root(&self) -> String {
        merkle_root(
            "ACCOUNT-ROTATION",
            &self
                .account_rotations
                .values()
                .map(AccountRotation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn wallet_session_root(&self) -> String {
        merkle_root(
            "WALLET-SESSION",
            &self
                .wallet_sessions
                .values()
                .map(WalletSession::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_snapshot(&self) -> Value {
        json!({
            "account_count": self.accounts.len(),
            "account_root": self.account_root(),
            "account_rotation_count": self.account_rotations.len(),
            "account_rotation_root": self.account_rotation_root(),
            "wallet_session_count": self.wallet_sessions.len(),
            "wallet_session_root": self.wallet_session_root(),
            "node_committee_key_id": self.node_committee_key_id,
            "node_network_root": self.node_network_root,
        })
    }

    fn apply_account_rotation(&mut self, rotation: &AccountRotation) -> AccountResult<()> {
        let account = self
            .accounts
            .get_mut(&rotation.account_id)
            .ok_or_else(|| "unknown account".to_string())?;
        self.retired_account_labels
            .insert(account.current_label.clone());
        *account = AccountState {
            account_id: account.account_id.clone(),
            current_label: rotation.new_label.clone(),
            spend_public_key: rotation.new_spend_public_key.clone(),
            recovery_public_key: rotation.new_recovery_public_key.clone(),
            network_public_key: rotation.new_network_public_key.clone(),
            rotation_nonce: rotation.rotation_nonce,
            status: account.status.clone(),
        };
        for session in self.wallet_sessions.values_mut() {
            if session.account_id == rotation.account_id && session.status == "active" {
                session.status = "revoked".to_string();
            }
        }
        Ok(())
    }
}

pub fn account_rotation_id(rotation: &AccountRotation) -> String {
    domain_hash(
        "ACCOUNT-ROTATION-ID",
        &[HashPart::Json(&rotation.public_record())],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn wallet_session_kem_envelope(
    account_id: &str,
    wallet_network_public_key: &str,
    node_committee_key_id: &str,
    node_network_root: &str,
    relay_path: &str,
    opened_at_height: u64,
    expires_at_height: u64,
    account_rotation_nonce: u64,
) -> KemEnvelope {
    let mut envelope = build_kem_envelope(
        CryptoRole::KeyEstablishment,
        node_committee_key_id,
        node_network_root,
        &wallet_session_kem_transcript(
            account_id,
            wallet_network_public_key,
            node_committee_key_id,
            node_network_root,
            relay_path,
            opened_at_height,
            expires_at_height,
            account_rotation_nonce,
        ),
    );
    envelope.ciphertext_hash = domain_hash(
        "WALLET-SESSION-ML-KEM-CIPHERTEXT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_id),
            HashPart::Str(wallet_network_public_key),
            HashPart::Str(node_committee_key_id),
            HashPart::Str(node_network_root),
            HashPart::Str(relay_path),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Int(account_rotation_nonce as i128),
        ],
        32,
    );
    envelope
}

#[allow(clippy::too_many_arguments)]
fn wallet_session_kem_transcript(
    account_id: &str,
    wallet_network_public_key: &str,
    node_committee_key_id: &str,
    node_network_root: &str,
    relay_path: &str,
    opened_at_height: u64,
    expires_at_height: u64,
    account_rotation_nonce: u64,
) -> Value {
    json!({
        "kind": "wallet_session_kem_transcript",
        "chain_id": CHAIN_ID,
        "account_id": account_id,
        "wallet_network_public_key": wallet_network_public_key,
        "node_committee_key_id": node_committee_key_id,
        "node_network_root": node_network_root,
        "relay_path_commitment": crate::mempool::relay_path_commitment(relay_path),
        "relay_path_policy": crate::mempool::relay_path_policy(relay_path),
        "relay_path_hop_count": crate::mempool::relay_path_hop_count(relay_path),
        "opened_at_height": opened_at_height,
        "expires_at_height": expires_at_height,
        "account_rotation_nonce": account_rotation_nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_registration_commits_public_state_without_label() {
        let mut registry = AccountRegistry::default();
        let account = registry.register_account("wallet-alpha").unwrap();

        assert_eq!(registry.accounts.len(), 1);
        assert!(registry.account_root().len() == 64);
        assert!(account.public_record().get("current_label").is_none());
        assert_eq!(
            account.state_record()["current_label"],
            Value::String("wallet-alpha".to_string())
        );
        assert!(registry.register_account("wallet-alpha").is_err());
    }

    #[test]
    fn recovery_rotation_updates_keys_and_revokes_sessions() {
        let mut registry = AccountRegistry::default();
        let account = registry.register_account("wallet-rotate").unwrap();
        let session = registry
            .open_wallet_session(
                &account.account_id,
                "wallet-rotate",
                "dandelion-stem-fluff",
                20,
            )
            .unwrap();
        let old_session_root = registry.wallet_session_root();

        let rotation = registry
            .submit_account_rotation(&account.account_id, "wallet-rotate-v2", "wallet-rotate")
            .unwrap();
        let updated = registry.accounts.get(&account.account_id).unwrap();

        assert!(rotation.verify_recovery_authorization());
        assert_eq!(updated.current_label, "wallet-rotate-v2");
        assert_eq!(updated.rotation_nonce, 1);
        assert_ne!(updated.spend_public_key, account.spend_public_key);
        assert_eq!(
            registry.wallet_sessions[&session.session_id].status,
            "revoked"
        );
        assert_ne!(registry.wallet_session_root(), old_session_root);
        assert!(registry.retired_account_labels.contains("wallet-rotate"));
        assert!(rotation.public_record().get("new_label").is_none());
        assert_eq!(
            rotation.state_record()["recovery_label"],
            Value::String("wallet-rotate".to_string())
        );
    }

    #[test]
    fn recovery_rotation_rejects_wrong_recovery_label() {
        let mut registry = AccountRegistry::default();
        let account = registry.register_account("wallet-owner").unwrap();
        let rotation =
            AccountRotation::build(&account, "wallet-owner-v2", "wrong-recovery-label").unwrap();

        assert_eq!(
            registry.verify_account_rotation(&rotation),
            Err("account rotation recovery key mismatch".to_string())
        );
    }

    #[test]
    fn wallet_sessions_hide_route_and_track_liveness() {
        let mut registry = AccountRegistry::default();
        let account = registry.register_account("wallet-session").unwrap();
        registry.set_height(7);
        let session = registry
            .open_wallet_session(
                &account.account_id,
                "wallet-session",
                "tor->mixnet->dandelion",
                2,
            )
            .unwrap();

        let public = session.public_record();
        assert!(public.get("relay_path").is_none());
        assert!(public.get("signer_label").is_none());
        assert_eq!(
            session.state_record()["relay_path"],
            Value::String("tor->mixnet->dandelion".to_string())
        );
        assert_eq!(
            registry.wallet_session_status(&session.session_id).unwrap()["status"],
            Value::String("active".to_string())
        );

        registry.set_height(10);
        assert_eq!(
            registry.wallet_session_status(&session.session_id).unwrap()["status"],
            Value::String("expired".to_string())
        );
    }

    #[test]
    fn wallet_session_reports_stale_node_network() {
        let mut registry = AccountRegistry::default();
        let account = registry.register_account("wallet-network").unwrap();
        let session = registry
            .open_wallet_session(&account.account_id, "wallet-network", "i2p-mix", 10)
            .unwrap();

        registry.set_node_network_root(domain_hash(
            "NODE-NETWORK-KEYS",
            &[HashPart::Str("new")],
            32,
        ));
        assert_eq!(
            registry.wallet_session_status(&session.session_id).unwrap()["status"],
            Value::String("stale_network".to_string())
        );
    }
}
