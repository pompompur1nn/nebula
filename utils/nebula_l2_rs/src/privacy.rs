use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{sign_authorization, verify_authorization, Authorization},
    hash::{domain_hash, merkle_root, HashPart},
    ACCOUNT_SIGNATURE_SCHEME, CHAIN_ID, DEVNET_PRIVACY_PROOF_BYTES,
};

pub type PrivacyResult<T> = Result<T, String>;

pub const PRIVACY_PROTOCOL_VERSION: u64 = 1;
pub const PRIVACY_DEFAULT_BUDGET_EPOCH_BLOCKS: u64 = 720;
pub const PRIVACY_DEFAULT_ACCOUNT_BUDGET_UNITS: u64 = 1_000_000;
pub const PRIVACY_DEFAULT_NOTE_TTL_BLOCKS: u64 = 20_160;
pub const PRIVACY_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 2_880;
pub const PRIVACY_MIN_VIEW_TAG_BITS: u16 = 16;
pub const PRIVACY_MAX_VIEW_TAG_BITS: u16 = 64;
pub const PRIVACY_AUTH_SCHEME: &str = ACCOUNT_SIGNATURE_SCHEME;
pub const PRIVACY_NOTE_PROOF_SYSTEM: &str = "devnet-mock-shielded-note-proof";
pub const PRIVACY_TRANSFER_PROOF_SYSTEM: &str = "devnet-mock-shielded-transfer-proof";
pub const PRIVACY_DISCLOSURE_PROOF_SYSTEM: &str = "devnet-mock-selective-disclosure-proof";
pub const PRIVACY_AUTH_TRANSCRIPT_PROOF_SYSTEM: &str = "devnet-ml-dsa-65-auth-transcript-root";
pub const PRIVACY_ENCRYPTED_PAYLOAD_KIND_JSON: &str = "json";
pub const PRIVACY_BUDGET_UNIT_PER_NOTE: u64 = 500;
pub const PRIVACY_BUDGET_UNIT_PER_NULLIFIER: u64 = 750;
pub const PRIVACY_BUDGET_UNIT_PER_DISCLOSURE: u64 = 250;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewingKeyPolicy {
    pub policy_id: String,
    pub account_id: String,
    pub view_key_commitment: String,
    pub disclosure_authority_commitment: String,
    pub default_scope: String,
    pub allowed_scopes: Vec<String>,
    pub view_tag_bits: u16,
    pub min_reveal_height: u64,
    pub expires_at_height: u64,
    pub audit_hint_root: String,
    pub metadata_root: String,
    pub status: String,
}

impl ViewingKeyPolicy {
    pub fn new(
        account_id: impl Into<String>,
        owner_view_key: &str,
        disclosure_authority: &str,
        default_scope: impl Into<String>,
        allowed_scopes: Vec<String>,
        view_tag_bits: u16,
        min_reveal_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivacyResult<Self> {
        let account_id = account_id.into();
        let default_scope = default_scope.into();
        if account_id.is_empty() {
            return Err("viewing key policy account_id is required".to_string());
        }
        if owner_view_key.is_empty() {
            return Err("viewing key policy owner_view_key is required".to_string());
        }
        if disclosure_authority.is_empty() {
            return Err("viewing key policy disclosure authority is required".to_string());
        }
        if default_scope.is_empty() {
            return Err("viewing key policy default scope is required".to_string());
        }
        validate_view_tag_bits(view_tag_bits)?;
        let allowed_scopes = normalize_scopes(default_scope.clone(), allowed_scopes)?;
        let audit_hint_root = privacy_metadata_root(&json!({
            "account_id": account_id,
            "default_scope": default_scope,
            "allowed_scope_root": privacy_scope_root(&allowed_scopes),
        }));
        let metadata_root = privacy_metadata_root(metadata);
        let mut policy = Self {
            policy_id: String::new(),
            account_id,
            view_key_commitment: viewing_key_commitment(owner_view_key),
            disclosure_authority_commitment: disclosure_authority_commitment(disclosure_authority),
            default_scope,
            allowed_scopes,
            view_tag_bits,
            min_reveal_height,
            expires_at_height,
            audit_hint_root,
            metadata_root,
            status: "active".to_string(),
        };
        policy.policy_id = viewing_key_policy_id(&policy.identity_record());
        policy.validate()?;
        Ok(policy)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "viewing_key_policy",
            "version": PRIVACY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "account_id": self.account_id,
            "view_key_commitment": self.view_key_commitment,
            "disclosure_authority_commitment": self.disclosure_authority_commitment,
            "default_scope": self.default_scope,
            "allowed_scope_root": privacy_scope_root(&self.allowed_scopes),
            "view_tag_bits": self.view_tag_bits,
            "min_reveal_height": self.min_reveal_height,
            "expires_at_height": self.expires_at_height,
            "audit_hint_root": self.audit_hint_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("viewing key policy public record object");
        object.insert(
            "policy_id".to_string(),
            Value::String(self.policy_id.clone()),
        );
        object.insert(
            "allowed_scopes".to_string(),
            Value::Array(
                self.allowed_scopes
                    .iter()
                    .map(|scope| Value::String(scope.clone()))
                    .collect(),
            ),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> PrivacyResult<String> {
        if self.policy_id != viewing_key_policy_id(&self.identity_record()) {
            return Err("viewing key policy id mismatch".to_string());
        }
        if self.account_id.is_empty() {
            return Err("viewing key policy account_id is required".to_string());
        }
        if self.view_key_commitment.is_empty()
            || self.disclosure_authority_commitment.is_empty()
            || self.metadata_root.is_empty()
        {
            return Err("viewing key policy commitment roots are required".to_string());
        }
        validate_view_tag_bits(self.view_tag_bits)?;
        if self.allowed_scopes.is_empty() {
            return Err("viewing key policy requires at least one scope".to_string());
        }
        if !self.allowed_scopes.contains(&self.default_scope) {
            return Err("viewing key policy default scope is not allowed".to_string());
        }
        ensure_status(&self.status, &["active", "revoked", "expired"])?;
        if self.expires_at_height != 0 && self.expires_at_height <= self.min_reveal_height {
            return Err("viewing key policy expiry must be after min reveal height".to_string());
        }
        Ok(self.policy_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedAccount {
    pub account_id: String,
    pub account_label: String,
    pub owner_commitment: String,
    pub spending_key_commitment: String,
    pub viewing_key_policy_id: String,
    pub viewing_key_policy_root: String,
    pub encrypted_payload_root: String,
    pub quantum_auth_root: String,
    pub privacy_budget_id: String,
    pub created_at_height: u64,
    pub account_nonce: u64,
    pub status: String,
    pub authorization: Authorization,
}

impl ShieldedAccount {
    pub fn build(
        account_label: impl Into<String>,
        owner_view_key: &str,
        spending_key: &str,
        viewing_key_policy: &ViewingKeyPolicy,
        encrypted_payload_root: impl Into<String>,
        quantum_auth_root: impl Into<String>,
        created_at_height: u64,
        account_nonce: u64,
    ) -> PrivacyResult<Self> {
        let account_label = account_label.into();
        if account_label.is_empty() {
            return Err("shielded account label is required".to_string());
        }
        if owner_view_key.is_empty() || spending_key.is_empty() {
            return Err("shielded account key material is required".to_string());
        }
        viewing_key_policy.validate()?;
        let owner_commitment = shielded_owner_commitment(owner_view_key);
        let spending_key_commitment = shielded_spending_key_commitment(spending_key);
        let account_id = shielded_account_id(
            &owner_commitment,
            &spending_key_commitment,
            created_at_height,
            account_nonce,
        );
        if viewing_key_policy.account_id != account_id {
            return Err("viewing key policy account mismatch".to_string());
        }
        let viewing_key_policy_root =
            viewing_key_policy_root(std::slice::from_ref(viewing_key_policy));
        let mut account = Self {
            account_id,
            account_label,
            owner_commitment,
            spending_key_commitment,
            viewing_key_policy_id: viewing_key_policy.policy_id.clone(),
            viewing_key_policy_root,
            encrypted_payload_root: encrypted_payload_root.into(),
            quantum_auth_root: quantum_auth_root.into(),
            privacy_budget_id: privacy_budget_id(
                &viewing_key_policy.view_key_commitment,
                0,
                0,
                PRIVACY_DEFAULT_BUDGET_EPOCH_BLOCKS,
                PRIVACY_DEFAULT_ACCOUNT_BUDGET_UNITS,
            ),
            created_at_height,
            account_nonce,
            status: "active".to_string(),
            authorization: empty_authorization(),
        };
        account.authorization = sign_authorization(
            &account.account_label,
            "shielded_account_register",
            &account.unsigned_record(),
        );
        account.validate(viewing_key_policy)?;
        Ok(account)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "shielded_account",
            "version": PRIVACY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "account_id": self.account_id,
            "owner_commitment": self.owner_commitment,
            "spending_key_commitment": self.spending_key_commitment,
            "viewing_key_policy_id": self.viewing_key_policy_id,
            "viewing_key_policy_root": self.viewing_key_policy_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "quantum_auth_root": self.quantum_auth_root,
            "privacy_budget_id": self.privacy_budget_id,
            "created_at_height": self.created_at_height,
            "account_nonce": self.account_nonce,
            "status": self.status,
        })
    }

    pub fn unsigned_record(&self) -> Value {
        self.identity_record()
    }

    pub fn public_record(&self) -> Value {
        with_authorization(self.unsigned_record(), &self.authorization, false)
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("shielded account state record object")
            .insert(
                "account_label".to_string(),
                Value::String(self.account_label.clone()),
            );
        record
    }

    pub fn validate(&self, viewing_key_policy: &ViewingKeyPolicy) -> PrivacyResult<String> {
        if self.account_id
            != shielded_account_id(
                &self.owner_commitment,
                &self.spending_key_commitment,
                self.created_at_height,
                self.account_nonce,
            )
        {
            return Err("shielded account id mismatch".to_string());
        }
        if viewing_key_policy.policy_id != self.viewing_key_policy_id {
            return Err("shielded account viewing key policy id mismatch".to_string());
        }
        if viewing_key_policy.account_id != self.account_id {
            return Err("shielded account viewing key policy account mismatch".to_string());
        }
        if self.viewing_key_policy_root
            != viewing_key_policy_root(std::slice::from_ref(viewing_key_policy))
        {
            return Err("shielded account viewing key policy root mismatch".to_string());
        }
        ensure_status(&self.status, &["active", "frozen", "closed"])?;
        if !verify_authorization(
            &self.account_label,
            "shielded_account_register",
            &self.unsigned_record(),
            &self.authorization,
        ) {
            return Err("invalid shielded account authorization".to_string());
        }
        Ok(self.account_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPayloadRecord {
    pub payload_id: String,
    pub payload_kind: String,
    pub payload_hash: String,
    pub recipient_key_root: String,
    pub disclosure_policy_root: String,
    pub kem_ciphertext_hash: String,
    pub payload_nonce: u64,
    pub payload_size_bytes: u64,
    pub created_at_height: u64,
    pub retention_policy: String,
    pub encrypted_payload: Value,
}

impl EncryptedPayloadRecord {
    pub fn new(
        payload_kind: impl Into<String>,
        recipient_key_root: impl Into<String>,
        disclosure_policy_root: impl Into<String>,
        payload_nonce: u64,
        created_at_height: u64,
        retention_policy: impl Into<String>,
        encrypted_payload: Value,
    ) -> PrivacyResult<Self> {
        let payload_kind = payload_kind.into();
        if payload_kind.is_empty() {
            return Err("encrypted payload kind is required".to_string());
        }
        let recipient_key_root = recipient_key_root.into();
        if recipient_key_root.is_empty() {
            return Err("encrypted payload recipient key root is required".to_string());
        }
        let disclosure_policy_root = disclosure_policy_root.into();
        if disclosure_policy_root.is_empty() {
            return Err("encrypted payload disclosure policy root is required".to_string());
        }
        let retention_policy = retention_policy.into();
        if retention_policy.is_empty() {
            return Err("encrypted payload retention policy is required".to_string());
        }
        let payload_hash = encrypted_payload_hash(&payload_kind, &encrypted_payload);
        let payload_size_bytes = serde_json::to_string(&encrypted_payload)
            .map_err(|err| format!("encrypted payload serialization failed: {err}"))?
            .len() as u64;
        let kem_ciphertext_hash = encrypted_payload_kem_ciphertext_hash(
            &recipient_key_root,
            &payload_hash,
            &disclosure_policy_root,
            payload_nonce,
        );
        let mut record = Self {
            payload_id: String::new(),
            payload_kind,
            payload_hash,
            recipient_key_root,
            disclosure_policy_root,
            kem_ciphertext_hash,
            payload_nonce,
            payload_size_bytes,
            created_at_height,
            retention_policy,
            encrypted_payload,
        };
        record.payload_id = encrypted_payload_id(&record.identity_record());
        record.validate()?;
        Ok(record)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "encrypted_payload",
            "version": PRIVACY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "payload_kind": self.payload_kind,
            "payload_hash": self.payload_hash,
            "recipient_key_root": self.recipient_key_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "kem_ciphertext_hash": self.kem_ciphertext_hash,
            "payload_nonce": self.payload_nonce,
            "payload_size_bytes": self.payload_size_bytes,
            "created_at_height": self.created_at_height,
            "retention_policy": self.retention_policy,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("encrypted payload public record object")
            .insert(
                "payload_id".to_string(),
                Value::String(self.payload_id.clone()),
            );
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("encrypted payload state record object")
            .insert(
                "encrypted_payload".to_string(),
                self.encrypted_payload.clone(),
            );
        record
    }

    pub fn validate(&self) -> PrivacyResult<String> {
        if self.payload_id != encrypted_payload_id(&self.identity_record()) {
            return Err("encrypted payload id mismatch".to_string());
        }
        if self.payload_hash != encrypted_payload_hash(&self.payload_kind, &self.encrypted_payload)
        {
            return Err("encrypted payload hash mismatch".to_string());
        }
        let expected_kem = encrypted_payload_kem_ciphertext_hash(
            &self.recipient_key_root,
            &self.payload_hash,
            &self.disclosure_policy_root,
            self.payload_nonce,
        );
        if self.kem_ciphertext_hash != expected_kem {
            return Err("encrypted payload KEM ciphertext mismatch".to_string());
        }
        if self.payload_size_bytes == 0 {
            return Err("encrypted payload size must be positive".to_string());
        }
        Ok(self.payload_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteCommitment {
    pub note_id: String,
    pub account_id: String,
    pub owner_view_key: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub asset_commitment: String,
    pub amount: u64,
    pub blinding: String,
    pub amount_commitment: String,
    pub commitment: String,
    pub encrypted_payload_id: String,
    pub encrypted_payload_hash: String,
    pub view_tag: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub note_nonce: u64,
    pub status: String,
    pub proof_system: String,
    pub proof_root: String,
}

impl NoteCommitment {
    pub fn create(
        account_id: impl Into<String>,
        owner_view_key: &str,
        asset_id: &str,
        amount: u64,
        note_nonce: u64,
        created_at_height: u64,
        expires_at_height: u64,
        encrypted_payload: &EncryptedPayloadRecord,
        view_tag_bits: u16,
    ) -> PrivacyResult<Self> {
        let account_id = account_id.into();
        if account_id.is_empty() {
            return Err("note account_id is required".to_string());
        }
        if owner_view_key.is_empty() {
            return Err("note owner_view_key is required".to_string());
        }
        if asset_id.is_empty() {
            return Err("note asset_id is required".to_string());
        }
        if amount == 0 {
            return Err("note amount must be positive".to_string());
        }
        validate_view_tag_bits(view_tag_bits)?;
        encrypted_payload.validate()?;
        if expires_at_height != 0 && expires_at_height <= created_at_height {
            return Err("note expiry must be after creation height".to_string());
        }
        let owner_commitment = shielded_owner_commitment(owner_view_key);
        let asset_commitment = privacy_asset_commitment(asset_id);
        let blinding = note_blinding(&account_id, owner_view_key, asset_id, amount, note_nonce);
        let amount_commitment = privacy_amount_commitment(amount, &blinding);
        let commitment = privacy_note_commitment(
            &account_id,
            &owner_commitment,
            &asset_commitment,
            &amount_commitment,
            &encrypted_payload.payload_hash,
            created_at_height,
            note_nonce,
        );
        let note_id = note_commitment_id(&commitment, created_at_height, note_nonce);
        let view_tag = privacy_view_tag(owner_view_key, &commitment, view_tag_bits);
        let proof_system = PRIVACY_NOTE_PROOF_SYSTEM.to_string();
        let proof_root = privacy_proof_root(
            &proof_system,
            &json!({
                "account_id": account_id,
                "owner_commitment": owner_commitment,
                "asset_commitment": asset_commitment,
                "amount_commitment": amount_commitment,
                "commitment": commitment,
                "encrypted_payload_hash": encrypted_payload.payload_hash,
                "view_tag": view_tag,
            }),
            &json!({
                "owner_view_key": owner_view_key,
                "asset_id": asset_id,
                "amount": amount,
                "blinding": blinding,
            }),
        );
        let note = Self {
            note_id,
            account_id,
            owner_view_key: owner_view_key.to_string(),
            owner_commitment,
            asset_id: asset_id.to_string(),
            asset_commitment,
            amount,
            blinding,
            amount_commitment,
            commitment,
            encrypted_payload_id: encrypted_payload.payload_id.clone(),
            encrypted_payload_hash: encrypted_payload.payload_hash.clone(),
            view_tag,
            created_at_height,
            expires_at_height,
            note_nonce,
            status: "unspent".to_string(),
            proof_system,
            proof_root,
        };
        note.validate()?;
        Ok(note)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "note_commitment",
            "version": PRIVACY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "note_id": self.note_id,
            "account_id": self.account_id,
            "owner_commitment": self.owner_commitment,
            "asset_commitment": self.asset_commitment,
            "amount_commitment": self.amount_commitment,
            "commitment": self.commitment,
            "encrypted_payload_id": self.encrypted_payload_id,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "view_tag": self.view_tag,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "note_nonce": self.note_nonce,
            "status": self.status,
            "proof_system": self.proof_system,
            "proof_root": self.proof_root,
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record
            .as_object_mut()
            .expect("note commitment state record object");
        object.insert(
            "owner_view_key".to_string(),
            Value::String(self.owner_view_key.clone()),
        );
        object.insert("asset_id".to_string(), Value::String(self.asset_id.clone()));
        object.insert("amount".to_string(), json!(self.amount));
        object.insert("blinding".to_string(), Value::String(self.blinding.clone()));
        record
    }

    pub fn validate(&self) -> PrivacyResult<String> {
        if self.note_id
            != note_commitment_id(&self.commitment, self.created_at_height, self.note_nonce)
        {
            return Err("note commitment id mismatch".to_string());
        }
        if self.owner_commitment != shielded_owner_commitment(&self.owner_view_key) {
            return Err("note owner commitment mismatch".to_string());
        }
        if self.asset_commitment != privacy_asset_commitment(&self.asset_id) {
            return Err("note asset commitment mismatch".to_string());
        }
        let expected_blinding = note_blinding(
            &self.account_id,
            &self.owner_view_key,
            &self.asset_id,
            self.amount,
            self.note_nonce,
        );
        if self.blinding != expected_blinding {
            return Err("note blinding mismatch".to_string());
        }
        if self.amount == 0 {
            return Err("note amount must be positive".to_string());
        }
        if self.amount_commitment != privacy_amount_commitment(self.amount, &self.blinding) {
            return Err("note amount commitment mismatch".to_string());
        }
        let expected_commitment = privacy_note_commitment(
            &self.account_id,
            &self.owner_commitment,
            &self.asset_commitment,
            &self.amount_commitment,
            &self.encrypted_payload_hash,
            self.created_at_height,
            self.note_nonce,
        );
        if self.commitment != expected_commitment {
            return Err("note commitment mismatch".to_string());
        }
        if self.view_tag.is_empty() {
            return Err("note view tag is required".to_string());
        }
        ensure_status(&self.status, &["unspent", "spent", "expired"])?;
        if self.expires_at_height != 0 && self.expires_at_height <= self.created_at_height {
            return Err("note expiry must be after creation height".to_string());
        }
        let expected_proof = privacy_proof_root(
            &self.proof_system,
            &json!({
                "account_id": self.account_id,
                "owner_commitment": self.owner_commitment,
                "asset_commitment": self.asset_commitment,
                "amount_commitment": self.amount_commitment,
                "commitment": self.commitment,
                "encrypted_payload_hash": self.encrypted_payload_hash,
                "view_tag": self.view_tag,
            }),
            &json!({
                "owner_view_key": self.owner_view_key,
                "asset_id": self.asset_id,
                "amount": self.amount,
                "blinding": self.blinding,
            }),
        );
        if self.proof_root != expected_proof {
            return Err("note proof root mismatch".to_string());
        }
        Ok(self.note_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierRecord {
    pub nullifier: String,
    pub note_id: String,
    pub note_commitment: String,
    pub account_id: String,
    pub spend_context_root: String,
    pub action_kind: String,
    pub spent_at_height: u64,
    pub quantum_auth_root: String,
    pub proof_system: String,
    pub proof_root: String,
    pub status: String,
}

impl NullifierRecord {
    pub fn for_note(
        note: &NoteCommitment,
        spend_context: &Value,
        action_kind: impl Into<String>,
        spent_at_height: u64,
        quantum_auth_root: impl Into<String>,
    ) -> PrivacyResult<Self> {
        note.validate()?;
        let action_kind = action_kind.into();
        if action_kind.is_empty() {
            return Err("nullifier action kind is required".to_string());
        }
        let spend_context_root = privacy_metadata_root(spend_context);
        let nullifier = privacy_nullifier(note, &spend_context_root);
        let quantum_auth_root = quantum_auth_root.into();
        let proof_system = PRIVACY_TRANSFER_PROOF_SYSTEM.to_string();
        let proof_root = privacy_proof_root(
            &proof_system,
            &json!({
                "nullifier": nullifier,
                "note_id": note.note_id,
                "note_commitment": note.commitment,
                "account_id": note.account_id,
                "spend_context_root": spend_context_root,
                "action_kind": action_kind,
                "quantum_auth_root": quantum_auth_root,
            }),
            &json!({
                "owner_view_key": note.owner_view_key,
                "blinding": note.blinding,
                "amount": note.amount,
            }),
        );
        let record = Self {
            nullifier,
            note_id: note.note_id.clone(),
            note_commitment: note.commitment.clone(),
            account_id: note.account_id.clone(),
            spend_context_root,
            action_kind,
            spent_at_height,
            quantum_auth_root,
            proof_system,
            proof_root,
            status: "spent".to_string(),
        };
        record.validate_against_note(note)?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "nullifier",
            "version": PRIVACY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "nullifier": self.nullifier,
            "note_id": self.note_id,
            "note_commitment": self.note_commitment,
            "account_id": self.account_id,
            "spend_context_root": self.spend_context_root,
            "action_kind": self.action_kind,
            "spent_at_height": self.spent_at_height,
            "quantum_auth_root": self.quantum_auth_root,
            "proof_system": self.proof_system,
            "proof_root": self.proof_root,
            "status": self.status,
        })
    }

    pub fn validate_against_note(&self, note: &NoteCommitment) -> PrivacyResult<String> {
        if self.note_id != note.note_id
            || self.note_commitment != note.commitment
            || self.account_id != note.account_id
        {
            return Err("nullifier note reference mismatch".to_string());
        }
        let expected_nullifier = privacy_nullifier(note, &self.spend_context_root);
        if self.nullifier != expected_nullifier {
            return Err("nullifier mismatch".to_string());
        }
        ensure_status(&self.status, &["spent", "pending"])?;
        if self.action_kind.is_empty() {
            return Err("nullifier action kind is required".to_string());
        }
        let expected_proof = privacy_proof_root(
            &self.proof_system,
            &json!({
                "nullifier": self.nullifier,
                "note_id": self.note_id,
                "note_commitment": self.note_commitment,
                "account_id": self.account_id,
                "spend_context_root": self.spend_context_root,
                "action_kind": self.action_kind,
                "quantum_auth_root": self.quantum_auth_root,
            }),
            &json!({
                "owner_view_key": note.owner_view_key,
                "blinding": note.blinding,
                "amount": note.amount,
            }),
        );
        if self.proof_root != expected_proof {
            return Err("nullifier proof root mismatch".to_string());
        }
        Ok(self.nullifier.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetAccount {
    pub budget_id: String,
    pub subject_commitment: String,
    pub epoch: u64,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub budget_units: u64,
    pub spent_units: u64,
    pub reserved_units: u64,
    pub status: String,
}

impl PrivacyBudgetAccount {
    pub fn new(
        subject_commitment: impl Into<String>,
        epoch: u64,
        epoch_start_height: u64,
        epoch_end_height: u64,
        budget_units: u64,
    ) -> PrivacyResult<Self> {
        let subject_commitment = subject_commitment.into();
        if subject_commitment.is_empty() {
            return Err("privacy budget subject commitment is required".to_string());
        }
        if epoch_end_height <= epoch_start_height {
            return Err("privacy budget epoch end must be after start".to_string());
        }
        if budget_units == 0 {
            return Err("privacy budget units must be positive".to_string());
        }
        let budget_id = privacy_budget_id(
            &subject_commitment,
            epoch,
            epoch_start_height,
            epoch_end_height,
            budget_units,
        );
        Ok(Self {
            budget_id,
            subject_commitment,
            epoch,
            epoch_start_height,
            epoch_end_height,
            budget_units,
            spent_units: 0,
            reserved_units: 0,
            status: "active".to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_budget_account",
            "version": PRIVACY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "budget_id": self.budget_id,
            "subject_commitment": self.subject_commitment,
            "epoch": self.epoch,
            "epoch_start_height": self.epoch_start_height,
            "epoch_end_height": self.epoch_end_height,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "reserved_units": self.reserved_units,
            "available_units": self.available_units(),
            "status": self.status,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.spent_units)
            .saturating_sub(self.reserved_units)
    }

    pub fn validate(&self) -> PrivacyResult<String> {
        if self.budget_id
            != privacy_budget_id(
                &self.subject_commitment,
                self.epoch,
                self.epoch_start_height,
                self.epoch_end_height,
                self.budget_units,
            )
        {
            return Err("privacy budget id mismatch".to_string());
        }
        if self.spent_units.saturating_add(self.reserved_units) > self.budget_units {
            return Err("privacy budget is overspent".to_string());
        }
        ensure_status(&self.status, &["active", "closed", "exhausted"])?;
        Ok(self.budget_id.clone())
    }

    fn apply_charge(&mut self, charge: &PrivacyBudgetCharge) -> PrivacyResult<String> {
        self.validate()?;
        charge.validate()?;
        if charge.status != "pending" {
            return Err("privacy budget charge must be pending".to_string());
        }
        if self.budget_id != charge.budget_id {
            return Err("privacy budget charge budget mismatch".to_string());
        }
        if self.subject_commitment != charge.subject_commitment {
            return Err("privacy budget charge subject mismatch".to_string());
        }
        if charge.charged_at_height < self.epoch_start_height
            || charge.charged_at_height > self.epoch_end_height
        {
            return Err("privacy budget charge outside epoch".to_string());
        }
        if self.available_units() < charge.units {
            return Err("privacy budget has insufficient available units".to_string());
        }
        self.spent_units = self
            .spent_units
            .checked_add(charge.units)
            .ok_or_else(|| "privacy budget spent units overflow".to_string())?;
        if self.available_units() == 0 {
            self.status = "exhausted".to_string();
        }
        Ok(self.budget_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetCharge {
    pub charge_id: String,
    pub budget_id: String,
    pub subject_commitment: String,
    pub charge_kind: String,
    pub units: u64,
    pub proof_bytes: u64,
    pub note_count: u64,
    pub nullifier_count: u64,
    pub disclosure_count: u64,
    pub tx_root: String,
    pub charged_at_height: u64,
    pub status: String,
}

impl PrivacyBudgetCharge {
    pub fn new(
        budget_id: impl Into<String>,
        subject_commitment: impl Into<String>,
        charge_kind: impl Into<String>,
        note_count: u64,
        nullifier_count: u64,
        disclosure_count: u64,
        tx_root: impl Into<String>,
        charged_at_height: u64,
    ) -> PrivacyResult<Self> {
        let budget_id = budget_id.into();
        let subject_commitment = subject_commitment.into();
        let charge_kind = charge_kind.into();
        let tx_root = tx_root.into();
        if budget_id.is_empty() {
            return Err("privacy budget charge budget_id is required".to_string());
        }
        if subject_commitment.is_empty() {
            return Err("privacy budget charge subject commitment is required".to_string());
        }
        if charge_kind.is_empty() {
            return Err("privacy budget charge kind is required".to_string());
        }
        if tx_root.is_empty() {
            return Err("privacy budget charge tx root is required".to_string());
        }
        let units = privacy_budget_units(note_count, nullifier_count, disclosure_count);
        let proof_bytes = privacy_proof_bytes(note_count, nullifier_count, disclosure_count);
        let mut charge = Self {
            charge_id: String::new(),
            budget_id,
            subject_commitment,
            charge_kind,
            units,
            proof_bytes,
            note_count,
            nullifier_count,
            disclosure_count,
            tx_root,
            charged_at_height,
            status: "pending".to_string(),
        };
        charge.charge_id = privacy_budget_charge_id(&charge.identity_record());
        charge.validate()?;
        Ok(charge)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "privacy_budget_charge",
            "version": PRIVACY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "budget_id": self.budget_id,
            "subject_commitment": self.subject_commitment,
            "charge_kind": self.charge_kind,
            "units": self.units,
            "proof_bytes": self.proof_bytes,
            "note_count": self.note_count,
            "nullifier_count": self.nullifier_count,
            "disclosure_count": self.disclosure_count,
            "tx_root": self.tx_root,
            "charged_at_height": self.charged_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("privacy budget charge public record object");
        object.insert(
            "charge_id".to_string(),
            Value::String(self.charge_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> PrivacyResult<String> {
        if self.charge_id != privacy_budget_charge_id(&self.identity_record()) {
            return Err("privacy budget charge id mismatch".to_string());
        }
        if self.units
            != privacy_budget_units(self.note_count, self.nullifier_count, self.disclosure_count)
        {
            return Err("privacy budget charge units mismatch".to_string());
        }
        if self.proof_bytes
            != privacy_proof_bytes(self.note_count, self.nullifier_count, self.disclosure_count)
        {
            return Err("privacy budget charge proof bytes mismatch".to_string());
        }
        if self.units == 0 {
            return Err("privacy budget charge units must be positive".to_string());
        }
        ensure_status(&self.status, &["pending", "applied", "rejected"])?;
        Ok(self.charge_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumSafeAuthorizationTranscript {
    pub transcript_id: String,
    pub authorization_domain: String,
    pub subject_id: String,
    pub payload_root: String,
    pub signer_commitment: String,
    pub created_at_height: u64,
    pub proof_system: String,
    pub authorization: Authorization,
    pub status: String,
}

impl QuantumSafeAuthorizationTranscript {
    pub fn build(
        signer_label: impl Into<String>,
        authorization_domain: impl Into<String>,
        subject_id: impl Into<String>,
        payload: &Value,
        created_at_height: u64,
    ) -> PrivacyResult<Self> {
        let signer_label = signer_label.into();
        let authorization_domain = authorization_domain.into();
        let subject_id = subject_id.into();
        if signer_label.is_empty() {
            return Err("authorization transcript signer label is required".to_string());
        }
        if authorization_domain.is_empty() || subject_id.is_empty() {
            return Err("authorization transcript domain and subject are required".to_string());
        }
        let payload_root = privacy_metadata_root(payload);
        let signer_commitment = privacy_signer_commitment(&signer_label);
        let mut transcript = Self {
            transcript_id: String::new(),
            authorization_domain,
            subject_id,
            payload_root,
            signer_commitment,
            created_at_height,
            proof_system: PRIVACY_AUTH_TRANSCRIPT_PROOF_SYSTEM.to_string(),
            authorization: empty_authorization(),
            status: "active".to_string(),
        };
        transcript.transcript_id = quantum_auth_transcript_id(&transcript.identity_record());
        transcript.authorization = sign_authorization(
            &signer_label,
            "privacy_quantum_auth_transcript",
            &transcript.signing_record(),
        );
        transcript.validate()?;
        Ok(transcript)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "quantum_safe_authorization_transcript",
            "version": PRIVACY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "authorization_domain": self.authorization_domain,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "signer_commitment": self.signer_commitment,
            "created_at_height": self.created_at_height,
            "proof_system": self.proof_system,
        })
    }

    pub fn signing_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("authorization transcript signing record object")
            .insert(
                "transcript_id".to_string(),
                Value::String(self.transcript_id.clone()),
            );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.signing_record();
        let object = record
            .as_object_mut()
            .expect("authorization transcript public record object");
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        object.insert(
            "authorization_root".to_string(),
            Value::String(privacy_authorization_root(&self.authorization)),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("authorization transcript state record object")
            .insert(
                "signer_label".to_string(),
                Value::String(self.authorization.signer_label.clone()),
            );
        record
    }

    pub fn validate(&self) -> PrivacyResult<String> {
        if self.transcript_id != quantum_auth_transcript_id(&self.identity_record()) {
            return Err("authorization transcript id mismatch".to_string());
        }
        if self.signer_commitment != privacy_signer_commitment(&self.authorization.signer_label) {
            return Err("authorization transcript signer commitment mismatch".to_string());
        }
        if !verify_authorization(
            &self.authorization.signer_label,
            "privacy_quantum_auth_transcript",
            &self.signing_record(),
            &self.authorization,
        ) {
            return Err("invalid authorization transcript signature".to_string());
        }
        ensure_status(&self.status, &["active", "revoked", "expired"])?;
        Ok(self.transcript_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveDisclosureReceipt {
    pub receipt_id: String,
    pub account_id: String,
    pub note_id: String,
    pub note_commitment: String,
    pub viewing_key_policy_id: String,
    pub recipient_commitment: String,
    pub disclosed_fields: Vec<String>,
    pub disclosure_root: String,
    pub revealed_record_root: String,
    pub statement_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub proof_system: String,
    pub proof_root: String,
    pub authorization: Authorization,
    pub status: String,
}

impl SelectiveDisclosureReceipt {
    pub fn build(
        note: &NoteCommitment,
        viewing_key_policy_id: impl Into<String>,
        recipient: &str,
        disclosed_fields: Vec<String>,
        revealed_record: &Value,
        issuer_label: impl Into<String>,
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> PrivacyResult<Self> {
        note.validate()?;
        let viewing_key_policy_id = viewing_key_policy_id.into();
        let issuer_label = issuer_label.into();
        if viewing_key_policy_id.is_empty() {
            return Err("selective disclosure viewing key policy id is required".to_string());
        }
        if recipient.is_empty() {
            return Err("selective disclosure recipient is required".to_string());
        }
        if issuer_label.is_empty() {
            return Err("selective disclosure issuer label is required".to_string());
        }
        let disclosed_fields = normalize_field_names(disclosed_fields)?;
        if expires_at_height <= issued_at_height {
            return Err("selective disclosure expiry must be after issue height".to_string());
        }
        let disclosure_root = privacy_scope_root(&disclosed_fields);
        let revealed_record_root = privacy_metadata_root(revealed_record);
        let statement_root = selective_disclosure_statement_root(
            &note.note_id,
            &note.commitment,
            &disclosure_root,
            &revealed_record_root,
        );
        let proof_system = PRIVACY_DISCLOSURE_PROOF_SYSTEM.to_string();
        let proof_root = privacy_proof_root(
            &proof_system,
            &json!({
                "account_id": note.account_id,
                "note_id": note.note_id,
                "note_commitment": note.commitment,
                "viewing_key_policy_id": viewing_key_policy_id,
                "recipient_commitment": privacy_recipient_commitment(recipient),
                "disclosure_root": disclosure_root,
                "revealed_record_root": revealed_record_root,
                "statement_root": statement_root,
            }),
            &json!({
                "owner_view_key": note.owner_view_key,
                "asset_id": note.asset_id,
                "amount": note.amount,
                "fields": disclosed_fields,
            }),
        );
        let mut receipt = Self {
            receipt_id: String::new(),
            account_id: note.account_id.clone(),
            note_id: note.note_id.clone(),
            note_commitment: note.commitment.clone(),
            viewing_key_policy_id,
            recipient_commitment: privacy_recipient_commitment(recipient),
            disclosed_fields,
            disclosure_root,
            revealed_record_root,
            statement_root,
            issued_at_height,
            expires_at_height,
            proof_system,
            proof_root,
            authorization: empty_authorization(),
            status: "issued".to_string(),
        };
        receipt.receipt_id = selective_disclosure_receipt_id(&receipt.identity_record());
        receipt.authorization = sign_authorization(
            &issuer_label,
            "selective_disclosure_receipt",
            &receipt.unsigned_record(),
        );
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "selective_disclosure_receipt",
            "version": PRIVACY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "account_id": self.account_id,
            "note_id": self.note_id,
            "note_commitment": self.note_commitment,
            "viewing_key_policy_id": self.viewing_key_policy_id,
            "recipient_commitment": self.recipient_commitment,
            "disclosure_root": self.disclosure_root,
            "revealed_record_root": self.revealed_record_root,
            "statement_root": self.statement_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "proof_system": self.proof_system,
            "proof_root": self.proof_root,
        })
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("selective disclosure unsigned record object");
        object.insert(
            "receipt_id".to_string(),
            Value::String(self.receipt_id.clone()),
        );
        object.insert(
            "disclosed_fields".to_string(),
            Value::Array(
                self.disclosed_fields
                    .iter()
                    .map(|field| Value::String(field.clone()))
                    .collect(),
            ),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = with_authorization(self.unsigned_record(), &self.authorization, false);
        record
            .as_object_mut()
            .expect("selective disclosure public record object")
            .insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn state_record(&self) -> Value {
        with_authorization(self.public_record(), &self.authorization, true)
    }

    pub fn validate(&self) -> PrivacyResult<String> {
        if self.receipt_id != selective_disclosure_receipt_id(&self.identity_record()) {
            return Err("selective disclosure receipt id mismatch".to_string());
        }
        if self.disclosed_fields.is_empty() {
            return Err("selective disclosure fields are required".to_string());
        }
        if self.disclosure_root != privacy_scope_root(&self.disclosed_fields) {
            return Err("selective disclosure field root mismatch".to_string());
        }
        if self.statement_root
            != selective_disclosure_statement_root(
                &self.note_id,
                &self.note_commitment,
                &self.disclosure_root,
                &self.revealed_record_root,
            )
        {
            return Err("selective disclosure statement root mismatch".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("selective disclosure expiry must be after issue height".to_string());
        }
        ensure_status(&self.status, &["issued", "revoked", "expired"])?;
        if !verify_authorization(
            &self.authorization.signer_label,
            "selective_disclosure_receipt",
            &self.unsigned_record(),
            &self.authorization,
        ) {
            return Err("invalid selective disclosure authorization".to_string());
        }
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedTransfer {
    pub transfer_id: String,
    pub account_id: String,
    pub action_kind: String,
    pub anchor_root: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub nullifier_root: String,
    pub encrypted_payload_root: String,
    pub disclosure_receipt_root: String,
    pub quantum_auth_root: String,
    pub budget_charge: PrivacyBudgetCharge,
    pub fee_asset_commitment: String,
    pub fee_amount_commitment: String,
    pub created_at_height: u64,
    pub proof_system: String,
    pub proof_root: String,
    pub input_nullifiers: Vec<NullifierRecord>,
    pub output_notes: Vec<NoteCommitment>,
    pub encrypted_payloads: Vec<EncryptedPayloadRecord>,
    pub disclosure_receipts: Vec<SelectiveDisclosureReceipt>,
    pub auth_transcript: QuantumSafeAuthorizationTranscript,
}

impl ShieldedTransfer {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        account_id: impl Into<String>,
        action_kind: impl Into<String>,
        anchor_root: impl Into<String>,
        input_nullifiers: Vec<NullifierRecord>,
        output_notes: Vec<NoteCommitment>,
        encrypted_payloads: Vec<EncryptedPayloadRecord>,
        disclosure_receipts: Vec<SelectiveDisclosureReceipt>,
        auth_transcript: QuantumSafeAuthorizationTranscript,
        budget_charge: PrivacyBudgetCharge,
        fee_asset_commitment: impl Into<String>,
        fee_amount_commitment: impl Into<String>,
        created_at_height: u64,
    ) -> PrivacyResult<Self> {
        let account_id = account_id.into();
        let action_kind = action_kind.into();
        let anchor_root = anchor_root.into();
        if account_id.is_empty() {
            return Err("shielded transfer account_id is required".to_string());
        }
        if action_kind.is_empty() {
            return Err("shielded transfer action kind is required".to_string());
        }
        if anchor_root.is_empty() {
            return Err("shielded transfer anchor root is required".to_string());
        }
        auth_transcript.validate()?;
        let input_note_root = nullifier_input_note_root(&input_nullifiers);
        let output_note_root = note_commitment_root(&output_notes);
        let nullifier_root = privacy_nullifier_root(&input_nullifiers);
        let encrypted_payload_root = encrypted_payload_root(&encrypted_payloads);
        let disclosure_receipt_root = selective_disclosure_receipt_root(&disclosure_receipts);
        let quantum_auth_root =
            quantum_auth_transcript_root(std::slice::from_ref(&auth_transcript));
        let mut transfer = Self {
            transfer_id: String::new(),
            account_id,
            action_kind,
            anchor_root,
            input_note_root,
            output_note_root,
            nullifier_root,
            encrypted_payload_root,
            disclosure_receipt_root,
            quantum_auth_root,
            budget_charge,
            fee_asset_commitment: fee_asset_commitment.into(),
            fee_amount_commitment: fee_amount_commitment.into(),
            created_at_height,
            proof_system: PRIVACY_TRANSFER_PROOF_SYSTEM.to_string(),
            proof_root: String::new(),
            input_nullifiers,
            output_notes,
            encrypted_payloads,
            disclosure_receipts,
            auth_transcript,
        };
        transfer.transfer_id = shielded_transfer_id(&transfer.identity_record());
        transfer.proof_root = privacy_proof_root(
            &transfer.proof_system,
            &transfer.identity_record(),
            &transfer.witness_record(),
        );
        transfer.validate_basic()?;
        Ok(transfer)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "shielded_transfer",
            "version": PRIVACY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "account_id": self.account_id,
            "action_kind": self.action_kind,
            "anchor_root": self.anchor_root,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "nullifier_root": self.nullifier_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "disclosure_receipt_root": self.disclosure_receipt_root,
            "quantum_auth_root": self.quantum_auth_root,
            "budget_charge_id": self.budget_charge.charge_id,
            "fee_asset_commitment": self.fee_asset_commitment,
            "fee_amount_commitment": self.fee_amount_commitment,
            "created_at_height": self.created_at_height,
            "proof_system": self.proof_system,
        })
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("shielded transfer unsigned record object");
        object.insert(
            "transfer_id".to_string(),
            Value::String(self.transfer_id.clone()),
        );
        object.insert(
            "proof_root".to_string(),
            Value::String(self.proof_root.clone()),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("shielded transfer public record object");
        object.insert(
            "input_nullifier_count".to_string(),
            json!(self.input_nullifiers.len() as u64),
        );
        object.insert(
            "output_note_count".to_string(),
            json!(self.output_notes.len() as u64),
        );
        object.insert(
            "encrypted_payload_count".to_string(),
            json!(self.encrypted_payloads.len() as u64),
        );
        object.insert(
            "disclosure_receipt_count".to_string(),
            json!(self.disclosure_receipts.len() as u64),
        );
        object.insert(
            "budget_charge".to_string(),
            self.budget_charge.public_record(),
        );
        object.insert(
            "auth_transcript".to_string(),
            self.auth_transcript.public_record(),
        );
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record
            .as_object_mut()
            .expect("shielded transfer state record object");
        object.insert(
            "input_nullifiers".to_string(),
            Value::Array(
                self.input_nullifiers
                    .iter()
                    .map(NullifierRecord::public_record)
                    .collect(),
            ),
        );
        object.insert(
            "output_notes".to_string(),
            Value::Array(
                self.output_notes
                    .iter()
                    .map(NoteCommitment::state_record)
                    .collect(),
            ),
        );
        object.insert(
            "encrypted_payloads".to_string(),
            Value::Array(
                self.encrypted_payloads
                    .iter()
                    .map(EncryptedPayloadRecord::state_record)
                    .collect(),
            ),
        );
        object.insert(
            "disclosure_receipts".to_string(),
            Value::Array(
                self.disclosure_receipts
                    .iter()
                    .map(SelectiveDisclosureReceipt::state_record)
                    .collect(),
            ),
        );
        record
    }

    pub fn auth_payload_record(&self) -> Value {
        shielded_transfer_auth_payload(
            &self.account_id,
            &self.action_kind,
            &self.anchor_root,
            &self.input_note_root,
            &self.output_note_root,
            &self.nullifier_root,
            &self.encrypted_payload_root,
            &self.disclosure_receipt_root,
            &self.budget_charge.charge_id,
            &self.fee_asset_commitment,
            &self.fee_amount_commitment,
            self.created_at_height,
        )
    }

    pub fn validate_basic(&self) -> PrivacyResult<String> {
        if self.transfer_id != shielded_transfer_id(&self.identity_record()) {
            return Err("shielded transfer id mismatch".to_string());
        }
        if self.input_note_root != nullifier_input_note_root(&self.input_nullifiers) {
            return Err("shielded transfer input note root mismatch".to_string());
        }
        if self.output_note_root != note_commitment_root(&self.output_notes) {
            return Err("shielded transfer output note root mismatch".to_string());
        }
        if self.nullifier_root != privacy_nullifier_root(&self.input_nullifiers) {
            return Err("shielded transfer nullifier root mismatch".to_string());
        }
        if self.encrypted_payload_root != encrypted_payload_root(&self.encrypted_payloads) {
            return Err("shielded transfer encrypted payload root mismatch".to_string());
        }
        if self.disclosure_receipt_root
            != selective_disclosure_receipt_root(&self.disclosure_receipts)
        {
            return Err("shielded transfer disclosure receipt root mismatch".to_string());
        }
        if self.quantum_auth_root
            != quantum_auth_transcript_root(std::slice::from_ref(&self.auth_transcript))
        {
            return Err("shielded transfer quantum auth root mismatch".to_string());
        }
        self.auth_transcript.validate()?;
        if self.auth_transcript.subject_id != self.account_id {
            return Err("shielded transfer authorization subject mismatch".to_string());
        }
        if self.auth_transcript.authorization_domain != "shielded_transfer" {
            return Err("shielded transfer authorization domain mismatch".to_string());
        }
        if self.auth_transcript.payload_root != privacy_metadata_root(&self.auth_payload_record()) {
            return Err("shielded transfer authorization payload root mismatch".to_string());
        }
        self.budget_charge.validate()?;
        if self.budget_charge.status != "pending" {
            return Err("shielded transfer budget charge must be pending".to_string());
        }
        if self.budget_charge.note_count != self.output_notes.len() as u64
            || self.budget_charge.nullifier_count != self.input_nullifiers.len() as u64
            || self.budget_charge.disclosure_count != self.disclosure_receipts.len() as u64
        {
            return Err("shielded transfer budget charge count mismatch".to_string());
        }
        if self.budget_charge.tx_root != privacy_metadata_root(&self.auth_payload_record()) {
            return Err("shielded transfer budget charge tx root mismatch".to_string());
        }
        let expected_proof = privacy_proof_root(
            &self.proof_system,
            &self.identity_record(),
            &self.witness_record(),
        );
        if self.proof_root != expected_proof {
            return Err("shielded transfer proof root mismatch".to_string());
        }
        let nullifiers = self
            .input_nullifiers
            .iter()
            .map(|record| record.nullifier.clone())
            .collect::<Vec<_>>();
        ensure_distinct(&nullifiers, "duplicate nullifier in shielded transfer")?;
        let output_ids = self
            .output_notes
            .iter()
            .map(|note| note.note_id.clone())
            .collect::<Vec<_>>();
        ensure_distinct(&output_ids, "duplicate output note in shielded transfer")?;
        Ok(self.transfer_id.clone())
    }

    fn witness_record(&self) -> Value {
        json!({
            "input_nullifiers": self.input_nullifiers.iter().map(NullifierRecord::public_record).collect::<Vec<_>>(),
            "output_notes": self.output_notes.iter().map(NoteCommitment::state_record).collect::<Vec<_>>(),
            "encrypted_payloads": self.encrypted_payloads.iter().map(EncryptedPayloadRecord::state_record).collect::<Vec<_>>(),
            "disclosure_receipts": self.disclosure_receipts.iter().map(SelectiveDisclosureReceipt::state_record).collect::<Vec<_>>(),
            "auth_transcript": self.auth_transcript.state_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyApplyOutcome {
    pub transfer_id: String,
    pub public_record: Value,
    pub state_record: Value,
    pub spent_nullifiers: Vec<String>,
    pub output_note_ids: Vec<String>,
    pub encrypted_payload_ids: Vec<String>,
    pub disclosure_receipt_ids: Vec<String>,
    pub budget_charge_id: String,
    pub note_root: String,
    pub nullifier_root: String,
    pub privacy_state_root: String,
}

impl PrivacyApplyOutcome {
    pub fn public_record(&self) -> Value {
        json!({
            "transfer_id": self.transfer_id,
            "public_record": self.public_record,
            "spent_nullifiers": self.spent_nullifiers,
            "output_note_ids": self.output_note_ids,
            "encrypted_payload_ids": self.encrypted_payload_ids,
            "disclosure_receipt_ids": self.disclosure_receipt_ids,
            "budget_charge_id": self.budget_charge_id,
            "note_root": self.note_root,
            "nullifier_root": self.nullifier_root,
            "privacy_state_root": self.privacy_state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyStateRoots {
    pub shielded_account_root: String,
    pub viewing_key_policy_root: String,
    pub note_root: String,
    pub nullifier_root: String,
    pub encrypted_payload_root: String,
    pub budget_root: String,
    pub budget_charge_root: String,
    pub quantum_auth_root: String,
    pub disclosure_receipt_root: String,
    pub transfer_root: String,
}

impl PrivacyStateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "shielded_account_root": self.shielded_account_root,
            "viewing_key_policy_root": self.viewing_key_policy_root,
            "note_root": self.note_root,
            "nullifier_root": self.nullifier_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "budget_root": self.budget_root,
            "budget_charge_root": self.budget_charge_root,
            "quantum_auth_root": self.quantum_auth_root,
            "disclosure_receipt_root": self.disclosure_receipt_root,
            "transfer_root": self.transfer_root,
        })
    }

    pub fn privacy_state_root(&self) -> String {
        privacy_state_root(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyState {
    pub height: u64,
    pub nonce: u64,
    pub shielded_accounts: BTreeMap<String, ShieldedAccount>,
    pub viewing_key_policies: BTreeMap<String, ViewingKeyPolicy>,
    pub note_commitments: BTreeMap<String, NoteCommitment>,
    pub spent_nullifiers: BTreeMap<String, NullifierRecord>,
    pub encrypted_payloads: BTreeMap<String, EncryptedPayloadRecord>,
    pub budget_accounts: BTreeMap<String, PrivacyBudgetAccount>,
    pub budget_charges: BTreeMap<String, PrivacyBudgetCharge>,
    pub auth_transcripts: BTreeMap<String, QuantumSafeAuthorizationTranscript>,
    pub disclosure_receipts: BTreeMap<String, SelectiveDisclosureReceipt>,
    pub transfers: BTreeMap<String, ShieldedTransfer>,
    pub spent_note_ids: BTreeSet<String>,
}

impl PrivacyState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn advance_height(&mut self, blocks: u64) -> PrivacyResult<String> {
        self.height = self
            .height
            .checked_add(blocks)
            .ok_or_else(|| "privacy state height overflow".to_string())?;
        Ok(self.height.to_string())
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce += 1;
        self.nonce
    }

    pub fn register_shielded_account(
        &mut self,
        account: ShieldedAccount,
        viewing_key_policy: ViewingKeyPolicy,
        budget: PrivacyBudgetAccount,
    ) -> PrivacyResult<String> {
        account.validate(&viewing_key_policy)?;
        viewing_key_policy.validate()?;
        budget.validate()?;
        if account.account_id != viewing_key_policy.account_id {
            return Err("privacy account and viewing policy mismatch".to_string());
        }
        if account.privacy_budget_id != budget.budget_id {
            return Err("privacy account budget id mismatch".to_string());
        }
        if self
            .viewing_key_policies
            .contains_key(&viewing_key_policy.policy_id)
        {
            return Err("viewing key policy already exists".to_string());
        }
        if self.budget_accounts.contains_key(&budget.budget_id) {
            return Err("privacy budget already exists".to_string());
        }
        if self.shielded_accounts.contains_key(&account.account_id) {
            return Err("shielded account already exists".to_string());
        }
        insert_unique_record(
            &mut self.viewing_key_policies,
            viewing_key_policy.policy_id.clone(),
            viewing_key_policy,
            "viewing key policy",
        )?;
        insert_unique_record(
            &mut self.budget_accounts,
            budget.budget_id.clone(),
            budget,
            "privacy budget",
        )?;
        insert_unique_record(
            &mut self.shielded_accounts,
            account.account_id.clone(),
            account.clone(),
            "shielded account",
        )?;
        Ok(account.account_id)
    }

    pub fn insert_viewing_key_policy(&mut self, policy: ViewingKeyPolicy) -> PrivacyResult<String> {
        policy.validate()?;
        let policy_id = policy.policy_id.clone();
        insert_unique_record(
            &mut self.viewing_key_policies,
            policy_id.clone(),
            policy,
            "viewing key policy",
        )?;
        Ok(policy_id)
    }

    pub fn insert_encrypted_payload(
        &mut self,
        payload: EncryptedPayloadRecord,
    ) -> PrivacyResult<String> {
        payload.validate()?;
        let payload_id = payload.payload_id.clone();
        insert_unique_record(
            &mut self.encrypted_payloads,
            payload_id.clone(),
            payload,
            "encrypted payload",
        )?;
        Ok(payload_id)
    }

    pub fn insert_note_commitment(&mut self, note: NoteCommitment) -> PrivacyResult<String> {
        note.validate()?;
        if !self.shielded_accounts.contains_key(&note.account_id) {
            return Err("note references unknown shielded account".to_string());
        }
        if !self
            .encrypted_payloads
            .contains_key(&note.encrypted_payload_id)
        {
            return Err("note references unknown encrypted payload".to_string());
        }
        let note_id = note.note_id.clone();
        insert_unique_record(
            &mut self.note_commitments,
            note_id.clone(),
            note,
            "note commitment",
        )?;
        Ok(note_id)
    }

    pub fn insert_auth_transcript(
        &mut self,
        transcript: QuantumSafeAuthorizationTranscript,
    ) -> PrivacyResult<String> {
        transcript.validate()?;
        let transcript_id = transcript.transcript_id.clone();
        insert_unique_record(
            &mut self.auth_transcripts,
            transcript_id.clone(),
            transcript,
            "authorization transcript",
        )?;
        Ok(transcript_id)
    }

    pub fn issue_disclosure_receipt(
        &mut self,
        receipt: SelectiveDisclosureReceipt,
    ) -> PrivacyResult<String> {
        receipt.validate()?;
        if !self.note_commitments.contains_key(&receipt.note_id)
            && !self.spent_note_ids.contains(&receipt.note_id)
        {
            return Err("selective disclosure references unknown note".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        insert_unique_record(
            &mut self.disclosure_receipts,
            receipt_id.clone(),
            receipt,
            "selective disclosure receipt",
        )?;
        Ok(receipt_id)
    }

    pub fn apply_budget_charge(&mut self, charge: PrivacyBudgetCharge) -> PrivacyResult<String> {
        charge.validate()?;
        if self.budget_charges.contains_key(&charge.charge_id) {
            return Err("privacy budget charge already exists".to_string());
        }
        let budget = self
            .budget_accounts
            .get_mut(&charge.budget_id)
            .ok_or_else(|| "unknown privacy budget".to_string())?;
        budget.apply_charge(&charge)?;
        let mut applied = charge;
        applied.status = "applied".to_string();
        let charge_id = applied.charge_id.clone();
        insert_unique_record(
            &mut self.budget_charges,
            charge_id.clone(),
            applied,
            "privacy budget charge",
        )?;
        Ok(charge_id)
    }

    pub fn validate_transfer(&self, transfer: &ShieldedTransfer) -> PrivacyResult<String> {
        transfer.validate_basic()?;
        let account = self
            .shielded_accounts
            .get(&transfer.account_id)
            .ok_or_else(|| "shielded transfer references unknown account".to_string())?;
        if account.status != "active" {
            return Err("shielded transfer account is not active".to_string());
        }
        if self.transfers.contains_key(&transfer.transfer_id) {
            return Err("shielded transfer already exists".to_string());
        }
        if self
            .auth_transcripts
            .contains_key(&transfer.auth_transcript.transcript_id)
        {
            return Err("shielded transfer authorization transcript already exists".to_string());
        }
        if self
            .budget_charges
            .contains_key(&transfer.budget_charge.charge_id)
        {
            return Err("privacy budget charge already exists".to_string());
        }
        for nullifier in &transfer.input_nullifiers {
            if self.spent_nullifiers.contains_key(&nullifier.nullifier) {
                return Err("duplicate nullifier".to_string());
            }
            if nullifier.account_id != transfer.account_id {
                return Err("shielded transfer nullifier account mismatch".to_string());
            }
            if nullifier.status != "spent" {
                return Err("shielded transfer nullifier must be spent".to_string());
            }
            let note = self
                .note_commitments
                .get(&nullifier.note_id)
                .ok_or_else(|| "shielded transfer references unknown input note".to_string())?;
            if note.status != "unspent" {
                return Err("shielded transfer input note is not unspent".to_string());
            }
            nullifier.validate_against_note(note)?;
        }
        for note in &transfer.output_notes {
            note.validate()?;
            if note.status != "unspent" {
                return Err("shielded transfer output note must be unspent".to_string());
            }
            if self.note_commitments.contains_key(&note.note_id) {
                return Err("shielded transfer output note already exists".to_string());
            }
            if !self.shielded_accounts.contains_key(&note.account_id) {
                return Err("shielded transfer output note account is unknown".to_string());
            }
        }
        for payload in &transfer.encrypted_payloads {
            payload.validate()?;
            if self.encrypted_payloads.contains_key(&payload.payload_id) {
                return Err("shielded transfer encrypted payload already exists".to_string());
            }
        }
        for receipt in &transfer.disclosure_receipts {
            receipt.validate()?;
            if self.disclosure_receipts.contains_key(&receipt.receipt_id) {
                return Err("shielded transfer disclosure receipt already exists".to_string());
            }
        }
        let budget = self
            .budget_accounts
            .get(&transfer.budget_charge.budget_id)
            .ok_or_else(|| "unknown privacy budget".to_string())?;
        if budget.available_units() < transfer.budget_charge.units {
            return Err("privacy budget has insufficient available units".to_string());
        }
        Ok(transfer.transfer_id.clone())
    }

    pub fn apply_transfer(&mut self, transfer: ShieldedTransfer) -> PrivacyResult<String> {
        self.apply_transfer_with_outcome(transfer)
            .map(|outcome| outcome.transfer_id)
    }

    pub fn apply_transfer_with_outcome(
        &mut self,
        transfer: ShieldedTransfer,
    ) -> PrivacyResult<PrivacyApplyOutcome> {
        self.validate_transfer(&transfer)?;
        let transfer_id = transfer.transfer_id.clone();
        for nullifier in &transfer.input_nullifiers {
            let mut note = self
                .note_commitments
                .remove(&nullifier.note_id)
                .ok_or_else(|| "shielded transfer input note disappeared".to_string())?;
            note.status = "spent".to_string();
            self.spent_note_ids.insert(note.note_id.clone());
            self.spent_nullifiers
                .insert(nullifier.nullifier.clone(), nullifier.clone());
        }
        for payload in &transfer.encrypted_payloads {
            self.encrypted_payloads
                .insert(payload.payload_id.clone(), payload.clone());
        }
        for note in &transfer.output_notes {
            self.note_commitments
                .insert(note.note_id.clone(), note.clone());
        }
        for receipt in &transfer.disclosure_receipts {
            self.disclosure_receipts
                .insert(receipt.receipt_id.clone(), receipt.clone());
        }
        self.insert_auth_transcript(transfer.auth_transcript.clone())?;
        self.apply_budget_charge(transfer.budget_charge.clone())?;
        self.transfers
            .insert(transfer.transfer_id.clone(), transfer.clone());
        let outcome = PrivacyApplyOutcome {
            transfer_id,
            public_record: transfer.public_record(),
            state_record: transfer.state_record(),
            spent_nullifiers: transfer
                .input_nullifiers
                .iter()
                .map(|record| record.nullifier.clone())
                .collect(),
            output_note_ids: transfer
                .output_notes
                .iter()
                .map(|note| note.note_id.clone())
                .collect(),
            encrypted_payload_ids: transfer
                .encrypted_payloads
                .iter()
                .map(|payload| payload.payload_id.clone())
                .collect(),
            disclosure_receipt_ids: transfer
                .disclosure_receipts
                .iter()
                .map(|receipt| receipt.receipt_id.clone())
                .collect(),
            budget_charge_id: transfer.budget_charge.charge_id,
            note_root: self.note_root(),
            nullifier_root: self.nullifier_root(),
            privacy_state_root: self.state_root(),
        };
        Ok(outcome)
    }

    pub fn account_root(&self) -> String {
        shielded_account_root(&self.shielded_accounts.values().cloned().collect::<Vec<_>>())
    }

    pub fn viewing_key_policy_root(&self) -> String {
        viewing_key_policy_root(
            &self
                .viewing_key_policies
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn note_root(&self) -> String {
        note_commitment_root(&self.note_commitments.values().cloned().collect::<Vec<_>>())
    }

    pub fn nullifier_root(&self) -> String {
        privacy_nullifier_root(&self.spent_nullifiers.values().cloned().collect::<Vec<_>>())
    }

    pub fn encrypted_payload_root(&self) -> String {
        encrypted_payload_root(
            &self
                .encrypted_payloads
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn budget_root(&self) -> String {
        privacy_budget_root(&self.budget_accounts.values().cloned().collect::<Vec<_>>())
    }

    pub fn budget_charge_root(&self) -> String {
        privacy_budget_charge_root(&self.budget_charges.values().cloned().collect::<Vec<_>>())
    }

    pub fn quantum_auth_root(&self) -> String {
        quantum_auth_transcript_root(&self.auth_transcripts.values().cloned().collect::<Vec<_>>())
    }

    pub fn disclosure_receipt_root(&self) -> String {
        selective_disclosure_receipt_root(
            &self
                .disclosure_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn transfer_root(&self) -> String {
        shielded_transfer_root(&self.transfers.values().cloned().collect::<Vec<_>>())
    }

    pub fn roots(&self) -> PrivacyStateRoots {
        PrivacyStateRoots {
            shielded_account_root: self.account_root(),
            viewing_key_policy_root: self.viewing_key_policy_root(),
            note_root: self.note_root(),
            nullifier_root: self.nullifier_root(),
            encrypted_payload_root: self.encrypted_payload_root(),
            budget_root: self.budget_root(),
            budget_charge_root: self.budget_charge_root(),
            quantum_auth_root: self.quantum_auth_root(),
            disclosure_receipt_root: self.disclosure_receipt_root(),
            transfer_root: self.transfer_root(),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().privacy_state_root()
    }

    pub fn public_snapshot(&self) -> Value {
        json!({
            "kind": "privacy_state",
            "version": PRIVACY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "nonce": self.nonce,
            "state_root": self.state_root(),
            "roots": self.roots().public_record(),
            "shielded_account_count": self.shielded_accounts.len() as u64,
            "viewing_key_policy_count": self.viewing_key_policies.len() as u64,
            "note_count": self.note_commitments.len() as u64,
            "spent_nullifier_count": self.spent_nullifiers.len() as u64,
            "encrypted_payload_count": self.encrypted_payloads.len() as u64,
            "budget_count": self.budget_accounts.len() as u64,
            "budget_charge_count": self.budget_charges.len() as u64,
            "auth_transcript_count": self.auth_transcripts.len() as u64,
            "disclosure_receipt_count": self.disclosure_receipts.len() as u64,
            "transfer_count": self.transfers.len() as u64,
        })
    }
}

pub fn shielded_owner_commitment(owner_view_key: &str) -> String {
    domain_hash(
        "PRIVACY-SHIELDED-OWNER",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(owner_view_key)],
        32,
    )
}

pub fn shielded_spending_key_commitment(spending_key: &str) -> String {
    domain_hash(
        "PRIVACY-SHIELDED-SPENDING-KEY",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(spending_key)],
        32,
    )
}

pub fn viewing_key_commitment(owner_view_key: &str) -> String {
    domain_hash(
        "PRIVACY-VIEWING-KEY",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(owner_view_key)],
        32,
    )
}

pub fn disclosure_authority_commitment(disclosure_authority: &str) -> String {
    domain_hash(
        "PRIVACY-DISCLOSURE-AUTHORITY",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(disclosure_authority)],
        32,
    )
}

pub fn shielded_account_id(
    owner_commitment: &str,
    spending_key_commitment: &str,
    created_at_height: u64,
    account_nonce: u64,
) -> String {
    domain_hash(
        "PRIVACY-SHIELDED-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(spending_key_commitment),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(account_nonce as i128),
        ],
        32,
    )
}

pub fn shielded_account_root(accounts: &[ShieldedAccount]) -> String {
    merkle_root(
        "PRIVACY-SHIELDED-ACCOUNT",
        &accounts
            .iter()
            .map(ShieldedAccount::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn viewing_key_policy_id(record: &Value) -> String {
    domain_hash(
        "PRIVACY-VIEWING-KEY-POLICY-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn viewing_key_policy_root(policies: &[ViewingKeyPolicy]) -> String {
    merkle_root(
        "PRIVACY-VIEWING-KEY-POLICY",
        &policies
            .iter()
            .map(ViewingKeyPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn privacy_asset_commitment(asset_id: &str) -> String {
    domain_hash(
        "PRIVACY-ASSET-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(asset_id)],
        32,
    )
}

pub fn note_blinding(
    account_id: &str,
    owner_view_key: &str,
    asset_id: &str,
    amount: u64,
    note_nonce: u64,
) -> String {
    domain_hash(
        "PRIVACY-NOTE-BLINDING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_id),
            HashPart::Str(owner_view_key),
            HashPart::Str(asset_id),
            HashPart::Int(amount as i128),
            HashPart::Int(note_nonce as i128),
        ],
        32,
    )
}

pub fn privacy_amount_commitment(amount: u64, blinding: &str) -> String {
    domain_hash(
        "PRIVACY-AMOUNT-COMMITMENT",
        &[HashPart::Int(amount as i128), HashPart::Str(blinding)],
        32,
    )
}

pub fn privacy_note_commitment(
    account_id: &str,
    owner_commitment: &str,
    asset_commitment: &str,
    amount_commitment: &str,
    encrypted_payload_hash: &str,
    created_at_height: u64,
    note_nonce: u64,
) -> String {
    domain_hash(
        "PRIVACY-NOTE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(asset_commitment),
            HashPart::Str(amount_commitment),
            HashPart::Str(encrypted_payload_hash),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(note_nonce as i128),
        ],
        32,
    )
}

pub fn note_commitment_id(commitment: &str, created_at_height: u64, note_nonce: u64) -> String {
    domain_hash(
        "PRIVACY-NOTE-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(commitment),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(note_nonce as i128),
        ],
        32,
    )
}

pub fn note_commitment_root(notes: &[NoteCommitment]) -> String {
    let mut leaves = notes
        .iter()
        .map(NoteCommitment::public_record)
        .collect::<Vec<_>>();
    leaves.sort_by_key(|record| record["note_id"].as_str().unwrap_or_default().to_string());
    merkle_root("PRIVACY-NOTE-COMMITMENT", &leaves)
}

pub fn privacy_nullifier(note: &NoteCommitment, spend_context_root: &str) -> String {
    domain_hash(
        "PRIVACY-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&note.note_id),
            HashPart::Str(&note.owner_view_key),
            HashPart::Str(&note.blinding),
            HashPart::Str(spend_context_root),
        ],
        32,
    )
}

pub fn privacy_nullifier_root(nullifiers: &[NullifierRecord]) -> String {
    let mut leaves = nullifiers
        .iter()
        .map(NullifierRecord::public_record)
        .collect::<Vec<_>>();
    leaves.sort_by_key(|record| record["nullifier"].as_str().unwrap_or_default().to_string());
    merkle_root("PRIVACY-NULLIFIER", &leaves)
}

pub fn nullifier_input_note_root(nullifiers: &[NullifierRecord]) -> String {
    let mut leaves = nullifiers
        .iter()
        .map(|record| {
            json!({
                "note_id": record.note_id,
                "note_commitment": record.note_commitment,
                "nullifier": record.nullifier,
            })
        })
        .collect::<Vec<_>>();
    leaves.sort_by_key(|record| record["nullifier"].as_str().unwrap_or_default().to_string());
    merkle_root("PRIVACY-NULLIFIER-INPUT-NOTE", &leaves)
}

pub fn privacy_view_tag(owner_view_key: &str, note_commitment: &str, view_tag_bits: u16) -> String {
    let byte_len = (view_tag_bits as usize).div_ceil(8).max(1);
    let tag = domain_hash(
        "PRIVACY-VIEW-TAG",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_view_key),
            HashPart::Str(note_commitment),
            HashPart::Int(view_tag_bits as i128),
        ],
        byte_len,
    );
    let hex_len = (view_tag_bits as usize).div_ceil(4);
    tag.chars().take(hex_len).collect()
}

pub fn encrypted_payload_hash(payload_kind: &str, encrypted_payload: &Value) -> String {
    domain_hash(
        "PRIVACY-ENCRYPTED-PAYLOAD-HASH",
        &[
            HashPart::Str(payload_kind),
            HashPart::Json(encrypted_payload),
        ],
        32,
    )
}

pub fn encrypted_payload_kem_ciphertext_hash(
    recipient_key_root: &str,
    payload_hash: &str,
    disclosure_policy_root: &str,
    payload_nonce: u64,
) -> String {
    domain_hash(
        "PRIVACY-ENCRYPTED-PAYLOAD-KEM",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(recipient_key_root),
            HashPart::Str(payload_hash),
            HashPart::Str(disclosure_policy_root),
            HashPart::Int(payload_nonce as i128),
        ],
        32,
    )
}

pub fn encrypted_payload_id(record: &Value) -> String {
    domain_hash(
        "PRIVACY-ENCRYPTED-PAYLOAD-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn encrypted_payload_root(payloads: &[EncryptedPayloadRecord]) -> String {
    merkle_root(
        "PRIVACY-ENCRYPTED-PAYLOAD",
        &payloads
            .iter()
            .map(EncryptedPayloadRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn privacy_metadata_root(metadata: &Value) -> String {
    domain_hash("PRIVACY-METADATA", &[HashPart::Json(metadata)], 32)
}

pub fn privacy_string_root(values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    merkle_root(
        "PRIVACY-STRING",
        &values.into_iter().map(Value::String).collect::<Vec<_>>(),
    )
}

pub fn privacy_scope_root(scopes: &[String]) -> String {
    let mut scopes = scopes.to_vec();
    scopes.sort();
    merkle_root(
        "PRIVACY-SCOPE",
        &scopes.into_iter().map(Value::String).collect::<Vec<_>>(),
    )
}

pub fn privacy_budget_id(
    subject_commitment: &str,
    epoch: u64,
    epoch_start_height: u64,
    epoch_end_height: u64,
    budget_units: u64,
) -> String {
    domain_hash(
        "PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_commitment),
            HashPart::Int(epoch as i128),
            HashPart::Int(epoch_start_height as i128),
            HashPart::Int(epoch_end_height as i128),
            HashPart::Int(budget_units as i128),
        ],
        32,
    )
}

pub fn privacy_budget_root(budgets: &[PrivacyBudgetAccount]) -> String {
    merkle_root(
        "PRIVACY-BUDGET",
        &budgets
            .iter()
            .map(PrivacyBudgetAccount::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn privacy_budget_units(note_count: u64, nullifier_count: u64, disclosure_count: u64) -> u64 {
    note_count
        .saturating_mul(PRIVACY_BUDGET_UNIT_PER_NOTE)
        .saturating_add(nullifier_count.saturating_mul(PRIVACY_BUDGET_UNIT_PER_NULLIFIER))
        .saturating_add(disclosure_count.saturating_mul(PRIVACY_BUDGET_UNIT_PER_DISCLOSURE))
}

pub fn privacy_proof_bytes(note_count: u64, nullifier_count: u64, disclosure_count: u64) -> u64 {
    note_count
        .saturating_add(nullifier_count)
        .saturating_add(disclosure_count)
        .saturating_mul(DEVNET_PRIVACY_PROOF_BYTES)
}

pub fn privacy_budget_charge_id(record: &Value) -> String {
    domain_hash("PRIVACY-BUDGET-CHARGE-ID", &[HashPart::Json(record)], 32)
}

pub fn privacy_budget_charge_root(charges: &[PrivacyBudgetCharge]) -> String {
    merkle_root(
        "PRIVACY-BUDGET-CHARGE",
        &charges
            .iter()
            .map(PrivacyBudgetCharge::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn privacy_signer_commitment(signer_label: &str) -> String {
    domain_hash(
        "PRIVACY-SIGNER-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(signer_label)],
        32,
    )
}

pub fn privacy_authorization_root(authorization: &Authorization) -> String {
    domain_hash(
        "PRIVACY-AUTHORIZATION",
        &[HashPart::Json(&privacy_authorization_public_record(
            authorization,
            false,
        ))],
        32,
    )
}

pub fn privacy_authorization_public_record(
    authorization: &Authorization,
    include_signer_label: bool,
) -> Value {
    let mut record = json!({
        "auth_scheme": authorization.auth_scheme,
        "auth_public_key": authorization.auth_public_key,
        "auth_transcript_hash": authorization.auth_transcript_hash,
        "auth_signature": authorization.auth_signature,
    });
    if include_signer_label {
        record
            .as_object_mut()
            .expect("privacy authorization record object")
            .insert(
                "signer_label".to_string(),
                Value::String(authorization.signer_label.clone()),
            );
    }
    record
}

pub fn quantum_auth_transcript_id(record: &Value) -> String {
    domain_hash(
        "PRIVACY-QUANTUM-AUTH-TRANSCRIPT-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn quantum_auth_transcript_root(transcripts: &[QuantumSafeAuthorizationTranscript]) -> String {
    merkle_root(
        "PRIVACY-QUANTUM-AUTH-TRANSCRIPT",
        &transcripts
            .iter()
            .map(QuantumSafeAuthorizationTranscript::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn privacy_recipient_commitment(recipient: &str) -> String {
    domain_hash(
        "PRIVACY-DISCLOSURE-RECIPIENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(recipient)],
        32,
    )
}

pub fn selective_disclosure_statement_root(
    note_id: &str,
    note_commitment: &str,
    disclosure_root: &str,
    revealed_record_root: &str,
) -> String {
    domain_hash(
        "PRIVACY-SELECTIVE-DISCLOSURE-STATEMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(note_id),
            HashPart::Str(note_commitment),
            HashPart::Str(disclosure_root),
            HashPart::Str(revealed_record_root),
        ],
        32,
    )
}

pub fn selective_disclosure_receipt_id(record: &Value) -> String {
    domain_hash(
        "PRIVACY-SELECTIVE-DISCLOSURE-RECEIPT-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn selective_disclosure_receipt_root(receipts: &[SelectiveDisclosureReceipt]) -> String {
    merkle_root(
        "PRIVACY-SELECTIVE-DISCLOSURE-RECEIPT",
        &receipts
            .iter()
            .map(SelectiveDisclosureReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn privacy_proof_root(
    proof_system: &str,
    public_inputs: &Value,
    private_witnesses: &Value,
) -> String {
    domain_hash(
        "PRIVACY-PROOF-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_system),
            HashPart::Json(public_inputs),
            HashPart::Json(private_witnesses),
        ],
        32,
    )
}

pub fn shielded_transfer_id(record: &Value) -> String {
    domain_hash(
        "PRIVACY-SHIELDED-TRANSFER-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn shielded_transfer_root(transfers: &[ShieldedTransfer]) -> String {
    merkle_root(
        "PRIVACY-SHIELDED-TRANSFER",
        &transfers
            .iter()
            .map(ShieldedTransfer::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn shielded_transfer_auth_payload(
    account_id: &str,
    action_kind: &str,
    anchor_root: &str,
    input_note_root: &str,
    output_note_root: &str,
    nullifier_root: &str,
    encrypted_payload_root: &str,
    disclosure_receipt_root: &str,
    budget_charge_id: &str,
    fee_asset_commitment: &str,
    fee_amount_commitment: &str,
    created_at_height: u64,
) -> Value {
    json!({
        "kind": "shielded_transfer_authorization_payload",
        "version": PRIVACY_PROTOCOL_VERSION,
        "chain_id": CHAIN_ID,
        "account_id": account_id,
        "action_kind": action_kind,
        "anchor_root": anchor_root,
        "input_note_root": input_note_root,
        "output_note_root": output_note_root,
        "nullifier_root": nullifier_root,
        "encrypted_payload_root": encrypted_payload_root,
        "disclosure_receipt_root": disclosure_receipt_root,
        "budget_charge_id": budget_charge_id,
        "fee_asset_commitment": fee_asset_commitment,
        "fee_amount_commitment": fee_amount_commitment,
        "created_at_height": created_at_height,
    })
}

pub fn privacy_state_root(record: &Value) -> String {
    domain_hash("PRIVACY-STATE", &[HashPart::Json(record)], 32)
}

fn validate_view_tag_bits(view_tag_bits: u16) -> PrivacyResult<String> {
    if !(PRIVACY_MIN_VIEW_TAG_BITS..=PRIVACY_MAX_VIEW_TAG_BITS).contains(&view_tag_bits) {
        return Err("view tag bits outside supported range".to_string());
    }
    Ok(view_tag_bits.to_string())
}

fn normalize_scopes(
    default_scope: String,
    allowed_scopes: Vec<String>,
) -> PrivacyResult<Vec<String>> {
    let default_scope = normalize_scope_name(default_scope);
    if default_scope.is_empty() {
        return Err("privacy default scope is required".to_string());
    }
    let mut scopes = allowed_scopes
        .into_iter()
        .map(normalize_scope_name)
        .filter(|scope| !scope.is_empty())
        .collect::<Vec<_>>();
    if !scopes.contains(&default_scope) {
        scopes.push(default_scope);
    }
    scopes.sort();
    scopes.dedup();
    if scopes.is_empty() {
        return Err("privacy scopes are required".to_string());
    }
    Ok(scopes)
}

fn normalize_field_names(fields: Vec<String>) -> PrivacyResult<Vec<String>> {
    let mut fields = fields
        .into_iter()
        .map(normalize_scope_name)
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    fields.sort();
    fields.dedup();
    if fields.is_empty() {
        return Err("selective disclosure fields are required".to_string());
    }
    Ok(fields)
}

fn normalize_scope_name(scope: String) -> String {
    scope.trim().to_ascii_lowercase().replace('-', "_")
}

fn ensure_status(status: &str, allowed: &[&str]) -> PrivacyResult<String> {
    if allowed.iter().any(|candidate| candidate == &status) {
        Ok(status.to_string())
    } else {
        Err(format!("unsupported privacy status: {status}"))
    }
}

fn ensure_distinct(values: &[String], message: &str) -> PrivacyResult<String> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.len() == values.len() {
        Ok(sorted.len().to_string())
    } else {
        Err(message.to_string())
    }
}

fn with_authorization(
    mut record: Value,
    authorization: &Authorization,
    include_signer_label: bool,
) -> Value {
    let object = record
        .as_object_mut()
        .expect("authorization record must be an object");
    if include_signer_label {
        object.insert(
            "signer_label".to_string(),
            Value::String(authorization.signer_label.clone()),
        );
    }
    object.insert(
        "auth_scheme".to_string(),
        Value::String(authorization.auth_scheme.clone()),
    );
    object.insert(
        "auth_public_key".to_string(),
        Value::String(authorization.auth_public_key.clone()),
    );
    object.insert(
        "auth_transcript_hash".to_string(),
        Value::String(authorization.auth_transcript_hash.clone()),
    );
    object.insert(
        "auth_signature".to_string(),
        Value::String(authorization.auth_signature.clone()),
    );
    record
}

fn empty_authorization() -> Authorization {
    Authorization {
        signer_label: String::new(),
        auth_scheme: PRIVACY_AUTH_SCHEME.to_string(),
        auth_public_key: String::new(),
        auth_transcript_hash: String::new(),
        auth_signature: String::new(),
    }
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> PrivacyResult<String> {
    if records.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    records.insert(id.clone(), record);
    Ok(id)
}
