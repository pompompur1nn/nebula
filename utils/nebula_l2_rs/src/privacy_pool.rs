use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivacyPoolResult<T> = Result<T, String>;

pub const PRIVACY_POOL_PROTOCOL_VERSION: &str = "nebula-privacy-pool-v1";
pub const PRIVACY_POOL_DEFAULT_EPOCH_LENGTH: u64 = 720;
pub const PRIVACY_POOL_DEFAULT_NOTE_TTL_BLOCKS: u64 = 20_160;
pub const PRIVACY_POOL_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 2_880;
pub const PRIVACY_POOL_DEFAULT_MIN_COMMITTEE_SIGNATURES: u16 = 2;
pub const PRIVACY_POOL_DEFAULT_MAX_DISCLOSURE_DEPTH: u8 = 4;
pub const PRIVACY_POOL_PROOF_SYSTEM_NOTE: &str = "devnet-privacy-pool-note";
pub const PRIVACY_POOL_PROOF_SYSTEM_JOIN: &str = "devnet-privacy-pool-join";
pub const PRIVACY_POOL_PROOF_SYSTEM_EXIT: &str = "devnet-privacy-pool-exit";
pub const PRIVACY_POOL_PROOF_SYSTEM_DISCLOSURE: &str = "devnet-privacy-pool-selective-disclosure";
pub const PRIVACY_POOL_PROOF_SYSTEM_COMPLIANCE: &str = "devnet-privacy-pool-compliance-root";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PoolTagKind {
    PrivateBridge,
    Defi,
    Settlement,
    Compliance,
    Custom,
}

impl PoolTagKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateBridge => "private_bridge",
            Self::Defi => "defi",
            Self::Settlement => "settlement",
            Self::Compliance => "compliance",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewingCommittee {
    pub committee_id: String,
    pub committee_label: String,
    pub member_commitments: Vec<String>,
    pub member_root: String,
    pub quorum_threshold: u16,
    pub activation_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl ViewingCommittee {
    pub fn new(
        committee_label: impl Into<String>,
        members: Vec<String>,
        quorum_threshold: u16,
        activation_height: u64,
        expires_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        let committee_label = normalize_label(committee_label.into());
        ensure_non_empty(&committee_label, "viewing committee label")?;
        let member_commitments = normalize_raw_set(
            members
                .into_iter()
                .map(|member| privacy_pool_viewer_commitment(&member))
                .collect(),
            "viewing committee members",
        )?;
        let member_root =
            privacy_pool_string_root("PRIVACY-POOL-VIEWING-COMMITTEE-MEMBER", &member_commitments);
        let mut committee = Self {
            committee_id: String::new(),
            committee_label,
            member_commitments,
            member_root,
            quorum_threshold,
            activation_height,
            expires_at_height,
            status: "active".to_string(),
        };
        committee.committee_id = privacy_pool_viewing_committee_id(&committee.identity_record());
        committee.validate()?;
        Ok(committee)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "privacy_pool_viewing_committee",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "committee_label": self.committee_label,
            "member_root": self.member_root,
            "quorum_threshold": self.quorum_threshold,
            "activation_height": self.activation_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("viewing committee public record object");
        object.insert(
            "committee_id".to_string(),
            Value::String(self.committee_id.clone()),
        );
        object.insert(
            "member_commitments".to_string(),
            Value::Array(
                self.member_commitments
                    .iter()
                    .map(|member| Value::String(member.clone()))
                    .collect(),
            ),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> PrivacyPoolResult<String> {
        ensure_non_empty(&self.committee_id, "viewing committee id")?;
        ensure_non_empty(&self.committee_label, "viewing committee label")?;
        if self.member_commitments.is_empty() {
            return Err("viewing committee requires at least one member".to_string());
        }
        if self.member_root
            != privacy_pool_string_root(
                "PRIVACY-POOL-VIEWING-COMMITTEE-MEMBER",
                &self.member_commitments,
            )
        {
            return Err("viewing committee member root mismatch".to_string());
        }
        if self.quorum_threshold == 0
            || self.quorum_threshold as usize > self.member_commitments.len()
        {
            return Err("viewing committee quorum is outside member set".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.activation_height {
            return Err("viewing committee expiry must be after activation".to_string());
        }
        ensure_status(&self.status, &["active", "rotating", "expired", "revoked"])?;
        if self.committee_id != privacy_pool_viewing_committee_id(&self.identity_record()) {
            return Err("viewing committee id mismatch".to_string());
        }
        Ok(self.committee_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveDisclosurePolicy {
    pub policy_id: String,
    pub policy_label: String,
    pub allowed_fields: Vec<String>,
    pub allowed_field_root: String,
    pub recipient_commitments: Vec<String>,
    pub recipient_root: String,
    pub max_disclosure_depth: u8,
    pub min_committee_signatures: u16,
    pub expires_after_blocks: u64,
    pub audit_scope_root: String,
    pub created_at_height: u64,
    pub status: String,
}

impl SelectiveDisclosurePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_label: impl Into<String>,
        allowed_fields: Vec<String>,
        recipients: Vec<String>,
        max_disclosure_depth: u8,
        min_committee_signatures: u16,
        expires_after_blocks: u64,
        audit_scopes: Vec<String>,
        created_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        let policy_label = normalize_label(policy_label.into());
        ensure_non_empty(&policy_label, "selective disclosure policy label")?;
        let allowed_fields =
            normalize_label_set(allowed_fields, "selective disclosure allowed fields")?;
        let recipient_commitments = normalize_raw_set(
            recipients
                .into_iter()
                .map(|recipient| privacy_pool_recipient_commitment(&recipient))
                .collect(),
            "selective disclosure recipients",
        )?;
        let audit_scopes = normalize_label_set(audit_scopes, "selective disclosure audit scopes")?;
        let allowed_field_root =
            privacy_pool_string_root("PRIVACY-POOL-DISCLOSURE-FIELD", &allowed_fields);
        let recipient_root =
            privacy_pool_string_root("PRIVACY-POOL-DISCLOSURE-RECIPIENT", &recipient_commitments);
        let audit_scope_root = privacy_pool_string_root("PRIVACY-POOL-AUDIT-SCOPE", &audit_scopes);
        let mut policy = Self {
            policy_id: String::new(),
            policy_label,
            allowed_fields,
            allowed_field_root,
            recipient_commitments,
            recipient_root,
            max_disclosure_depth,
            min_committee_signatures,
            expires_after_blocks,
            audit_scope_root,
            created_at_height,
            status: "active".to_string(),
        };
        policy.policy_id = privacy_pool_disclosure_policy_id(&policy.identity_record());
        policy.validate()?;
        Ok(policy)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "privacy_pool_selective_disclosure_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "policy_label": self.policy_label,
            "allowed_field_root": self.allowed_field_root,
            "recipient_root": self.recipient_root,
            "max_disclosure_depth": self.max_disclosure_depth,
            "min_committee_signatures": self.min_committee_signatures,
            "expires_after_blocks": self.expires_after_blocks,
            "audit_scope_root": self.audit_scope_root,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("selective disclosure policy public record object");
        object.insert(
            "policy_id".to_string(),
            Value::String(self.policy_id.clone()),
        );
        object.insert(
            "allowed_fields".to_string(),
            Value::Array(
                self.allowed_fields
                    .iter()
                    .map(|field| Value::String(field.clone()))
                    .collect(),
            ),
        );
        object.insert(
            "recipient_commitments".to_string(),
            Value::Array(
                self.recipient_commitments
                    .iter()
                    .map(|recipient| Value::String(recipient.clone()))
                    .collect(),
            ),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> PrivacyPoolResult<String> {
        ensure_non_empty(&self.policy_id, "selective disclosure policy id")?;
        ensure_non_empty(&self.policy_label, "selective disclosure policy label")?;
        if self.allowed_fields.is_empty() {
            return Err("selective disclosure policy requires fields".to_string());
        }
        if self.allowed_field_root
            != privacy_pool_string_root("PRIVACY-POOL-DISCLOSURE-FIELD", &self.allowed_fields)
        {
            return Err("selective disclosure field root mismatch".to_string());
        }
        if self.recipient_commitments.is_empty() {
            return Err("selective disclosure policy requires recipients".to_string());
        }
        if self.recipient_root
            != privacy_pool_string_root(
                "PRIVACY-POOL-DISCLOSURE-RECIPIENT",
                &self.recipient_commitments,
            )
        {
            return Err("selective disclosure recipient root mismatch".to_string());
        }
        if self.max_disclosure_depth == 0 {
            return Err("selective disclosure depth must be positive".to_string());
        }
        if self.min_committee_signatures == 0 {
            return Err("selective disclosure signatures must be positive".to_string());
        }
        if self.expires_after_blocks == 0 {
            return Err("selective disclosure ttl must be positive".to_string());
        }
        ensure_status(&self.status, &["active", "paused", "expired", "revoked"])?;
        if self.policy_id != privacy_pool_disclosure_policy_id(&self.identity_record()) {
            return Err("selective disclosure policy id mismatch".to_string());
        }
        Ok(self.policy_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivatePoolTag {
    pub tag_id: String,
    pub tag_kind: PoolTagKind,
    pub tag_label: String,
    pub tag_label_commitment: String,
    pub venue_commitment: String,
    pub route_commitment: String,
    pub asset_commitment_root: String,
    pub risk_bucket: String,
    pub metadata_root: String,
    pub created_at_height: u64,
    pub status: String,
}

impl PrivatePoolTag {
    pub fn new(
        tag_kind: PoolTagKind,
        tag_label: impl Into<String>,
        venue: impl Into<String>,
        route: impl Into<String>,
        assets: Vec<String>,
        risk_bucket: impl Into<String>,
        metadata: &Value,
        created_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        let tag_label = normalize_label(tag_label.into());
        let venue = venue.into();
        let route = route.into();
        let risk_bucket = normalize_label(risk_bucket.into());
        ensure_non_empty(&tag_label, "private pool tag label")?;
        ensure_non_empty(&venue, "private pool tag venue")?;
        ensure_non_empty(&route, "private pool tag route")?;
        ensure_non_empty(&risk_bucket, "private pool tag risk bucket")?;
        let asset_commitments = normalize_raw_set(
            assets
                .into_iter()
                .map(|asset| privacy_pool_asset_commitment(&asset))
                .collect(),
            "private pool tag assets",
        )?;
        let mut tag = Self {
            tag_id: String::new(),
            tag_kind,
            tag_label_commitment: privacy_pool_tag_label_commitment(&tag_label),
            tag_label,
            venue_commitment: privacy_pool_tag_component_commitment("venue", &venue),
            route_commitment: privacy_pool_tag_component_commitment("route", &route),
            asset_commitment_root: privacy_pool_string_root(
                "PRIVACY-POOL-TAG-ASSET",
                &asset_commitments,
            ),
            risk_bucket,
            metadata_root: privacy_pool_payload_root("PRIVACY-POOL-TAG-METADATA", metadata),
            created_at_height,
            status: "active".to_string(),
        };
        tag.tag_id = privacy_pool_tag_id(&tag.identity_record());
        tag.validate()?;
        Ok(tag)
    }

    pub fn private_bridge(
        tag_label: impl Into<String>,
        source_network: impl Into<String>,
        asset_id: impl Into<String>,
        destination_domain: impl Into<String>,
        risk_bucket: impl Into<String>,
        metadata: &Value,
        created_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        let source_network = source_network.into();
        let asset_id = asset_id.into();
        let destination_domain = destination_domain.into();
        Self::new(
            PoolTagKind::PrivateBridge,
            tag_label,
            format!("private_bridge:{source_network}:{destination_domain}"),
            format!("{source_network}->{destination_domain}:{asset_id}"),
            vec![asset_id],
            risk_bucket,
            metadata,
            created_at_height,
        )
    }

    pub fn defi(
        tag_label: impl Into<String>,
        protocol: impl Into<String>,
        asset_in: impl Into<String>,
        asset_out: impl Into<String>,
        risk_bucket: impl Into<String>,
        metadata: &Value,
        created_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        let protocol = protocol.into();
        let asset_in = asset_in.into();
        let asset_out = asset_out.into();
        Self::new(
            PoolTagKind::Defi,
            tag_label,
            protocol.clone(),
            format!("{protocol}:{asset_in}:{asset_out}"),
            vec![asset_in, asset_out],
            risk_bucket,
            metadata,
            created_at_height,
        )
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "privacy_pool_private_tag",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "tag_kind": self.tag_kind.as_str(),
            "tag_label_commitment": self.tag_label_commitment,
            "venue_commitment": self.venue_commitment,
            "route_commitment": self.route_commitment,
            "asset_commitment_root": self.asset_commitment_root,
            "risk_bucket": self.risk_bucket,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("private pool tag public record object");
        object.insert("tag_id".to_string(), Value::String(self.tag_id.clone()));
        object.insert(
            "tag_label".to_string(),
            Value::String(self.tag_label.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> PrivacyPoolResult<String> {
        ensure_non_empty(&self.tag_id, "private pool tag id")?;
        ensure_non_empty(&self.tag_label, "private pool tag label")?;
        ensure_non_empty(
            &self.tag_label_commitment,
            "private pool tag label commitment",
        )?;
        ensure_non_empty(&self.venue_commitment, "private pool tag venue commitment")?;
        ensure_non_empty(&self.route_commitment, "private pool tag route commitment")?;
        ensure_non_empty(&self.asset_commitment_root, "private pool tag asset root")?;
        ensure_non_empty(&self.risk_bucket, "private pool tag risk bucket")?;
        ensure_non_empty(&self.metadata_root, "private pool tag metadata root")?;
        ensure_status(&self.status, &["active", "paused", "retired"])?;
        if self.tag_id != privacy_pool_tag_id(&self.identity_record()) {
            return Err("private pool tag id mismatch".to_string());
        }
        Ok(self.tag_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolNoteCommitment {
    pub note_id: String,
    pub pool_id: String,
    pub epoch_id: String,
    pub owner_commitment: String,
    pub asset_commitment: String,
    pub value_bucket_commitment: String,
    pub blinding_commitment: String,
    pub disclosure_policy_id: String,
    pub viewing_committee_id: String,
    pub tag_ids: Vec<String>,
    pub tag_root: String,
    pub commitment: String,
    pub leaf_hash: String,
    pub joined_at_height: u64,
    pub expires_at_height: u64,
    pub note_nonce: u64,
    pub compliance_proof_root: String,
    pub status: String,
}

impl PoolNoteCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: impl Into<String>,
        epoch_id: impl Into<String>,
        owner_secret: &str,
        asset_id: &str,
        value_bucket: &str,
        blinding_seed: &str,
        disclosure_policy_id: impl Into<String>,
        viewing_committee_id: impl Into<String>,
        tag_ids: Vec<String>,
        joined_at_height: u64,
        note_nonce: u64,
        expires_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        ensure_non_empty(owner_secret, "privacy pool note owner secret")?;
        ensure_non_empty(asset_id, "privacy pool note asset")?;
        ensure_non_empty(value_bucket, "privacy pool note value bucket")?;
        ensure_non_empty(blinding_seed, "privacy pool note blinding seed")?;
        let owner_commitment = privacy_pool_owner_commitment(owner_secret);
        let asset_commitment = privacy_pool_asset_commitment(asset_id);
        let value_bucket_commitment = privacy_pool_value_bucket_commitment(value_bucket);
        let blinding_commitment = privacy_pool_blinding_commitment(blinding_seed);
        let public_inputs = json!({
            "pool_id": pool_id.into(),
            "epoch_id": epoch_id.into(),
            "owner_commitment": owner_commitment,
            "asset_commitment": asset_commitment,
            "value_bucket_commitment": value_bucket_commitment,
            "blinding_commitment": blinding_commitment,
            "disclosure_policy_id": disclosure_policy_id.into(),
            "viewing_committee_id": viewing_committee_id.into(),
            "tag_root": privacy_pool_string_root("PRIVACY-POOL-NOTE-TAG", &tag_ids),
            "joined_at_height": joined_at_height,
            "note_nonce": note_nonce,
        });
        let private_witness = json!({
            "owner_secret": owner_secret,
            "asset_id": asset_id,
            "value_bucket": value_bucket,
            "blinding_seed": blinding_seed,
        });
        let compliance_proof_root = privacy_pool_compliance_proof_root(
            PRIVACY_POOL_PROOF_SYSTEM_NOTE,
            &public_inputs,
            &private_witness,
        );
        Self::from_commitments(
            public_inputs["pool_id"].as_str().unwrap_or_default(),
            public_inputs["epoch_id"].as_str().unwrap_or_default(),
            public_inputs["owner_commitment"]
                .as_str()
                .unwrap_or_default(),
            public_inputs["asset_commitment"]
                .as_str()
                .unwrap_or_default(),
            public_inputs["value_bucket_commitment"]
                .as_str()
                .unwrap_or_default(),
            public_inputs["blinding_commitment"]
                .as_str()
                .unwrap_or_default(),
            public_inputs["disclosure_policy_id"]
                .as_str()
                .unwrap_or_default(),
            public_inputs["viewing_committee_id"]
                .as_str()
                .unwrap_or_default(),
            tag_ids,
            joined_at_height,
            note_nonce,
            expires_at_height,
            compliance_proof_root,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_commitments(
        pool_id: impl Into<String>,
        epoch_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        asset_commitment: impl Into<String>,
        value_bucket_commitment: impl Into<String>,
        blinding_commitment: impl Into<String>,
        disclosure_policy_id: impl Into<String>,
        viewing_committee_id: impl Into<String>,
        tag_ids: Vec<String>,
        joined_at_height: u64,
        note_nonce: u64,
        expires_at_height: u64,
        compliance_proof_root: impl Into<String>,
    ) -> PrivacyPoolResult<Self> {
        let tag_ids = normalize_raw_set(tag_ids, "privacy pool note tags")?;
        let mut note = Self {
            note_id: String::new(),
            pool_id: pool_id.into(),
            epoch_id: epoch_id.into(),
            owner_commitment: owner_commitment.into(),
            asset_commitment: asset_commitment.into(),
            value_bucket_commitment: value_bucket_commitment.into(),
            blinding_commitment: blinding_commitment.into(),
            disclosure_policy_id: disclosure_policy_id.into(),
            viewing_committee_id: viewing_committee_id.into(),
            tag_root: privacy_pool_string_root("PRIVACY-POOL-NOTE-TAG", &tag_ids),
            tag_ids,
            commitment: String::new(),
            leaf_hash: String::new(),
            joined_at_height,
            expires_at_height,
            note_nonce,
            compliance_proof_root: compliance_proof_root.into(),
            status: "unspent".to_string(),
        };
        note.commitment = privacy_pool_note_commitment(
            &note.pool_id,
            &note.epoch_id,
            &note.owner_commitment,
            &note.asset_commitment,
            &note.value_bucket_commitment,
            &note.blinding_commitment,
            &note.disclosure_policy_id,
            &note.viewing_committee_id,
            &note.tag_root,
            note.note_nonce,
        );
        note.note_id =
            privacy_pool_note_id(&note.commitment, note.joined_at_height, note.note_nonce);
        note.leaf_hash = privacy_pool_note_leaf_hash(&note.membership_record());
        note.validate()?;
        Ok(note)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "privacy_pool_note_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "epoch_id": self.epoch_id,
            "owner_commitment": self.owner_commitment,
            "asset_commitment": self.asset_commitment,
            "value_bucket_commitment": self.value_bucket_commitment,
            "blinding_commitment": self.blinding_commitment,
            "disclosure_policy_id": self.disclosure_policy_id,
            "viewing_committee_id": self.viewing_committee_id,
            "tag_root": self.tag_root,
            "joined_at_height": self.joined_at_height,
            "expires_at_height": self.expires_at_height,
            "note_nonce": self.note_nonce,
        })
    }

    pub fn membership_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("privacy pool note membership record object");
        object.insert("note_id".to_string(), Value::String(self.note_id.clone()));
        object.insert(
            "commitment".to_string(),
            Value::String(self.commitment.clone()),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.membership_record();
        let object = record
            .as_object_mut()
            .expect("privacy pool note public record object");
        object.insert(
            "leaf_hash".to_string(),
            Value::String(self.leaf_hash.clone()),
        );
        object.insert(
            "tag_ids".to_string(),
            Value::Array(
                self.tag_ids
                    .iter()
                    .map(|tag_id| Value::String(tag_id.clone()))
                    .collect(),
            ),
        );
        object.insert(
            "compliance_proof_root".to_string(),
            Value::String(self.compliance_proof_root.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> PrivacyPoolResult<String> {
        ensure_non_empty(&self.note_id, "privacy pool note id")?;
        ensure_non_empty(&self.pool_id, "privacy pool note pool id")?;
        ensure_non_empty(&self.epoch_id, "privacy pool note epoch id")?;
        ensure_non_empty(&self.owner_commitment, "privacy pool note owner commitment")?;
        ensure_non_empty(&self.asset_commitment, "privacy pool note asset commitment")?;
        ensure_non_empty(
            &self.value_bucket_commitment,
            "privacy pool note value bucket commitment",
        )?;
        ensure_non_empty(
            &self.blinding_commitment,
            "privacy pool note blinding commitment",
        )?;
        ensure_non_empty(
            &self.disclosure_policy_id,
            "privacy pool note disclosure policy",
        )?;
        ensure_non_empty(
            &self.viewing_committee_id,
            "privacy pool note viewing committee",
        )?;
        if self.tag_root != privacy_pool_string_root("PRIVACY-POOL-NOTE-TAG", &self.tag_ids) {
            return Err("privacy pool note tag root mismatch".to_string());
        }
        let expected_commitment = privacy_pool_note_commitment(
            &self.pool_id,
            &self.epoch_id,
            &self.owner_commitment,
            &self.asset_commitment,
            &self.value_bucket_commitment,
            &self.blinding_commitment,
            &self.disclosure_policy_id,
            &self.viewing_committee_id,
            &self.tag_root,
            self.note_nonce,
        );
        if self.commitment != expected_commitment {
            return Err("privacy pool note commitment mismatch".to_string());
        }
        if self.note_id
            != privacy_pool_note_id(&self.commitment, self.joined_at_height, self.note_nonce)
        {
            return Err("privacy pool note id mismatch".to_string());
        }
        if self.leaf_hash != privacy_pool_note_leaf_hash(&self.membership_record()) {
            return Err("privacy pool note leaf hash mismatch".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.joined_at_height {
            return Err("privacy pool note expiry must be after join height".to_string());
        }
        ensure_non_empty(
            &self.compliance_proof_root,
            "privacy pool note compliance proof root",
        )?;
        ensure_status(
            &self.status,
            &["unspent", "spent", "exited", "expired", "frozen"],
        )?;
        Ok(self.note_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierRecord {
    pub nullifier: String,
    pub pool_id: String,
    pub epoch_id: String,
    pub note_id: String,
    pub note_commitment: String,
    pub nullifier_secret_commitment: String,
    pub exit_context_root: String,
    pub exit_commitment: String,
    pub action_kind: String,
    pub spent_at_height: u64,
    pub compliance_proof_root: String,
    pub status: String,
}

impl NullifierRecord {
    pub fn for_note(
        note: &PoolNoteCommitment,
        nullifier_secret: &str,
        action_kind: impl Into<String>,
        exit_context: &Value,
        exit_commitment: impl Into<String>,
        spent_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        note.validate()?;
        ensure_non_empty(nullifier_secret, "privacy pool nullifier secret")?;
        let action_kind = normalize_label(action_kind.into());
        ensure_non_empty(&action_kind, "privacy pool nullifier action kind")?;
        let exit_context_root =
            privacy_pool_payload_root("PRIVACY-POOL-NULLIFIER-CONTEXT", exit_context);
        let exit_commitment = exit_commitment.into();
        ensure_non_empty(&exit_commitment, "privacy pool nullifier exit commitment")?;
        let nullifier_secret_commitment =
            privacy_pool_nullifier_secret_commitment(nullifier_secret);
        let nullifier = privacy_pool_nullifier(
            &note.note_id,
            &note.commitment,
            &nullifier_secret_commitment,
            &exit_context_root,
        );
        let public_inputs = json!({
            "pool_id": note.pool_id,
            "epoch_id": note.epoch_id,
            "note_id": note.note_id,
            "note_commitment": note.commitment,
            "nullifier": nullifier,
            "nullifier_secret_commitment": nullifier_secret_commitment,
            "exit_context_root": exit_context_root,
            "exit_commitment": exit_commitment,
            "action_kind": action_kind,
            "spent_at_height": spent_at_height,
        });
        let private_witness = json!({
            "nullifier_secret": nullifier_secret,
            "exit_context": exit_context,
        });
        let compliance_proof_root = privacy_pool_compliance_proof_root(
            PRIVACY_POOL_PROOF_SYSTEM_EXIT,
            &public_inputs,
            &private_witness,
        );
        let record = Self {
            nullifier,
            pool_id: note.pool_id.clone(),
            epoch_id: note.epoch_id.clone(),
            note_id: note.note_id.clone(),
            note_commitment: note.commitment.clone(),
            nullifier_secret_commitment,
            exit_context_root,
            exit_commitment,
            action_kind,
            spent_at_height,
            compliance_proof_root,
            status: "spent".to_string(),
        };
        record.validate_against_note(note)?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_pool_nullifier",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "nullifier": self.nullifier,
            "pool_id": self.pool_id,
            "epoch_id": self.epoch_id,
            "note_id": self.note_id,
            "note_commitment": self.note_commitment,
            "nullifier_secret_commitment": self.nullifier_secret_commitment,
            "exit_context_root": self.exit_context_root,
            "exit_commitment": self.exit_commitment,
            "action_kind": self.action_kind,
            "spent_at_height": self.spent_at_height,
            "compliance_proof_root": self.compliance_proof_root,
            "status": self.status,
        })
    }

    pub fn validate_against_note(&self, note: &PoolNoteCommitment) -> PrivacyPoolResult<String> {
        if self.pool_id != note.pool_id
            || self.epoch_id != note.epoch_id
            || self.note_id != note.note_id
            || self.note_commitment != note.commitment
        {
            return Err("privacy pool nullifier note reference mismatch".to_string());
        }
        let expected_nullifier = privacy_pool_nullifier(
            &self.note_id,
            &self.note_commitment,
            &self.nullifier_secret_commitment,
            &self.exit_context_root,
        );
        if self.nullifier != expected_nullifier {
            return Err("privacy pool nullifier mismatch".to_string());
        }
        ensure_non_empty(
            &self.compliance_proof_root,
            "privacy pool nullifier compliance proof root",
        )?;
        ensure_status(&self.status, &["pending", "spent", "revoked"])?;
        Ok(self.nullifier.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierRegistry {
    pub registry_id: String,
    pub pool_id: String,
    pub epoch_id: String,
    pub nullifier_root: String,
    pub nullifier_count: u64,
    pub latest_nullifier: String,
    pub updated_at_height: u64,
    pub status: String,
}

impl NullifierRegistry {
    pub fn from_nullifiers(
        pool_id: impl Into<String>,
        epoch_id: impl Into<String>,
        nullifiers: &[NullifierRecord],
        updated_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        let pool_id = pool_id.into();
        let epoch_id = epoch_id.into();
        ensure_non_empty(&pool_id, "privacy pool nullifier registry pool id")?;
        ensure_non_empty(&epoch_id, "privacy pool nullifier registry epoch id")?;
        let nullifier_root = privacy_pool_nullifier_root(nullifiers);
        let latest_nullifier = nullifiers
            .iter()
            .map(|record| record.nullifier.clone())
            .max()
            .unwrap_or_default();
        let nullifier_count = nullifiers.len() as u64;
        let registry_id = privacy_pool_nullifier_registry_id(
            &pool_id,
            &epoch_id,
            &nullifier_root,
            nullifier_count,
            updated_at_height,
        );
        let registry = Self {
            registry_id,
            pool_id,
            epoch_id,
            nullifier_root,
            nullifier_count,
            latest_nullifier,
            updated_at_height,
            status: "active".to_string(),
        };
        registry.validate()?;
        Ok(registry)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_pool_nullifier_registry",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "registry_id": self.registry_id,
            "pool_id": self.pool_id,
            "epoch_id": self.epoch_id,
            "nullifier_root": self.nullifier_root,
            "nullifier_count": self.nullifier_count,
            "latest_nullifier": self.latest_nullifier,
            "updated_at_height": self.updated_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivacyPoolResult<String> {
        ensure_non_empty(&self.registry_id, "privacy pool nullifier registry id")?;
        ensure_non_empty(&self.pool_id, "privacy pool nullifier registry pool id")?;
        ensure_non_empty(&self.epoch_id, "privacy pool nullifier registry epoch id")?;
        ensure_non_empty(&self.nullifier_root, "privacy pool nullifier registry root")?;
        ensure_status(&self.status, &["active", "sealed", "superseded"])?;
        if self.registry_id
            != privacy_pool_nullifier_registry_id(
                &self.pool_id,
                &self.epoch_id,
                &self.nullifier_root,
                self.nullifier_count,
                self.updated_at_height,
            )
        {
            return Err("privacy pool nullifier registry id mismatch".to_string());
        }
        Ok(self.registry_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolJoin {
    pub join_id: String,
    pub pool_id: String,
    pub epoch_id: String,
    pub note_id: String,
    pub note_commitment: String,
    pub note_leaf_hash: String,
    pub membership_root_after: String,
    pub tag_root: String,
    pub joined_at_height: u64,
    pub proof_system: String,
    pub compliance_proof_root: String,
    pub status: String,
}

impl PoolJoin {
    pub fn new(
        note: &PoolNoteCommitment,
        membership_root_after: impl Into<String>,
        joined_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        note.validate()?;
        let mut join = Self {
            join_id: String::new(),
            pool_id: note.pool_id.clone(),
            epoch_id: note.epoch_id.clone(),
            note_id: note.note_id.clone(),
            note_commitment: note.commitment.clone(),
            note_leaf_hash: note.leaf_hash.clone(),
            membership_root_after: membership_root_after.into(),
            tag_root: note.tag_root.clone(),
            joined_at_height,
            proof_system: PRIVACY_POOL_PROOF_SYSTEM_JOIN.to_string(),
            compliance_proof_root: note.compliance_proof_root.clone(),
            status: "applied".to_string(),
        };
        join.join_id = privacy_pool_join_id(&join.identity_record());
        join.validate()?;
        Ok(join)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "privacy_pool_join",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "epoch_id": self.epoch_id,
            "note_id": self.note_id,
            "note_commitment": self.note_commitment,
            "note_leaf_hash": self.note_leaf_hash,
            "membership_root_after": self.membership_root_after,
            "tag_root": self.tag_root,
            "joined_at_height": self.joined_at_height,
            "proof_system": self.proof_system,
            "compliance_proof_root": self.compliance_proof_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("privacy pool join public record object");
        object.insert("join_id".to_string(), Value::String(self.join_id.clone()));
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> PrivacyPoolResult<String> {
        ensure_non_empty(&self.join_id, "privacy pool join id")?;
        ensure_non_empty(&self.pool_id, "privacy pool join pool id")?;
        ensure_non_empty(&self.epoch_id, "privacy pool join epoch id")?;
        ensure_non_empty(&self.note_id, "privacy pool join note id")?;
        ensure_non_empty(&self.note_commitment, "privacy pool join note commitment")?;
        ensure_non_empty(&self.note_leaf_hash, "privacy pool join note leaf")?;
        ensure_non_empty(
            &self.membership_root_after,
            "privacy pool join membership root",
        )?;
        ensure_non_empty(&self.compliance_proof_root, "privacy pool join proof root")?;
        ensure_status(&self.status, &["pending", "applied", "rejected"])?;
        if self.join_id != privacy_pool_join_id(&self.identity_record()) {
            return Err("privacy pool join id mismatch".to_string());
        }
        Ok(self.join_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolExit {
    pub exit_id: String,
    pub pool_id: String,
    pub epoch_id: String,
    pub note_id: String,
    pub note_commitment: String,
    pub nullifier: String,
    pub exit_context_root: String,
    pub withdrawal_commitment: String,
    pub membership_root: String,
    pub nullifier_root_after: String,
    pub exited_at_height: u64,
    pub proof_system: String,
    pub compliance_proof_root: String,
    pub status: String,
}

impl PoolExit {
    pub fn new(
        note: &PoolNoteCommitment,
        nullifier: &NullifierRecord,
        membership_root: impl Into<String>,
        nullifier_root_after: impl Into<String>,
        exited_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        nullifier.validate_against_note(note)?;
        let mut exit = Self {
            exit_id: String::new(),
            pool_id: note.pool_id.clone(),
            epoch_id: note.epoch_id.clone(),
            note_id: note.note_id.clone(),
            note_commitment: note.commitment.clone(),
            nullifier: nullifier.nullifier.clone(),
            exit_context_root: nullifier.exit_context_root.clone(),
            withdrawal_commitment: nullifier.exit_commitment.clone(),
            membership_root: membership_root.into(),
            nullifier_root_after: nullifier_root_after.into(),
            exited_at_height,
            proof_system: PRIVACY_POOL_PROOF_SYSTEM_EXIT.to_string(),
            compliance_proof_root: nullifier.compliance_proof_root.clone(),
            status: "applied".to_string(),
        };
        exit.exit_id = privacy_pool_exit_id(&exit.identity_record());
        exit.validate()?;
        Ok(exit)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "privacy_pool_exit",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "epoch_id": self.epoch_id,
            "note_id": self.note_id,
            "note_commitment": self.note_commitment,
            "nullifier": self.nullifier,
            "exit_context_root": self.exit_context_root,
            "withdrawal_commitment": self.withdrawal_commitment,
            "membership_root": self.membership_root,
            "nullifier_root_after": self.nullifier_root_after,
            "exited_at_height": self.exited_at_height,
            "proof_system": self.proof_system,
            "compliance_proof_root": self.compliance_proof_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("privacy pool exit public record object");
        object.insert("exit_id".to_string(), Value::String(self.exit_id.clone()));
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> PrivacyPoolResult<String> {
        ensure_non_empty(&self.exit_id, "privacy pool exit id")?;
        ensure_non_empty(&self.pool_id, "privacy pool exit pool id")?;
        ensure_non_empty(&self.epoch_id, "privacy pool exit epoch id")?;
        ensure_non_empty(&self.note_id, "privacy pool exit note id")?;
        ensure_non_empty(&self.note_commitment, "privacy pool exit note commitment")?;
        ensure_non_empty(&self.nullifier, "privacy pool exit nullifier")?;
        ensure_non_empty(&self.exit_context_root, "privacy pool exit context root")?;
        ensure_non_empty(
            &self.withdrawal_commitment,
            "privacy pool exit withdrawal commitment",
        )?;
        ensure_non_empty(&self.membership_root, "privacy pool exit membership root")?;
        ensure_non_empty(
            &self.nullifier_root_after,
            "privacy pool exit nullifier root",
        )?;
        ensure_non_empty(&self.compliance_proof_root, "privacy pool exit proof root")?;
        ensure_status(&self.status, &["pending", "applied", "rejected"])?;
        if self.exit_id != privacy_pool_exit_id(&self.identity_record()) {
            return Err("privacy pool exit id mismatch".to_string());
        }
        Ok(self.exit_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveDisclosureReceipt {
    pub receipt_id: String,
    pub pool_id: String,
    pub epoch_id: String,
    pub note_id: String,
    pub note_commitment: String,
    pub policy_id: String,
    pub committee_id: String,
    pub recipient_commitment: String,
    pub disclosed_fields: Vec<String>,
    pub field_root: String,
    pub revealed_record_root: String,
    pub statement_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub proof_system: String,
    pub compliance_proof_root: String,
    pub status: String,
}

impl SelectiveDisclosureReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        note: &PoolNoteCommitment,
        policy: &SelectiveDisclosurePolicy,
        committee: &ViewingCommittee,
        recipient: &str,
        disclosed_fields: Vec<String>,
        revealed_record: &Value,
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        note.validate()?;
        policy.validate()?;
        committee.validate()?;
        ensure_non_empty(recipient, "privacy pool disclosure recipient")?;
        if policy.status != "active" {
            return Err("privacy pool disclosure policy is not active".to_string());
        }
        if committee.status != "active" {
            return Err("privacy pool viewing committee is not active".to_string());
        }
        let disclosed_fields =
            normalize_label_set(disclosed_fields, "privacy pool disclosed fields")?;
        if disclosed_fields.len() > policy.max_disclosure_depth as usize {
            return Err("privacy pool disclosure exceeds policy depth".to_string());
        }
        for field in &disclosed_fields {
            if !policy.allowed_fields.contains(field) {
                return Err("privacy pool disclosure field is not allowed".to_string());
            }
        }
        if expires_at_height <= issued_at_height {
            return Err("privacy pool disclosure expiry must be after issue height".to_string());
        }
        let field_root =
            privacy_pool_string_root("PRIVACY-POOL-DISCLOSURE-FIELD", &disclosed_fields);
        let revealed_record_root =
            privacy_pool_payload_root("PRIVACY-POOL-DISCLOSURE-REVEALED", revealed_record);
        let recipient_commitment = privacy_pool_recipient_commitment(recipient);
        let statement_root = privacy_pool_disclosure_statement_root(
            &note.note_id,
            &note.commitment,
            &policy.policy_id,
            &committee.committee_id,
            &recipient_commitment,
            &field_root,
            &revealed_record_root,
        );
        let public_inputs = json!({
            "pool_id": note.pool_id,
            "epoch_id": note.epoch_id,
            "note_id": note.note_id,
            "note_commitment": note.commitment,
            "policy_id": policy.policy_id,
            "committee_id": committee.committee_id,
            "recipient_commitment": recipient_commitment,
            "field_root": field_root,
            "revealed_record_root": revealed_record_root,
            "statement_root": statement_root,
        });
        let private_witness = json!({
            "revealed_record": revealed_record,
        });
        let mut receipt = Self {
            receipt_id: String::new(),
            pool_id: note.pool_id.clone(),
            epoch_id: note.epoch_id.clone(),
            note_id: note.note_id.clone(),
            note_commitment: note.commitment.clone(),
            policy_id: policy.policy_id.clone(),
            committee_id: committee.committee_id.clone(),
            recipient_commitment,
            disclosed_fields,
            field_root,
            revealed_record_root,
            statement_root,
            issued_at_height,
            expires_at_height,
            proof_system: PRIVACY_POOL_PROOF_SYSTEM_DISCLOSURE.to_string(),
            compliance_proof_root: privacy_pool_compliance_proof_root(
                PRIVACY_POOL_PROOF_SYSTEM_DISCLOSURE,
                &public_inputs,
                &private_witness,
            ),
            status: "issued".to_string(),
        };
        receipt.receipt_id = privacy_pool_disclosure_receipt_id(&receipt.identity_record());
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "privacy_pool_selective_disclosure_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "epoch_id": self.epoch_id,
            "note_id": self.note_id,
            "note_commitment": self.note_commitment,
            "policy_id": self.policy_id,
            "committee_id": self.committee_id,
            "recipient_commitment": self.recipient_commitment,
            "field_root": self.field_root,
            "revealed_record_root": self.revealed_record_root,
            "statement_root": self.statement_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "proof_system": self.proof_system,
            "compliance_proof_root": self.compliance_proof_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("selective disclosure receipt public record object");
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
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> PrivacyPoolResult<String> {
        ensure_non_empty(&self.receipt_id, "privacy pool disclosure receipt id")?;
        ensure_non_empty(&self.pool_id, "privacy pool disclosure pool id")?;
        ensure_non_empty(&self.epoch_id, "privacy pool disclosure epoch id")?;
        ensure_non_empty(&self.note_id, "privacy pool disclosure note id")?;
        ensure_non_empty(
            &self.note_commitment,
            "privacy pool disclosure note commitment",
        )?;
        ensure_non_empty(&self.policy_id, "privacy pool disclosure policy id")?;
        ensure_non_empty(&self.committee_id, "privacy pool disclosure committee id")?;
        ensure_non_empty(
            &self.recipient_commitment,
            "privacy pool disclosure recipient commitment",
        )?;
        if self.field_root
            != privacy_pool_string_root("PRIVACY-POOL-DISCLOSURE-FIELD", &self.disclosed_fields)
        {
            return Err("privacy pool disclosure field root mismatch".to_string());
        }
        if self.statement_root
            != privacy_pool_disclosure_statement_root(
                &self.note_id,
                &self.note_commitment,
                &self.policy_id,
                &self.committee_id,
                &self.recipient_commitment,
                &self.field_root,
                &self.revealed_record_root,
            )
        {
            return Err("privacy pool disclosure statement root mismatch".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("privacy pool disclosure expiry must be after issue height".to_string());
        }
        ensure_non_empty(
            &self.compliance_proof_root,
            "privacy pool disclosure proof root",
        )?;
        ensure_status(&self.status, &["issued", "revoked", "expired"])?;
        if self.receipt_id != privacy_pool_disclosure_receipt_id(&self.identity_record()) {
            return Err("privacy pool disclosure receipt id mismatch".to_string());
        }
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceProofRoot {
    pub proof_id: String,
    pub pool_id: String,
    pub epoch_id: String,
    pub proof_system: String,
    pub public_input_root: String,
    pub private_witness_root: String,
    pub policy_root: String,
    pub committee_root: String,
    pub membership_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub issued_at_height: u64,
    pub status: String,
}

impl ComplianceProofRoot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: impl Into<String>,
        epoch_id: impl Into<String>,
        proof_system: impl Into<String>,
        public_inputs: &Value,
        private_witness: &Value,
        policy_root: impl Into<String>,
        committee_root: impl Into<String>,
        membership_root: impl Into<String>,
        nullifier_root: impl Into<String>,
        issued_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        let proof_system = proof_system.into();
        let public_input_root =
            privacy_pool_payload_root("PRIVACY-POOL-COMPLIANCE-PUBLIC-INPUT", public_inputs);
        let private_witness_root =
            privacy_pool_payload_root("PRIVACY-POOL-COMPLIANCE-PRIVATE-WITNESS", private_witness);
        Self::from_roots(
            pool_id,
            epoch_id,
            proof_system,
            public_input_root,
            private_witness_root,
            policy_root,
            committee_root,
            membership_root,
            nullifier_root,
            issued_at_height,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_roots(
        pool_id: impl Into<String>,
        epoch_id: impl Into<String>,
        proof_system: impl Into<String>,
        public_input_root: impl Into<String>,
        private_witness_root: impl Into<String>,
        policy_root: impl Into<String>,
        committee_root: impl Into<String>,
        membership_root: impl Into<String>,
        nullifier_root: impl Into<String>,
        issued_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        let mut proof = Self {
            proof_id: String::new(),
            pool_id: pool_id.into(),
            epoch_id: epoch_id.into(),
            proof_system: proof_system.into(),
            public_input_root: public_input_root.into(),
            private_witness_root: private_witness_root.into(),
            policy_root: policy_root.into(),
            committee_root: committee_root.into(),
            membership_root: membership_root.into(),
            nullifier_root: nullifier_root.into(),
            proof_root: String::new(),
            issued_at_height,
            status: "active".to_string(),
        };
        proof.proof_root = privacy_pool_compliance_proof_root_from_roots(
            &proof.proof_system,
            &proof.public_input_root,
            &proof.private_witness_root,
            &proof.policy_root,
            &proof.committee_root,
            &proof.membership_root,
            &proof.nullifier_root,
        );
        proof.proof_id = privacy_pool_compliance_proof_id(&proof.identity_record());
        proof.validate()?;
        Ok(proof)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "privacy_pool_compliance_proof_root",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "epoch_id": self.epoch_id,
            "proof_system": self.proof_system,
            "public_input_root": self.public_input_root,
            "private_witness_root": self.private_witness_root,
            "policy_root": self.policy_root,
            "committee_root": self.committee_root,
            "membership_root": self.membership_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "issued_at_height": self.issued_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("compliance proof public record object");
        object.insert("proof_id".to_string(), Value::String(self.proof_id.clone()));
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> PrivacyPoolResult<String> {
        ensure_non_empty(&self.proof_id, "privacy pool compliance proof id")?;
        ensure_non_empty(&self.pool_id, "privacy pool compliance proof pool id")?;
        ensure_non_empty(&self.epoch_id, "privacy pool compliance proof epoch id")?;
        ensure_non_empty(&self.proof_system, "privacy pool compliance proof system")?;
        ensure_non_empty(
            &self.public_input_root,
            "privacy pool compliance public input root",
        )?;
        ensure_non_empty(
            &self.private_witness_root,
            "privacy pool compliance private witness root",
        )?;
        let expected_proof_root = privacy_pool_compliance_proof_root_from_roots(
            &self.proof_system,
            &self.public_input_root,
            &self.private_witness_root,
            &self.policy_root,
            &self.committee_root,
            &self.membership_root,
            &self.nullifier_root,
        );
        if self.proof_root != expected_proof_root {
            return Err("privacy pool compliance proof root mismatch".to_string());
        }
        ensure_status(&self.status, &["active", "revoked", "expired"])?;
        if self.proof_id != privacy_pool_compliance_proof_id(&self.identity_record()) {
            return Err("privacy pool compliance proof id mismatch".to_string());
        }
        Ok(self.proof_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnonymitySetMetrics {
    pub metrics_id: String,
    pub pool_id: String,
    pub epoch_id: String,
    pub membership_root: String,
    pub nullifier_root: String,
    pub note_count: u64,
    pub active_note_count: u64,
    pub spent_nullifier_count: u64,
    pub unique_asset_commitment_count: u64,
    pub unique_note_tag_root_count: u64,
    pub pool_tag_count: u64,
    pub largest_equivalence_class: u64,
    pub smallest_equivalence_class: u64,
    pub effective_anonymity_set: u64,
    pub diversity_score_bps: u64,
    pub linkability_resistance_bps: u64,
    pub computed_at_height: u64,
}

impl AnonymitySetMetrics {
    pub fn from_records(
        pool_id: impl Into<String>,
        epoch_id: impl Into<String>,
        notes: &[PoolNoteCommitment],
        nullifiers: &[NullifierRecord],
        tags: &[PrivatePoolTag],
        computed_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        let pool_id = pool_id.into();
        let epoch_id = epoch_id.into();
        ensure_non_empty(&pool_id, "privacy pool metrics pool id")?;
        ensure_non_empty(&epoch_id, "privacy pool metrics epoch id")?;
        let membership_root = privacy_pool_membership_root(notes);
        let nullifier_root = privacy_pool_nullifier_root(nullifiers);
        let active_notes = notes
            .iter()
            .filter(|note| note.status == "unspent")
            .collect::<Vec<_>>();
        let active_note_count = active_notes.len() as u64;
        let mut asset_buckets = BTreeMap::<String, u64>::new();
        let mut tag_buckets = BTreeMap::<String, u64>::new();
        for note in active_notes {
            *asset_buckets
                .entry(note.asset_commitment.clone())
                .or_insert(0) += 1;
            *tag_buckets.entry(note.tag_root.clone()).or_insert(0) += 1;
        }
        let unique_asset_commitment_count = asset_buckets.len() as u64;
        let unique_note_tag_root_count = tag_buckets.len() as u64;
        let bucket_counts = asset_buckets
            .values()
            .chain(tag_buckets.values())
            .copied()
            .filter(|value| *value > 0)
            .collect::<Vec<_>>();
        let largest_equivalence_class = bucket_counts.iter().copied().max().unwrap_or(0);
        let smallest_equivalence_class = bucket_counts.iter().copied().min().unwrap_or(0);
        let effective_anonymity_set = if active_note_count == 0 {
            0
        } else {
            smallest_equivalence_class.max(1)
        };
        let diversity_score_bps = if active_note_count == 0 {
            0
        } else {
            unique_asset_commitment_count
                .saturating_add(unique_note_tag_root_count)
                .saturating_mul(10_000)
                .checked_div(active_note_count.saturating_mul(2).max(1))
                .unwrap_or(0)
                .min(10_000)
        };
        let linkability_resistance_bps = if active_note_count == 0 {
            0
        } else {
            active_note_count
                .saturating_sub(largest_equivalence_class)
                .saturating_mul(10_000)
                .checked_div(active_note_count)
                .unwrap_or(0)
        };
        let mut metrics = Self {
            metrics_id: String::new(),
            pool_id,
            epoch_id,
            membership_root,
            nullifier_root,
            note_count: notes.len() as u64,
            active_note_count,
            spent_nullifier_count: nullifiers.len() as u64,
            unique_asset_commitment_count,
            unique_note_tag_root_count,
            pool_tag_count: tags.len() as u64,
            largest_equivalence_class,
            smallest_equivalence_class,
            effective_anonymity_set,
            diversity_score_bps,
            linkability_resistance_bps,
            computed_at_height,
        };
        metrics.metrics_id = privacy_pool_anonymity_metrics_id(&metrics.identity_record());
        metrics.validate()?;
        Ok(metrics)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "privacy_pool_anonymity_set_metrics",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "epoch_id": self.epoch_id,
            "membership_root": self.membership_root,
            "nullifier_root": self.nullifier_root,
            "note_count": self.note_count,
            "active_note_count": self.active_note_count,
            "spent_nullifier_count": self.spent_nullifier_count,
            "unique_asset_commitment_count": self.unique_asset_commitment_count,
            "unique_note_tag_root_count": self.unique_note_tag_root_count,
            "pool_tag_count": self.pool_tag_count,
            "largest_equivalence_class": self.largest_equivalence_class,
            "smallest_equivalence_class": self.smallest_equivalence_class,
            "effective_anonymity_set": self.effective_anonymity_set,
            "diversity_score_bps": self.diversity_score_bps,
            "linkability_resistance_bps": self.linkability_resistance_bps,
            "computed_at_height": self.computed_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("anonymity set metrics public record object")
            .insert(
                "metrics_id".to_string(),
                Value::String(self.metrics_id.clone()),
            );
        record
    }

    pub fn validate(&self) -> PrivacyPoolResult<String> {
        ensure_non_empty(&self.metrics_id, "privacy pool metrics id")?;
        ensure_non_empty(&self.pool_id, "privacy pool metrics pool id")?;
        ensure_non_empty(&self.epoch_id, "privacy pool metrics epoch id")?;
        ensure_non_empty(
            &self.membership_root,
            "privacy pool metrics membership root",
        )?;
        ensure_non_empty(&self.nullifier_root, "privacy pool metrics nullifier root")?;
        if self.active_note_count > self.note_count {
            return Err("privacy pool metrics active notes exceed notes".to_string());
        }
        if self.effective_anonymity_set > self.active_note_count {
            return Err("privacy pool metrics effective set exceeds active notes".to_string());
        }
        if self.diversity_score_bps > 10_000 || self.linkability_resistance_bps > 10_000 {
            return Err("privacy pool metrics bps exceeds 10000".to_string());
        }
        if self.metrics_id != privacy_pool_anonymity_metrics_id(&self.identity_record()) {
            return Err("privacy pool metrics id mismatch".to_string());
        }
        Ok(self.metrics_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPoolEpoch {
    pub pool_id: String,
    pub epoch_id: String,
    pub epoch_index: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub membership_root: String,
    pub note_commitment_root: String,
    pub nullifier_root: String,
    pub nullifier_registry_root: String,
    pub disclosure_policy_root: String,
    pub viewing_committee_root: String,
    pub tag_root: String,
    pub compliance_proof_root: String,
    pub metrics_root: String,
    pub opened_at_height: u64,
    pub closed_at_height: u64,
    pub status: String,
}

impl PrivacyPoolEpoch {
    pub fn new(
        pool_id: impl Into<String>,
        epoch_index: u64,
        start_height: u64,
        end_height: u64,
        opened_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        let pool_id = pool_id.into();
        ensure_non_empty(&pool_id, "privacy pool epoch pool id")?;
        if end_height <= start_height {
            return Err("privacy pool epoch end must be after start".to_string());
        }
        let epoch_id = privacy_pool_epoch_id(&pool_id, epoch_index, start_height, end_height);
        let epoch = Self {
            pool_id,
            epoch_id,
            epoch_index,
            start_height,
            end_height,
            membership_root: privacy_pool_membership_root(&[]),
            note_commitment_root: privacy_pool_note_commitment_root(&[]),
            nullifier_root: privacy_pool_nullifier_root(&[]),
            nullifier_registry_root: privacy_pool_nullifier_registry_root(&[]),
            disclosure_policy_root: privacy_pool_disclosure_policy_root(&[]),
            viewing_committee_root: privacy_pool_viewing_committee_root(&[]),
            tag_root: privacy_pool_tag_root(&[]),
            compliance_proof_root: privacy_pool_compliance_proof_anchor_root(&[]),
            metrics_root: privacy_pool_anonymity_metrics_root(&[]),
            opened_at_height,
            closed_at_height: 0,
            status: "open".to_string(),
        };
        epoch.validate()?;
        Ok(epoch)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "privacy_pool_epoch",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "end_height": self.end_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("privacy pool epoch public record object");
        object.insert("epoch_id".to_string(), Value::String(self.epoch_id.clone()));
        object.insert(
            "membership_root".to_string(),
            Value::String(self.membership_root.clone()),
        );
        object.insert(
            "note_commitment_root".to_string(),
            Value::String(self.note_commitment_root.clone()),
        );
        object.insert(
            "nullifier_root".to_string(),
            Value::String(self.nullifier_root.clone()),
        );
        object.insert(
            "nullifier_registry_root".to_string(),
            Value::String(self.nullifier_registry_root.clone()),
        );
        object.insert(
            "disclosure_policy_root".to_string(),
            Value::String(self.disclosure_policy_root.clone()),
        );
        object.insert(
            "viewing_committee_root".to_string(),
            Value::String(self.viewing_committee_root.clone()),
        );
        object.insert("tag_root".to_string(), Value::String(self.tag_root.clone()));
        object.insert(
            "compliance_proof_root".to_string(),
            Value::String(self.compliance_proof_root.clone()),
        );
        object.insert(
            "metrics_root".to_string(),
            Value::String(self.metrics_root.clone()),
        );
        object.insert(
            "opened_at_height".to_string(),
            Value::Number(self.opened_at_height.into()),
        );
        object.insert(
            "closed_at_height".to_string(),
            Value::Number(self.closed_at_height.into()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> PrivacyPoolResult<String> {
        ensure_non_empty(&self.pool_id, "privacy pool epoch pool id")?;
        ensure_non_empty(&self.epoch_id, "privacy pool epoch id")?;
        if self.end_height <= self.start_height {
            return Err("privacy pool epoch end must be after start".to_string());
        }
        if self.closed_at_height != 0 && self.closed_at_height < self.opened_at_height {
            return Err("privacy pool epoch close cannot precede open".to_string());
        }
        ensure_status(&self.status, &["open", "sealed", "closed"])?;
        if self.epoch_id
            != privacy_pool_epoch_id(
                &self.pool_id,
                self.epoch_index,
                self.start_height,
                self.end_height,
            )
        {
            return Err("privacy pool epoch id mismatch".to_string());
        }
        Ok(self.epoch_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPoolPublicRecord {
    pub record_id: String,
    pub object_kind: String,
    pub object_id: String,
    pub record_root: String,
    pub recorded_at_height: u64,
}

impl PrivacyPoolPublicRecord {
    pub fn new(
        object_kind: impl Into<String>,
        object_id: impl Into<String>,
        record: &Value,
        recorded_at_height: u64,
    ) -> PrivacyPoolResult<Self> {
        let object_kind = normalize_label(object_kind.into());
        let object_id = object_id.into();
        ensure_non_empty(&object_kind, "privacy pool public record object kind")?;
        ensure_non_empty(&object_id, "privacy pool public record object id")?;
        let record_root = privacy_pool_public_record_root(record);
        let record_id = privacy_pool_public_record_id(
            &object_kind,
            &object_id,
            &record_root,
            recorded_at_height,
        );
        let record = Self {
            record_id,
            object_kind,
            object_id,
            record_root,
            recorded_at_height,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_pool_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "record_root": self.record_root,
            "recorded_at_height": self.recorded_at_height,
        })
    }

    pub fn validate(&self) -> PrivacyPoolResult<String> {
        ensure_non_empty(&self.record_id, "privacy pool public record id")?;
        ensure_non_empty(&self.object_kind, "privacy pool public record object kind")?;
        ensure_non_empty(&self.object_id, "privacy pool public record object id")?;
        ensure_non_empty(&self.record_root, "privacy pool public record root")?;
        if self.record_id
            != privacy_pool_public_record_id(
                &self.object_kind,
                &self.object_id,
                &self.record_root,
                self.recorded_at_height,
            )
        {
            return Err("privacy pool public record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPoolStateRoots {
    pub epoch_root: String,
    pub membership_root: String,
    pub note_commitment_root: String,
    pub nullifier_root: String,
    pub nullifier_registry_root: String,
    pub join_root: String,
    pub exit_root: String,
    pub disclosure_policy_root: String,
    pub disclosure_receipt_root: String,
    pub viewing_committee_root: String,
    pub tag_root: String,
    pub anonymity_metrics_root: String,
    pub compliance_proof_root: String,
    pub public_record_root: String,
}

impl PrivacyPoolStateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_pool_state_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "epoch_root": self.epoch_root,
            "membership_root": self.membership_root,
            "note_commitment_root": self.note_commitment_root,
            "nullifier_root": self.nullifier_root,
            "nullifier_registry_root": self.nullifier_registry_root,
            "join_root": self.join_root,
            "exit_root": self.exit_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "disclosure_receipt_root": self.disclosure_receipt_root,
            "viewing_committee_root": self.viewing_committee_root,
            "tag_root": self.tag_root,
            "anonymity_metrics_root": self.anonymity_metrics_root,
            "compliance_proof_root": self.compliance_proof_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        privacy_pool_state_root(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPoolState {
    pub height: u64,
    pub nonce: u64,
    pub active_epoch_id: String,
    pub epochs: BTreeMap<String, PrivacyPoolEpoch>,
    pub note_commitments: BTreeMap<String, PoolNoteCommitment>,
    pub spent_nullifiers: BTreeMap<String, NullifierRecord>,
    pub nullifier_registries: BTreeMap<String, NullifierRegistry>,
    pub joins: BTreeMap<String, PoolJoin>,
    pub exits: BTreeMap<String, PoolExit>,
    pub disclosure_policies: BTreeMap<String, SelectiveDisclosurePolicy>,
    pub disclosure_receipts: BTreeMap<String, SelectiveDisclosureReceipt>,
    pub viewing_committees: BTreeMap<String, ViewingCommittee>,
    pub pool_tags: BTreeMap<String, PrivatePoolTag>,
    pub anonymity_metrics: BTreeMap<String, AnonymitySetMetrics>,
    pub compliance_proofs: BTreeMap<String, ComplianceProofRoot>,
    pub public_records: BTreeMap<String, PrivacyPoolPublicRecord>,
}

impl PrivacyPoolState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet() -> PrivacyPoolResult<Self> {
        let mut state = Self::new();
        state.height = 1;

        let policy = SelectiveDisclosurePolicy::new(
            "devnet selective disclosure",
            vec![
                "asset_bucket".to_string(),
                "bridge_route".to_string(),
                "defi_venue".to_string(),
                "jurisdiction_attestation".to_string(),
            ],
            vec![
                "devnet-auditor-a".to_string(),
                "devnet-auditor-b".to_string(),
                "devnet-compliance-safe".to_string(),
            ],
            PRIVACY_POOL_DEFAULT_MAX_DISCLOSURE_DEPTH,
            PRIVACY_POOL_DEFAULT_MIN_COMMITTEE_SIGNATURES,
            PRIVACY_POOL_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            vec!["compliance".to_string(), "settlement".to_string()],
            state.height,
        )?;
        let policy_id = policy.policy_id.clone();
        state.insert_disclosure_policy(policy)?;

        let committee = ViewingCommittee::new(
            "devnet viewing committee",
            vec![
                "devnet-viewer-a".to_string(),
                "devnet-viewer-b".to_string(),
                "devnet-viewer-c".to_string(),
            ],
            PRIVACY_POOL_DEFAULT_MIN_COMMITTEE_SIGNATURES,
            0,
            PRIVACY_POOL_DEFAULT_EPOCH_LENGTH * 4,
        )?;
        let committee_id = committee.committee_id.clone();
        state.insert_viewing_committee(committee)?;

        let bridge_tag = PrivatePoolTag::private_bridge(
            "devnet wxmr bridge",
            "monero-devnet",
            "wxmr-devnet",
            "nebula-l2",
            "low",
            &json!({"lane": "private-bridge", "settlement": "delayed-release"}),
            state.height,
        )?;
        let bridge_tag_id = bridge_tag.tag_id.clone();
        state.insert_pool_tag(bridge_tag)?;

        let defi_tag = PrivatePoolTag::defi(
            "devnet amm swap",
            "devnet-amm",
            "wxmr-devnet",
            "usdd-devnet",
            "medium",
            &json!({"lane": "defi-private-orderflow", "max_hops": 2}),
            state.height,
        )?;
        let defi_tag_id = defi_tag.tag_id.clone();
        state.insert_pool_tag(defi_tag)?;

        let pool_id = privacy_pool_id("devnet-shielded-pool", "wxmr-usdd");
        let epoch = PrivacyPoolEpoch::new(
            pool_id.as_str(),
            0,
            0,
            PRIVACY_POOL_DEFAULT_EPOCH_LENGTH,
            state.height,
        )?;
        let epoch_id = epoch.epoch_id.clone();
        state.open_epoch(epoch)?;

        let nonce = state.next_nonce();
        let note_a = PoolNoteCommitment::new(
            pool_id.as_str(),
            epoch_id.as_str(),
            "devnet-alice-view-secret",
            "wxmr-devnet",
            "10k_100k",
            "devnet-note-blinding-a",
            policy_id.as_str(),
            committee_id.as_str(),
            vec![bridge_tag_id.clone()],
            state.height,
            nonce,
            state.height + PRIVACY_POOL_DEFAULT_NOTE_TTL_BLOCKS,
        )?;
        let note_a_id = note_a.note_id.clone();
        state.join_pool(note_a)?;

        let nonce = state.next_nonce();
        let note_b = PoolNoteCommitment::new(
            pool_id.as_str(),
            epoch_id.as_str(),
            "devnet-bob-view-secret",
            "usdd-devnet",
            "100k_1m",
            "devnet-note-blinding-b",
            policy_id.as_str(),
            committee_id.as_str(),
            vec![defi_tag_id.clone()],
            state.height,
            nonce,
            state.height + PRIVACY_POOL_DEFAULT_NOTE_TTL_BLOCKS,
        )?;
        let note_b_id = note_b.note_id.clone();
        state.join_pool(note_b)?;

        let note_b = state
            .note_commitments
            .get(&note_b_id)
            .cloned()
            .ok_or_else(|| "devnet disclosure note missing".to_string())?;
        let policy = state
            .disclosure_policies
            .get(&policy_id)
            .cloned()
            .ok_or_else(|| "devnet disclosure policy missing".to_string())?;
        let committee = state
            .viewing_committees
            .get(&committee_id)
            .cloned()
            .ok_or_else(|| "devnet viewing committee missing".to_string())?;
        let disclosure = SelectiveDisclosureReceipt::new(
            &note_b,
            &policy,
            &committee,
            "devnet-compliance-safe",
            vec!["asset_bucket".to_string(), "defi_venue".to_string()],
            &json!({
                "asset_bucket": "100k_1m",
                "defi_venue": "devnet-amm",
            }),
            state.height,
            state.height + PRIVACY_POOL_DEFAULT_DISCLOSURE_TTL_BLOCKS,
        )?;
        state.issue_disclosure_receipt(disclosure)?;

        state.exit_pool(
            &note_a_id,
            "devnet-alice-nullifier-secret",
            "private_bridge_exit",
            &json!({"route": "monero-devnet", "bucket": "10k_100k"}),
            "devnet-alice-withdrawal-address",
        )?;

        state.record_anonymity_metrics(&pool_id, &epoch_id)?;
        let proof = ComplianceProofRoot::new(
            pool_id.as_str(),
            epoch_id.as_str(),
            PRIVACY_POOL_PROOF_SYSTEM_COMPLIANCE,
            &state.public_record_without_root(),
            &json!({"devnet": "compliance-safe-root-only"}),
            state.disclosure_policy_root(),
            state.viewing_committee_root(),
            state.membership_root(),
            state.nullifier_root(),
            state.height,
        )?;
        state.insert_compliance_proof(proof)?;
        state.refresh_epoch_roots(&epoch_id)?;
        let snapshot = state.public_record_without_root();
        state.publish_public_record("privacy_pool_devnet", "bootstrap", &snapshot)?;
        state.refresh_epoch_roots(&epoch_id)?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce = self.nonce.saturating_add(1);
        self.nonce
    }

    pub fn open_epoch(&mut self, epoch: PrivacyPoolEpoch) -> PrivacyPoolResult<String> {
        epoch.validate()?;
        if self.epochs.contains_key(&epoch.epoch_id) {
            return Err("privacy pool epoch already exists".to_string());
        }
        let epoch_id = epoch.epoch_id.clone();
        if self.active_epoch_id.is_empty() || epoch.status == "open" {
            self.active_epoch_id = epoch_id.clone();
        }
        self.epochs.insert(epoch_id.clone(), epoch);
        self.refresh_epoch_roots(&epoch_id)?;
        Ok(epoch_id)
    }

    pub fn insert_disclosure_policy(
        &mut self,
        policy: SelectiveDisclosurePolicy,
    ) -> PrivacyPoolResult<String> {
        policy.validate()?;
        let policy_id = policy.policy_id.clone();
        insert_unique_record(
            &mut self.disclosure_policies,
            policy_id.clone(),
            policy,
            "selective disclosure policy",
        )?;
        self.refresh_active_epoch_roots()?;
        Ok(policy_id)
    }

    pub fn insert_viewing_committee(
        &mut self,
        committee: ViewingCommittee,
    ) -> PrivacyPoolResult<String> {
        committee.validate()?;
        let committee_id = committee.committee_id.clone();
        insert_unique_record(
            &mut self.viewing_committees,
            committee_id.clone(),
            committee,
            "viewing committee",
        )?;
        self.refresh_active_epoch_roots()?;
        Ok(committee_id)
    }

    pub fn insert_pool_tag(&mut self, tag: PrivatePoolTag) -> PrivacyPoolResult<String> {
        tag.validate()?;
        let tag_id = tag.tag_id.clone();
        insert_unique_record(&mut self.pool_tags, tag_id.clone(), tag, "private pool tag")?;
        self.refresh_active_epoch_roots()?;
        Ok(tag_id)
    }

    pub fn insert_compliance_proof(
        &mut self,
        proof: ComplianceProofRoot,
    ) -> PrivacyPoolResult<String> {
        proof.validate()?;
        let proof_id = proof.proof_id.clone();
        insert_unique_record(
            &mut self.compliance_proofs,
            proof_id.clone(),
            proof,
            "compliance proof root",
        )?;
        self.refresh_active_epoch_roots()?;
        Ok(proof_id)
    }

    pub fn join_pool(&mut self, note: PoolNoteCommitment) -> PrivacyPoolResult<PoolJoin> {
        note.validate()?;
        if self.note_commitments.contains_key(&note.note_id) {
            return Err("privacy pool note already exists".to_string());
        }
        let epoch = self
            .epochs
            .get(&note.epoch_id)
            .ok_or_else(|| "privacy pool note references unknown epoch".to_string())?;
        if epoch.status != "open" {
            return Err("privacy pool epoch is not open".to_string());
        }
        if epoch.pool_id != note.pool_id {
            return Err("privacy pool note pool mismatch".to_string());
        }
        if !self
            .disclosure_policies
            .contains_key(&note.disclosure_policy_id)
        {
            return Err("privacy pool note references unknown disclosure policy".to_string());
        }
        if !self
            .viewing_committees
            .contains_key(&note.viewing_committee_id)
        {
            return Err("privacy pool note references unknown viewing committee".to_string());
        }
        for tag_id in &note.tag_ids {
            if !self.pool_tags.contains_key(tag_id) {
                return Err("privacy pool note references unknown pool tag".to_string());
            }
        }
        self.note_commitments
            .insert(note.note_id.clone(), note.clone());
        let membership_root_after = self.epoch_membership_root(&note.epoch_id);
        let join = PoolJoin::new(&note, membership_root_after, self.height)?;
        self.joins.insert(join.join_id.clone(), join.clone());
        self.refresh_epoch_roots(&note.epoch_id)?;
        Ok(join)
    }

    pub fn exit_pool(
        &mut self,
        note_id: &str,
        nullifier_secret: &str,
        action_kind: impl Into<String>,
        exit_context: &Value,
        withdrawal_target: &str,
    ) -> PrivacyPoolResult<PoolExit> {
        let note = self
            .note_commitments
            .get(note_id)
            .cloned()
            .ok_or_else(|| "privacy pool exit references unknown note".to_string())?;
        note.validate()?;
        if note.status != "unspent" {
            return Err("privacy pool exit note is not unspent".to_string());
        }
        let withdrawal_commitment = privacy_pool_recipient_commitment(withdrawal_target);
        let nullifier = NullifierRecord::for_note(
            &note,
            nullifier_secret,
            action_kind,
            exit_context,
            withdrawal_commitment,
            self.height,
        )?;
        if self.spent_nullifiers.contains_key(&nullifier.nullifier) {
            return Err("privacy pool nullifier already spent".to_string());
        }
        self.spent_nullifiers
            .insert(nullifier.nullifier.clone(), nullifier.clone());
        if let Some(stored_note) = self.note_commitments.get_mut(note_id) {
            stored_note.status = "spent".to_string();
        }
        self.refresh_nullifier_registry(&note.pool_id, &note.epoch_id)?;
        let membership_root = self.epoch_membership_root(&note.epoch_id);
        let nullifier_root_after = self.epoch_nullifier_root(&note.epoch_id);
        let exit = PoolExit::new(
            &note,
            &nullifier,
            membership_root,
            nullifier_root_after,
            self.height,
        )?;
        self.exits.insert(exit.exit_id.clone(), exit.clone());
        self.refresh_epoch_roots(&note.epoch_id)?;
        Ok(exit)
    }

    pub fn issue_disclosure_receipt(
        &mut self,
        receipt: SelectiveDisclosureReceipt,
    ) -> PrivacyPoolResult<String> {
        receipt.validate()?;
        if !self.note_commitments.contains_key(&receipt.note_id) {
            return Err("privacy pool disclosure references unknown note".to_string());
        }
        if !self.disclosure_policies.contains_key(&receipt.policy_id) {
            return Err("privacy pool disclosure references unknown policy".to_string());
        }
        if !self.viewing_committees.contains_key(&receipt.committee_id) {
            return Err("privacy pool disclosure references unknown committee".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        insert_unique_record(
            &mut self.disclosure_receipts,
            receipt_id.clone(),
            receipt,
            "selective disclosure receipt",
        )?;
        self.refresh_active_epoch_roots()?;
        Ok(receipt_id)
    }

    pub fn record_anonymity_metrics(
        &mut self,
        pool_id: &str,
        epoch_id: &str,
    ) -> PrivacyPoolResult<String> {
        let notes = self
            .note_commitments
            .values()
            .filter(|note| note.pool_id == pool_id && note.epoch_id == epoch_id)
            .cloned()
            .collect::<Vec<_>>();
        let nullifiers = self
            .spent_nullifiers
            .values()
            .filter(|nullifier| nullifier.pool_id == pool_id && nullifier.epoch_id == epoch_id)
            .cloned()
            .collect::<Vec<_>>();
        let tags = self.pool_tags.values().cloned().collect::<Vec<_>>();
        let metrics = AnonymitySetMetrics::from_records(
            pool_id,
            epoch_id,
            &notes,
            &nullifiers,
            &tags,
            self.height,
        )?;
        let metrics_id = metrics.metrics_id.clone();
        self.anonymity_metrics.insert(metrics_id.clone(), metrics);
        self.refresh_epoch_roots(epoch_id)?;
        Ok(metrics_id)
    }

    pub fn refresh_nullifier_registry(
        &mut self,
        pool_id: &str,
        epoch_id: &str,
    ) -> PrivacyPoolResult<String> {
        let nullifiers = self
            .spent_nullifiers
            .values()
            .filter(|nullifier| nullifier.pool_id == pool_id && nullifier.epoch_id == epoch_id)
            .cloned()
            .collect::<Vec<_>>();
        let old_registry_ids = self
            .nullifier_registries
            .iter()
            .filter(|(_, registry)| registry.pool_id == pool_id && registry.epoch_id == epoch_id)
            .map(|(registry_id, _)| registry_id.clone())
            .collect::<Vec<_>>();
        for registry_id in old_registry_ids {
            self.nullifier_registries.remove(&registry_id);
        }
        let registry =
            NullifierRegistry::from_nullifiers(pool_id, epoch_id, &nullifiers, self.height)?;
        let registry_id = registry.registry_id.clone();
        self.nullifier_registries
            .insert(registry_id.clone(), registry);
        Ok(registry_id)
    }

    pub fn publish_public_record(
        &mut self,
        object_kind: impl Into<String>,
        object_id: impl Into<String>,
        record: &Value,
    ) -> PrivacyPoolResult<String> {
        let public_record =
            PrivacyPoolPublicRecord::new(object_kind, object_id, record, self.height)?;
        let record_id = public_record.record_id.clone();
        self.public_records.insert(record_id.clone(), public_record);
        self.refresh_active_epoch_roots()?;
        Ok(record_id)
    }

    pub fn refresh_epoch_roots(&mut self, epoch_id: &str) -> PrivacyPoolResult<String> {
        let epoch = self
            .epochs
            .get(epoch_id)
            .cloned()
            .ok_or_else(|| "privacy pool epoch is missing".to_string())?;
        let membership_root = self.epoch_membership_root(epoch_id);
        let note_commitment_root = self.epoch_note_commitment_root(epoch_id);
        let nullifier_root = self.epoch_nullifier_root(epoch_id);
        let nullifier_registry_root = self.epoch_nullifier_registry_root(epoch_id);
        let disclosure_policy_root = self.disclosure_policy_root();
        let viewing_committee_root = self.viewing_committee_root();
        let tag_root = self.tag_root();
        let compliance_proof_root = self.epoch_compliance_proof_root(epoch_id);
        let metrics_root = self.epoch_anonymity_metrics_root(epoch_id);
        let stored_epoch = self
            .epochs
            .get_mut(epoch_id)
            .ok_or_else(|| "privacy pool epoch disappeared".to_string())?;
        stored_epoch.membership_root = membership_root;
        stored_epoch.note_commitment_root = note_commitment_root;
        stored_epoch.nullifier_root = nullifier_root;
        stored_epoch.nullifier_registry_root = nullifier_registry_root;
        stored_epoch.disclosure_policy_root = disclosure_policy_root;
        stored_epoch.viewing_committee_root = viewing_committee_root;
        stored_epoch.tag_root = tag_root;
        stored_epoch.compliance_proof_root = compliance_proof_root;
        stored_epoch.metrics_root = metrics_root;
        stored_epoch.validate()?;
        Ok(epoch.epoch_id)
    }

    pub fn epoch_root(&self) -> String {
        privacy_pool_epoch_root(&self.epochs.values().cloned().collect::<Vec<_>>())
    }

    pub fn membership_root(&self) -> String {
        privacy_pool_membership_root(&self.note_commitments.values().cloned().collect::<Vec<_>>())
    }

    pub fn note_commitment_root(&self) -> String {
        privacy_pool_note_commitment_root(
            &self.note_commitments.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn nullifier_root(&self) -> String {
        privacy_pool_nullifier_root(&self.spent_nullifiers.values().cloned().collect::<Vec<_>>())
    }

    pub fn nullifier_registry_root(&self) -> String {
        privacy_pool_nullifier_registry_root(
            &self
                .nullifier_registries
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn join_root(&self) -> String {
        privacy_pool_join_root(&self.joins.values().cloned().collect::<Vec<_>>())
    }

    pub fn exit_root(&self) -> String {
        privacy_pool_exit_root(&self.exits.values().cloned().collect::<Vec<_>>())
    }

    pub fn disclosure_policy_root(&self) -> String {
        privacy_pool_disclosure_policy_root(
            &self
                .disclosure_policies
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn disclosure_receipt_root(&self) -> String {
        privacy_pool_disclosure_receipt_root(
            &self
                .disclosure_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn viewing_committee_root(&self) -> String {
        privacy_pool_viewing_committee_root(
            &self
                .viewing_committees
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn tag_root(&self) -> String {
        privacy_pool_tag_root(&self.pool_tags.values().cloned().collect::<Vec<_>>())
    }

    pub fn anonymity_metrics_root(&self) -> String {
        privacy_pool_anonymity_metrics_root(
            &self.anonymity_metrics.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn compliance_proof_root(&self) -> String {
        privacy_pool_compliance_proof_anchor_root(
            &self.compliance_proofs.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        privacy_pool_public_record_list_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> PrivacyPoolStateRoots {
        PrivacyPoolStateRoots {
            epoch_root: self.epoch_root(),
            membership_root: self.membership_root(),
            note_commitment_root: self.note_commitment_root(),
            nullifier_root: self.nullifier_root(),
            nullifier_registry_root: self.nullifier_registry_root(),
            join_root: self.join_root(),
            exit_root: self.exit_root(),
            disclosure_policy_root: self.disclosure_policy_root(),
            disclosure_receipt_root: self.disclosure_receipt_root(),
            viewing_committee_root: self.viewing_committee_root(),
            tag_root: self.tag_root(),
            anonymity_metrics_root: self.anonymity_metrics_root(),
            compliance_proof_root: self.compliance_proof_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root()
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        let object = record
            .as_object_mut()
            .expect("privacy pool state public record object");
        object.insert("state_root".to_string(), Value::String(self.state_root()));
        object.insert("roots".to_string(), self.roots().public_record());
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "privacy_pool_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_POOL_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "active_epoch_id": self.active_epoch_id,
            "epoch_count": self.epochs.len() as u64,
            "note_commitment_count": self.note_commitments.len() as u64,
            "spent_nullifier_count": self.spent_nullifiers.len() as u64,
            "nullifier_registry_count": self.nullifier_registries.len() as u64,
            "join_count": self.joins.len() as u64,
            "exit_count": self.exits.len() as u64,
            "disclosure_policy_count": self.disclosure_policies.len() as u64,
            "disclosure_receipt_count": self.disclosure_receipts.len() as u64,
            "viewing_committee_count": self.viewing_committees.len() as u64,
            "pool_tag_count": self.pool_tags.len() as u64,
            "anonymity_metrics_count": self.anonymity_metrics.len() as u64,
            "compliance_proof_count": self.compliance_proofs.len() as u64,
            "public_record_count": self.public_records.len() as u64,
        })
    }

    fn refresh_active_epoch_roots(&mut self) -> PrivacyPoolResult<String> {
        if self.active_epoch_id.is_empty() {
            return Ok(String::new());
        }
        let active_epoch_id = self.active_epoch_id.clone();
        self.refresh_epoch_roots(&active_epoch_id)
    }

    fn epoch_membership_root(&self, epoch_id: &str) -> String {
        privacy_pool_membership_root(
            &self
                .note_commitments
                .values()
                .filter(|note| note.epoch_id == epoch_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn epoch_note_commitment_root(&self, epoch_id: &str) -> String {
        privacy_pool_note_commitment_root(
            &self
                .note_commitments
                .values()
                .filter(|note| note.epoch_id == epoch_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn epoch_nullifier_root(&self, epoch_id: &str) -> String {
        privacy_pool_nullifier_root(
            &self
                .spent_nullifiers
                .values()
                .filter(|nullifier| nullifier.epoch_id == epoch_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn epoch_nullifier_registry_root(&self, epoch_id: &str) -> String {
        privacy_pool_nullifier_registry_root(
            &self
                .nullifier_registries
                .values()
                .filter(|registry| registry.epoch_id == epoch_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn epoch_anonymity_metrics_root(&self, epoch_id: &str) -> String {
        privacy_pool_anonymity_metrics_root(
            &self
                .anonymity_metrics
                .values()
                .filter(|metrics| metrics.epoch_id == epoch_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn epoch_compliance_proof_root(&self, epoch_id: &str) -> String {
        privacy_pool_compliance_proof_anchor_root(
            &self
                .compliance_proofs
                .values()
                .filter(|proof| proof.epoch_id == epoch_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }
}

pub fn privacy_pool_id(pool_label: &str, asset_domain: &str) -> String {
    domain_hash(
        "PRIVACY-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_label),
            HashPart::Str(asset_domain),
        ],
        32,
    )
}

pub fn privacy_pool_epoch_id(
    pool_id: &str,
    epoch_index: u64,
    start_height: u64,
    end_height: u64,
) -> String {
    domain_hash(
        "PRIVACY-POOL-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Int(epoch_index as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
        ],
        32,
    )
}

pub fn privacy_pool_owner_commitment(owner_secret: &str) -> String {
    domain_hash(
        "PRIVACY-POOL-OWNER-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(owner_secret)],
        32,
    )
}

pub fn privacy_pool_asset_commitment(asset_id: &str) -> String {
    domain_hash(
        "PRIVACY-POOL-ASSET-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(asset_id)],
        32,
    )
}

pub fn privacy_pool_value_bucket_commitment(value_bucket: &str) -> String {
    domain_hash(
        "PRIVACY-POOL-VALUE-BUCKET-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(value_bucket)],
        32,
    )
}

pub fn privacy_pool_blinding_commitment(blinding_seed: &str) -> String {
    domain_hash(
        "PRIVACY-POOL-BLINDING-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(blinding_seed)],
        32,
    )
}

pub fn privacy_pool_viewer_commitment(viewer_label: &str) -> String {
    domain_hash(
        "PRIVACY-POOL-VIEWER-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(viewer_label)],
        32,
    )
}

pub fn privacy_pool_recipient_commitment(recipient: &str) -> String {
    domain_hash(
        "PRIVACY-POOL-RECIPIENT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(recipient)],
        32,
    )
}

pub fn privacy_pool_tag_label_commitment(label: &str) -> String {
    domain_hash(
        "PRIVACY-POOL-TAG-LABEL-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn privacy_pool_tag_component_commitment(component_kind: &str, value: &str) -> String {
    domain_hash(
        "PRIVACY-POOL-TAG-COMPONENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(component_kind),
            HashPart::Str(value),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn privacy_pool_note_commitment(
    pool_id: &str,
    epoch_id: &str,
    owner_commitment: &str,
    asset_commitment: &str,
    value_bucket_commitment: &str,
    blinding_commitment: &str,
    disclosure_policy_id: &str,
    viewing_committee_id: &str,
    tag_root: &str,
    note_nonce: u64,
) -> String {
    domain_hash(
        "PRIVACY-POOL-NOTE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(epoch_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(asset_commitment),
            HashPart::Str(value_bucket_commitment),
            HashPart::Str(blinding_commitment),
            HashPart::Str(disclosure_policy_id),
            HashPart::Str(viewing_committee_id),
            HashPart::Str(tag_root),
            HashPart::Int(note_nonce as i128),
        ],
        32,
    )
}

pub fn privacy_pool_note_id(commitment: &str, joined_at_height: u64, note_nonce: u64) -> String {
    domain_hash(
        "PRIVACY-POOL-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(commitment),
            HashPart::Int(joined_at_height as i128),
            HashPart::Int(note_nonce as i128),
        ],
        32,
    )
}

pub fn privacy_pool_note_leaf_hash(record: &Value) -> String {
    domain_hash(
        "PRIVACY-POOL-NOTE-LEAF",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn privacy_pool_nullifier_secret_commitment(nullifier_secret: &str) -> String {
    domain_hash(
        "PRIVACY-POOL-NULLIFIER-SECRET",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(nullifier_secret)],
        32,
    )
}

pub fn privacy_pool_nullifier(
    note_id: &str,
    note_commitment: &str,
    nullifier_secret_commitment: &str,
    exit_context_root: &str,
) -> String {
    domain_hash(
        "PRIVACY-POOL-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(note_id),
            HashPart::Str(note_commitment),
            HashPart::Str(nullifier_secret_commitment),
            HashPart::Str(exit_context_root),
        ],
        32,
    )
}

pub fn privacy_pool_viewing_committee_id(record: &Value) -> String {
    domain_hash(
        "PRIVACY-POOL-VIEWING-COMMITTEE-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn privacy_pool_disclosure_policy_id(record: &Value) -> String {
    domain_hash(
        "PRIVACY-POOL-DISCLOSURE-POLICY-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn privacy_pool_tag_id(record: &Value) -> String {
    domain_hash("PRIVACY-POOL-TAG-ID", &[HashPart::Json(record)], 32)
}

pub fn privacy_pool_join_id(record: &Value) -> String {
    domain_hash("PRIVACY-POOL-JOIN-ID", &[HashPart::Json(record)], 32)
}

pub fn privacy_pool_exit_id(record: &Value) -> String {
    domain_hash("PRIVACY-POOL-EXIT-ID", &[HashPart::Json(record)], 32)
}

pub fn privacy_pool_disclosure_receipt_id(record: &Value) -> String {
    domain_hash(
        "PRIVACY-POOL-DISCLOSURE-RECEIPT-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn privacy_pool_anonymity_metrics_id(record: &Value) -> String {
    domain_hash(
        "PRIVACY-POOL-ANONYMITY-METRICS-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn privacy_pool_compliance_proof_id(record: &Value) -> String {
    domain_hash(
        "PRIVACY-POOL-COMPLIANCE-PROOF-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn privacy_pool_nullifier_registry_id(
    pool_id: &str,
    epoch_id: &str,
    nullifier_root: &str,
    nullifier_count: u64,
    updated_at_height: u64,
) -> String {
    domain_hash(
        "PRIVACY-POOL-NULLIFIER-REGISTRY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(epoch_id),
            HashPart::Str(nullifier_root),
            HashPart::Int(nullifier_count as i128),
            HashPart::Int(updated_at_height as i128),
        ],
        32,
    )
}

pub fn privacy_pool_public_record_id(
    object_kind: &str,
    object_id: &str,
    record_root: &str,
    recorded_at_height: u64,
) -> String {
    domain_hash(
        "PRIVACY-POOL-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(object_kind),
            HashPart::Str(object_id),
            HashPart::Str(record_root),
            HashPart::Int(recorded_at_height as i128),
        ],
        32,
    )
}

pub fn privacy_pool_disclosure_statement_root(
    note_id: &str,
    note_commitment: &str,
    policy_id: &str,
    committee_id: &str,
    recipient_commitment: &str,
    field_root: &str,
    revealed_record_root: &str,
) -> String {
    domain_hash(
        "PRIVACY-POOL-DISCLOSURE-STATEMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(note_id),
            HashPart::Str(note_commitment),
            HashPart::Str(policy_id),
            HashPart::Str(committee_id),
            HashPart::Str(recipient_commitment),
            HashPart::Str(field_root),
            HashPart::Str(revealed_record_root),
        ],
        32,
    )
}

pub fn privacy_pool_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn privacy_pool_public_record_root(record: &Value) -> String {
    domain_hash(
        "PRIVACY-POOL-PUBLIC-RECORD",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn privacy_pool_compliance_proof_root(
    proof_system: &str,
    public_inputs: &Value,
    private_witness: &Value,
) -> String {
    let public_input_root =
        privacy_pool_payload_root("PRIVACY-POOL-COMPLIANCE-PUBLIC-INPUT", public_inputs);
    let private_witness_root =
        privacy_pool_payload_root("PRIVACY-POOL-COMPLIANCE-PRIVATE-WITNESS", private_witness);
    privacy_pool_compliance_proof_root_from_roots(
        proof_system,
        &public_input_root,
        &private_witness_root,
        "",
        "",
        "",
        "",
    )
}

pub fn privacy_pool_compliance_proof_root_from_roots(
    proof_system: &str,
    public_input_root: &str,
    private_witness_root: &str,
    policy_root: &str,
    committee_root: &str,
    membership_root: &str,
    nullifier_root: &str,
) -> String {
    domain_hash(
        "PRIVACY-POOL-COMPLIANCE-PROOF-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_system),
            HashPart::Str(public_input_root),
            HashPart::Str(private_witness_root),
            HashPart::Str(policy_root),
            HashPart::Str(committee_root),
            HashPart::Str(membership_root),
            HashPart::Str(nullifier_root),
        ],
        32,
    )
}

pub fn privacy_pool_string_root(domain: &str, values: &[String]) -> String {
    let mut values = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    merkle_root(
        domain,
        &values.into_iter().map(Value::String).collect::<Vec<_>>(),
    )
}

pub fn privacy_pool_epoch_root(epochs: &[PrivacyPoolEpoch]) -> String {
    sorted_merkle_root(
        "PRIVACY-POOL-EPOCH",
        epochs.iter().map(PrivacyPoolEpoch::public_record).collect(),
        "epoch_id",
    )
}

pub fn privacy_pool_membership_root(notes: &[PoolNoteCommitment]) -> String {
    sorted_merkle_root(
        "PRIVACY-POOL-MEMBERSHIP",
        notes
            .iter()
            .map(PoolNoteCommitment::membership_record)
            .collect(),
        "note_id",
    )
}

pub fn privacy_pool_note_commitment_root(notes: &[PoolNoteCommitment]) -> String {
    sorted_merkle_root(
        "PRIVACY-POOL-NOTE-COMMITMENT",
        notes
            .iter()
            .map(PoolNoteCommitment::public_record)
            .collect(),
        "note_id",
    )
}

pub fn privacy_pool_nullifier_root(nullifiers: &[NullifierRecord]) -> String {
    sorted_merkle_root(
        "PRIVACY-POOL-NULLIFIER",
        nullifiers
            .iter()
            .map(NullifierRecord::public_record)
            .collect(),
        "nullifier",
    )
}

pub fn privacy_pool_nullifier_registry_root(registries: &[NullifierRegistry]) -> String {
    sorted_merkle_root(
        "PRIVACY-POOL-NULLIFIER-REGISTRY",
        registries
            .iter()
            .map(NullifierRegistry::public_record)
            .collect(),
        "registry_id",
    )
}

pub fn privacy_pool_join_root(joins: &[PoolJoin]) -> String {
    sorted_merkle_root(
        "PRIVACY-POOL-JOIN",
        joins.iter().map(PoolJoin::public_record).collect(),
        "join_id",
    )
}

pub fn privacy_pool_exit_root(exits: &[PoolExit]) -> String {
    sorted_merkle_root(
        "PRIVACY-POOL-EXIT",
        exits.iter().map(PoolExit::public_record).collect(),
        "exit_id",
    )
}

pub fn privacy_pool_disclosure_policy_root(policies: &[SelectiveDisclosurePolicy]) -> String {
    sorted_merkle_root(
        "PRIVACY-POOL-DISCLOSURE-POLICY",
        policies
            .iter()
            .map(SelectiveDisclosurePolicy::public_record)
            .collect(),
        "policy_id",
    )
}

pub fn privacy_pool_disclosure_receipt_root(receipts: &[SelectiveDisclosureReceipt]) -> String {
    sorted_merkle_root(
        "PRIVACY-POOL-DISCLOSURE-RECEIPT",
        receipts
            .iter()
            .map(SelectiveDisclosureReceipt::public_record)
            .collect(),
        "receipt_id",
    )
}

pub fn privacy_pool_viewing_committee_root(committees: &[ViewingCommittee]) -> String {
    sorted_merkle_root(
        "PRIVACY-POOL-VIEWING-COMMITTEE",
        committees
            .iter()
            .map(ViewingCommittee::public_record)
            .collect(),
        "committee_id",
    )
}

pub fn privacy_pool_tag_root(tags: &[PrivatePoolTag]) -> String {
    sorted_merkle_root(
        "PRIVACY-POOL-TAG",
        tags.iter().map(PrivatePoolTag::public_record).collect(),
        "tag_id",
    )
}

pub fn privacy_pool_anonymity_metrics_root(metrics: &[AnonymitySetMetrics]) -> String {
    sorted_merkle_root(
        "PRIVACY-POOL-ANONYMITY-METRICS",
        metrics
            .iter()
            .map(AnonymitySetMetrics::public_record)
            .collect(),
        "metrics_id",
    )
}

pub fn privacy_pool_compliance_proof_anchor_root(proofs: &[ComplianceProofRoot]) -> String {
    sorted_merkle_root(
        "PRIVACY-POOL-COMPLIANCE-PROOF-ANCHOR",
        proofs
            .iter()
            .map(ComplianceProofRoot::public_record)
            .collect(),
        "proof_id",
    )
}

pub fn privacy_pool_public_record_list_root(records: &[PrivacyPoolPublicRecord]) -> String {
    sorted_merkle_root(
        "PRIVACY-POOL-PUBLIC-RECORD-LIST",
        records
            .iter()
            .map(PrivacyPoolPublicRecord::public_record)
            .collect(),
        "record_id",
    )
}

pub fn privacy_pool_state_root(record: &Value) -> String {
    domain_hash(
        "PRIVACY-POOL-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn sorted_merkle_root(domain: &str, mut leaves: Vec<Value>, sort_key: &str) -> String {
    leaves.sort_by_key(|record| {
        record
            .get(sort_key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    });
    merkle_root(domain, &leaves)
}

fn normalize_label(value: String) -> String {
    let mut normalized = String::new();
    let mut last_was_separator = false;
    for character in value.trim().chars() {
        if character.is_ascii_alphanumeric() {
            normalized.push(character.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            normalized.push('_');
            last_was_separator = true;
        }
    }
    normalized.trim_matches('_').to_string()
}

fn normalize_label_set(values: Vec<String>, label: &str) -> PrivacyPoolResult<Vec<String>> {
    normalize_raw_set(values.into_iter().map(normalize_label).collect(), label)
}

fn normalize_raw_set(values: Vec<String>, label: &str) -> PrivacyPoolResult<Vec<String>> {
    let mut values = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    if values.is_empty() {
        return Err(format!("{label} are required"));
    }
    Ok(values)
}

fn ensure_non_empty(value: &str, label: &str) -> PrivacyPoolResult<String> {
    if value.is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(value.to_string())
    }
}

fn ensure_status(status: &str, allowed: &[&str]) -> PrivacyPoolResult<String> {
    if allowed.iter().any(|candidate| candidate == &status) {
        Ok(status.to_string())
    } else {
        Err(format!("unsupported privacy pool status: {status}"))
    }
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> PrivacyPoolResult<String> {
    if records.contains_key(&key) {
        return Err(format!("{label} already exists"));
    }
    records.insert(key.clone(), value);
    Ok(key)
}
