use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type FeeCompressionResult<T> = Result<T, String>;

pub const FEE_COMPRESSION_PROTOCOL_VERSION: &str = "nebula-fee-compression-v1";
pub const FEE_COMPRESSION_DEVNET_ASSET_ID: &str = "asset:wxmr";
pub const FEE_COMPRESSION_DEVNET_STABLE_ASSET_ID: &str = "asset:usdd";
pub const FEE_COMPRESSION_DEVNET_PAYMASTER: &str = "devnet-low-fee-paymaster";
pub const FEE_COMPRESSION_STATUS_ACTIVE: &str = "active";
pub const FEE_COMPRESSION_STATUS_PENDING: &str = "pending";
pub const FEE_COMPRESSION_STATUS_SETTLED: &str = "settled";
pub const FEE_COMPRESSION_STATUS_EXPIRED: &str = "expired";
pub const FEE_COMPRESSION_STATUS_PAUSED: &str = "paused";
pub const FEE_COMPRESSION_STATUS_CHALLENGED: &str = "challenged";
pub const FEE_COMPRESSION_DEFAULT_BATCH_LIMIT: u64 = 64;
pub const FEE_COMPRESSION_DEFAULT_TARGET_COMPRESSION_BPS: u64 = 2_500;
pub const FEE_COMPRESSION_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 7_500;
pub const FEE_COMPRESSION_DEFAULT_PRIVACY_BUDGET_BPS: u64 = 1_500;
pub const FEE_COMPRESSION_DEFAULT_TTL_BLOCKS: u64 = 48;
pub const FEE_COMPRESSION_DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 2;
pub const FEE_COMPRESSION_MAX_BPS: u64 = 10_000;
pub const FEE_COMPRESSION_MAX_BATCH_PACKETS: usize = 256;
pub const FEE_COMPRESSION_MAX_DISCLOSURES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCompressionLaneKind {
    Wallet,
    PrivateDefi,
    Bridge,
    Contract,
    Governance,
    Maintenance,
}

impl FeeCompressionLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::PrivateDefi => "private_defi",
            Self::Bridge => "bridge",
            Self::Contract => "contract",
            Self::Governance => "governance",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::Bridge => 1_000,
            Self::PrivateDefi => 800,
            Self::Contract => 700,
            Self::Wallet => 550,
            Self::Governance => 450,
            Self::Maintenance => 250,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(self, Self::Wallet | Self::PrivateDefi | Self::Contract)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCompressionProofKind {
    BatchSavings,
    SponsorAuthorization,
    PaymasterNetting,
    SettlementInclusion,
    PrivacyDisclosure,
}

impl FeeCompressionProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BatchSavings => "batch_savings",
            Self::SponsorAuthorization => "sponsor_authorization",
            Self::PaymasterNetting => "paymaster_netting",
            Self::SettlementInclusion => "settlement_inclusion",
            Self::PrivacyDisclosure => "privacy_disclosure",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCompressionConfig {
    pub config_id: String,
    pub fee_asset_id: String,
    pub stable_asset_id: String,
    pub max_batch_packets: u64,
    pub target_compression_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub max_privacy_budget_bps: u64,
    pub default_ttl_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub require_payload_roots_only: bool,
    pub paymaster_netting_enabled: bool,
    pub status: String,
}

impl Default for FeeCompressionConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            fee_asset_id: FEE_COMPRESSION_DEVNET_ASSET_ID.to_string(),
            stable_asset_id: FEE_COMPRESSION_DEVNET_STABLE_ASSET_ID.to_string(),
            max_batch_packets: FEE_COMPRESSION_DEFAULT_BATCH_LIMIT,
            target_compression_bps: FEE_COMPRESSION_DEFAULT_TARGET_COMPRESSION_BPS,
            low_fee_rebate_bps: FEE_COMPRESSION_DEFAULT_LOW_FEE_REBATE_BPS,
            max_privacy_budget_bps: FEE_COMPRESSION_DEFAULT_PRIVACY_BUDGET_BPS,
            default_ttl_blocks: FEE_COMPRESSION_DEFAULT_TTL_BLOCKS,
            settlement_delay_blocks: FEE_COMPRESSION_DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            require_payload_roots_only: true,
            paymaster_netting_enabled: true,
            status: FEE_COMPRESSION_STATUS_ACTIVE.to_string(),
        };
        config.config_id = fee_compression_config_id(&config.identity_record());
        config
    }
}

impl FeeCompressionConfig {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "fee_compression_config",
            "chain_id": CHAIN_ID,
            "protocol_version": FEE_COMPRESSION_PROTOCOL_VERSION,
            "fee_asset_id": self.fee_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "max_batch_packets": self.max_batch_packets,
            "target_compression_bps": self.target_compression_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_privacy_budget_bps": self.max_privacy_budget_bps,
            "default_ttl_blocks": self.default_ttl_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "require_payload_roots_only": self.require_payload_roots_only,
            "paymaster_netting_enabled": self.paymaster_netting_enabled,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("fee compression config record object");
        object.insert(
            "config_id".to_string(),
            Value::String(self.config_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert("config_root".to_string(), Value::String(self.config_root()));
        record
    }

    pub fn config_root(&self) -> String {
        fee_compression_payload_root("FEE-COMPRESSION-CONFIG", &self.identity_record())
    }

    pub fn validate(&self) -> FeeCompressionResult<String> {
        ensure_non_empty(&self.config_id, "fee compression config id")?;
        ensure_non_empty(&self.fee_asset_id, "fee compression fee asset")?;
        ensure_non_empty(&self.stable_asset_id, "fee compression stable asset")?;
        ensure_positive(self.max_batch_packets, "fee compression max batch packets")?;
        validate_bps(
            self.target_compression_bps,
            "fee compression target compression bps",
        )?;
        validate_bps(
            self.low_fee_rebate_bps,
            "fee compression low fee rebate bps",
        )?;
        validate_bps(
            self.max_privacy_budget_bps,
            "fee compression privacy budget bps",
        )?;
        ensure_positive(self.default_ttl_blocks, "fee compression ttl")?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeePacketCommitment {
    pub packet_id: String,
    pub payer_commitment: String,
    pub lane_kind: FeeCompressionLaneKind,
    pub asset_id: String,
    pub gross_fee_units: u64,
    pub compressed_fee_units: u64,
    pub discount_bps: u64,
    pub low_fee_credit_units: u64,
    pub payload_root: String,
    pub privacy_label_root: String,
    pub nullifier_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub priority: u64,
    pub status: String,
}

impl FeePacketCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        payer_commitment: impl Into<String>,
        lane_kind: FeeCompressionLaneKind,
        asset_id: impl Into<String>,
        gross_fee_units: u64,
        compressed_fee_units: u64,
        low_fee_credit_units: u64,
        payload_root: impl Into<String>,
        privacy_label_root: impl Into<String>,
        nullifier_root: impl Into<String>,
        submitted_at_height: u64,
        expires_at_height: u64,
        priority: u64,
    ) -> FeeCompressionResult<Self> {
        let payer_commitment = payer_commitment.into();
        let asset_id = asset_id.into();
        let payload_root = payload_root.into();
        let privacy_label_root = privacy_label_root.into();
        let nullifier_root = nullifier_root.into();
        ensure_non_empty(&payer_commitment, "fee packet payer commitment")?;
        ensure_non_empty(&asset_id, "fee packet asset")?;
        ensure_positive(gross_fee_units, "fee packet gross fee")?;
        if compressed_fee_units > gross_fee_units {
            return Err("compressed fee cannot exceed gross fee".to_string());
        }
        ensure_non_empty(&payload_root, "fee packet payload root")?;
        ensure_non_empty(&privacy_label_root, "fee packet privacy label root")?;
        ensure_non_empty(&nullifier_root, "fee packet nullifier root")?;
        if expires_at_height <= submitted_at_height {
            return Err("fee packet expiry must be after submission".to_string());
        }
        let discount_bps = compression_discount_bps(gross_fee_units, compressed_fee_units);
        let packet_id = fee_packet_id(
            &payer_commitment,
            lane_kind,
            &asset_id,
            gross_fee_units,
            compressed_fee_units,
            low_fee_credit_units,
            &payload_root,
            &privacy_label_root,
            &nullifier_root,
            submitted_at_height,
            expires_at_height,
        );
        Ok(Self {
            packet_id,
            payer_commitment,
            lane_kind,
            asset_id,
            gross_fee_units,
            compressed_fee_units,
            discount_bps,
            low_fee_credit_units,
            payload_root,
            privacy_label_root,
            nullifier_root,
            submitted_at_height,
            expires_at_height,
            priority,
            status: FEE_COMPRESSION_STATUS_PENDING.to_string(),
        })
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height
    }

    pub fn effective_priority(&self) -> u64 {
        self.priority
            .saturating_add(self.lane_kind.default_priority())
            .saturating_add(self.low_fee_credit_units.min(1_000_000))
            .saturating_add(self.discount_bps)
    }

    pub fn savings_units(&self) -> u64 {
        self.gross_fee_units
            .saturating_sub(self.compressed_fee_units)
            .saturating_add(self.low_fee_credit_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_packet_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": FEE_COMPRESSION_PROTOCOL_VERSION,
            "packet_id": self.packet_id,
            "payer_commitment": self.payer_commitment,
            "lane_kind": self.lane_kind.as_str(),
            "asset_id": self.asset_id,
            "gross_fee_units": self.gross_fee_units,
            "compressed_fee_units": self.compressed_fee_units,
            "discount_bps": self.discount_bps,
            "low_fee_credit_units": self.low_fee_credit_units,
            "payload_root": self.payload_root,
            "privacy_label_root": self.privacy_label_root,
            "nullifier_root": self.nullifier_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "priority": self.priority,
            "status": self.status,
        })
    }

    pub fn packet_root(&self) -> String {
        fee_compression_payload_root("FEE-PACKET-COMMITMENT", &self.public_record())
    }

    pub fn validate(&self) -> FeeCompressionResult<String> {
        ensure_non_empty(&self.packet_id, "fee packet id")?;
        ensure_non_empty(&self.payer_commitment, "fee packet payer commitment")?;
        ensure_non_empty(&self.asset_id, "fee packet asset id")?;
        ensure_positive(self.gross_fee_units, "fee packet gross fee")?;
        if self.compressed_fee_units > self.gross_fee_units {
            return Err("fee packet compressed fee exceeds gross fee".to_string());
        }
        validate_bps(self.discount_bps, "fee packet discount bps")?;
        ensure_non_empty(&self.payload_root, "fee packet payload root")?;
        ensure_non_empty(&self.privacy_label_root, "fee packet privacy label root")?;
        ensure_non_empty(&self.nullifier_root, "fee packet nullifier root")?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err("fee packet expiry must be after submission".to_string());
        }
        Ok(self.packet_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorshipWindow {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub lane_kind: FeeCompressionLaneKind,
    pub asset_id: String,
    pub total_budget_units: u64,
    pub spent_budget_units: u64,
    pub min_discount_bps: u64,
    pub max_packet_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl LowFeeSponsorshipWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: impl Into<String>,
        lane_kind: FeeCompressionLaneKind,
        asset_id: impl Into<String>,
        total_budget_units: u64,
        min_discount_bps: u64,
        max_packet_units: u64,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> FeeCompressionResult<Self> {
        let sponsor_commitment = sponsor_commitment.into();
        let asset_id = asset_id.into();
        ensure_non_empty(&sponsor_commitment, "fee sponsor commitment")?;
        ensure_non_empty(&asset_id, "fee sponsorship asset")?;
        ensure_positive(total_budget_units, "fee sponsorship budget")?;
        validate_bps(min_discount_bps, "fee sponsorship min discount")?;
        ensure_positive(max_packet_units, "fee sponsorship max packet units")?;
        if expires_at_height <= opened_at_height {
            return Err("fee sponsorship expiry must be after opening".to_string());
        }
        let sponsorship_id = fee_sponsorship_id(
            &sponsor_commitment,
            lane_kind,
            &asset_id,
            total_budget_units,
            min_discount_bps,
            max_packet_units,
            opened_at_height,
            expires_at_height,
        );
        Ok(Self {
            sponsorship_id,
            sponsor_commitment,
            lane_kind,
            asset_id,
            total_budget_units,
            spent_budget_units: 0,
            min_discount_bps,
            max_packet_units,
            opened_at_height,
            expires_at_height,
            status: FEE_COMPRESSION_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status == FEE_COMPRESSION_STATUS_ACTIVE {
            self.status = FEE_COMPRESSION_STATUS_EXPIRED.to_string();
        }
    }

    pub fn available_units(&self, height: u64) -> u64 {
        if self.status != FEE_COMPRESSION_STATUS_ACTIVE || height >= self.expires_at_height {
            0
        } else {
            self.total_budget_units
                .saturating_sub(self.spent_budget_units)
        }
    }

    pub fn eligible_packet(&self, packet: &FeePacketCommitment, height: u64) -> bool {
        self.available_units(height) > 0
            && self.lane_kind == packet.lane_kind
            && self.asset_id == packet.asset_id
            && packet.discount_bps >= self.min_discount_bps
            && packet.compressed_fee_units <= self.max_packet_units
    }

    pub fn charge(&mut self, units: u64, height: u64) -> FeeCompressionResult<()> {
        if self.available_units(height) < units {
            return Err("fee sponsorship budget insufficient".to_string());
        }
        self.spent_budget_units = self.spent_budget_units.saturating_add(units);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsorship_window",
            "chain_id": CHAIN_ID,
            "protocol_version": FEE_COMPRESSION_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane_kind": self.lane_kind.as_str(),
            "asset_id": self.asset_id,
            "total_budget_units": self.total_budget_units,
            "spent_budget_units": self.spent_budget_units,
            "remaining_budget_units": self.total_budget_units.saturating_sub(self.spent_budget_units),
            "min_discount_bps": self.min_discount_bps,
            "max_packet_units": self.max_packet_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        fee_compression_payload_root("LOW-FEE-SPONSORSHIP", &self.public_record())
    }

    pub fn validate(&self) -> FeeCompressionResult<String> {
        ensure_non_empty(&self.sponsorship_id, "fee sponsorship id")?;
        ensure_non_empty(&self.sponsor_commitment, "fee sponsor commitment")?;
        ensure_non_empty(&self.asset_id, "fee sponsorship asset")?;
        ensure_positive(self.total_budget_units, "fee sponsorship budget")?;
        if self.spent_budget_units > self.total_budget_units {
            return Err("fee sponsorship spent budget exceeds total budget".to_string());
        }
        validate_bps(self.min_discount_bps, "fee sponsorship min discount")?;
        ensure_positive(self.max_packet_units, "fee sponsorship max packet units")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("fee sponsorship expiry must be after opening".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymasterNettingPosition {
    pub position_id: String,
    pub paymaster_commitment: String,
    pub asset_id: String,
    pub debit_units: u64,
    pub credit_units: u64,
    pub packet_root: String,
    pub batch_root: String,
    pub nonce: u64,
    pub height: u64,
}

impl PaymasterNettingPosition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        paymaster_commitment: impl Into<String>,
        asset_id: impl Into<String>,
        debit_units: u64,
        credit_units: u64,
        packet_root: impl Into<String>,
        batch_root: impl Into<String>,
        nonce: u64,
        height: u64,
    ) -> FeeCompressionResult<Self> {
        let paymaster_commitment = paymaster_commitment.into();
        let asset_id = asset_id.into();
        let packet_root = packet_root.into();
        let batch_root = batch_root.into();
        ensure_non_empty(&paymaster_commitment, "paymaster commitment")?;
        ensure_non_empty(&asset_id, "paymaster asset")?;
        ensure_non_empty(&packet_root, "paymaster packet root")?;
        ensure_non_empty(&batch_root, "paymaster batch root")?;
        let position_id = paymaster_netting_position_id(
            &paymaster_commitment,
            &asset_id,
            debit_units,
            credit_units,
            &packet_root,
            &batch_root,
            nonce,
            height,
        );
        Ok(Self {
            position_id,
            paymaster_commitment,
            asset_id,
            debit_units,
            credit_units,
            packet_root,
            batch_root,
            nonce,
            height,
        })
    }

    pub fn net_units(&self) -> i128 {
        self.debit_units as i128 - self.credit_units as i128
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "paymaster_netting_position",
            "chain_id": CHAIN_ID,
            "protocol_version": FEE_COMPRESSION_PROTOCOL_VERSION,
            "position_id": self.position_id,
            "paymaster_commitment": self.paymaster_commitment,
            "asset_id": self.asset_id,
            "debit_units": self.debit_units,
            "credit_units": self.credit_units,
            "net_units": self.net_units(),
            "packet_root": self.packet_root,
            "batch_root": self.batch_root,
            "nonce": self.nonce,
            "height": self.height,
        })
    }

    pub fn position_root(&self) -> String {
        fee_compression_payload_root("PAYMASTER-NETTING-POSITION", &self.public_record())
    }

    pub fn validate(&self) -> FeeCompressionResult<String> {
        ensure_non_empty(&self.position_id, "paymaster netting position id")?;
        ensure_non_empty(&self.paymaster_commitment, "paymaster commitment")?;
        ensure_non_empty(&self.asset_id, "paymaster asset")?;
        ensure_non_empty(&self.packet_root, "paymaster packet root")?;
        ensure_non_empty(&self.batch_root, "paymaster batch root")?;
        Ok(self.position_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCompressionProof {
    pub proof_id: String,
    pub proof_kind: FeeCompressionProofKind,
    pub subject_id: String,
    pub subject_root: String,
    pub statement_root: String,
    pub verifier_committee_root: String,
    pub pq_signature_root: String,
    pub produced_at_height: u64,
    pub status: String,
}

impl FeeCompressionProof {
    pub fn new(
        proof_kind: FeeCompressionProofKind,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        statement_root: impl Into<String>,
        verifier_committee_root: impl Into<String>,
        pq_signature_root: impl Into<String>,
        produced_at_height: u64,
    ) -> FeeCompressionResult<Self> {
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let statement_root = statement_root.into();
        let verifier_committee_root = verifier_committee_root.into();
        let pq_signature_root = pq_signature_root.into();
        ensure_non_empty(&subject_id, "fee proof subject id")?;
        ensure_non_empty(&subject_root, "fee proof subject root")?;
        ensure_non_empty(&statement_root, "fee proof statement root")?;
        ensure_non_empty(
            &verifier_committee_root,
            "fee proof verifier committee root",
        )?;
        ensure_non_empty(&pq_signature_root, "fee proof signature root")?;
        let proof_id = fee_compression_proof_id(
            proof_kind,
            &subject_id,
            &subject_root,
            &statement_root,
            &verifier_committee_root,
            &pq_signature_root,
            produced_at_height,
        );
        Ok(Self {
            proof_id,
            proof_kind,
            subject_id,
            subject_root,
            statement_root,
            verifier_committee_root,
            pq_signature_root,
            produced_at_height,
            status: FEE_COMPRESSION_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_compression_proof",
            "chain_id": CHAIN_ID,
            "protocol_version": FEE_COMPRESSION_PROTOCOL_VERSION,
            "proof_id": self.proof_id,
            "proof_kind": self.proof_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "statement_root": self.statement_root,
            "verifier_committee_root": self.verifier_committee_root,
            "pq_signature_root": self.pq_signature_root,
            "produced_at_height": self.produced_at_height,
            "status": self.status,
        })
    }

    pub fn proof_root(&self) -> String {
        fee_compression_payload_root("FEE-COMPRESSION-PROOF", &self.public_record())
    }

    pub fn validate(&self) -> FeeCompressionResult<String> {
        ensure_non_empty(&self.proof_id, "fee compression proof id")?;
        ensure_non_empty(&self.subject_id, "fee compression proof subject")?;
        ensure_non_empty(&self.subject_root, "fee compression proof subject root")?;
        ensure_non_empty(&self.statement_root, "fee compression proof statement root")?;
        ensure_non_empty(
            &self.verifier_committee_root,
            "fee compression proof committee root",
        )?;
        ensure_non_empty(&self.pq_signature_root, "fee compression proof signature")?;
        Ok(self.proof_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeePrivacyDisclosure {
    pub disclosure_id: String,
    pub subject_id: String,
    pub disclosed_root: String,
    pub privacy_budget_bps: u64,
    pub audience_root: String,
    pub auditor_commitment: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl FeePrivacyDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_id: impl Into<String>,
        disclosed_root: impl Into<String>,
        privacy_budget_bps: u64,
        audience_root: impl Into<String>,
        auditor_commitment: impl Into<String>,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> FeeCompressionResult<Self> {
        let subject_id = subject_id.into();
        let disclosed_root = disclosed_root.into();
        let audience_root = audience_root.into();
        let auditor_commitment = auditor_commitment.into();
        ensure_non_empty(&subject_id, "fee privacy disclosure subject")?;
        ensure_non_empty(&disclosed_root, "fee privacy disclosed root")?;
        validate_bps(privacy_budget_bps, "fee privacy budget")?;
        ensure_non_empty(&audience_root, "fee privacy audience root")?;
        ensure_non_empty(&auditor_commitment, "fee privacy auditor commitment")?;
        if expires_at_height <= opened_at_height {
            return Err("fee privacy disclosure expiry must be after open".to_string());
        }
        let disclosure_id = fee_privacy_disclosure_id(
            &subject_id,
            &disclosed_root,
            privacy_budget_bps,
            &audience_root,
            &auditor_commitment,
            opened_at_height,
            expires_at_height,
        );
        Ok(Self {
            disclosure_id,
            subject_id,
            disclosed_root,
            privacy_budget_bps,
            audience_root,
            auditor_commitment,
            opened_at_height,
            expires_at_height,
            status: FEE_COMPRESSION_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status == FEE_COMPRESSION_STATUS_ACTIVE {
            self.status = FEE_COMPRESSION_STATUS_EXPIRED.to_string();
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_privacy_disclosure",
            "chain_id": CHAIN_ID,
            "protocol_version": FEE_COMPRESSION_PROTOCOL_VERSION,
            "disclosure_id": self.disclosure_id,
            "subject_id": self.subject_id,
            "disclosed_root": self.disclosed_root,
            "privacy_budget_bps": self.privacy_budget_bps,
            "audience_root": self.audience_root,
            "auditor_commitment": self.auditor_commitment,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn disclosure_root(&self) -> String {
        fee_compression_payload_root("FEE-PRIVACY-DISCLOSURE", &self.public_record())
    }

    pub fn validate(&self) -> FeeCompressionResult<String> {
        ensure_non_empty(&self.disclosure_id, "fee privacy disclosure id")?;
        ensure_non_empty(&self.subject_id, "fee privacy disclosure subject")?;
        ensure_non_empty(&self.disclosed_root, "fee privacy disclosed root")?;
        validate_bps(self.privacy_budget_bps, "fee privacy budget")?;
        ensure_non_empty(&self.audience_root, "fee privacy audience root")?;
        ensure_non_empty(&self.auditor_commitment, "fee privacy auditor commitment")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("fee privacy disclosure expiry must be after open".to_string());
        }
        Ok(self.disclosure_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCompressionBatch {
    pub batch_id: String,
    pub height: u64,
    pub lane_kind: FeeCompressionLaneKind,
    pub asset_id: String,
    pub packet_root: String,
    pub packet_ids: Vec<String>,
    pub gross_fee_units: u64,
    pub compressed_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub savings_bps: u64,
    pub paymaster_root: String,
    pub privacy_disclosure_root: String,
    pub proof_root: String,
    pub settlement_due_height: u64,
    pub status: String,
}

impl FeeCompressionBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        lane_kind: FeeCompressionLaneKind,
        asset_id: impl Into<String>,
        packets: &[FeePacketCommitment],
        paymaster_root: impl Into<String>,
        privacy_disclosure_root: impl Into<String>,
        proof_root: impl Into<String>,
        settlement_delay_blocks: u64,
    ) -> FeeCompressionResult<Self> {
        let asset_id = asset_id.into();
        let paymaster_root = paymaster_root.into();
        let privacy_disclosure_root = privacy_disclosure_root.into();
        let proof_root = proof_root.into();
        ensure_non_empty(&asset_id, "fee batch asset")?;
        ensure_non_empty(&paymaster_root, "fee batch paymaster root")?;
        ensure_non_empty(&privacy_disclosure_root, "fee batch privacy root")?;
        ensure_non_empty(&proof_root, "fee batch proof root")?;
        if packets.is_empty() {
            return Err("fee compression batch cannot be empty".to_string());
        }
        if packets.len() > FEE_COMPRESSION_MAX_BATCH_PACKETS {
            return Err("fee compression batch packet limit exceeded".to_string());
        }
        let mut packet_ids = Vec::new();
        let mut seen_nullifiers = BTreeSet::new();
        let mut gross_fee_units = 0_u64;
        let mut compressed_fee_units = 0_u64;
        let mut sponsored_fee_units = 0_u64;
        for packet in packets {
            packet.validate()?;
            if packet.asset_id != asset_id {
                return Err("fee compression batch mixes assets".to_string());
            }
            if packet.lane_kind != lane_kind {
                return Err("fee compression batch mixes lanes".to_string());
            }
            if !seen_nullifiers.insert(packet.nullifier_root.clone()) {
                return Err("fee compression batch has duplicate nullifier root".to_string());
            }
            packet_ids.push(packet.packet_id.clone());
            gross_fee_units = gross_fee_units.saturating_add(packet.gross_fee_units);
            compressed_fee_units = compressed_fee_units.saturating_add(packet.compressed_fee_units);
            sponsored_fee_units = sponsored_fee_units.saturating_add(packet.low_fee_credit_units);
        }
        packet_ids.sort();
        let packet_root = fee_packet_collection_root(packets);
        let savings_bps = compression_discount_bps(gross_fee_units, compressed_fee_units);
        let settlement_due_height = height.saturating_add(settlement_delay_blocks.max(1));
        let batch_id = fee_compression_batch_id(
            height,
            lane_kind,
            &asset_id,
            &packet_root,
            gross_fee_units,
            compressed_fee_units,
            sponsored_fee_units,
            &paymaster_root,
            &privacy_disclosure_root,
            &proof_root,
            settlement_due_height,
        );
        Ok(Self {
            batch_id,
            height,
            lane_kind,
            asset_id,
            packet_root,
            packet_ids,
            gross_fee_units,
            compressed_fee_units,
            sponsored_fee_units,
            savings_bps,
            paymaster_root,
            privacy_disclosure_root,
            proof_root,
            settlement_due_height,
            status: FEE_COMPRESSION_STATUS_PENDING.to_string(),
        })
    }

    pub fn payable_units(&self) -> u64 {
        self.compressed_fee_units
            .saturating_sub(self.sponsored_fee_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_compression_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": FEE_COMPRESSION_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "height": self.height,
            "lane_kind": self.lane_kind.as_str(),
            "asset_id": self.asset_id,
            "packet_root": self.packet_root,
            "packet_id_root": fee_compression_string_set_root("FEE-BATCH-PACKET-ID", &self.packet_ids),
            "packet_count": self.packet_ids.len() as u64,
            "gross_fee_units": self.gross_fee_units,
            "compressed_fee_units": self.compressed_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "payable_units": self.payable_units(),
            "savings_bps": self.savings_bps,
            "paymaster_root": self.paymaster_root,
            "privacy_disclosure_root": self.privacy_disclosure_root,
            "proof_root": self.proof_root,
            "settlement_due_height": self.settlement_due_height,
            "status": self.status,
        })
    }

    pub fn batch_root(&self) -> String {
        fee_compression_payload_root("FEE-COMPRESSION-BATCH", &self.public_record())
    }

    pub fn validate(&self) -> FeeCompressionResult<String> {
        ensure_non_empty(&self.batch_id, "fee compression batch id")?;
        ensure_non_empty(&self.asset_id, "fee compression batch asset")?;
        ensure_non_empty(&self.packet_root, "fee compression batch packet root")?;
        if self.packet_ids.is_empty() {
            return Err("fee compression batch packet ids are empty".to_string());
        }
        ensure_unique_strings(&self.packet_ids, "fee compression batch packet ids")?;
        if self.compressed_fee_units > self.gross_fee_units {
            return Err("fee compression batch compressed fee exceeds gross fee".to_string());
        }
        validate_bps(self.savings_bps, "fee compression batch savings bps")?;
        ensure_non_empty(&self.paymaster_root, "fee compression batch paymaster root")?;
        ensure_non_empty(
            &self.privacy_disclosure_root,
            "fee compression batch privacy disclosure root",
        )?;
        ensure_non_empty(&self.proof_root, "fee compression batch proof root")?;
        if self.settlement_due_height <= self.height {
            return Err("fee compression settlement due height must follow height".to_string());
        }
        Ok(self.batch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSettlementEnvelope {
    pub envelope_id: String,
    pub batch_id: String,
    pub batch_root: String,
    pub asset_id: String,
    pub payer_set_root: String,
    pub paymaster_netting_root: String,
    pub amount_units: u64,
    pub sponsored_units: u64,
    pub settlement_account_root: String,
    pub finality_hint_root: String,
    pub settled_at_height: u64,
    pub status: String,
}

impl FeeSettlementEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch: &FeeCompressionBatch,
        payer_set_root: impl Into<String>,
        paymaster_netting_root: impl Into<String>,
        settlement_account_root: impl Into<String>,
        finality_hint_root: impl Into<String>,
        settled_at_height: u64,
    ) -> FeeCompressionResult<Self> {
        let payer_set_root = payer_set_root.into();
        let paymaster_netting_root = paymaster_netting_root.into();
        let settlement_account_root = settlement_account_root.into();
        let finality_hint_root = finality_hint_root.into();
        ensure_non_empty(&payer_set_root, "fee settlement payer set root")?;
        ensure_non_empty(&paymaster_netting_root, "fee settlement netting root")?;
        ensure_non_empty(&settlement_account_root, "fee settlement account root")?;
        ensure_non_empty(&finality_hint_root, "fee settlement finality hint root")?;
        let batch_root = batch.batch_root();
        let envelope_id = fee_settlement_envelope_id(
            &batch.batch_id,
            &batch_root,
            &batch.asset_id,
            &payer_set_root,
            &paymaster_netting_root,
            batch.payable_units(),
            batch.sponsored_fee_units,
            &settlement_account_root,
            &finality_hint_root,
            settled_at_height,
        );
        Ok(Self {
            envelope_id,
            batch_id: batch.batch_id.clone(),
            batch_root,
            asset_id: batch.asset_id.clone(),
            payer_set_root,
            paymaster_netting_root,
            amount_units: batch.payable_units(),
            sponsored_units: batch.sponsored_fee_units,
            settlement_account_root,
            finality_hint_root,
            settled_at_height,
            status: FEE_COMPRESSION_STATUS_SETTLED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_settlement_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": FEE_COMPRESSION_PROTOCOL_VERSION,
            "envelope_id": self.envelope_id,
            "batch_id": self.batch_id,
            "batch_root": self.batch_root,
            "asset_id": self.asset_id,
            "payer_set_root": self.payer_set_root,
            "paymaster_netting_root": self.paymaster_netting_root,
            "amount_units": self.amount_units,
            "sponsored_units": self.sponsored_units,
            "settlement_account_root": self.settlement_account_root,
            "finality_hint_root": self.finality_hint_root,
            "settled_at_height": self.settled_at_height,
            "status": self.status,
        })
    }

    pub fn envelope_root(&self) -> String {
        fee_compression_payload_root("FEE-SETTLEMENT-ENVELOPE", &self.public_record())
    }

    pub fn validate(&self) -> FeeCompressionResult<String> {
        ensure_non_empty(&self.envelope_id, "fee settlement envelope id")?;
        ensure_non_empty(&self.batch_id, "fee settlement batch id")?;
        ensure_non_empty(&self.batch_root, "fee settlement batch root")?;
        ensure_non_empty(&self.asset_id, "fee settlement asset id")?;
        ensure_non_empty(&self.payer_set_root, "fee settlement payer set root")?;
        ensure_non_empty(&self.paymaster_netting_root, "fee settlement netting root")?;
        ensure_non_empty(&self.settlement_account_root, "fee settlement account root")?;
        ensure_non_empty(&self.finality_hint_root, "fee settlement finality root")?;
        Ok(self.envelope_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCompressionChallenge {
    pub challenge_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub bond_units: u64,
    pub status: String,
}

impl FeeCompressionChallenge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        challenger_commitment: impl Into<String>,
        evidence_root: impl Into<String>,
        opened_at_height: u64,
        ttl_blocks: u64,
        bond_units: u64,
    ) -> FeeCompressionResult<Self> {
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let challenger_commitment = challenger_commitment.into();
        let evidence_root = evidence_root.into();
        ensure_non_empty(&subject_id, "fee challenge subject")?;
        ensure_non_empty(&subject_root, "fee challenge subject root")?;
        ensure_non_empty(&challenger_commitment, "fee challenge challenger")?;
        ensure_non_empty(&evidence_root, "fee challenge evidence")?;
        ensure_positive(ttl_blocks, "fee challenge ttl")?;
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let challenge_id = fee_compression_challenge_id(
            &subject_id,
            &subject_root,
            &challenger_commitment,
            &evidence_root,
            opened_at_height,
            expires_at_height,
            bond_units,
        );
        Ok(Self {
            challenge_id,
            subject_id,
            subject_root,
            challenger_commitment,
            evidence_root,
            opened_at_height,
            expires_at_height,
            bond_units,
            status: FEE_COMPRESSION_STATUS_CHALLENGED.to_string(),
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status == FEE_COMPRESSION_STATUS_CHALLENGED {
            self.status = FEE_COMPRESSION_STATUS_EXPIRED.to_string();
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_compression_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": FEE_COMPRESSION_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "bond_units": self.bond_units,
            "status": self.status,
        })
    }

    pub fn challenge_root(&self) -> String {
        fee_compression_payload_root("FEE-COMPRESSION-CHALLENGE", &self.public_record())
    }

    pub fn validate(&self) -> FeeCompressionResult<String> {
        ensure_non_empty(&self.challenge_id, "fee challenge id")?;
        ensure_non_empty(&self.subject_id, "fee challenge subject")?;
        ensure_non_empty(&self.subject_root, "fee challenge subject root")?;
        ensure_non_empty(&self.challenger_commitment, "fee challenge challenger")?;
        ensure_non_empty(&self.evidence_root, "fee challenge evidence")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("fee challenge expiry must be after open".to_string());
        }
        Ok(self.challenge_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCompressionRoots {
    pub config_root: String,
    pub packet_root: String,
    pub batch_root: String,
    pub sponsorship_root: String,
    pub paymaster_position_root: String,
    pub proof_root: String,
    pub privacy_disclosure_root: String,
    pub settlement_envelope_root: String,
    pub challenge_root: String,
}

impl FeeCompressionRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_compression_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": FEE_COMPRESSION_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "packet_root": self.packet_root,
            "batch_root": self.batch_root,
            "sponsorship_root": self.sponsorship_root,
            "paymaster_position_root": self.paymaster_position_root,
            "proof_root": self.proof_root,
            "privacy_disclosure_root": self.privacy_disclosure_root,
            "settlement_envelope_root": self.settlement_envelope_root,
            "challenge_root": self.challenge_root,
        })
    }

    pub fn roots_root(&self) -> String {
        fee_compression_payload_root("FEE-COMPRESSION-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCompressionState {
    pub height: u64,
    pub config: FeeCompressionConfig,
    pub packets: BTreeMap<String, FeePacketCommitment>,
    pub batches: BTreeMap<String, FeeCompressionBatch>,
    pub sponsorships: BTreeMap<String, LowFeeSponsorshipWindow>,
    pub paymaster_positions: BTreeMap<String, PaymasterNettingPosition>,
    pub proofs: BTreeMap<String, FeeCompressionProof>,
    pub privacy_disclosures: BTreeMap<String, FeePrivacyDisclosure>,
    pub settlements: BTreeMap<String, FeeSettlementEnvelope>,
    pub challenges: BTreeMap<String, FeeCompressionChallenge>,
}

impl Default for FeeCompressionState {
    fn default() -> Self {
        Self {
            height: 0,
            config: FeeCompressionConfig::default(),
            packets: BTreeMap::new(),
            batches: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            paymaster_positions: BTreeMap::new(),
            proofs: BTreeMap::new(),
            privacy_disclosures: BTreeMap::new(),
            settlements: BTreeMap::new(),
            challenges: BTreeMap::new(),
        }
    }
}

impl FeeCompressionState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet(operator_label: &str) -> FeeCompressionResult<Self> {
        ensure_non_empty(operator_label, "fee compression operator label")?;
        let mut state = Self::new();
        state.set_height(8);
        let sponsorship = LowFeeSponsorshipWindow::new(
            fee_compression_string_root("FEE-DEVNET-SPONSOR", operator_label),
            FeeCompressionLaneKind::PrivateDefi,
            FEE_COMPRESSION_DEVNET_ASSET_ID,
            2_500_000,
            1_500,
            50_000,
            state.height,
            state.height.saturating_add(1_000),
        )?;
        let sponsorship_id = state.insert_sponsorship(sponsorship)?;

        let mut packets = Vec::new();
        for (index, label) in ["swap", "lend", "bridge", "contract"].iter().enumerate() {
            let lane_kind = if *label == "bridge" {
                FeeCompressionLaneKind::Bridge
            } else if *label == "contract" {
                FeeCompressionLaneKind::Contract
            } else {
                FeeCompressionLaneKind::PrivateDefi
            };
            let gross = 40_000_u64.saturating_add((index as u64).saturating_mul(3_000));
            let compressed = gross.saturating_mul(7_000).saturating_div(10_000);
            let packet = FeePacketCommitment::new(
                fee_compression_string_root("FEE-DEVNET-PAYER", label),
                lane_kind,
                FEE_COMPRESSION_DEVNET_ASSET_ID,
                gross,
                compressed,
                if lane_kind == FeeCompressionLaneKind::PrivateDefi {
                    5_000
                } else {
                    0
                },
                fee_compression_string_root("FEE-DEVNET-PAYLOAD", label),
                fee_compression_string_root("FEE-DEVNET-PRIVACY-LABEL", label),
                fee_compression_string_root("FEE-DEVNET-NULLIFIER", label),
                state.height,
                state.height.saturating_add(state.config.default_ttl_blocks),
                100 + index as u64,
            )?;
            let packet_id = state.insert_packet(packet.clone())?;
            if packet.lane_kind == FeeCompressionLaneKind::PrivateDefi {
                packets.push(packet);
            }
            let disclosure = FeePrivacyDisclosure::new(
                packet_id,
                fee_compression_string_root("FEE-DEVNET-DISCLOSURE", label),
                500,
                fee_compression_string_root("FEE-DEVNET-AUDIENCE", "auditor"),
                fee_compression_string_root("FEE-DEVNET-AUDITOR", "fee-auditor"),
                state.height,
                state.height.saturating_add(144),
            )?;
            state.insert_privacy_disclosure(disclosure)?;
        }
        let packet_root = fee_packet_collection_root(&packets);
        let paymaster = PaymasterNettingPosition::new(
            fee_compression_string_root("FEE-DEVNET-PAYMASTER", FEE_COMPRESSION_DEVNET_PAYMASTER),
            FEE_COMPRESSION_DEVNET_ASSET_ID,
            packets
                .iter()
                .map(|packet| packet.compressed_fee_units)
                .sum::<u64>(),
            packets
                .iter()
                .map(FeePacketCommitment::savings_units)
                .sum::<u64>(),
            &packet_root,
            fee_compression_string_root("FEE-DEVNET-BATCH", "private-defi"),
            0,
            state.height,
        )?;
        let paymaster_root = paymaster.position_root();
        state.insert_paymaster_position(paymaster)?;
        let privacy_root = state.privacy_disclosure_root();
        let proof = FeeCompressionProof::new(
            FeeCompressionProofKind::BatchSavings,
            "devnet-private-defi-fee-batch",
            &packet_root,
            fee_compression_string_root("FEE-DEVNET-SAVINGS", "private-defi"),
            fee_compression_string_root("FEE-DEVNET-COMMITTEE", "fee-verifiers"),
            fee_compression_signature_root(operator_label, &packet_root),
            state.height,
        )?;
        let proof_root = proof.proof_root();
        state.insert_proof(proof)?;
        let batch = FeeCompressionBatch::new(
            state.height,
            FeeCompressionLaneKind::PrivateDefi,
            FEE_COMPRESSION_DEVNET_ASSET_ID,
            &packets,
            paymaster_root,
            privacy_root,
            proof_root,
            state.config.settlement_delay_blocks,
        )?;
        let batch_id = state.insert_batch(batch.clone())?;
        state.apply_sponsorship_to_batch(&batch_id, &sponsorship_id)?;
        let settled_batch = state
            .batches
            .get(&batch_id)
            .cloned()
            .ok_or_else(|| "devnet fee batch missing".to_string())?;
        let envelope = FeeSettlementEnvelope::new(
            &settled_batch,
            fee_compression_string_root("FEE-DEVNET-PAYER-SET", "private-defi"),
            state.paymaster_position_root(),
            fee_compression_string_root("FEE-DEVNET-SETTLEMENT-ACCOUNT", "fee-vault"),
            fee_compression_string_root("FEE-DEVNET-FINALITY", "soft-final"),
            state
                .height
                .saturating_add(state.config.settlement_delay_blocks),
        )?;
        state.insert_settlement(envelope)?;
        let challenge = FeeCompressionChallenge::new(
            settled_batch.batch_id.clone(),
            settled_batch.batch_root(),
            fee_compression_string_root("FEE-DEVNET-CHALLENGER", "watchtower"),
            fee_compression_string_root("FEE-DEVNET-EVIDENCE", "sampled-fee-batch"),
            state.height,
            64,
            25_000,
        )?;
        state.insert_challenge(challenge)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for packet in self.packets.values_mut() {
            if packet.status == FEE_COMPRESSION_STATUS_PENDING && packet.is_expired_at(height) {
                packet.status = FEE_COMPRESSION_STATUS_EXPIRED.to_string();
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            sponsorship.set_height(height);
        }
        for disclosure in self.privacy_disclosures.values_mut() {
            disclosure.set_height(height);
        }
        for challenge in self.challenges.values_mut() {
            challenge.set_height(height);
        }
    }

    pub fn insert_packet(&mut self, packet: FeePacketCommitment) -> FeeCompressionResult<String> {
        packet.validate()?;
        if packet.submitted_at_height > self.height {
            return Err("fee packet submission height is in the future".to_string());
        }
        let packet_id = packet.packet_id.clone();
        self.packets.insert(packet_id.clone(), packet);
        Ok(packet_id)
    }

    pub fn insert_batch(&mut self, batch: FeeCompressionBatch) -> FeeCompressionResult<String> {
        batch.validate()?;
        for packet_id in &batch.packet_ids {
            let packet = self
                .packets
                .get_mut(packet_id)
                .ok_or_else(|| format!("fee batch references missing packet {packet_id}"))?;
            if packet.status == FEE_COMPRESSION_STATUS_EXPIRED {
                return Err("fee batch references expired packet".to_string());
            }
            packet.status = FEE_COMPRESSION_STATUS_SETTLED.to_string();
        }
        let batch_id = batch.batch_id.clone();
        self.batches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeSponsorshipWindow,
    ) -> FeeCompressionResult<String> {
        sponsorship.validate()?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        Ok(sponsorship_id)
    }

    pub fn insert_paymaster_position(
        &mut self,
        position: PaymasterNettingPosition,
    ) -> FeeCompressionResult<String> {
        position.validate()?;
        let position_id = position.position_id.clone();
        self.paymaster_positions
            .insert(position_id.clone(), position);
        Ok(position_id)
    }

    pub fn insert_proof(&mut self, proof: FeeCompressionProof) -> FeeCompressionResult<String> {
        proof.validate()?;
        let proof_id = proof.proof_id.clone();
        self.proofs.insert(proof_id.clone(), proof);
        Ok(proof_id)
    }

    pub fn insert_privacy_disclosure(
        &mut self,
        disclosure: FeePrivacyDisclosure,
    ) -> FeeCompressionResult<String> {
        if self.privacy_disclosures.len() >= FEE_COMPRESSION_MAX_DISCLOSURES
            && !self
                .privacy_disclosures
                .contains_key(&disclosure.disclosure_id)
        {
            return Err("fee privacy disclosure limit exceeded".to_string());
        }
        disclosure.validate()?;
        if disclosure.privacy_budget_bps > self.config.max_privacy_budget_bps {
            return Err("fee privacy disclosure exceeds configured budget".to_string());
        }
        let disclosure_id = disclosure.disclosure_id.clone();
        self.privacy_disclosures
            .insert(disclosure_id.clone(), disclosure);
        Ok(disclosure_id)
    }

    pub fn insert_settlement(
        &mut self,
        settlement: FeeSettlementEnvelope,
    ) -> FeeCompressionResult<String> {
        settlement.validate()?;
        if !self.batches.contains_key(&settlement.batch_id) {
            return Err("fee settlement references unknown batch".to_string());
        }
        let envelope_id = settlement.envelope_id.clone();
        self.settlements.insert(envelope_id.clone(), settlement);
        Ok(envelope_id)
    }

    pub fn insert_challenge(
        &mut self,
        challenge: FeeCompressionChallenge,
    ) -> FeeCompressionResult<String> {
        challenge.validate()?;
        let challenge_id = challenge.challenge_id.clone();
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn apply_sponsorship_to_batch(
        &mut self,
        batch_id: &str,
        sponsorship_id: &str,
    ) -> FeeCompressionResult<u64> {
        let batch = self
            .batches
            .get(batch_id)
            .ok_or_else(|| "fee sponsorship references unknown batch".to_string())?
            .clone();
        let sponsorship = self
            .sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "fee sponsorship id is unknown".to_string())?;
        let eligible = batch
            .packet_ids
            .iter()
            .filter_map(|packet_id| self.packets.get(packet_id))
            .filter(|packet| sponsorship.eligible_packet(packet, self.height))
            .map(|packet| {
                packet
                    .low_fee_credit_units
                    .min(packet.compressed_fee_units)
                    .min(sponsorship.max_packet_units)
            })
            .sum::<u64>();
        let charge = eligible.min(sponsorship.available_units(self.height));
        sponsorship.charge(charge, self.height)?;
        if let Some(stored) = self.batches.get_mut(batch_id) {
            stored.sponsored_fee_units = stored.sponsored_fee_units.saturating_add(charge);
            stored.status = FEE_COMPRESSION_STATUS_SETTLED.to_string();
        }
        Ok(charge)
    }

    pub fn compress_pending_for_lane(
        &mut self,
        lane_kind: FeeCompressionLaneKind,
        asset_id: &str,
    ) -> FeeCompressionResult<Option<FeeCompressionBatch>> {
        let mut packets = self
            .packets
            .values()
            .filter(|packet| {
                packet.status == FEE_COMPRESSION_STATUS_PENDING
                    && packet.lane_kind == lane_kind
                    && packet.asset_id == asset_id
                    && !packet.is_expired_at(self.height)
            })
            .cloned()
            .collect::<Vec<_>>();
        if packets.is_empty() {
            return Ok(None);
        }
        packets.sort_by(|left, right| {
            right
                .effective_priority()
                .cmp(&left.effective_priority())
                .then_with(|| left.submitted_at_height.cmp(&right.submitted_at_height))
                .then_with(|| left.packet_id.cmp(&right.packet_id))
        });
        packets.truncate(
            self.config
                .max_batch_packets
                .min(FEE_COMPRESSION_MAX_BATCH_PACKETS as u64) as usize,
        );
        let packet_root = fee_packet_collection_root(&packets);
        let paymaster = PaymasterNettingPosition::new(
            fee_compression_string_root("FEE-PAYMASTER", FEE_COMPRESSION_DEVNET_PAYMASTER),
            asset_id,
            packets
                .iter()
                .map(|packet| packet.compressed_fee_units)
                .sum::<u64>(),
            packets
                .iter()
                .map(FeePacketCommitment::savings_units)
                .sum::<u64>(),
            &packet_root,
            fee_compression_string_root(
                "FEE-BATCH-AUTO",
                &format!("{}:{}", lane_kind.as_str(), self.height),
            ),
            self.batches.len() as u64,
            self.height,
        )?;
        let paymaster_root = paymaster.position_root();
        self.insert_paymaster_position(paymaster)?;
        let proof = FeeCompressionProof::new(
            FeeCompressionProofKind::BatchSavings,
            format!("auto-fee-batch-{}-{}", lane_kind.as_str(), self.height),
            &packet_root,
            fee_compression_payload_root(
                "FEE-AUTO-SAVINGS-STATEMENT",
                &json!({"lane_kind": lane_kind.as_str(), "height": self.height}),
            ),
            fee_compression_string_root("FEE-AUTO-VERIFIER", "fee-verifier-committee"),
            fee_compression_signature_root("fee-compressor", &packet_root),
            self.height,
        )?;
        let proof_root = proof.proof_root();
        self.insert_proof(proof)?;
        let batch = FeeCompressionBatch::new(
            self.height,
            lane_kind,
            asset_id,
            &packets,
            paymaster_root,
            self.privacy_disclosure_root(),
            proof_root,
            self.config.settlement_delay_blocks,
        )?;
        self.insert_batch(batch.clone())?;
        Ok(Some(batch))
    }

    pub fn roots(&self) -> FeeCompressionRoots {
        FeeCompressionRoots {
            config_root: self.config.config_root(),
            packet_root: self.packet_root(),
            batch_root: self.batch_root(),
            sponsorship_root: self.sponsorship_root(),
            paymaster_position_root: self.paymaster_position_root(),
            proof_root: self.proof_root(),
            privacy_disclosure_root: self.privacy_disclosure_root(),
            settlement_envelope_root: self.settlement_envelope_root(),
            challenge_root: self.challenge_root(),
        }
    }

    pub fn packet_root(&self) -> String {
        fee_packet_collection_root(&self.packets.values().cloned().collect::<Vec<_>>())
    }

    pub fn batch_root(&self) -> String {
        fee_batch_collection_root(&self.batches.values().cloned().collect::<Vec<_>>())
    }

    pub fn sponsorship_root(&self) -> String {
        fee_sponsorship_collection_root(&self.sponsorships.values().cloned().collect::<Vec<_>>())
    }

    pub fn paymaster_position_root(&self) -> String {
        paymaster_position_collection_root(
            &self
                .paymaster_positions
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn proof_root(&self) -> String {
        fee_proof_collection_root(&self.proofs.values().cloned().collect::<Vec<_>>())
    }

    pub fn privacy_disclosure_root(&self) -> String {
        fee_privacy_disclosure_collection_root(
            &self
                .privacy_disclosures
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn settlement_envelope_root(&self) -> String {
        fee_settlement_collection_root(&self.settlements.values().cloned().collect::<Vec<_>>())
    }

    pub fn challenge_root(&self) -> String {
        fee_challenge_collection_root(&self.challenges.values().cloned().collect::<Vec<_>>())
    }

    pub fn pending_packet_count(&self) -> u64 {
        self.packets
            .values()
            .filter(|packet| packet.status == FEE_COMPRESSION_STATUS_PENDING)
            .count() as u64
    }

    pub fn settled_batch_count(&self) -> u64 {
        self.batches
            .values()
            .filter(|batch| batch.status == FEE_COMPRESSION_STATUS_SETTLED)
            .count() as u64
    }

    pub fn available_sponsorship_units(&self) -> u64 {
        self.sponsorships
            .values()
            .map(|sponsorship| sponsorship.available_units(self.height))
            .sum()
    }

    pub fn total_compressed_fee_units(&self) -> u64 {
        self.batches
            .values()
            .map(|batch| batch.compressed_fee_units)
            .sum()
    }

    pub fn total_savings_units(&self) -> u64 {
        self.batches
            .values()
            .map(|batch| {
                batch
                    .gross_fee_units
                    .saturating_sub(batch.compressed_fee_units)
            })
            .sum()
    }

    pub fn state_root(&self) -> String {
        fee_compression_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("fee compression state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "fee_compression_state",
            "chain_id": CHAIN_ID,
            "protocol_version": FEE_COMPRESSION_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "packet_count": self.packets.len() as u64,
            "pending_packet_count": self.pending_packet_count(),
            "batch_count": self.batches.len() as u64,
            "settled_batch_count": self.settled_batch_count(),
            "sponsorship_count": self.sponsorships.len() as u64,
            "available_sponsorship_units": self.available_sponsorship_units(),
            "paymaster_position_count": self.paymaster_positions.len() as u64,
            "proof_count": self.proofs.len() as u64,
            "privacy_disclosure_count": self.privacy_disclosures.len() as u64,
            "settlement_count": self.settlements.len() as u64,
            "challenge_count": self.challenges.len() as u64,
            "total_compressed_fee_units": self.total_compressed_fee_units(),
            "total_savings_units": self.total_savings_units(),
        })
    }

    pub fn validate(&self) -> FeeCompressionResult<String> {
        self.config.validate()?;
        for packet in self.packets.values() {
            packet.validate()?;
        }
        for batch in self.batches.values() {
            batch.validate()?;
            for packet_id in &batch.packet_ids {
                if !self.packets.contains_key(packet_id) {
                    return Err("fee batch references unknown packet".to_string());
                }
            }
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
        }
        for position in self.paymaster_positions.values() {
            position.validate()?;
        }
        for proof in self.proofs.values() {
            proof.validate()?;
        }
        for disclosure in self.privacy_disclosures.values() {
            disclosure.validate()?;
            if disclosure.privacy_budget_bps > self.config.max_privacy_budget_bps {
                return Err("fee privacy disclosure exceeds configured budget".to_string());
            }
        }
        for settlement in self.settlements.values() {
            settlement.validate()?;
            if !self.batches.contains_key(&settlement.batch_id) {
                return Err("fee settlement references unknown batch".to_string());
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn fee_compression_config_id(payload: &Value) -> String {
    fee_compression_payload_root("FEE-COMPRESSION-CONFIG-ID", payload)
}

#[allow(clippy::too_many_arguments)]
pub fn fee_packet_id(
    payer_commitment: &str,
    lane_kind: FeeCompressionLaneKind,
    asset_id: &str,
    gross_fee_units: u64,
    compressed_fee_units: u64,
    low_fee_credit_units: u64,
    payload_root: &str,
    privacy_label_root: &str,
    nullifier_root: &str,
    submitted_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "FEE-PACKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(payer_commitment),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(asset_id),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(compressed_fee_units as i128),
            HashPart::Int(low_fee_credit_units as i128),
            HashPart::Str(payload_root),
            HashPart::Str(privacy_label_root),
            HashPart::Str(nullifier_root),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fee_sponsorship_id(
    sponsor_commitment: &str,
    lane_kind: FeeCompressionLaneKind,
    asset_id: &str,
    total_budget_units: u64,
    min_discount_bps: u64,
    max_packet_units: u64,
    opened_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "FEE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(asset_id),
            HashPart::Int(total_budget_units as i128),
            HashPart::Int(min_discount_bps as i128),
            HashPart::Int(max_packet_units as i128),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn paymaster_netting_position_id(
    paymaster_commitment: &str,
    asset_id: &str,
    debit_units: u64,
    credit_units: u64,
    packet_root: &str,
    batch_root: &str,
    nonce: u64,
    height: u64,
) -> String {
    domain_hash(
        "PAYMASTER-NETTING-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(paymaster_commitment),
            HashPart::Str(asset_id),
            HashPart::Int(debit_units as i128),
            HashPart::Int(credit_units as i128),
            HashPart::Str(packet_root),
            HashPart::Str(batch_root),
            HashPart::Int(nonce as i128),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fee_compression_proof_id(
    proof_kind: FeeCompressionProofKind,
    subject_id: &str,
    subject_root: &str,
    statement_root: &str,
    verifier_committee_root: &str,
    pq_signature_root: &str,
    produced_at_height: u64,
) -> String {
    domain_hash(
        "FEE-COMPRESSION-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(statement_root),
            HashPart::Str(verifier_committee_root),
            HashPart::Str(pq_signature_root),
            HashPart::Int(produced_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fee_privacy_disclosure_id(
    subject_id: &str,
    disclosed_root: &str,
    privacy_budget_bps: u64,
    audience_root: &str,
    auditor_commitment: &str,
    opened_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "FEE-PRIVACY-DISCLOSURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(disclosed_root),
            HashPart::Int(privacy_budget_bps as i128),
            HashPart::Str(audience_root),
            HashPart::Str(auditor_commitment),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fee_compression_batch_id(
    height: u64,
    lane_kind: FeeCompressionLaneKind,
    asset_id: &str,
    packet_root: &str,
    gross_fee_units: u64,
    compressed_fee_units: u64,
    sponsored_fee_units: u64,
    paymaster_root: &str,
    privacy_disclosure_root: &str,
    proof_root: &str,
    settlement_due_height: u64,
) -> String {
    domain_hash(
        "FEE-COMPRESSION-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(asset_id),
            HashPart::Str(packet_root),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(compressed_fee_units as i128),
            HashPart::Int(sponsored_fee_units as i128),
            HashPart::Str(paymaster_root),
            HashPart::Str(privacy_disclosure_root),
            HashPart::Str(proof_root),
            HashPart::Int(settlement_due_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fee_settlement_envelope_id(
    batch_id: &str,
    batch_root: &str,
    asset_id: &str,
    payer_set_root: &str,
    paymaster_netting_root: &str,
    amount_units: u64,
    sponsored_units: u64,
    settlement_account_root: &str,
    finality_hint_root: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "FEE-SETTLEMENT-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(batch_root),
            HashPart::Str(asset_id),
            HashPart::Str(payer_set_root),
            HashPart::Str(paymaster_netting_root),
            HashPart::Int(amount_units as i128),
            HashPart::Int(sponsored_units as i128),
            HashPart::Str(settlement_account_root),
            HashPart::Str(finality_hint_root),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fee_compression_challenge_id(
    subject_id: &str,
    subject_root: &str,
    challenger_commitment: &str,
    evidence_root: &str,
    opened_at_height: u64,
    expires_at_height: u64,
    bond_units: u64,
) -> String {
    domain_hash(
        "FEE-COMPRESSION-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Int(bond_units as i128),
        ],
        32,
    )
}

pub fn fee_packet_collection_root(packets: &[FeePacketCommitment]) -> String {
    merkle_root(
        "FEE-PACKET-COLLECTION",
        &packets
            .iter()
            .map(FeePacketCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fee_batch_collection_root(batches: &[FeeCompressionBatch]) -> String {
    merkle_root(
        "FEE-BATCH-COLLECTION",
        &batches
            .iter()
            .map(FeeCompressionBatch::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fee_sponsorship_collection_root(sponsorships: &[LowFeeSponsorshipWindow]) -> String {
    merkle_root(
        "FEE-SPONSORSHIP-COLLECTION",
        &sponsorships
            .iter()
            .map(LowFeeSponsorshipWindow::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn paymaster_position_collection_root(positions: &[PaymasterNettingPosition]) -> String {
    merkle_root(
        "PAYMASTER-POSITION-COLLECTION",
        &positions
            .iter()
            .map(PaymasterNettingPosition::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fee_proof_collection_root(proofs: &[FeeCompressionProof]) -> String {
    merkle_root(
        "FEE-PROOF-COLLECTION",
        &proofs
            .iter()
            .map(FeeCompressionProof::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fee_privacy_disclosure_collection_root(disclosures: &[FeePrivacyDisclosure]) -> String {
    merkle_root(
        "FEE-PRIVACY-DISCLOSURE-COLLECTION",
        &disclosures
            .iter()
            .map(FeePrivacyDisclosure::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fee_settlement_collection_root(settlements: &[FeeSettlementEnvelope]) -> String {
    merkle_root(
        "FEE-SETTLEMENT-COLLECTION",
        &settlements
            .iter()
            .map(FeeSettlementEnvelope::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fee_challenge_collection_root(challenges: &[FeeCompressionChallenge]) -> String {
    merkle_root(
        "FEE-CHALLENGE-COLLECTION",
        &challenges
            .iter()
            .map(FeeCompressionChallenge::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fee_compression_state_root_from_record(record: &Value) -> String {
    fee_compression_payload_root("FEE-COMPRESSION-STATE", record)
}

pub fn fee_compression_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn fee_compression_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn fee_compression_string_set_root(domain: &str, values: &[String]) -> String {
    let records = values
        .iter()
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn fee_compression_signature_root(signer_label: &str, message_root: &str) -> String {
    domain_hash(
        "FEE-COMPRESSION-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(signer_label),
            HashPart::Str(message_root),
            HashPart::Str("ML-DSA-65"),
        ],
        32,
    )
}

pub fn compression_discount_bps(gross_units: u64, compressed_units: u64) -> u64 {
    if gross_units == 0 || compressed_units >= gross_units {
        0
    } else {
        gross_units
            .saturating_sub(compressed_units)
            .saturating_mul(FEE_COMPRESSION_MAX_BPS)
            .saturating_div(gross_units)
    }
}

fn ensure_non_empty(value: &str, label: &str) -> FeeCompressionResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> FeeCompressionResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn validate_bps(value: u64, label: &str) -> FeeCompressionResult<()> {
    if value > FEE_COMPRESSION_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> FeeCompressionResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicates"));
        }
    }
    Ok(())
}
