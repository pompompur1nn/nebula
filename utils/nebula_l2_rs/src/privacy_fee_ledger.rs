use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivacyFeeLedgerResult<T> = Result<T, String>;

pub const PRIVACY_FEE_LEDGER_PROTOCOL_VERSION: &str = "nebula-privacy-fee-ledger-v1";
pub const PRIVACY_FEE_LEDGER_COMMITMENT_SCHEME: &str = "pedersen-shake256-fee-commitment-v1";
pub const PRIVACY_FEE_LEDGER_NULLIFIER_SCHEME: &str = "shake256-private-fee-nullifier-v1";
pub const PRIVACY_FEE_LEDGER_PQ_ATTESTATION_SCHEME: &str = "ml-dsa-65-fee-sponsor-attestation-v1";
pub const PRIVACY_FEE_LEDGER_REBATE_PROOF_SCHEME: &str = "zk-fee-rebate-range-proof-devnet-v1";
pub const PRIVACY_FEE_LEDGER_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVACY_FEE_LEDGER_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 1_440;
pub const PRIVACY_FEE_LEDGER_DEFAULT_AUDIT_WINDOW_BLOCKS: u64 = 120;
pub const PRIVACY_FEE_LEDGER_DEFAULT_MAX_DISCLOSURE_BPS: u64 = 1_500;
pub const PRIVACY_FEE_LEDGER_MAX_BPS: u64 = 10_000;
pub const PRIVACY_FEE_LEDGER_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFeeLane {
    PrivateTransfer,
    MoneroBridge,
    SmallDefi,
    ContractCall,
    ProofJob,
    WalletRecovery,
    EmergencyExit,
}

impl PrivacyFeeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::SmallDefi => "small_defi",
            Self::ContractCall => "contract_call",
            Self::ProofJob => "proof_job",
            Self::WalletRecovery => "wallet_recovery",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_priority_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 100,
            Self::MoneroBridge => 90,
            Self::WalletRecovery => 80,
            Self::PrivateTransfer => 70,
            Self::SmallDefi => 65,
            Self::ContractCall => 60,
            Self::ProofJob => 55,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeDisclosureLevel {
    None,
    LaneOnly,
    SponsorOnly,
    Aggregate,
    RegulatorView,
}

impl FeeDisclosureLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::LaneOnly => "lane_only",
            Self::SponsorOnly => "sponsor_only",
            Self::Aggregate => "aggregate",
            Self::RegulatorView => "regulator_view",
        }
    }

    pub fn reveals_sponsor(self) -> bool {
        matches!(self, Self::SponsorOnly | Self::RegulatorView)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPolicyStatus {
    Active,
    Reserved,
    Exhausted,
    Paused,
    Expired,
    Revoked,
}

impl SponsorPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn can_spend(self) -> bool {
        matches!(self, Self::Active | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCommitmentStatus {
    Quoted,
    Included,
    RebatePending,
    RebateSettled,
    Expired,
    Disputed,
}

impl FeeCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Included => "included",
            Self::RebatePending => "rebate_pending",
            Self::RebateSettled => "rebate_settled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateSettlementStatus {
    Pending,
    Settled,
    PartiallySettled,
    Rejected,
    Challenged,
    Expired,
}

impl RebateSettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn is_final(self) -> bool {
        matches!(self, Self::Settled | Self::Rejected | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditWindowStatus {
    Open,
    Sealed,
    Challenged,
    Published,
}

impl AuditWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Challenged => "challenged",
            Self::Published => "published",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFeeLedgerConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub audit_window_blocks: u64,
    pub max_public_disclosure_bps: u64,
    pub commitment_scheme: String,
    pub nullifier_scheme: String,
    pub pq_attestation_scheme: String,
    pub rebate_proof_scheme: String,
}

impl PrivacyFeeLedgerConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVACY_FEE_LEDGER_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: PRIVACY_FEE_LEDGER_DEVNET_FEE_ASSET_ID.to_string(),
            epoch_blocks: PRIVACY_FEE_LEDGER_DEFAULT_EPOCH_BLOCKS,
            sponsor_ttl_blocks: PRIVACY_FEE_LEDGER_DEFAULT_SPONSOR_TTL_BLOCKS,
            audit_window_blocks: PRIVACY_FEE_LEDGER_DEFAULT_AUDIT_WINDOW_BLOCKS,
            max_public_disclosure_bps: PRIVACY_FEE_LEDGER_DEFAULT_MAX_DISCLOSURE_BPS,
            commitment_scheme: PRIVACY_FEE_LEDGER_COMMITMENT_SCHEME.to_string(),
            nullifier_scheme: PRIVACY_FEE_LEDGER_NULLIFIER_SCHEME.to_string(),
            pq_attestation_scheme: PRIVACY_FEE_LEDGER_PQ_ATTESTATION_SCHEME.to_string(),
            rebate_proof_scheme: PRIVACY_FEE_LEDGER_REBATE_PROOF_SCHEME.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_fee_ledger_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "audit_window_blocks": self.audit_window_blocks,
            "max_public_disclosure_bps": self.max_public_disclosure_bps,
            "commitment_scheme": self.commitment_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "rebate_proof_scheme": self.rebate_proof_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        privacy_fee_ledger_payload_root("PRIVACY-FEE-LEDGER-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivacyFeeLedgerResult<String> {
        ensure_eq(
            "protocol version",
            &self.protocol_version,
            PRIVACY_FEE_LEDGER_PROTOCOL_VERSION,
        )?;
        ensure_eq("chain id", &self.chain_id, CHAIN_ID)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("epoch blocks", self.epoch_blocks)?;
        ensure_positive("sponsor ttl blocks", self.sponsor_ttl_blocks)?;
        ensure_positive("audit window blocks", self.audit_window_blocks)?;
        ensure_bps("max public disclosure bps", self.max_public_disclosure_bps)?;
        ensure_eq(
            "commitment scheme",
            &self.commitment_scheme,
            PRIVACY_FEE_LEDGER_COMMITMENT_SCHEME,
        )?;
        ensure_eq(
            "nullifier scheme",
            &self.nullifier_scheme,
            PRIVACY_FEE_LEDGER_NULLIFIER_SCHEME,
        )?;
        ensure_eq(
            "pq attestation scheme",
            &self.pq_attestation_scheme,
            PRIVACY_FEE_LEDGER_PQ_ATTESTATION_SCHEME,
        )?;
        ensure_eq(
            "rebate proof scheme",
            &self.rebate_proof_scheme,
            PRIVACY_FEE_LEDGER_REBATE_PROOF_SCHEME,
        )?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedFeeSponsor {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub lane: PrivacyFeeLane,
    pub fee_asset_id: String,
    pub total_budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_rebate_bps: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub pq_operator_key_root: String,
    pub pq_attestation_root: String,
    pub disclosure_level: FeeDisclosureLevel,
    pub status: SponsorPolicyStatus,
}

impl ShieldedFeeSponsor {
    pub fn new(
        sponsor_label: &str,
        lane: PrivacyFeeLane,
        fee_asset_id: &str,
        total_budget_units: u64,
        max_rebate_bps: u64,
        valid_from_height: u64,
        valid_until_height: u64,
        disclosure_level: FeeDisclosureLevel,
        nonce: u64,
    ) -> PrivacyFeeLedgerResult<Self> {
        ensure_non_empty("sponsor label", sponsor_label)?;
        ensure_non_empty("fee asset id", fee_asset_id)?;
        ensure_positive("total budget units", total_budget_units)?;
        ensure_bps("max rebate bps", max_rebate_bps)?;
        ensure_height_window(valid_from_height, valid_until_height, "sponsor policy")?;
        let sponsor_commitment =
            privacy_fee_ledger_commitment("SPONSOR-COMMITMENT", sponsor_label, nonce);
        let pq_operator_key_root =
            privacy_fee_ledger_string_root("SPONSOR-PQ-KEY", &format!("{sponsor_label}:{nonce}"));
        let pq_attestation_root = privacy_fee_ledger_payload_root(
            "SPONSOR-PQ-ATTESTATION",
            &json!({
                "scheme": PRIVACY_FEE_LEDGER_PQ_ATTESTATION_SCHEME,
                "label": sponsor_label,
                "lane": lane.as_str(),
                "key_root": pq_operator_key_root,
            }),
        );
        let sponsor_id = privacy_fee_sponsor_id(
            &sponsor_commitment,
            lane,
            fee_asset_id,
            valid_from_height,
            valid_until_height,
        );
        Ok(Self {
            sponsor_id,
            sponsor_commitment,
            lane,
            fee_asset_id: fee_asset_id.to_string(),
            total_budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_rebate_bps,
            valid_from_height,
            valid_until_height,
            pq_operator_key_root,
            pq_attestation_root,
            disclosure_level,
            status: SponsorPolicyStatus::Active,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.can_spend()
            && height >= self.valid_from_height
            && height <= self.valid_until_height
            && self.available_units() > 0
    }

    pub fn available_units(&self) -> u64 {
        self.total_budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn reserve(&mut self, units: u64) -> PrivacyFeeLedgerResult<()> {
        ensure_positive("reserve units", units)?;
        if units > self.available_units() {
            return Err("sponsor reserve exceeds available units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        if self.available_units() == 0 {
            self.status = SponsorPolicyStatus::Reserved;
        }
        Ok(())
    }

    pub fn spend_reserved(&mut self, units: u64) -> PrivacyFeeLedgerResult<()> {
        ensure_positive("spend units", units)?;
        if units > self.reserved_units {
            return Err("sponsor spend exceeds reserved units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.spent_units = self.spent_units.saturating_add(units);
        if self.available_units() == 0 && self.reserved_units == 0 {
            self.status = SponsorPolicyStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_fee_sponsor",
            "chain_id": CHAIN_ID,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane": self.lane.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "total_budget_units": self.total_budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_rebate_bps": self.max_rebate_bps,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "pq_operator_key_root": self.pq_operator_key_root,
            "pq_attestation_root": self.pq_attestation_root,
            "disclosure_level": self.disclosure_level.as_str(),
            "status": self.status.as_str(),
        })
    }

    pub fn sponsor_root(&self) -> String {
        privacy_fee_ledger_payload_root("PRIVACY-FEE-SPONSOR", &self.public_record())
    }

    pub fn validate(&self) -> PrivacyFeeLedgerResult<String> {
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_positive("total budget units", self.total_budget_units)?;
        ensure_bps("max rebate bps", self.max_rebate_bps)?;
        ensure_height_window(
            self.valid_from_height,
            self.valid_until_height,
            "sponsor policy",
        )?;
        if self.reserved_units.saturating_add(self.spent_units) > self.total_budget_units {
            return Err("sponsor reserved plus spent exceeds total budget".to_string());
        }
        let expected_id = privacy_fee_sponsor_id(
            &self.sponsor_commitment,
            self.lane,
            &self.fee_asset_id,
            self.valid_from_height,
            self.valid_until_height,
        );
        if self.sponsor_id != expected_id {
            return Err("sponsor id mismatch".to_string());
        }
        ensure_non_empty("sponsor pq operator key root", &self.pq_operator_key_root)?;
        ensure_non_empty("sponsor pq attestation root", &self.pq_attestation_root)?;
        Ok(self.sponsor_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedFeeCommitment {
    pub commitment_id: String,
    pub lane: PrivacyFeeLane,
    pub fee_asset_id: String,
    pub payer_nullifier: String,
    pub fee_commitment: String,
    pub amount_upper_bound_units: u64,
    pub max_rebate_units: u64,
    pub sponsor_id: String,
    pub quote_root: String,
    pub inclusion_height: u64,
    pub expires_at_height: u64,
    pub private_metadata_root: String,
    pub rebate_proof_root: String,
    pub disclosure_level: FeeDisclosureLevel,
    pub status: FeeCommitmentStatus,
}

impl BlindedFeeCommitment {
    pub fn new(
        lane: PrivacyFeeLane,
        fee_asset_id: &str,
        payer_label: &str,
        amount_upper_bound_units: u64,
        max_rebate_units: u64,
        sponsor_id: &str,
        inclusion_height: u64,
        expires_at_height: u64,
        disclosure_level: FeeDisclosureLevel,
        nonce: u64,
    ) -> PrivacyFeeLedgerResult<Self> {
        ensure_non_empty("fee asset id", fee_asset_id)?;
        ensure_non_empty("payer label", payer_label)?;
        ensure_positive("amount upper bound units", amount_upper_bound_units)?;
        ensure_non_empty("sponsor id", sponsor_id)?;
        ensure_height_window(inclusion_height, expires_at_height, "fee commitment")?;
        if max_rebate_units > amount_upper_bound_units {
            return Err("max rebate exceeds amount upper bound".to_string());
        }
        let payer_nullifier =
            privacy_fee_ledger_commitment("FEE-PAYER-NULLIFIER", payer_label, nonce);
        let fee_commitment =
            privacy_fee_ledger_commitment("FEE-AMOUNT-COMMITMENT", fee_asset_id, nonce);
        let quote_root = privacy_fee_ledger_payload_root(
            "FEE-QUOTE",
            &json!({
                "lane": lane.as_str(),
                "fee_asset_id": fee_asset_id,
                "amount_upper_bound_units": amount_upper_bound_units,
                "max_rebate_units": max_rebate_units,
                "sponsor_id": sponsor_id,
            }),
        );
        let private_metadata_root = privacy_fee_ledger_payload_root(
            "FEE-PRIVATE-METADATA",
            &json!({
                "payer_nullifier": payer_nullifier,
                "lane": lane.as_str(),
                "nonce": nonce,
            }),
        );
        let rebate_proof_root = privacy_fee_ledger_payload_root(
            "FEE-REBATE-PROOF",
            &json!({
                "scheme": PRIVACY_FEE_LEDGER_REBATE_PROOF_SCHEME,
                "commitment": fee_commitment,
                "upper_bound_units": amount_upper_bound_units,
                "max_rebate_units": max_rebate_units,
            }),
        );
        let commitment_id = privacy_fee_commitment_id(
            &payer_nullifier,
            &fee_commitment,
            sponsor_id,
            inclusion_height,
            expires_at_height,
        );
        Ok(Self {
            commitment_id,
            lane,
            fee_asset_id: fee_asset_id.to_string(),
            payer_nullifier,
            fee_commitment,
            amount_upper_bound_units,
            max_rebate_units,
            sponsor_id: sponsor_id.to_string(),
            quote_root,
            inclusion_height,
            expires_at_height,
            private_metadata_root,
            rebate_proof_root,
            disclosure_level,
            status: FeeCommitmentStatus::Quoted,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        height >= self.inclusion_height
            && height <= self.expires_at_height
            && !matches!(
                self.status,
                FeeCommitmentStatus::Expired
                    | FeeCommitmentStatus::Disputed
                    | FeeCommitmentStatus::RebateSettled
            )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "blinded_fee_commitment",
            "chain_id": CHAIN_ID,
            "commitment_id": self.commitment_id,
            "lane": self.lane.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "payer_nullifier": self.payer_nullifier,
            "fee_commitment": self.fee_commitment,
            "amount_upper_bound_units": self.amount_upper_bound_units,
            "max_rebate_units": self.max_rebate_units,
            "sponsor_id": self.sponsor_id,
            "quote_root": self.quote_root,
            "inclusion_height": self.inclusion_height,
            "expires_at_height": self.expires_at_height,
            "private_metadata_root": self.private_metadata_root,
            "rebate_proof_root": self.rebate_proof_root,
            "disclosure_level": self.disclosure_level.as_str(),
            "status": self.status.as_str(),
        })
    }

    pub fn commitment_root(&self) -> String {
        privacy_fee_ledger_payload_root("PRIVACY-FEE-COMMITMENT", &self.public_record())
    }

    pub fn validate(&self) -> PrivacyFeeLedgerResult<String> {
        ensure_non_empty("commitment id", &self.commitment_id)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_non_empty("payer nullifier", &self.payer_nullifier)?;
        ensure_non_empty("fee commitment", &self.fee_commitment)?;
        ensure_positive("amount upper bound units", self.amount_upper_bound_units)?;
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_height_window(
            self.inclusion_height,
            self.expires_at_height,
            "fee commitment",
        )?;
        if self.max_rebate_units > self.amount_upper_bound_units {
            return Err("commitment rebate exceeds upper bound".to_string());
        }
        let expected_id = privacy_fee_commitment_id(
            &self.payer_nullifier,
            &self.fee_commitment,
            &self.sponsor_id,
            self.inclusion_height,
            self.expires_at_height,
        );
        if self.commitment_id != expected_id {
            return Err("commitment id mismatch".to_string());
        }
        ensure_non_empty("quote root", &self.quote_root)?;
        ensure_non_empty("private metadata root", &self.private_metadata_root)?;
        ensure_non_empty("rebate proof root", &self.rebate_proof_root)?;
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeRebate {
    pub rebate_id: String,
    pub commitment_id: String,
    pub sponsor_id: String,
    pub claimed_units: u64,
    pub settled_units: u64,
    pub fee_asset_id: String,
    pub settlement_height: u64,
    pub nullifier_set_root: String,
    pub payout_commitment: String,
    pub settlement_proof_root: String,
    pub status: RebateSettlementStatus,
}

impl PrivateFeeRebate {
    pub fn new(
        commitment_id: &str,
        sponsor_id: &str,
        claimed_units: u64,
        settled_units: u64,
        fee_asset_id: &str,
        settlement_height: u64,
        nonce: u64,
    ) -> PrivacyFeeLedgerResult<Self> {
        ensure_non_empty("commitment id", commitment_id)?;
        ensure_non_empty("sponsor id", sponsor_id)?;
        ensure_positive("claimed units", claimed_units)?;
        ensure_non_empty("fee asset id", fee_asset_id)?;
        if settled_units > claimed_units {
            return Err("settled rebate exceeds claimed rebate".to_string());
        }
        let nullifier_set_root = privacy_fee_ledger_string_root(
            "REBATE-NULLIFIER-SET",
            &format!("{commitment_id}:{sponsor_id}:{nonce}"),
        );
        let payout_commitment =
            privacy_fee_ledger_commitment("REBATE-PAYOUT", commitment_id, nonce);
        let settlement_proof_root = privacy_fee_ledger_payload_root(
            "REBATE-SETTLEMENT-PROOF",
            &json!({
                "scheme": PRIVACY_FEE_LEDGER_REBATE_PROOF_SCHEME,
                "commitment_id": commitment_id,
                "sponsor_id": sponsor_id,
                "claimed_units": claimed_units,
                "settled_units": settled_units,
            }),
        );
        let rebate_id = privacy_fee_rebate_id(
            commitment_id,
            sponsor_id,
            &payout_commitment,
            settlement_height,
        );
        let status = if settled_units == claimed_units {
            RebateSettlementStatus::Settled
        } else if settled_units > 0 {
            RebateSettlementStatus::PartiallySettled
        } else {
            RebateSettlementStatus::Pending
        };
        Ok(Self {
            rebate_id,
            commitment_id: commitment_id.to_string(),
            sponsor_id: sponsor_id.to_string(),
            claimed_units,
            settled_units,
            fee_asset_id: fee_asset_id.to_string(),
            settlement_height,
            nullifier_set_root,
            payout_commitment,
            settlement_proof_root,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_fee_rebate",
            "chain_id": CHAIN_ID,
            "rebate_id": self.rebate_id,
            "commitment_id": self.commitment_id,
            "sponsor_id": self.sponsor_id,
            "claimed_units": self.claimed_units,
            "settled_units": self.settled_units,
            "fee_asset_id": self.fee_asset_id,
            "settlement_height": self.settlement_height,
            "nullifier_set_root": self.nullifier_set_root,
            "payout_commitment": self.payout_commitment,
            "settlement_proof_root": self.settlement_proof_root,
            "status": self.status.as_str(),
        })
    }

    pub fn rebate_root(&self) -> String {
        privacy_fee_ledger_payload_root("PRIVACY-FEE-REBATE", &self.public_record())
    }

    pub fn validate(&self) -> PrivacyFeeLedgerResult<String> {
        ensure_non_empty("rebate id", &self.rebate_id)?;
        ensure_non_empty("commitment id", &self.commitment_id)?;
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_positive("claimed units", self.claimed_units)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        if self.settled_units > self.claimed_units {
            return Err("settled rebate exceeds claimed rebate".to_string());
        }
        ensure_non_empty("nullifier set root", &self.nullifier_set_root)?;
        ensure_non_empty("payout commitment", &self.payout_commitment)?;
        ensure_non_empty("settlement proof root", &self.settlement_proof_root)?;
        let expected_id = privacy_fee_rebate_id(
            &self.commitment_id,
            &self.sponsor_id,
            &self.payout_commitment,
            self.settlement_height,
        );
        if self.rebate_id != expected_id {
            return Err("rebate id mismatch".to_string());
        }
        Ok(self.rebate_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeDisclosureReceipt {
    pub receipt_id: String,
    pub scope: FeeDisclosureLevel,
    pub lane: PrivacyFeeLane,
    pub commitment_root: String,
    pub sponsor_root: String,
    pub aggregate_amount_floor_units: u64,
    pub aggregate_amount_ceiling_units: u64,
    pub disclosed_at_height: u64,
    pub recipient_commitment: String,
    pub disclosure_proof_root: String,
}

impl FeeDisclosureReceipt {
    pub fn new(
        scope: FeeDisclosureLevel,
        lane: PrivacyFeeLane,
        commitment_root: &str,
        sponsor_root: &str,
        aggregate_amount_floor_units: u64,
        aggregate_amount_ceiling_units: u64,
        disclosed_at_height: u64,
        recipient_label: &str,
        nonce: u64,
    ) -> PrivacyFeeLedgerResult<Self> {
        ensure_non_empty("commitment root", commitment_root)?;
        ensure_non_empty("sponsor root", sponsor_root)?;
        ensure_non_empty("recipient label", recipient_label)?;
        if aggregate_amount_floor_units > aggregate_amount_ceiling_units {
            return Err("disclosure floor exceeds ceiling".to_string());
        }
        let recipient_commitment =
            privacy_fee_ledger_commitment("DISCLOSURE-RECIPIENT", recipient_label, nonce);
        let disclosure_proof_root = privacy_fee_ledger_payload_root(
            "DISCLOSURE-PROOF",
            &json!({
                "scope": scope.as_str(),
                "lane": lane.as_str(),
                "commitment_root": commitment_root,
                "sponsor_root": sponsor_root,
                "floor_units": aggregate_amount_floor_units,
                "ceiling_units": aggregate_amount_ceiling_units,
            }),
        );
        let receipt_id = privacy_fee_disclosure_id(
            scope,
            lane,
            commitment_root,
            sponsor_root,
            disclosed_at_height,
        );
        Ok(Self {
            receipt_id,
            scope,
            lane,
            commitment_root: commitment_root.to_string(),
            sponsor_root: sponsor_root.to_string(),
            aggregate_amount_floor_units,
            aggregate_amount_ceiling_units,
            disclosed_at_height,
            recipient_commitment,
            disclosure_proof_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_disclosure_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "scope": self.scope.as_str(),
            "lane": self.lane.as_str(),
            "commitment_root": self.commitment_root,
            "sponsor_root": self.sponsor_root,
            "aggregate_amount_floor_units": self.aggregate_amount_floor_units,
            "aggregate_amount_ceiling_units": self.aggregate_amount_ceiling_units,
            "disclosed_at_height": self.disclosed_at_height,
            "recipient_commitment": self.recipient_commitment,
            "disclosure_proof_root": self.disclosure_proof_root,
        })
    }

    pub fn receipt_root(&self) -> String {
        privacy_fee_ledger_payload_root("PRIVACY-FEE-DISCLOSURE", &self.public_record())
    }

    pub fn validate(&self) -> PrivacyFeeLedgerResult<String> {
        ensure_non_empty("disclosure receipt id", &self.receipt_id)?;
        ensure_non_empty("commitment root", &self.commitment_root)?;
        ensure_non_empty("sponsor root", &self.sponsor_root)?;
        if self.aggregate_amount_floor_units > self.aggregate_amount_ceiling_units {
            return Err("disclosure floor exceeds ceiling".to_string());
        }
        ensure_non_empty("recipient commitment", &self.recipient_commitment)?;
        ensure_non_empty("disclosure proof root", &self.disclosure_proof_root)?;
        let expected_id = privacy_fee_disclosure_id(
            self.scope,
            self.lane,
            &self.commitment_root,
            &self.sponsor_root,
            self.disclosed_at_height,
        );
        if self.receipt_id != expected_id {
            return Err("disclosure receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFeeAuditWindow {
    pub window_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub sponsor_root: String,
    pub commitment_root: String,
    pub rebate_root: String,
    pub disclosure_root: String,
    pub fee_asset_id: String,
    pub total_budget_units: u64,
    pub total_reserved_units: u64,
    pub total_spent_units: u64,
    pub total_rebate_units: u64,
    pub public_disclosure_bps: u64,
    pub status: AuditWindowStatus,
}

impl PrivacyFeeAuditWindow {
    pub fn new(
        start_height: u64,
        end_height: u64,
        fee_asset_id: &str,
        sponsor_root: &str,
        commitment_root: &str,
        rebate_root: &str,
        disclosure_root: &str,
        totals: AuditWindowTotals,
    ) -> PrivacyFeeLedgerResult<Self> {
        ensure_height_window(start_height, end_height, "privacy fee audit window")?;
        ensure_non_empty("fee asset id", fee_asset_id)?;
        ensure_non_empty("sponsor root", sponsor_root)?;
        ensure_non_empty("commitment root", commitment_root)?;
        ensure_non_empty("rebate root", rebate_root)?;
        ensure_non_empty("disclosure root", disclosure_root)?;
        totals.validate()?;
        let window_id = privacy_fee_audit_window_id(start_height, end_height, fee_asset_id);
        Ok(Self {
            window_id,
            start_height,
            end_height,
            sponsor_root: sponsor_root.to_string(),
            commitment_root: commitment_root.to_string(),
            rebate_root: rebate_root.to_string(),
            disclosure_root: disclosure_root.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            total_budget_units: totals.total_budget_units,
            total_reserved_units: totals.total_reserved_units,
            total_spent_units: totals.total_spent_units,
            total_rebate_units: totals.total_rebate_units,
            public_disclosure_bps: totals.public_disclosure_bps,
            status: AuditWindowStatus::Open,
        })
    }

    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_fee_audit_window",
            "chain_id": CHAIN_ID,
            "window_id": self.window_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "sponsor_root": self.sponsor_root,
            "commitment_root": self.commitment_root,
            "rebate_root": self.rebate_root,
            "disclosure_root": self.disclosure_root,
            "fee_asset_id": self.fee_asset_id,
            "total_budget_units": self.total_budget_units,
            "total_reserved_units": self.total_reserved_units,
            "total_spent_units": self.total_spent_units,
            "total_rebate_units": self.total_rebate_units,
            "public_disclosure_bps": self.public_disclosure_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn window_root(&self) -> String {
        privacy_fee_ledger_payload_root("PRIVACY-FEE-AUDIT-WINDOW", &self.public_record())
    }

    pub fn validate(&self) -> PrivacyFeeLedgerResult<String> {
        ensure_non_empty("audit window id", &self.window_id)?;
        ensure_height_window(
            self.start_height,
            self.end_height,
            "privacy fee audit window",
        )?;
        ensure_non_empty("sponsor root", &self.sponsor_root)?;
        ensure_non_empty("commitment root", &self.commitment_root)?;
        ensure_non_empty("rebate root", &self.rebate_root)?;
        ensure_non_empty("disclosure root", &self.disclosure_root)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_bps("public disclosure bps", self.public_disclosure_bps)?;
        if self
            .total_reserved_units
            .saturating_add(self.total_spent_units)
            > self.total_budget_units
        {
            return Err("audit reserved plus spent exceeds total budget".to_string());
        }
        if self.total_rebate_units
            > self
                .total_spent_units
                .saturating_add(self.total_reserved_units)
        {
            return Err("audit rebate exceeds accounted spend".to_string());
        }
        let expected_id =
            privacy_fee_audit_window_id(self.start_height, self.end_height, &self.fee_asset_id);
        if self.window_id != expected_id {
            return Err("audit window id mismatch".to_string());
        }
        Ok(self.window_root())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditWindowTotals {
    pub total_budget_units: u64,
    pub total_reserved_units: u64,
    pub total_spent_units: u64,
    pub total_rebate_units: u64,
    pub public_disclosure_bps: u64,
}

impl AuditWindowTotals {
    pub fn validate(self) -> PrivacyFeeLedgerResult<()> {
        ensure_bps("public disclosure bps", self.public_disclosure_bps)?;
        if self
            .total_reserved_units
            .saturating_add(self.total_spent_units)
            > self.total_budget_units
        {
            return Err("audit totals exceed budget".to_string());
        }
        if self.total_rebate_units
            > self
                .total_spent_units
                .saturating_add(self.total_reserved_units)
        {
            return Err("audit rebates exceed spend plus reserves".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFeeLedgerRoots {
    pub config_root: String,
    pub sponsor_root: String,
    pub commitment_root: String,
    pub rebate_root: String,
    pub disclosure_root: String,
    pub audit_window_root: String,
    pub active_lane_root: String,
    pub nullifier_root: String,
}

impl PrivacyFeeLedgerRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_fee_ledger_roots",
            "config_root": self.config_root,
            "sponsor_root": self.sponsor_root,
            "commitment_root": self.commitment_root,
            "rebate_root": self.rebate_root,
            "disclosure_root": self.disclosure_root,
            "audit_window_root": self.audit_window_root,
            "active_lane_root": self.active_lane_root,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFeeLedgerCounters {
    pub sponsor_count: u64,
    pub active_sponsor_count: u64,
    pub commitment_count: u64,
    pub live_commitment_count: u64,
    pub rebate_count: u64,
    pub settled_rebate_count: u64,
    pub disclosure_receipt_count: u64,
    pub audit_window_count: u64,
    pub open_audit_window_count: u64,
    pub active_lane_count: u64,
    pub total_budget_units: u64,
    pub total_available_units: u64,
    pub total_reserved_units: u64,
    pub total_spent_units: u64,
    pub total_claimed_rebate_units: u64,
    pub total_settled_rebate_units: u64,
}

impl PrivacyFeeLedgerCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_fee_ledger_counters",
            "sponsor_count": self.sponsor_count,
            "active_sponsor_count": self.active_sponsor_count,
            "commitment_count": self.commitment_count,
            "live_commitment_count": self.live_commitment_count,
            "rebate_count": self.rebate_count,
            "settled_rebate_count": self.settled_rebate_count,
            "disclosure_receipt_count": self.disclosure_receipt_count,
            "audit_window_count": self.audit_window_count,
            "open_audit_window_count": self.open_audit_window_count,
            "active_lane_count": self.active_lane_count,
            "total_budget_units": self.total_budget_units,
            "total_available_units": self.total_available_units,
            "total_reserved_units": self.total_reserved_units,
            "total_spent_units": self.total_spent_units,
            "total_claimed_rebate_units": self.total_claimed_rebate_units,
            "total_settled_rebate_units": self.total_settled_rebate_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFeeLedgerState {
    pub height: u64,
    pub config: PrivacyFeeLedgerConfig,
    pub sponsors: BTreeMap<String, ShieldedFeeSponsor>,
    pub commitments: BTreeMap<String, BlindedFeeCommitment>,
    pub rebates: BTreeMap<String, PrivateFeeRebate>,
    pub disclosures: BTreeMap<String, FeeDisclosureReceipt>,
    pub audit_windows: BTreeMap<String, PrivacyFeeAuditWindow>,
}

impl Default for PrivacyFeeLedgerState {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivacyFeeLedgerState {
    pub fn new() -> Self {
        Self {
            height: 0,
            config: PrivacyFeeLedgerConfig::devnet(),
            sponsors: BTreeMap::new(),
            commitments: BTreeMap::new(),
            rebates: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            audit_windows: BTreeMap::new(),
        }
    }

    pub fn with_config(config: PrivacyFeeLedgerConfig) -> PrivacyFeeLedgerResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> PrivacyFeeLedgerResult<Self> {
        let mut state = Self::with_config(PrivacyFeeLedgerConfig::devnet())?;
        state.set_height(96);
        let fee_asset_id = state.config.fee_asset_id.clone();

        let privacy_sponsor = ShieldedFeeSponsor::new(
            "devnet-private-transfer-sponsor",
            PrivacyFeeLane::PrivateTransfer,
            &fee_asset_id,
            2_500_000,
            8_500,
            state.height.saturating_sub(48),
            state.height.saturating_add(720),
            FeeDisclosureLevel::Aggregate,
            1,
        )?;
        let bridge_sponsor = ShieldedFeeSponsor::new(
            "devnet-monero-bridge-sponsor",
            PrivacyFeeLane::MoneroBridge,
            &fee_asset_id,
            4_000_000,
            9_000,
            state.height.saturating_sub(24),
            state.height.saturating_add(960),
            FeeDisclosureLevel::LaneOnly,
            2,
        )?;
        let defi_sponsor = ShieldedFeeSponsor::new(
            "devnet-small-defi-sponsor",
            PrivacyFeeLane::SmallDefi,
            &fee_asset_id,
            1_750_000,
            7_500,
            state.height.saturating_sub(16),
            state.height.saturating_add(480),
            FeeDisclosureLevel::Aggregate,
            3,
        )?;

        let privacy_sponsor_id = state.insert_sponsor(privacy_sponsor)?;
        let bridge_sponsor_id = state.insert_sponsor(bridge_sponsor)?;
        let defi_sponsor_id = state.insert_sponsor(defi_sponsor)?;

        let mut private_commitment = BlindedFeeCommitment::new(
            PrivacyFeeLane::PrivateTransfer,
            &fee_asset_id,
            "devnet-alice-private-transfer",
            1_800,
            1_500,
            &privacy_sponsor_id,
            state.height,
            state.height.saturating_add(12),
            FeeDisclosureLevel::None,
            10,
        )?;
        private_commitment.status = FeeCommitmentStatus::RebatePending;
        let private_commitment_id = state.insert_commitment(private_commitment)?;

        let mut bridge_commitment = BlindedFeeCommitment::new(
            PrivacyFeeLane::MoneroBridge,
            &fee_asset_id,
            "devnet-bob-bridge-exit",
            3_400,
            3_000,
            &bridge_sponsor_id,
            state.height,
            state.height.saturating_add(18),
            FeeDisclosureLevel::None,
            11,
        )?;
        bridge_commitment.status = FeeCommitmentStatus::Included;
        state.insert_commitment(bridge_commitment)?;

        let mut defi_commitment = BlindedFeeCommitment::new(
            PrivacyFeeLane::SmallDefi,
            &fee_asset_id,
            "devnet-carol-private-swap",
            2_200,
            1_650,
            &defi_sponsor_id,
            state.height,
            state.height.saturating_add(16),
            FeeDisclosureLevel::None,
            12,
        )?;
        defi_commitment.status = FeeCommitmentStatus::RebatePending;
        let defi_commitment_id = state.insert_commitment(defi_commitment)?;

        let privacy_rebate = PrivateFeeRebate::new(
            &private_commitment_id,
            &privacy_sponsor_id,
            1_500,
            1_500,
            &fee_asset_id,
            state.height.saturating_add(1),
            20,
        )?;
        state.insert_rebate(privacy_rebate)?;

        let defi_rebate = PrivateFeeRebate::new(
            &defi_commitment_id,
            &defi_sponsor_id,
            1_650,
            1_200,
            &fee_asset_id,
            state.height.saturating_add(1),
            21,
        )?;
        state.insert_rebate(defi_rebate)?;

        let disclosure = FeeDisclosureReceipt::new(
            FeeDisclosureLevel::Aggregate,
            PrivacyFeeLane::SmallDefi,
            &state.commitment_root(),
            &state.sponsor_root(),
            1_000,
            5_000,
            state.height,
            "devnet-auditor-aggregate-view",
            30,
        )?;
        state.insert_disclosure(disclosure)?;

        state.refresh_current_audit_window()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for sponsor in self.sponsors.values_mut() {
            if self.height > sponsor.valid_until_height && sponsor.status.can_spend() {
                sponsor.status = SponsorPolicyStatus::Expired;
            }
            if sponsor.available_units() == 0 && sponsor.reserved_units == 0 {
                sponsor.status = SponsorPolicyStatus::Exhausted;
            }
        }
        for commitment in self.commitments.values_mut() {
            if self.height > commitment.expires_at_height
                && matches!(
                    commitment.status,
                    FeeCommitmentStatus::Quoted
                        | FeeCommitmentStatus::Included
                        | FeeCommitmentStatus::RebatePending
                )
            {
                commitment.status = FeeCommitmentStatus::Expired;
            }
        }
    }

    pub fn insert_sponsor(
        &mut self,
        sponsor: ShieldedFeeSponsor,
    ) -> PrivacyFeeLedgerResult<String> {
        let sponsor_id = sponsor.sponsor_id.clone();
        sponsor.validate()?;
        if self.sponsors.contains_key(&sponsor_id) {
            return Err("duplicate fee sponsor".to_string());
        }
        self.sponsors.insert(sponsor_id.clone(), sponsor);
        Ok(sponsor_id)
    }

    pub fn insert_commitment(
        &mut self,
        commitment: BlindedFeeCommitment,
    ) -> PrivacyFeeLedgerResult<String> {
        let commitment_id = commitment.commitment_id.clone();
        commitment.validate()?;
        if self.commitments.contains_key(&commitment_id) {
            return Err("duplicate fee commitment".to_string());
        }
        let sponsor = self
            .sponsors
            .get_mut(&commitment.sponsor_id)
            .ok_or_else(|| "fee commitment sponsor missing".to_string())?;
        if sponsor.lane != commitment.lane {
            return Err("fee commitment lane does not match sponsor lane".to_string());
        }
        let reserve_units = commitment
            .max_rebate_units
            .min(commitment.amount_upper_bound_units);
        sponsor.reserve(reserve_units)?;
        self.commitments.insert(commitment_id.clone(), commitment);
        Ok(commitment_id)
    }

    pub fn insert_rebate(&mut self, rebate: PrivateFeeRebate) -> PrivacyFeeLedgerResult<String> {
        let rebate_id = rebate.rebate_id.clone();
        rebate.validate()?;
        if self.rebates.contains_key(&rebate_id) {
            return Err("duplicate fee rebate".to_string());
        }
        let commitment = self
            .commitments
            .get_mut(&rebate.commitment_id)
            .ok_or_else(|| "rebate commitment missing".to_string())?;
        if commitment.sponsor_id != rebate.sponsor_id {
            return Err("rebate sponsor does not match commitment sponsor".to_string());
        }
        if rebate.claimed_units > commitment.max_rebate_units {
            return Err("rebate claim exceeds commitment max rebate".to_string());
        }
        let sponsor = self
            .sponsors
            .get_mut(&rebate.sponsor_id)
            .ok_or_else(|| "rebate sponsor missing".to_string())?;
        sponsor.spend_reserved(rebate.settled_units)?;
        if rebate.status.is_final() {
            commitment.status = FeeCommitmentStatus::RebateSettled;
        }
        self.rebates.insert(rebate_id.clone(), rebate);
        Ok(rebate_id)
    }

    pub fn insert_disclosure(
        &mut self,
        disclosure: FeeDisclosureReceipt,
    ) -> PrivacyFeeLedgerResult<String> {
        let receipt_id = disclosure.receipt_id.clone();
        disclosure.validate()?;
        if self.disclosures.contains_key(&receipt_id) {
            return Err("duplicate fee disclosure receipt".to_string());
        }
        self.disclosures.insert(receipt_id.clone(), disclosure);
        Ok(receipt_id)
    }

    pub fn refresh_current_audit_window(&mut self) -> PrivacyFeeLedgerResult<String> {
        let window_start = self
            .height
            .saturating_sub(self.height % self.config.audit_window_blocks);
        let window_end = window_start
            .saturating_add(self.config.audit_window_blocks)
            .saturating_sub(1);
        let counters = self.counters();
        let totals = AuditWindowTotals {
            total_budget_units: counters.total_budget_units,
            total_reserved_units: counters.total_reserved_units,
            total_spent_units: counters.total_spent_units,
            total_rebate_units: counters.total_settled_rebate_units,
            public_disclosure_bps: self.public_disclosure_bps(),
        };
        let window = PrivacyFeeAuditWindow::new(
            window_start,
            window_end,
            &self.config.fee_asset_id,
            &self.sponsor_root(),
            &self.commitment_root(),
            &self.rebate_root(),
            &self.disclosure_root(),
            totals,
        )?;
        let window_id = window.window_id.clone();
        self.audit_windows.insert(window_id.clone(), window);
        Ok(window_id)
    }

    pub fn active_lane_keys(&self) -> Vec<String> {
        self.sponsors
            .values()
            .filter(|sponsor| sponsor.is_active_at(self.height))
            .map(|sponsor| sponsor.lane.as_str().to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn active_lane_root(&self) -> String {
        let lanes = self
            .active_lane_keys()
            .into_iter()
            .map(Value::String)
            .collect::<Vec<_>>();
        merkle_root("PRIVACY-FEE-ACTIVE-LANES", &lanes)
    }

    pub fn nullifier_root(&self) -> String {
        let nullifiers = self
            .commitments
            .values()
            .map(|commitment| Value::String(commitment.payer_nullifier.clone()))
            .collect::<Vec<_>>();
        merkle_root("PRIVACY-FEE-NULLIFIERS", &nullifiers)
    }

    pub fn sponsor_root(&self) -> String {
        privacy_fee_sponsor_set_root(&self.sponsors.values().cloned().collect::<Vec<_>>())
    }

    pub fn commitment_root(&self) -> String {
        privacy_fee_commitment_set_root(&self.commitments.values().cloned().collect::<Vec<_>>())
    }

    pub fn rebate_root(&self) -> String {
        privacy_fee_rebate_set_root(&self.rebates.values().cloned().collect::<Vec<_>>())
    }

    pub fn disclosure_root(&self) -> String {
        privacy_fee_disclosure_set_root(&self.disclosures.values().cloned().collect::<Vec<_>>())
    }

    pub fn audit_window_root(&self) -> String {
        privacy_fee_audit_window_set_root(&self.audit_windows.values().cloned().collect::<Vec<_>>())
    }

    pub fn roots(&self) -> PrivacyFeeLedgerRoots {
        PrivacyFeeLedgerRoots {
            config_root: self.config.config_root(),
            sponsor_root: self.sponsor_root(),
            commitment_root: self.commitment_root(),
            rebate_root: self.rebate_root(),
            disclosure_root: self.disclosure_root(),
            audit_window_root: self.audit_window_root(),
            active_lane_root: self.active_lane_root(),
            nullifier_root: self.nullifier_root(),
        }
    }

    pub fn counters(&self) -> PrivacyFeeLedgerCounters {
        let mut counters = PrivacyFeeLedgerCounters {
            sponsor_count: self.sponsors.len() as u64,
            commitment_count: self.commitments.len() as u64,
            rebate_count: self.rebates.len() as u64,
            disclosure_receipt_count: self.disclosures.len() as u64,
            audit_window_count: self.audit_windows.len() as u64,
            active_lane_count: self.active_lane_keys().len() as u64,
            ..PrivacyFeeLedgerCounters::default()
        };
        for sponsor in self.sponsors.values() {
            if sponsor.is_active_at(self.height) {
                counters.active_sponsor_count = counters.active_sponsor_count.saturating_add(1);
            }
            counters.total_budget_units = counters
                .total_budget_units
                .saturating_add(sponsor.total_budget_units);
            counters.total_available_units = counters
                .total_available_units
                .saturating_add(sponsor.available_units());
            counters.total_reserved_units = counters
                .total_reserved_units
                .saturating_add(sponsor.reserved_units);
            counters.total_spent_units = counters
                .total_spent_units
                .saturating_add(sponsor.spent_units);
        }
        for commitment in self.commitments.values() {
            if commitment.is_live_at(self.height) {
                counters.live_commitment_count = counters.live_commitment_count.saturating_add(1);
            }
        }
        for rebate in self.rebates.values() {
            counters.total_claimed_rebate_units = counters
                .total_claimed_rebate_units
                .saturating_add(rebate.claimed_units);
            counters.total_settled_rebate_units = counters
                .total_settled_rebate_units
                .saturating_add(rebate.settled_units);
            if rebate.status.is_final() {
                counters.settled_rebate_count = counters.settled_rebate_count.saturating_add(1);
            }
        }
        for window in self.audit_windows.values() {
            if matches!(window.status, AuditWindowStatus::Open)
                && window.contains_height(self.height)
            {
                counters.open_audit_window_count =
                    counters.open_audit_window_count.saturating_add(1);
            }
        }
        counters
    }

    pub fn public_disclosure_bps(&self) -> u64 {
        let total = self.commitments.len() as u64;
        if total == 0 {
            return 0;
        }
        let disclosed = self
            .commitments
            .values()
            .filter(|commitment| commitment.disclosure_level != FeeDisclosureLevel::None)
            .count() as u64;
        ratio_bps(disclosed, total)
    }

    pub fn public_record_root(&self) -> String {
        privacy_fee_ledger_payload_root("PRIVACY-FEE-LEDGER-PUBLIC-RECORD", &self.public_record())
    }

    pub fn state_root(&self) -> String {
        privacy_fee_ledger_state_root_from_record(&self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "privacy_fee_ledger_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVACY_FEE_LEDGER_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "public_disclosure_bps": self.public_disclosure_bps(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> PrivacyFeeLedgerResult<String> {
        self.config.validate()?;
        let mut sponsor_lanes = BTreeMap::<String, PrivacyFeeLane>::new();
        for (id, sponsor) in &self.sponsors {
            if id != &sponsor.sponsor_id {
                return Err("sponsor map key mismatch".to_string());
            }
            sponsor.validate()?;
            sponsor_lanes.insert(id.clone(), sponsor.lane);
        }
        let mut commitment_nullifiers = BTreeSet::<String>::new();
        for (id, commitment) in &self.commitments {
            if id != &commitment.commitment_id {
                return Err("commitment map key mismatch".to_string());
            }
            commitment.validate()?;
            let lane = sponsor_lanes
                .get(&commitment.sponsor_id)
                .ok_or_else(|| "commitment references missing sponsor".to_string())?;
            if lane != &commitment.lane {
                return Err("commitment sponsor lane mismatch".to_string());
            }
            if !commitment_nullifiers.insert(commitment.payer_nullifier.clone()) {
                return Err("duplicate fee payer nullifier".to_string());
            }
        }
        for (id, rebate) in &self.rebates {
            if id != &rebate.rebate_id {
                return Err("rebate map key mismatch".to_string());
            }
            rebate.validate()?;
            let commitment = self
                .commitments
                .get(&rebate.commitment_id)
                .ok_or_else(|| "rebate references missing commitment".to_string())?;
            if commitment.sponsor_id != rebate.sponsor_id {
                return Err("rebate sponsor mismatch".to_string());
            }
            if rebate.claimed_units > commitment.max_rebate_units {
                return Err("rebate exceeds commitment max rebate".to_string());
            }
        }
        for (id, disclosure) in &self.disclosures {
            if id != &disclosure.receipt_id {
                return Err("disclosure map key mismatch".to_string());
            }
            disclosure.validate()?;
        }
        for (id, window) in &self.audit_windows {
            if id != &window.window_id {
                return Err("audit window map key mismatch".to_string());
            }
            window.validate()?;
            if window.public_disclosure_bps > self.config.max_public_disclosure_bps {
                return Err("audit public disclosure exceeds configured privacy bound".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn privacy_fee_ledger_state_root_from_record(record: &Value) -> String {
    privacy_fee_ledger_payload_root("PRIVACY-FEE-LEDGER-STATE", record)
}

pub fn privacy_fee_ledger_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn privacy_fee_ledger_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn privacy_fee_ledger_commitment(domain: &str, label: &str, nonce: u64) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(label), HashPart::Int(nonce as i128)],
        32,
    )
}

pub fn privacy_fee_sponsor_id(
    sponsor_commitment: &str,
    lane: PrivacyFeeLane,
    fee_asset_id: &str,
    valid_from_height: u64,
    valid_until_height: u64,
) -> String {
    domain_hash(
        "PRIVACY-FEE-SPONSOR-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Str(fee_asset_id),
            HashPart::Int(valid_from_height as i128),
            HashPart::Int(valid_until_height as i128),
        ],
        20,
    )
}

pub fn privacy_fee_commitment_id(
    payer_nullifier: &str,
    fee_commitment: &str,
    sponsor_id: &str,
    inclusion_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "PRIVACY-FEE-COMMITMENT-ID",
        &[
            HashPart::Str(payer_nullifier),
            HashPart::Str(fee_commitment),
            HashPart::Str(sponsor_id),
            HashPart::Int(inclusion_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        20,
    )
}

pub fn privacy_fee_rebate_id(
    commitment_id: &str,
    sponsor_id: &str,
    payout_commitment: &str,
    settlement_height: u64,
) -> String {
    domain_hash(
        "PRIVACY-FEE-REBATE-ID",
        &[
            HashPart::Str(commitment_id),
            HashPart::Str(sponsor_id),
            HashPart::Str(payout_commitment),
            HashPart::Int(settlement_height as i128),
        ],
        20,
    )
}

pub fn privacy_fee_disclosure_id(
    scope: FeeDisclosureLevel,
    lane: PrivacyFeeLane,
    commitment_root: &str,
    sponsor_root: &str,
    disclosed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVACY-FEE-DISCLOSURE-ID",
        &[
            HashPart::Str(scope.as_str()),
            HashPart::Str(lane.as_str()),
            HashPart::Str(commitment_root),
            HashPart::Str(sponsor_root),
            HashPart::Int(disclosed_at_height as i128),
        ],
        20,
    )
}

pub fn privacy_fee_audit_window_id(
    start_height: u64,
    end_height: u64,
    fee_asset_id: &str,
) -> String {
    domain_hash(
        "PRIVACY-FEE-AUDIT-WINDOW-ID",
        &[
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(fee_asset_id),
        ],
        20,
    )
}

pub fn privacy_fee_sponsor_set_root(sponsors: &[ShieldedFeeSponsor]) -> String {
    let leaves = sponsors
        .iter()
        .map(ShieldedFeeSponsor::public_record)
        .collect::<Vec<_>>();
    merkle_root("PRIVACY-FEE-SPONSOR-SET", &leaves)
}

pub fn privacy_fee_commitment_set_root(commitments: &[BlindedFeeCommitment]) -> String {
    let leaves = commitments
        .iter()
        .map(BlindedFeeCommitment::public_record)
        .collect::<Vec<_>>();
    merkle_root("PRIVACY-FEE-COMMITMENT-SET", &leaves)
}

pub fn privacy_fee_rebate_set_root(rebates: &[PrivateFeeRebate]) -> String {
    let leaves = rebates
        .iter()
        .map(PrivateFeeRebate::public_record)
        .collect::<Vec<_>>();
    merkle_root("PRIVACY-FEE-REBATE-SET", &leaves)
}

pub fn privacy_fee_disclosure_set_root(disclosures: &[FeeDisclosureReceipt]) -> String {
    let leaves = disclosures
        .iter()
        .map(FeeDisclosureReceipt::public_record)
        .collect::<Vec<_>>();
    merkle_root("PRIVACY-FEE-DISCLOSURE-SET", &leaves)
}

pub fn privacy_fee_audit_window_set_root(windows: &[PrivacyFeeAuditWindow]) -> String {
    let leaves = windows
        .iter()
        .map(PrivacyFeeAuditWindow::public_record)
        .collect::<Vec<_>>();
    merkle_root("PRIVACY-FEE-AUDIT-WINDOW-SET", &leaves)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(PRIVACY_FEE_LEDGER_MAX_BPS)
        .saturating_div(denominator)
}

fn ensure_eq(label: &str, actual: &str, expected: &str) -> PrivacyFeeLedgerResult<()> {
    if actual != expected {
        return Err(format!("{label} mismatch"));
    }
    Ok(())
}

fn ensure_non_empty(label: &str, value: &str) -> PrivacyFeeLedgerResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} is empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> PrivacyFeeLedgerResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> PrivacyFeeLedgerResult<()> {
    if value > PRIVACY_FEE_LEDGER_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn ensure_height_window(start: u64, end: u64, label: &str) -> PrivacyFeeLedgerResult<()> {
    if end < start {
        return Err(format!("{label} height window is inverted"));
    }
    Ok(())
}
