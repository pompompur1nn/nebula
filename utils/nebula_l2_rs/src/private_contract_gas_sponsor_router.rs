use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateContractGasSponsorRouterResult<T> = Result<T, String>;

pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_PROTOCOL_VERSION: &str =
    "nebula-private-contract-gas-sponsor-router-v1";
pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87-private-gas-sponsor-router-v1";
pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_QUOTE_SCHEME: &str =
    "private-contract-gas-quote-commitment-v1";
pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_RECEIPT_SCHEME: &str =
    "private-contract-gas-settlement-receipt-v1";
pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_HEIGHT: u64 = 640;
pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 16;
pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_EPOCH_BLOCKS: u64 = 96;
pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_MAX_SPONSOR_EXPOSURE_BPS: u64 = 6_500;
pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_REBATE_BPS: u64 = 8_000;
pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_CHALLENGE_BLOCKS: u64 = 72;
pub const PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasSponsorLaneKind {
    PrivateTransfer,
    ContractCall,
    DefiSwap,
    Lending,
    MoneroBridgeExit,
    Recovery,
}

impl GasSponsorLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ContractCall => "contract_call",
            Self::DefiSwap => "defi_swap",
            Self::Lending => "lending",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::Recovery => "recovery",
        }
    }

    pub fn default_price_micro_units(self) -> u64 {
        match self {
            Self::PrivateTransfer => 150,
            Self::ContractCall => 420,
            Self::DefiSwap => 360,
            Self::Lending => 480,
            Self::MoneroBridgeExit => 620,
            Self::Recovery => 240,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasSponsorLaneStatus {
    Active,
    Throttled,
    Paused,
    Retired,
}

impl GasSponsorLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_quotes(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasQuoteStatus {
    Open,
    Reserved,
    Settled,
    Expired,
    Rejected,
    Challenged,
}

impl GasQuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Expired | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Draining,
    Exhausted,
    Slashed,
    Closed,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Exhausted => "exhausted",
            Self::Slashed => "slashed",
            Self::Closed => "closed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasChallengeStatus {
    Open,
    Proving,
    Upheld,
    Rejected,
    Expired,
}

impl GasChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Proving => "proving",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractGasSponsorRouterConfig {
    pub fee_asset_id: String,
    pub quote_ttl_blocks: u64,
    pub epoch_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_sponsor_exposure_bps: u64,
    pub rebate_bps: u64,
    pub challenge_blocks: u64,
    pub hash_suite: String,
    pub pq_auth_scheme: String,
    pub quote_scheme: String,
    pub receipt_scheme: String,
}

impl PrivateContractGasSponsorRouterConfig {
    pub fn devnet() -> Self {
        Self {
            fee_asset_id: PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_FEE_ASSET_ID.to_string(),
            quote_ttl_blocks: PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_QUOTE_TTL_BLOCKS,
            epoch_blocks: PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_EPOCH_BLOCKS,
            min_pq_security_bits: PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_sponsor_exposure_bps:
                PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_MAX_SPONSOR_EXPOSURE_BPS,
            rebate_bps: PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_REBATE_BPS,
            challenge_blocks: PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_CHALLENGE_BLOCKS,
            hash_suite: PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_HASH_SUITE.to_string(),
            pq_auth_scheme: PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_PQ_AUTH_SCHEME.to_string(),
            quote_scheme: PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_QUOTE_SCHEME.to_string(),
            receipt_scheme: PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_RECEIPT_SCHEME.to_string(),
        }
    }

    pub fn validate(&self) -> PrivateContractGasSponsorRouterResult<()> {
        ensure_nonempty("config.fee_asset_id", &self.fee_asset_id)?;
        ensure_positive("config.quote_ttl_blocks", self.quote_ttl_blocks)?;
        ensure_positive("config.epoch_blocks", self.epoch_blocks)?;
        ensure_positive("config.min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_bps(
            "config.max_sponsor_exposure_bps",
            self.max_sponsor_exposure_bps,
        )?;
        ensure_bps("config.rebate_bps", self.rebate_bps)?;
        ensure_positive("config.challenge_blocks", self.challenge_blocks)?;
        ensure_nonempty("config.hash_suite", &self.hash_suite)?;
        ensure_nonempty("config.pq_auth_scheme", &self.pq_auth_scheme)?;
        ensure_nonempty("config.quote_scheme", &self.quote_scheme)?;
        ensure_nonempty("config.receipt_scheme", &self.receipt_scheme)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fee_asset_id": self.fee_asset_id,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "epoch_blocks": self.epoch_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_sponsor_exposure_bps": self.max_sponsor_exposure_bps,
            "rebate_bps": self.rebate_bps,
            "challenge_blocks": self.challenge_blocks,
            "hash_suite": self.hash_suite,
            "pq_auth_scheme": self.pq_auth_scheme,
            "quote_scheme": self.quote_scheme,
            "receipt_scheme": self.receipt_scheme,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasSponsorLane {
    pub lane_id: String,
    pub lane_kind: GasSponsorLaneKind,
    pub status: GasSponsorLaneStatus,
    pub base_price_micro_units: u64,
    pub privacy_set_size: u64,
    pub allowed_contract_root: String,
    pub current_epoch: u64,
}

impl GasSponsorLane {
    pub fn devnet(
        lane_kind: GasSponsorLaneKind,
        epoch: u64,
        config: &PrivateContractGasSponsorRouterConfig,
    ) -> Self {
        let lane_id = format!("lane:private-gas:{}", lane_kind.as_str());
        Self {
            lane_id: lane_id.clone(),
            lane_kind,
            status: GasSponsorLaneStatus::Active,
            base_price_micro_units: lane_kind.default_price_micro_units(),
            privacy_set_size: config.min_privacy_set_size,
            allowed_contract_root: pcgsr_string_root("LANE-CONTRACTS", &lane_id),
            current_epoch: epoch,
        }
    }

    pub fn validate(
        &self,
        config: &PrivateContractGasSponsorRouterConfig,
    ) -> PrivateContractGasSponsorRouterResult<()> {
        ensure_nonempty("lane.lane_id", &self.lane_id)?;
        ensure_positive("lane.base_price_micro_units", self.base_price_micro_units)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("lane {} below privacy floor", self.lane_id));
        }
        ensure_nonempty("lane.allowed_contract_root", &self.allowed_contract_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "gas_sponsor_lane",
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "status": self.status.as_str(),
            "base_price_micro_units": self.base_price_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "allowed_contract_root": self.allowed_contract_root,
            "current_epoch": self.current_epoch,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGasSponsor {
    pub sponsor_id: String,
    pub commitment_root: String,
    pub status: SponsorStatus,
    pub accepted_lane_ids: BTreeSet<String>,
    pub budget_micro_units: u64,
    pub reserved_micro_units: u64,
    pub settled_micro_units: u64,
    pub max_exposure_bps: u64,
    pub pq_key_root: String,
}

impl PrivateGasSponsor {
    pub fn devnet(
        sponsor_id: &str,
        lane_ids: &[String],
        config: &PrivateContractGasSponsorRouterConfig,
    ) -> Self {
        Self {
            sponsor_id: sponsor_id.to_string(),
            commitment_root: pcgsr_string_root("SPONSOR-COMMITMENT", sponsor_id),
            status: SponsorStatus::Active,
            accepted_lane_ids: lane_ids.iter().cloned().collect(),
            budget_micro_units: 1_500_000,
            reserved_micro_units: 120_000,
            settled_micro_units: 0,
            max_exposure_bps: config.max_sponsor_exposure_bps,
            pq_key_root: pcgsr_string_root("SPONSOR-PQ-KEY", sponsor_id),
        }
    }

    pub fn available_micro_units(&self) -> u64 {
        self.budget_micro_units
            .saturating_sub(self.reserved_micro_units)
            .saturating_sub(self.settled_micro_units)
    }

    pub fn validate(
        &self,
        lanes: &BTreeMap<String, GasSponsorLane>,
    ) -> PrivateContractGasSponsorRouterResult<()> {
        ensure_nonempty("sponsor.sponsor_id", &self.sponsor_id)?;
        ensure_nonempty("sponsor.commitment_root", &self.commitment_root)?;
        ensure_nonempty("sponsor.pq_key_root", &self.pq_key_root)?;
        ensure_positive("sponsor.budget_micro_units", self.budget_micro_units)?;
        ensure_bps("sponsor.max_exposure_bps", self.max_exposure_bps)?;
        if self.accepted_lane_ids.is_empty() {
            return Err(format!("sponsor {} accepts no lanes", self.sponsor_id));
        }
        for lane_id in &self.accepted_lane_ids {
            if !lanes.contains_key(lane_id) {
                return Err(format!(
                    "sponsor {} references missing lane {}",
                    self.sponsor_id, lane_id
                ));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_gas_sponsor",
            "sponsor_id": self.sponsor_id,
            "commitment_root": self.commitment_root,
            "status": self.status.as_str(),
            "accepted_lane_ids": self.accepted_lane_ids.iter().cloned().collect::<Vec<_>>(),
            "budget_micro_units": self.budget_micro_units,
            "reserved_micro_units": self.reserved_micro_units,
            "settled_micro_units": self.settled_micro_units,
            "available_micro_units": self.available_micro_units(),
            "max_exposure_bps": self.max_exposure_bps,
            "pq_key_root": self.pq_key_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGasQuote {
    pub quote_id: String,
    pub lane_id: String,
    pub sponsor_id: String,
    pub contract_call_root: String,
    pub account_commitment_root: String,
    pub gas_units: u64,
    pub fee_micro_units: u64,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub status: GasQuoteStatus,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl PrivateGasQuote {
    pub fn devnet(
        quote_id: &str,
        lane: &GasSponsorLane,
        sponsor: &PrivateGasSponsor,
        height: u64,
        config: &PrivateContractGasSponsorRouterConfig,
    ) -> Self {
        let gas_units = match lane.lane_kind {
            GasSponsorLaneKind::ContractCall => 220_000,
            GasSponsorLaneKind::DefiSwap => 180_000,
            GasSponsorLaneKind::Lending => 260_000,
            GasSponsorLaneKind::MoneroBridgeExit => 320_000,
            GasSponsorLaneKind::PrivateTransfer | GasSponsorLaneKind::Recovery => 90_000,
        };
        Self {
            quote_id: quote_id.to_string(),
            lane_id: lane.lane_id.clone(),
            sponsor_id: sponsor.sponsor_id.clone(),
            contract_call_root: pcgsr_string_root("QUOTE-CONTRACT-CALL", quote_id),
            account_commitment_root: pcgsr_string_root("QUOTE-ACCOUNT", quote_id),
            gas_units,
            fee_micro_units: lane
                .base_price_micro_units
                .saturating_mul(gas_units.saturating_add(999).saturating_div(1_000)),
            rebate_bps: config.rebate_bps,
            privacy_set_size: lane.privacy_set_size,
            status: GasQuoteStatus::Open,
            submitted_height: height,
            expires_height: height.saturating_add(config.quote_ttl_blocks),
        }
    }

    pub fn validate(
        &self,
        lanes: &BTreeMap<String, GasSponsorLane>,
        sponsors: &BTreeMap<String, PrivateGasSponsor>,
        config: &PrivateContractGasSponsorRouterConfig,
    ) -> PrivateContractGasSponsorRouterResult<()> {
        ensure_nonempty("quote.quote_id", &self.quote_id)?;
        ensure_nonempty("quote.contract_call_root", &self.contract_call_root)?;
        ensure_nonempty(
            "quote.account_commitment_root",
            &self.account_commitment_root,
        )?;
        ensure_positive("quote.gas_units", self.gas_units)?;
        ensure_positive("quote.fee_micro_units", self.fee_micro_units)?;
        ensure_bps("quote.rebate_bps", self.rebate_bps)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("quote {} below privacy floor", self.quote_id));
        }
        if self.submitted_height >= self.expires_height {
            return Err(format!("quote {} has invalid expiry", self.quote_id));
        }
        let lane = lanes
            .get(&self.lane_id)
            .ok_or_else(|| format!("quote {} missing lane {}", self.quote_id, self.lane_id))?;
        if !lane.status.accepts_quotes() && !self.status.terminal() {
            return Err(format!("quote {} lane is closed", self.quote_id));
        }
        let sponsor = sponsors.get(&self.sponsor_id).ok_or_else(|| {
            format!(
                "quote {} missing sponsor {}",
                self.quote_id, self.sponsor_id
            )
        })?;
        if !sponsor.accepted_lane_ids.contains(&self.lane_id) {
            return Err(format!(
                "quote {} sponsor does not accept lane",
                self.quote_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_gas_quote",
            "quote_id": self.quote_id,
            "lane_id": self.lane_id,
            "sponsor_id": self.sponsor_id,
            "contract_call_root": self.contract_call_root,
            "account_commitment_root": self.account_commitment_root,
            "gas_units": self.gas_units,
            "fee_micro_units": self.fee_micro_units,
            "rebate_bps": self.rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasSponsorAttestation {
    pub attestation_id: String,
    pub quote_id: String,
    pub signer_id: String,
    pub pq_signature_root: String,
    pub policy_root: String,
    pub security_bits: u16,
    pub height: u64,
}

impl GasSponsorAttestation {
    pub fn devnet(
        attestation_id: &str,
        quote_id: &str,
        signer_id: &str,
        height: u64,
        config: &PrivateContractGasSponsorRouterConfig,
    ) -> Self {
        Self {
            attestation_id: attestation_id.to_string(),
            quote_id: quote_id.to_string(),
            signer_id: signer_id.to_string(),
            pq_signature_root: pcgsr_string_root("ATTESTATION-PQ-SIGNATURE", attestation_id),
            policy_root: pcgsr_string_root("ATTESTATION-POLICY", attestation_id),
            security_bits: config.min_pq_security_bits,
            height,
        }
    }

    pub fn validate(
        &self,
        quotes: &BTreeMap<String, PrivateGasQuote>,
        config: &PrivateContractGasSponsorRouterConfig,
    ) -> PrivateContractGasSponsorRouterResult<()> {
        ensure_nonempty("attestation.attestation_id", &self.attestation_id)?;
        ensure_nonempty("attestation.signer_id", &self.signer_id)?;
        ensure_nonempty("attestation.pq_signature_root", &self.pq_signature_root)?;
        ensure_nonempty("attestation.policy_root", &self.policy_root)?;
        if self.security_bits < config.min_pq_security_bits {
            return Err(format!(
                "attestation {} below pq security floor",
                self.attestation_id
            ));
        }
        if !quotes.contains_key(&self.quote_id) {
            return Err(format!("attestation {} missing quote", self.attestation_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "gas_sponsor_attestation",
            "attestation_id": self.attestation_id,
            "quote_id": self.quote_id,
            "signer_id": self.signer_id,
            "pq_signature_root": self.pq_signature_root,
            "policy_root": self.policy_root,
            "security_bits": self.security_bits,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasSettlementReceipt {
    pub receipt_id: String,
    pub quote_id: String,
    pub settlement_root: String,
    pub paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub settled_height: u64,
}

impl GasSettlementReceipt {
    pub fn devnet(receipt_id: &str, quote: &PrivateGasQuote, height: u64) -> Self {
        Self {
            receipt_id: receipt_id.to_string(),
            quote_id: quote.quote_id.clone(),
            settlement_root: pcgsr_string_root("SETTLEMENT-ROOT", receipt_id),
            paid_micro_units: quote.fee_micro_units,
            rebate_micro_units: quote
                .fee_micro_units
                .saturating_mul(quote.rebate_bps)
                .saturating_div(PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_MAX_BPS),
            settled_height: height,
        }
    }

    pub fn validate(
        &self,
        quotes: &BTreeMap<String, PrivateGasQuote>,
    ) -> PrivateContractGasSponsorRouterResult<()> {
        ensure_nonempty("receipt.receipt_id", &self.receipt_id)?;
        ensure_nonempty("receipt.settlement_root", &self.settlement_root)?;
        ensure_positive("receipt.paid_micro_units", self.paid_micro_units)?;
        if !quotes.contains_key(&self.quote_id) {
            return Err(format!("receipt {} missing quote", self.receipt_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "gas_settlement_receipt",
            "receipt_id": self.receipt_id,
            "quote_id": self.quote_id,
            "settlement_root": self.settlement_root,
            "paid_micro_units": self.paid_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "settled_height": self.settled_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasSponsorChallenge {
    pub challenge_id: String,
    pub quote_id: String,
    pub status: GasChallengeStatus,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl GasSponsorChallenge {
    pub fn devnet(
        challenge_id: &str,
        quote_id: &str,
        height: u64,
        config: &PrivateContractGasSponsorRouterConfig,
    ) -> Self {
        Self {
            challenge_id: challenge_id.to_string(),
            quote_id: quote_id.to_string(),
            status: GasChallengeStatus::Open,
            challenger_commitment: pcgsr_string_root("CHALLENGER", challenge_id),
            evidence_root: pcgsr_string_root("CHALLENGE-EVIDENCE", challenge_id),
            opened_height: height,
            expires_height: height.saturating_add(config.challenge_blocks),
        }
    }

    pub fn validate(
        &self,
        quotes: &BTreeMap<String, PrivateGasQuote>,
    ) -> PrivateContractGasSponsorRouterResult<()> {
        ensure_nonempty("challenge.challenge_id", &self.challenge_id)?;
        ensure_nonempty(
            "challenge.challenger_commitment",
            &self.challenger_commitment,
        )?;
        ensure_nonempty("challenge.evidence_root", &self.evidence_root)?;
        if self.opened_height >= self.expires_height {
            return Err(format!(
                "challenge {} has invalid expiry",
                self.challenge_id
            ));
        }
        if !quotes.contains_key(&self.quote_id) {
            return Err(format!("challenge {} missing quote", self.challenge_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "gas_sponsor_challenge",
            "challenge_id": self.challenge_id,
            "quote_id": self.quote_id,
            "status": self.status.as_str(),
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractGasSponsorRouterRoots {
    pub config_root: String,
    pub lane_root: String,
    pub sponsor_root: String,
    pub quote_root: String,
    pub attestation_root: String,
    pub receipt_root: String,
    pub challenge_root: String,
}

impl PrivateContractGasSponsorRouterRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "sponsor_root": self.sponsor_root,
            "quote_root": self.quote_root,
            "attestation_root": self.attestation_root,
            "receipt_root": self.receipt_root,
            "challenge_root": self.challenge_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractGasSponsorRouterCounters {
    pub lane_count: u64,
    pub sponsor_count: u64,
    pub usable_sponsor_count: u64,
    pub quote_count: u64,
    pub live_quote_count: u64,
    pub attestation_count: u64,
    pub receipt_count: u64,
    pub challenge_count: u64,
    pub available_sponsor_micro_units: u64,
}

impl PrivateContractGasSponsorRouterCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "sponsor_count": self.sponsor_count,
            "usable_sponsor_count": self.usable_sponsor_count,
            "quote_count": self.quote_count,
            "live_quote_count": self.live_quote_count,
            "attestation_count": self.attestation_count,
            "receipt_count": self.receipt_count,
            "challenge_count": self.challenge_count,
            "available_sponsor_micro_units": self.available_sponsor_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractGasSponsorRouterState {
    pub config: PrivateContractGasSponsorRouterConfig,
    pub height: u64,
    pub lanes: BTreeMap<String, GasSponsorLane>,
    pub sponsors: BTreeMap<String, PrivateGasSponsor>,
    pub quotes: BTreeMap<String, PrivateGasQuote>,
    pub attestations: BTreeMap<String, GasSponsorAttestation>,
    pub receipts: BTreeMap<String, GasSettlementReceipt>,
    pub challenges: BTreeMap<String, GasSponsorChallenge>,
}

impl PrivateContractGasSponsorRouterState {
    pub fn devnet() -> PrivateContractGasSponsorRouterResult<Self> {
        let config = PrivateContractGasSponsorRouterConfig::devnet();
        let height = PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_DEFAULT_HEIGHT;
        let mut state = Self {
            config,
            height,
            lanes: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            quotes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
        };
        for lane_kind in [
            GasSponsorLaneKind::ContractCall,
            GasSponsorLaneKind::DefiSwap,
            GasSponsorLaneKind::MoneroBridgeExit,
            GasSponsorLaneKind::Recovery,
        ] {
            state.insert_lane(GasSponsorLane::devnet(lane_kind, 0, &state.config))?;
        }
        let lane_ids = state.lanes.keys().cloned().collect::<Vec<_>>();
        let sponsor =
            PrivateGasSponsor::devnet("sponsor:private-gas:devnet", &lane_ids, &state.config);
        state.insert_sponsor(sponsor)?;
        let lane = state
            .lanes
            .get("lane:private-gas:contract_call")
            .cloned()
            .ok_or_else(|| "missing devnet gas sponsor lane".to_string())?;
        let sponsor = state
            .sponsors
            .get("sponsor:private-gas:devnet")
            .cloned()
            .ok_or_else(|| "missing devnet gas sponsor".to_string())?;
        let mut quote = PrivateGasQuote::devnet(
            "quote:private-gas:contract-call:1",
            &lane,
            &sponsor,
            height,
            &state.config,
        );
        quote.status = GasQuoteStatus::Reserved;
        state.insert_quote(quote.clone())?;
        state.insert_attestation(GasSponsorAttestation::devnet(
            "attestation:private-gas:1",
            &quote.quote_id,
            "pq-sponsor-signer:devnet",
            height.saturating_add(1),
            &state.config,
        ))?;
        state.insert_receipt(GasSettlementReceipt::devnet(
            "receipt:private-gas:1",
            &quote,
            height.saturating_add(2),
        ))?;
        state.insert_challenge(GasSponsorChallenge::devnet(
            "challenge:private-gas:1",
            &quote.quote_id,
            height.saturating_add(3),
            &state.config,
        ))?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateContractGasSponsorRouterResult<()> {
        if height < self.height {
            return Err(format!(
                "private contract gas sponsor router height cannot move backward from {} to {}",
                self.height, height
            ));
        }
        self.height = height;
        for quote in self.quotes.values_mut() {
            if !quote.status.terminal() && height > quote.expires_height {
                quote.status = GasQuoteStatus::Expired;
            }
        }
        Ok(())
    }

    pub fn insert_lane(
        &mut self,
        lane: GasSponsorLane,
    ) -> PrivateContractGasSponsorRouterResult<()> {
        lane.validate(&self.config)?;
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn insert_sponsor(
        &mut self,
        sponsor: PrivateGasSponsor,
    ) -> PrivateContractGasSponsorRouterResult<()> {
        sponsor.validate(&self.lanes)?;
        self.sponsors.insert(sponsor.sponsor_id.clone(), sponsor);
        Ok(())
    }

    pub fn insert_quote(
        &mut self,
        quote: PrivateGasQuote,
    ) -> PrivateContractGasSponsorRouterResult<()> {
        quote.validate(&self.lanes, &self.sponsors, &self.config)?;
        self.quotes.insert(quote.quote_id.clone(), quote);
        Ok(())
    }

    pub fn insert_attestation(
        &mut self,
        attestation: GasSponsorAttestation,
    ) -> PrivateContractGasSponsorRouterResult<()> {
        attestation.validate(&self.quotes, &self.config)?;
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_receipt(
        &mut self,
        receipt: GasSettlementReceipt,
    ) -> PrivateContractGasSponsorRouterResult<()> {
        receipt.validate(&self.quotes)?;
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_challenge(
        &mut self,
        challenge: GasSponsorChallenge,
    ) -> PrivateContractGasSponsorRouterResult<()> {
        challenge.validate(&self.quotes)?;
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn active_lane_ids(&self) -> Vec<String> {
        self.lanes
            .values()
            .filter(|lane| lane.status.accepts_quotes())
            .map(|lane| lane.lane_id.clone())
            .collect()
    }

    pub fn live_quote_ids(&self) -> Vec<String> {
        self.quotes
            .values()
            .filter(|quote| !quote.status.terminal())
            .map(|quote| quote.quote_id.clone())
            .collect()
    }

    pub fn total_available_sponsor_micro_units(&self) -> u64 {
        self.sponsors
            .values()
            .filter(|sponsor| sponsor.status.usable())
            .map(PrivateGasSponsor::available_micro_units)
            .sum()
    }

    pub fn roots(&self) -> PrivateContractGasSponsorRouterRoots {
        PrivateContractGasSponsorRouterRoots {
            config_root: pcgsr_payload_root("CONFIG", &self.config.public_record()),
            lane_root: map_root("LANES", &self.lanes, GasSponsorLane::public_record),
            sponsor_root: map_root("SPONSORS", &self.sponsors, PrivateGasSponsor::public_record),
            quote_root: map_root("QUOTES", &self.quotes, PrivateGasQuote::public_record),
            attestation_root: map_root(
                "ATTESTATIONS",
                &self.attestations,
                GasSponsorAttestation::public_record,
            ),
            receipt_root: map_root(
                "RECEIPTS",
                &self.receipts,
                GasSettlementReceipt::public_record,
            ),
            challenge_root: map_root(
                "CHALLENGES",
                &self.challenges,
                GasSponsorChallenge::public_record,
            ),
        }
    }

    pub fn counters(&self) -> PrivateContractGasSponsorRouterCounters {
        PrivateContractGasSponsorRouterCounters {
            lane_count: self.lanes.len() as u64,
            sponsor_count: self.sponsors.len() as u64,
            usable_sponsor_count: self
                .sponsors
                .values()
                .filter(|sponsor| sponsor.status.usable())
                .count() as u64,
            quote_count: self.quotes.len() as u64,
            live_quote_count: self
                .quotes
                .values()
                .filter(|quote| !quote.status.terminal())
                .count() as u64,
            attestation_count: self.attestations.len() as u64,
            receipt_count: self.receipts.len() as u64,
            challenge_count: self.challenges.len() as u64,
            available_sponsor_micro_units: self.total_available_sponsor_micro_units(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_gas_sponsor_router_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_gas_sponsor_router_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PrivateContractGasSponsorRouterResult<()> {
        self.config.validate()?;
        for lane in self.lanes.values() {
            lane.validate(&self.config)?;
        }
        for sponsor in self.sponsors.values() {
            sponsor.validate(&self.lanes)?;
        }
        for quote in self.quotes.values() {
            quote.validate(&self.lanes, &self.sponsors, &self.config)?;
        }
        for attestation in self.attestations.values() {
            attestation.validate(&self.quotes, &self.config)?;
        }
        for receipt in self.receipts.values() {
            receipt.validate(&self.quotes)?;
        }
        for challenge in self.challenges.values() {
            challenge.validate(&self.quotes)?;
        }
        Ok(())
    }
}

pub fn private_contract_gas_sponsor_router_state_root_from_record(record: &Value) -> String {
    pcgsr_payload_root("STATE", record)
}

fn ensure_nonempty(label: &str, value: &str) -> PrivateContractGasSponsorRouterResult<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> PrivateContractGasSponsorRouterResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> PrivateContractGasSponsorRouterResult<()> {
    if value > PRIVATE_CONTRACT_GAS_SPONSOR_ROUTER_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(id, value)| json!({"id": id, "record": record(value)}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-CONTRACT-GAS-SPONSOR-ROUTER-{domain}"),
        &leaves,
    )
}

fn pcgsr_payload_root(domain: &str, payload: &Value) -> String {
    pcgsr_hash(domain, &[HashPart::Json(payload)])
}

fn pcgsr_string_root(domain: &str, value: &str) -> String {
    pcgsr_hash(domain, &[HashPart::Str(value)])
}

fn pcgsr_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-CONTRACT-GAS-SPONSOR-ROUTER-{domain}"),
        parts,
        32,
    )
}
