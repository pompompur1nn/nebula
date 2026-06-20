use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateContractWitnessFeeMarketResult<T> = Result<T, String>;

pub const PRIVATE_CONTRACT_WITNESS_FEE_MARKET_PROTOCOL_VERSION: &str =
    "nebula-private-contract-witness-fee-market-v1";
pub const PRIVATE_CONTRACT_WITNESS_FEE_MARKET_PROOF_SYSTEM: &str =
    "zk-private-contract-witness-fee-range-v1";
pub const PRIVATE_CONTRACT_WITNESS_FEE_MARKET_PQ_SIGNATURE_SCHEME: &str =
    "ml-dsa-87+shake256-witness-fee-attestation";
pub const PRIVATE_CONTRACT_WITNESS_FEE_MARKET_DEFAULT_EPOCH_BLOCKS: u64 = 96;
pub const PRIVATE_CONTRACT_WITNESS_FEE_MARKET_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_CONTRACT_WITNESS_FEE_MARKET_DEFAULT_MIN_SECURITY_BITS: u16 = 256;
pub const PRIVATE_CONTRACT_WITNESS_FEE_MARKET_DEFAULT_FEE_CAP_MICRO_UNITS: u64 = 2_000;
pub const PRIVATE_CONTRACT_WITNESS_FEE_MARKET_DEFAULT_SPONSOR_UNITS: u64 = 500_000;
pub const PRIVATE_CONTRACT_WITNESS_FEE_MARKET_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WitnessFeeLane {
    ContractCall,
    StorageRead,
    StorageWrite,
    ZkProof,
    MoneroExitHook,
}

impl WitnessFeeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::StorageRead => "storage_read",
            Self::StorageWrite => "storage_write",
            Self::ZkProof => "zk_proof",
            Self::MoneroExitHook => "monero_exit_hook",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::ContractCall => 4,
            Self::StorageRead => 1,
            Self::StorageWrite => 3,
            Self::ZkProof => 6,
            Self::MoneroExitHook => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WitnessQuoteStatus {
    Open,
    Matched,
    Settled,
    Expired,
    Challenged,
}

impl WitnessQuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Matched | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SponsorStatus {
    Active,
    Reserved,
    Settled,
    Slashed,
    Expired,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SettlementStatus {
    Pending,
    Verified,
    Paid,
    Rejected,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Paid => "paid",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChallengeStatus {
    Open,
    Proving,
    Upheld,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Proving => "proving",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Open | Self::Proving)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractWitnessFeeMarketConfig {
    pub epoch_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub default_fee_cap_micro_units: u64,
    pub default_sponsor_units: u64,
    pub min_pq_security_bits: u16,
    pub proof_system: String,
    pub pq_signature_scheme: String,
}

impl PrivateContractWitnessFeeMarketConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: PRIVATE_CONTRACT_WITNESS_FEE_MARKET_DEFAULT_EPOCH_BLOCKS,
            quote_ttl_blocks: PRIVATE_CONTRACT_WITNESS_FEE_MARKET_DEFAULT_QUOTE_TTL_BLOCKS,
            default_fee_cap_micro_units:
                PRIVATE_CONTRACT_WITNESS_FEE_MARKET_DEFAULT_FEE_CAP_MICRO_UNITS,
            default_sponsor_units: PRIVATE_CONTRACT_WITNESS_FEE_MARKET_DEFAULT_SPONSOR_UNITS,
            min_pq_security_bits: PRIVATE_CONTRACT_WITNESS_FEE_MARKET_DEFAULT_MIN_SECURITY_BITS,
            proof_system: PRIVATE_CONTRACT_WITNESS_FEE_MARKET_PROOF_SYSTEM.to_string(),
            pq_signature_scheme: PRIVATE_CONTRACT_WITNESS_FEE_MARKET_PQ_SIGNATURE_SCHEME
                .to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "default_fee_cap_micro_units": self.default_fee_cap_micro_units,
            "default_sponsor_units": self.default_sponsor_units,
            "min_pq_security_bits": self.min_pq_security_bits,
            "proof_system": self.proof_system,
            "pq_signature_scheme": self.pq_signature_scheme,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_witness_fee_market_payload_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractWitnessFeeMarketResult<()> {
        ensure_positive("epoch_blocks", self.epoch_blocks)?;
        ensure_positive("quote_ttl_blocks", self.quote_ttl_blocks)?;
        ensure_positive(
            "default_fee_cap_micro_units",
            self.default_fee_cap_micro_units,
        )?;
        ensure_positive("default_sponsor_units", self.default_sponsor_units)?;
        ensure_nonempty("proof_system", &self.proof_system)?;
        ensure_nonempty("pq_signature_scheme", &self.pq_signature_scheme)?;
        if self.min_pq_security_bits < 192 {
            return Err("private contract witness fee market pq security below policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessFeeProvider {
    pub provider_id: String,
    pub operator_commitment: String,
    pub pq_public_key_commitment: String,
    pub supported_lanes: Vec<WitnessFeeLane>,
    pub bond_asset_id: String,
    pub bond_units: u64,
    pub max_quote_micro_units: u64,
    pub last_seen_height: u64,
    pub active: bool,
}

impl WitnessFeeProvider {
    pub fn devnet(label: &str, lanes: Vec<WitnessFeeLane>, height: u64) -> Self {
        Self {
            provider_id: pcwfm_string_root("PROVIDER-ID", label),
            operator_commitment: pcwfm_string_root("PROVIDER-OPERATOR", label),
            pq_public_key_commitment: pcwfm_string_root("PROVIDER-PQ-PUBKEY", label),
            supported_lanes: lanes,
            bond_asset_id: "dxmr".to_string(),
            bond_units: 75_000,
            max_quote_micro_units: PRIVATE_CONTRACT_WITNESS_FEE_MARKET_DEFAULT_FEE_CAP_MICRO_UNITS
                * 4,
            last_seen_height: height,
            active: true,
        }
    }

    pub fn set_height(&mut self, height: u64, ttl_blocks: u64) {
        if height > self.last_seen_height.saturating_add(ttl_blocks) {
            self.active = false;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "operator_commitment": self.operator_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "supported_lanes": self.supported_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "bond_asset_id": self.bond_asset_id,
            "bond_units": self.bond_units,
            "max_quote_micro_units": self.max_quote_micro_units,
            "last_seen_height": self.last_seen_height,
            "active": self.active,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_witness_fee_market_payload_root("PROVIDER", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractWitnessFeeMarketResult<()> {
        ensure_nonempty("provider_id", &self.provider_id)?;
        ensure_nonempty("operator_commitment", &self.operator_commitment)?;
        ensure_nonempty("pq_public_key_commitment", &self.pq_public_key_commitment)?;
        ensure_nonempty("bond_asset_id", &self.bond_asset_id)?;
        ensure_positive("bond_units", self.bond_units)?;
        ensure_positive("max_quote_micro_units", self.max_quote_micro_units)?;
        if self.supported_lanes.is_empty() {
            return Err(format!(
                "provider {} has no supported lanes",
                self.provider_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessFeeQuote {
    pub quote_id: String,
    pub provider_id: String,
    pub lane: WitnessFeeLane,
    pub contract_commitment: String,
    pub witness_shape_root: String,
    pub encrypted_cost_breakdown_root: String,
    pub fee_cap_micro_units: u64,
    pub quoted_fee_micro_units: u64,
    pub compression_factor_bps: u64,
    pub status: WitnessQuoteStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub matched_settlement_id: Option<String>,
}

impl WitnessFeeQuote {
    pub fn devnet(
        index: u64,
        provider_id: &str,
        lane: WitnessFeeLane,
        height: u64,
        config: &PrivateContractWitnessFeeMarketConfig,
    ) -> Self {
        let seed = format!("quote:{index}:{provider_id}:{}", lane.as_str());
        let lane_weight = lane.default_weight();
        Self {
            quote_id: pcwfm_string_root("QUOTE-ID", &seed),
            provider_id: provider_id.to_string(),
            lane,
            contract_commitment: pcwfm_string_root("CONTRACT", &seed),
            witness_shape_root: pcwfm_string_root("WITNESS-SHAPE", &seed),
            encrypted_cost_breakdown_root: pcwfm_string_root("ENCRYPTED-COST", &seed),
            fee_cap_micro_units: config.default_fee_cap_micro_units * lane_weight,
            quoted_fee_micro_units: config.default_fee_cap_micro_units * lane_weight / 2,
            compression_factor_bps: 6_500,
            status: WitnessQuoteStatus::Open,
            opened_at_height: height,
            expires_at_height: height.saturating_add(config.quote_ttl_blocks),
            matched_settlement_id: None,
        }
    }

    pub fn set_height(&mut self, height: u64) {
        if height > self.expires_at_height && self.status.live() {
            self.status = WitnessQuoteStatus::Expired;
        }
    }

    pub fn mark_matched(&mut self, settlement_id: &str) {
        if self.status.live() {
            self.status = WitnessQuoteStatus::Matched;
            self.matched_settlement_id = Some(settlement_id.to_string());
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "provider_id": self.provider_id,
            "lane": self.lane.as_str(),
            "contract_commitment": self.contract_commitment,
            "witness_shape_root": self.witness_shape_root,
            "encrypted_cost_breakdown_root": self.encrypted_cost_breakdown_root,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "quoted_fee_micro_units": self.quoted_fee_micro_units,
            "compression_factor_bps": self.compression_factor_bps,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "matched_settlement_id": self.matched_settlement_id,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_witness_fee_market_payload_root("QUOTE", &self.public_record())
    }

    pub fn validate(
        &self,
        providers: &BTreeMap<String, WitnessFeeProvider>,
    ) -> PrivateContractWitnessFeeMarketResult<()> {
        ensure_nonempty("quote_id", &self.quote_id)?;
        ensure_nonempty("provider_id", &self.provider_id)?;
        ensure_nonempty("contract_commitment", &self.contract_commitment)?;
        ensure_nonempty("witness_shape_root", &self.witness_shape_root)?;
        ensure_nonempty(
            "encrypted_cost_breakdown_root",
            &self.encrypted_cost_breakdown_root,
        )?;
        ensure_positive("fee_cap_micro_units", self.fee_cap_micro_units)?;
        ensure_positive("quoted_fee_micro_units", self.quoted_fee_micro_units)?;
        ensure_bps("compression_factor_bps", self.compression_factor_bps)?;
        ensure_ordered_heights(
            "witness fee quote",
            self.opened_at_height,
            self.expires_at_height,
        )?;
        let provider = providers
            .get(&self.provider_id)
            .ok_or_else(|| format!("quote {} references missing provider", self.quote_id))?;
        if !provider.supported_lanes.contains(&self.lane) {
            return Err(format!(
                "quote {} uses unsupported lane {}",
                self.quote_id,
                self.lane.as_str()
            ));
        }
        if self.quoted_fee_micro_units > self.fee_cap_micro_units {
            return Err(format!("quote {} exceeds fee cap", self.quote_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeWitnessSponsor {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_policy_root: String,
    pub status: SponsorStatus,
    pub funded_units: u64,
    pub reserved_units: u64,
    pub lane_allowlist: Vec<WitnessFeeLane>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeWitnessSponsor {
    pub fn devnet(
        index: u64,
        lanes: Vec<WitnessFeeLane>,
        height: u64,
        config: &PrivateContractWitnessFeeMarketConfig,
    ) -> Self {
        let seed = format!("sponsor:{index}:{height}");
        Self {
            sponsor_id: pcwfm_string_root("SPONSOR-ID", &seed),
            sponsor_commitment: pcwfm_string_root("SPONSOR", &seed),
            beneficiary_policy_root: pcwfm_string_root("BENEFICIARY-POLICY", &seed),
            status: SponsorStatus::Active,
            funded_units: config.default_sponsor_units,
            reserved_units: config.default_sponsor_units / 5,
            lane_allowlist: lanes,
            opened_at_height: height,
            expires_at_height: height.saturating_add(config.epoch_blocks * 4),
        }
    }

    pub fn available_units(&self) -> u64 {
        self.funded_units.saturating_sub(self.reserved_units)
    }

    pub fn set_height(&mut self, height: u64) {
        if height > self.expires_at_height && self.status.usable() {
            self.status = SponsorStatus::Expired;
            self.reserved_units = 0;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_policy_root": self.beneficiary_policy_root,
            "status": self.status.as_str(),
            "funded_units": self.funded_units,
            "reserved_units": self.reserved_units,
            "available_units": self.available_units(),
            "lane_allowlist": self.lane_allowlist.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_witness_fee_market_payload_root("SPONSOR", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractWitnessFeeMarketResult<()> {
        ensure_nonempty("sponsor_id", &self.sponsor_id)?;
        ensure_nonempty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_nonempty("beneficiary_policy_root", &self.beneficiary_policy_root)?;
        ensure_positive("funded_units", self.funded_units)?;
        ensure_ordered_heights(
            "low fee witness sponsor",
            self.opened_at_height,
            self.expires_at_height,
        )?;
        if self.reserved_units > self.funded_units {
            return Err(format!("sponsor {} over-reserved", self.sponsor_id));
        }
        if self.lane_allowlist.is_empty() {
            return Err(format!("sponsor {} has no allowed lanes", self.sponsor_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessFeeSettlement {
    pub settlement_id: String,
    pub quote_id: String,
    pub sponsor_id: Option<String>,
    pub execution_receipt_root: String,
    pub compressed_witness_root: String,
    pub pq_attestation_root: String,
    pub paid_fee_micro_units: u64,
    pub status: SettlementStatus,
    pub settled_at_height: u64,
}

impl WitnessFeeSettlement {
    pub fn devnet(index: u64, quote_id: &str, sponsor_id: Option<String>, height: u64) -> Self {
        let seed = format!("settlement:{index}:{quote_id}");
        Self {
            settlement_id: pcwfm_string_root("SETTLEMENT-ID", &seed),
            quote_id: quote_id.to_string(),
            sponsor_id,
            execution_receipt_root: pcwfm_string_root("EXECUTION-RECEIPT", &seed),
            compressed_witness_root: pcwfm_string_root("COMPRESSED-WITNESS", &seed),
            pq_attestation_root: pcwfm_string_root("PQ-ATTESTATION", &seed),
            paid_fee_micro_units: PRIVATE_CONTRACT_WITNESS_FEE_MARKET_DEFAULT_FEE_CAP_MICRO_UNITS,
            status: SettlementStatus::Verified,
            settled_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "quote_id": self.quote_id,
            "sponsor_id": self.sponsor_id,
            "execution_receipt_root": self.execution_receipt_root,
            "compressed_witness_root": self.compressed_witness_root,
            "pq_attestation_root": self.pq_attestation_root,
            "paid_fee_micro_units": self.paid_fee_micro_units,
            "status": self.status.as_str(),
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_witness_fee_market_payload_root("SETTLEMENT", &self.public_record())
    }

    pub fn validate(
        &self,
        quotes: &BTreeMap<String, WitnessFeeQuote>,
        sponsors: &BTreeMap<String, LowFeeWitnessSponsor>,
    ) -> PrivateContractWitnessFeeMarketResult<()> {
        ensure_nonempty("settlement_id", &self.settlement_id)?;
        ensure_nonempty("quote_id", &self.quote_id)?;
        ensure_nonempty("execution_receipt_root", &self.execution_receipt_root)?;
        ensure_nonempty("compressed_witness_root", &self.compressed_witness_root)?;
        ensure_nonempty("pq_attestation_root", &self.pq_attestation_root)?;
        ensure_positive("paid_fee_micro_units", self.paid_fee_micro_units)?;
        if !quotes.contains_key(&self.quote_id) {
            return Err(format!(
                "settlement {} references missing quote {}",
                self.settlement_id, self.quote_id
            ));
        }
        if let Some(sponsor_id) = &self.sponsor_id {
            if !sponsors.contains_key(sponsor_id) {
                return Err(format!(
                    "settlement {} references missing sponsor {}",
                    self.settlement_id, sponsor_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessFeeChallenge {
    pub challenge_id: String,
    pub target_quote_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub status: ChallengeStatus,
    pub opened_at_height: u64,
    pub response_deadline_height: u64,
}

impl WitnessFeeChallenge {
    pub fn devnet(
        index: u64,
        target_quote_id: &str,
        height: u64,
        config: &PrivateContractWitnessFeeMarketConfig,
    ) -> Self {
        let seed = format!("challenge:{index}:{target_quote_id}");
        Self {
            challenge_id: pcwfm_string_root("CHALLENGE-ID", &seed),
            target_quote_id: target_quote_id.to_string(),
            challenger_commitment: pcwfm_string_root("CHALLENGER", &seed),
            evidence_root: pcwfm_string_root("CHALLENGE-EVIDENCE", &seed),
            status: ChallengeStatus::Open,
            opened_at_height: height,
            response_deadline_height: height.saturating_add(config.quote_ttl_blocks),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        if height > self.response_deadline_height && self.status.open() {
            self.status = ChallengeStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "target_quote_id": self.target_quote_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "response_deadline_height": self.response_deadline_height,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_witness_fee_market_payload_root("CHALLENGE", &self.public_record())
    }

    pub fn validate(
        &self,
        quotes: &BTreeMap<String, WitnessFeeQuote>,
    ) -> PrivateContractWitnessFeeMarketResult<()> {
        ensure_nonempty("challenge_id", &self.challenge_id)?;
        ensure_nonempty("target_quote_id", &self.target_quote_id)?;
        ensure_nonempty("challenger_commitment", &self.challenger_commitment)?;
        ensure_nonempty("evidence_root", &self.evidence_root)?;
        ensure_ordered_heights(
            "witness fee challenge",
            self.opened_at_height,
            self.response_deadline_height,
        )?;
        if !quotes.contains_key(&self.target_quote_id) {
            return Err(format!(
                "challenge {} references missing quote {}",
                self.challenge_id, self.target_quote_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractWitnessFeeMarketRoots {
    pub provider_root: String,
    pub quote_root: String,
    pub sponsor_root: String,
    pub settlement_root: String,
    pub challenge_root: String,
}

impl PrivateContractWitnessFeeMarketRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "provider_root": self.provider_root,
            "quote_root": self.quote_root,
            "sponsor_root": self.sponsor_root,
            "settlement_root": self.settlement_root,
            "challenge_root": self.challenge_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_contract_witness_fee_market_payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractWitnessFeeMarketCounters {
    pub providers: usize,
    pub active_providers: usize,
    pub quotes: usize,
    pub live_quotes: usize,
    pub sponsors: usize,
    pub usable_sponsors: usize,
    pub settlements: usize,
    pub challenges: usize,
    pub open_challenges: usize,
    pub available_sponsor_units: u64,
}

impl PrivateContractWitnessFeeMarketCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "providers": self.providers,
            "active_providers": self.active_providers,
            "quotes": self.quotes,
            "live_quotes": self.live_quotes,
            "sponsors": self.sponsors,
            "usable_sponsors": self.usable_sponsors,
            "settlements": self.settlements,
            "challenges": self.challenges,
            "open_challenges": self.open_challenges,
            "available_sponsor_units": self.available_sponsor_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateContractWitnessFeeMarketState {
    pub protocol_version: String,
    pub height: u64,
    pub config: PrivateContractWitnessFeeMarketConfig,
    pub providers: BTreeMap<String, WitnessFeeProvider>,
    pub quotes: BTreeMap<String, WitnessFeeQuote>,
    pub sponsors: BTreeMap<String, LowFeeWitnessSponsor>,
    pub settlements: BTreeMap<String, WitnessFeeSettlement>,
    pub challenges: BTreeMap<String, WitnessFeeChallenge>,
    pub settled_quote_ids: BTreeSet<String>,
}

impl PrivateContractWitnessFeeMarketState {
    pub fn devnet() -> PrivateContractWitnessFeeMarketResult<Self> {
        let config = PrivateContractWitnessFeeMarketConfig::devnet();
        let height = 1;
        let mut state = Self {
            protocol_version: PRIVATE_CONTRACT_WITNESS_FEE_MARKET_PROTOCOL_VERSION.to_string(),
            height,
            config,
            providers: BTreeMap::new(),
            quotes: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            settlements: BTreeMap::new(),
            challenges: BTreeMap::new(),
            settled_quote_ids: BTreeSet::new(),
        };

        state.add_provider(WitnessFeeProvider::devnet(
            "provider-fast-zk",
            vec![WitnessFeeLane::ContractCall, WitnessFeeLane::ZkProof],
            height,
        ))?;
        state.add_provider(WitnessFeeProvider::devnet(
            "provider-storage",
            vec![WitnessFeeLane::StorageRead, WitnessFeeLane::StorageWrite],
            height,
        ))?;
        state.add_provider(WitnessFeeProvider::devnet(
            "provider-monero-exit",
            vec![WitnessFeeLane::MoneroExitHook, WitnessFeeLane::ContractCall],
            height,
        ))?;

        let sponsor = LowFeeWitnessSponsor::devnet(
            0,
            vec![WitnessFeeLane::ContractCall, WitnessFeeLane::StorageRead],
            height,
            &state.config,
        );
        let sponsor_id = sponsor.sponsor_id.clone();
        state.add_sponsor(sponsor)?;

        let provider_lanes = state
            .providers
            .iter()
            .map(|(provider_id, provider)| (provider_id.clone(), provider.supported_lanes[0]))
            .collect::<Vec<_>>();
        for (index, (provider_id, lane)) in provider_lanes.into_iter().enumerate() {
            state.add_quote(WitnessFeeQuote::devnet(
                index as u64,
                &provider_id,
                lane,
                height,
                &state.config,
            ))?;
        }

        let quote_id = state
            .quotes
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet witness fee market missing quote".to_string())?;
        let settlement = WitnessFeeSettlement::devnet(0, &quote_id, Some(sponsor_id), height);
        let settlement_id = settlement.settlement_id.clone();
        if let Some(quote) = state.quotes.get_mut(&quote_id) {
            quote.mark_matched(&settlement_id);
        }
        state.add_settlement(settlement)?;
        state.add_challenge(WitnessFeeChallenge::devnet(
            0,
            &quote_id,
            height,
            &state.config,
        ))?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateContractWitnessFeeMarketResult<()> {
        if height < self.height {
            return Err(
                "private contract witness fee market height cannot move backwards".to_string(),
            );
        }
        self.height = height;
        for provider in self.providers.values_mut() {
            provider.set_height(height, self.config.quote_ttl_blocks * 4);
        }
        for quote in self.quotes.values_mut() {
            quote.set_height(height);
        }
        for sponsor in self.sponsors.values_mut() {
            sponsor.set_height(height);
        }
        for challenge in self.challenges.values_mut() {
            challenge.set_height(height);
        }
        self.validate()
    }

    pub fn roots(&self) -> PrivateContractWitnessFeeMarketRoots {
        PrivateContractWitnessFeeMarketRoots {
            provider_root: merkle_record_root("PCWFM-PROVIDERS", &self.providers),
            quote_root: merkle_record_root("PCWFM-QUOTES", &self.quotes),
            sponsor_root: merkle_record_root("PCWFM-SPONSORS", &self.sponsors),
            settlement_root: merkle_record_root("PCWFM-SETTLEMENTS", &self.settlements),
            challenge_root: merkle_record_root("PCWFM-CHALLENGES", &self.challenges),
        }
    }

    pub fn counters(&self) -> PrivateContractWitnessFeeMarketCounters {
        PrivateContractWitnessFeeMarketCounters {
            providers: self.providers.len(),
            active_providers: self
                .providers
                .values()
                .filter(|provider| provider.active)
                .count(),
            quotes: self.quotes.len(),
            live_quotes: self
                .quotes
                .values()
                .filter(|quote| quote.status.live())
                .count(),
            sponsors: self.sponsors.len(),
            usable_sponsors: self
                .sponsors
                .values()
                .filter(|sponsor| sponsor.status.usable())
                .count(),
            settlements: self.settlements.len(),
            challenges: self.challenges.len(),
            open_challenges: self
                .challenges
                .values()
                .filter(|challenge| challenge.status.open())
                .count(),
            available_sponsor_units: self
                .sponsors
                .values()
                .map(LowFeeWitnessSponsor::available_units)
                .sum(),
        }
    }

    pub fn live_quote_ids(&self) -> Vec<String> {
        self.quotes
            .values()
            .filter(|quote| quote.status.live())
            .map(|quote| quote.quote_id.clone())
            .collect()
    }

    pub fn active_provider_ids(&self) -> Vec<String> {
        self.providers
            .values()
            .filter(|provider| provider.active)
            .map(|provider| provider.provider_id.clone())
            .collect()
    }

    pub fn lane_quote_pressure(&self) -> BTreeMap<String, u64> {
        let mut pressure = BTreeMap::new();
        for quote in self.quotes.values().filter(|quote| quote.status.live()) {
            *pressure.entry(quote.lane.as_str().to_string()).or_insert(0) +=
                quote.quoted_fee_micro_units;
        }
        pressure
    }

    pub fn state_root(&self) -> String {
        private_contract_witness_fee_market_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(map) = &mut record {
            map.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> PrivateContractWitnessFeeMarketResult<()> {
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        self.config.validate()?;
        for (id, provider) in &self.providers {
            if id != &provider.provider_id {
                return Err(format!("provider key mismatch {id}"));
            }
            provider.validate()?;
        }
        for (id, quote) in &self.quotes {
            if id != &quote.quote_id {
                return Err(format!("quote key mismatch {id}"));
            }
            quote.validate(&self.providers)?;
        }
        for (id, sponsor) in &self.sponsors {
            if id != &sponsor.sponsor_id {
                return Err(format!("sponsor key mismatch {id}"));
            }
            sponsor.validate()?;
        }
        for (id, settlement) in &self.settlements {
            if id != &settlement.settlement_id {
                return Err(format!("settlement key mismatch {id}"));
            }
            settlement.validate(&self.quotes, &self.sponsors)?;
        }
        for quote_id in &self.settled_quote_ids {
            if !self.quotes.contains_key(quote_id) {
                return Err(format!(
                    "settled quote index references missing quote {quote_id}"
                ));
            }
        }
        for (id, challenge) in &self.challenges {
            if id != &challenge.challenge_id {
                return Err(format!("challenge key mismatch {id}"));
            }
            challenge.validate(&self.quotes)?;
        }
        Ok(())
    }

    pub fn add_provider(
        &mut self,
        provider: WitnessFeeProvider,
    ) -> PrivateContractWitnessFeeMarketResult<()> {
        provider.validate()?;
        self.providers
            .insert(provider.provider_id.clone(), provider);
        Ok(())
    }

    pub fn add_quote(
        &mut self,
        quote: WitnessFeeQuote,
    ) -> PrivateContractWitnessFeeMarketResult<()> {
        quote.validate(&self.providers)?;
        self.quotes.insert(quote.quote_id.clone(), quote);
        Ok(())
    }

    pub fn add_sponsor(
        &mut self,
        sponsor: LowFeeWitnessSponsor,
    ) -> PrivateContractWitnessFeeMarketResult<()> {
        sponsor.validate()?;
        self.sponsors.insert(sponsor.sponsor_id.clone(), sponsor);
        Ok(())
    }

    pub fn add_settlement(
        &mut self,
        settlement: WitnessFeeSettlement,
    ) -> PrivateContractWitnessFeeMarketResult<()> {
        settlement.validate(&self.quotes, &self.sponsors)?;
        self.settled_quote_ids.insert(settlement.quote_id.clone());
        self.settlements
            .insert(settlement.settlement_id.clone(), settlement);
        Ok(())
    }

    pub fn add_challenge(
        &mut self,
        challenge: WitnessFeeChallenge,
    ) -> PrivateContractWitnessFeeMarketResult<()> {
        challenge.validate(&self.quotes)?;
        if let Some(quote) = self.quotes.get_mut(&challenge.target_quote_id) {
            quote.status = WitnessQuoteStatus::Challenged;
        }
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_contract_witness_fee_market_state",
            "protocol_version": self.protocol_version,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "providers": keyed_records(&self.providers),
            "quotes": keyed_records(&self.quotes),
            "sponsors": keyed_records(&self.sponsors),
            "settlements": keyed_records(&self.settlements),
            "challenges": keyed_records(&self.challenges),
            "settled_quote_root": merkle_root(
                "PCWFM-SETTLED-QUOTE-IDS",
                &self
                    .settled_quote_ids
                    .iter()
                    .map(|quote_id| json!(quote_id))
                    .collect::<Vec<_>>(),
            ),
        })
    }
}

pub fn private_contract_witness_fee_market_state_root_from_record(record: &Value) -> String {
    private_contract_witness_fee_market_payload_root("STATE", record)
}

pub fn private_contract_witness_fee_market_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-CONTRACT-WITNESS-FEE-MARKET-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

fn pcwfm_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-CONTRACT-WITNESS-FEE-MARKET-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Str(value)],
        32,
    )
}

trait FeeMarketPublicRecord {
    fn public_record(&self) -> Value;
}

impl FeeMarketPublicRecord for WitnessFeeProvider {
    fn public_record(&self) -> Value {
        WitnessFeeProvider::public_record(self)
    }
}

impl FeeMarketPublicRecord for WitnessFeeQuote {
    fn public_record(&self) -> Value {
        WitnessFeeQuote::public_record(self)
    }
}

impl FeeMarketPublicRecord for LowFeeWitnessSponsor {
    fn public_record(&self) -> Value {
        LowFeeWitnessSponsor::public_record(self)
    }
}

impl FeeMarketPublicRecord for WitnessFeeSettlement {
    fn public_record(&self) -> Value {
        WitnessFeeSettlement::public_record(self)
    }
}

impl FeeMarketPublicRecord for WitnessFeeChallenge {
    fn public_record(&self) -> Value {
        WitnessFeeChallenge::public_record(self)
    }
}

fn keyed_records<T: FeeMarketPublicRecord>(records: &BTreeMap<String, T>) -> Vec<Value> {
    records
        .iter()
        .map(|(id, record)| json!({ "id": id, "record": record.public_record() }))
        .collect()
}

fn merkle_record_root<T: FeeMarketPublicRecord>(
    domain: &str,
    records: &BTreeMap<String, T>,
) -> String {
    merkle_root(
        domain,
        &records
            .iter()
            .map(|(id, record)| {
                json!({
                    "id": id,
                    "root": private_contract_witness_fee_market_payload_root(
                        domain,
                        &json!({ "id": id, "record": record.public_record() }),
                    ),
                })
            })
            .collect::<Vec<_>>(),
    )
}

fn ensure_nonempty(field: &str, value: &str) -> PrivateContractWitnessFeeMarketResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(field: &str, value: u64) -> PrivateContractWitnessFeeMarketResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> PrivateContractWitnessFeeMarketResult<()> {
    if value > PRIVATE_CONTRACT_WITNESS_FEE_MARKET_MAX_BPS {
        Err(format!("{field} exceeds bps denominator"))
    } else {
        Ok(())
    }
}

fn ensure_ordered_heights(
    label: &str,
    start_height: u64,
    end_height: u64,
) -> PrivateContractWitnessFeeMarketResult<()> {
    if end_height <= start_height {
        Err(format!("{label} end height must be after start height"))
    } else {
        Ok(())
    }
}
