use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivatePaymasterResult<T> = Result<T, String>;

pub const PRIVATE_PAYMASTER_PROTOCOL_VERSION: &str = "nebula-private-paymaster-v1";
pub const PRIVATE_PAYMASTER_DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const PRIVATE_PAYMASTER_DEFAULT_INTENT_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_PAYMASTER_DEFAULT_MAX_BATCH_ITEMS: usize = 64;
pub const PRIVATE_PAYMASTER_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const PRIVATE_PAYMASTER_DEFAULT_MAX_FEE_UNITS: u64 = 8;
pub const PRIVATE_PAYMASTER_DEFAULT_MIN_POOL_RESERVE_UNITS: u64 = 64;
pub const PRIVATE_PAYMASTER_DEFAULT_PRIVACY_SET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateFeeLane {
    WalletTransfer,
    MoneroBridge,
    DefiSwap,
    ContractCall,
    ProofJob,
    ExitLiquidity,
}

impl PrivateFeeLane {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::DefiSwap => "defi_swap",
            Self::ContractCall => "contract_call",
            Self::ProofJob => "proof_job",
            Self::ExitLiquidity => "exit_liquidity",
        }
    }

    pub fn default_fee_units(&self) -> u64 {
        match self {
            Self::WalletTransfer => 1,
            Self::MoneroBridge => 3,
            Self::DefiSwap => 2,
            Self::ContractCall => 4,
            Self::ProofJob => 5,
            Self::ExitLiquidity => 3,
        }
    }

    pub fn privacy_floor(&self) -> u64 {
        match self {
            Self::WalletTransfer => 128,
            Self::MoneroBridge => 96,
            Self::DefiSwap => 80,
            Self::ContractCall => 64,
            Self::ProofJob => 48,
            Self::ExitLiquidity => 96,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateFeeIntentStatus {
    Open,
    Quoted,
    Admitted,
    Settled,
    Expired,
    Rejected,
}

impl PrivateFeeIntentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Quoted => "quoted",
            Self::Admitted => "admitted",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivatePaymasterBatchStatus {
    Open,
    Sealed,
    Posted,
    Challenged,
    Finalized,
}

impl PrivatePaymasterBatchStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Posted => "posted",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateSponsorMode {
    PublicPool,
    ShieldedPool,
    Hybrid,
}

impl PrivateSponsorMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PublicPool => "public_pool",
            Self::ShieldedPool => "shielded_pool",
            Self::Hybrid => "hybrid",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivatePaymasterConfig {
    pub epoch_blocks: u64,
    pub default_intent_ttl_blocks: u64,
    pub max_batch_items: usize,
    pub max_fee_units_per_intent: u64,
    pub min_pool_reserve_units: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub allow_public_fallback: bool,
    pub sponsor_mode: PrivateSponsorMode,
}

impl Default for PrivatePaymasterConfig {
    fn default() -> Self {
        Self {
            epoch_blocks: PRIVATE_PAYMASTER_DEFAULT_EPOCH_BLOCKS,
            default_intent_ttl_blocks: PRIVATE_PAYMASTER_DEFAULT_INTENT_TTL_BLOCKS,
            max_batch_items: PRIVATE_PAYMASTER_DEFAULT_MAX_BATCH_ITEMS,
            max_fee_units_per_intent: PRIVATE_PAYMASTER_DEFAULT_MAX_FEE_UNITS,
            min_pool_reserve_units: PRIVATE_PAYMASTER_DEFAULT_MIN_POOL_RESERVE_UNITS,
            min_privacy_set_size: PRIVATE_PAYMASTER_DEFAULT_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_PAYMASTER_MIN_PQ_SECURITY_BITS,
            allow_public_fallback: false,
            sponsor_mode: PrivateSponsorMode::Hybrid,
        }
    }
}

impl PrivatePaymasterConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: 60,
            default_intent_ttl_blocks: 12,
            max_batch_items: 32,
            max_fee_units_per_intent: 12,
            min_pool_reserve_units: 96,
            min_privacy_set_size: 96,
            min_pq_security_bits: 192,
            allow_public_fallback: false,
            sponsor_mode: PrivateSponsorMode::Hybrid,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_paymaster_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_PAYMASTER_PROTOCOL_VERSION,
            "epoch_blocks": self.epoch_blocks,
            "default_intent_ttl_blocks": self.default_intent_ttl_blocks,
            "max_batch_items": self.max_batch_items,
            "max_fee_units_per_intent": self.max_fee_units_per_intent,
            "min_pool_reserve_units": self.min_pool_reserve_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "allow_public_fallback": self.allow_public_fallback,
            "sponsor_mode": self.sponsor_mode.as_str(),
        })
    }

    pub fn config_root(&self) -> String {
        domain_hash(
            "PRIVATE-PAYMASTER-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSponsorPool {
    pub pool_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub lane: PrivateFeeLane,
    pub mode: PrivateSponsorMode,
    pub reserve_units: u64,
    pub committed_units: u64,
    pub spent_units: u64,
    pub refill_commitment_root: String,
    pub policy_root: String,
    pub epoch: u64,
    pub last_refill_height: u64,
    pub paused: bool,
}

impl PrivateSponsorPool {
    pub fn new(
        sponsor_commitment: &str,
        fee_asset_id: &str,
        lane: PrivateFeeLane,
        mode: PrivateSponsorMode,
        reserve_units: u64,
        height: u64,
    ) -> Self {
        let policy = json!({
            "sponsor_commitment": sponsor_commitment,
            "fee_asset_id": fee_asset_id,
            "lane": lane.as_str(),
            "mode": mode.as_str(),
            "reserve_units": reserve_units,
            "height": height,
        });
        let pool_id = domain_hash(
            "PRIVATE-PAYMASTER-POOL-ID",
            &[
                HashPart::Str(sponsor_commitment),
                HashPart::Str(fee_asset_id),
                HashPart::Str(lane.as_str()),
                HashPart::Int(height as i128),
            ],
            24,
        );
        Self {
            pool_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            lane,
            mode,
            reserve_units,
            committed_units: 0,
            spent_units: 0,
            refill_commitment_root: domain_hash(
                "PRIVATE-PAYMASTER-REFILL",
                &[HashPart::Json(&policy)],
                32,
            ),
            policy_root: domain_hash("PRIVATE-PAYMASTER-POLICY", &[HashPart::Json(&policy)], 32),
            epoch: 0,
            last_refill_height: height,
            paused: false,
        }
    }

    pub fn available_units(&self) -> u64 {
        self.reserve_units
            .saturating_sub(self.committed_units)
            .saturating_sub(self.spent_units)
    }

    pub fn reserve_ratio_bps(&self) -> u64 {
        if self.reserve_units == 0 {
            return 0;
        }
        self.available_units().saturating_mul(10_000) / self.reserve_units
    }

    pub fn can_sponsor(&self, lane: PrivateFeeLane, fee_units: u64) -> bool {
        !self.paused && self.lane == lane && self.available_units() >= fee_units
    }

    pub fn commit(&mut self, fee_units: u64) -> PrivatePaymasterResult<()> {
        if self.available_units() < fee_units {
            return Err("private paymaster pool has insufficient available units".to_string());
        }
        self.committed_units = self.committed_units.saturating_add(fee_units);
        Ok(())
    }

    pub fn settle(&mut self, fee_units: u64) {
        self.committed_units = self.committed_units.saturating_sub(fee_units);
        self.spent_units = self.spent_units.saturating_add(fee_units);
    }

    pub fn release(&mut self, fee_units: u64) {
        self.committed_units = self.committed_units.saturating_sub(fee_units);
    }

    pub fn refill(&mut self, units: u64, commitment_root: &str, height: u64) {
        self.reserve_units = self.reserve_units.saturating_add(units);
        self.refill_commitment_root = commitment_root.to_string();
        self.last_refill_height = height;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_sponsor_pool",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_PAYMASTER_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "lane": self.lane.as_str(),
            "mode": self.mode.as_str(),
            "reserve_units": self.reserve_units,
            "committed_units": self.committed_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "reserve_ratio_bps": self.reserve_ratio_bps(),
            "refill_commitment_root": self.refill_commitment_root,
            "policy_root": self.policy_root,
            "epoch": self.epoch,
            "last_refill_height": self.last_refill_height,
            "paused": self.paused,
        })
    }

    pub fn pool_root(&self) -> String {
        domain_hash(
            "PRIVATE-PAYMASTER-POOL",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeQuote {
    pub quote_id: String,
    pub pool_id: String,
    pub lane: PrivateFeeLane,
    pub max_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub relayer_tip_units: u64,
    pub valid_until_height: u64,
    pub quote_commitment_root: String,
    pub liquidity_score_bps: u64,
    pub privacy_score_bps: u64,
}

impl PrivateFeeQuote {
    pub fn new(
        pool_id: &str,
        lane: PrivateFeeLane,
        max_fee_units: u64,
        relayer_tip_units: u64,
        valid_until_height: u64,
        privacy_score_bps: u64,
    ) -> Self {
        let quote_payload = json!({
            "pool_id": pool_id,
            "lane": lane.as_str(),
            "max_fee_units": max_fee_units,
            "relayer_tip_units": relayer_tip_units,
            "valid_until_height": valid_until_height,
            "privacy_score_bps": privacy_score_bps,
        });
        let quote_id = domain_hash(
            "PRIVATE-PAYMASTER-QUOTE-ID",
            &[HashPart::Json(&quote_payload)],
            24,
        );
        Self {
            quote_id,
            pool_id: pool_id.to_string(),
            lane,
            max_fee_units,
            sponsored_fee_units: max_fee_units,
            relayer_tip_units,
            valid_until_height,
            quote_commitment_root: domain_hash(
                "PRIVATE-PAYMASTER-QUOTE-COMMITMENT",
                &[HashPart::Json(&quote_payload)],
                32,
            ),
            liquidity_score_bps: 10_000,
            privacy_score_bps,
        }
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height > self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_fee_quote",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_PAYMASTER_PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "max_fee_units": self.max_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "relayer_tip_units": self.relayer_tip_units,
            "valid_until_height": self.valid_until_height,
            "quote_commitment_root": self.quote_commitment_root,
            "liquidity_score_bps": self.liquidity_score_bps,
            "privacy_score_bps": self.privacy_score_bps,
        })
    }

    pub fn quote_root(&self) -> String {
        domain_hash(
            "PRIVATE-PAYMASTER-QUOTE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeIntent {
    pub intent_id: String,
    pub lane: PrivateFeeLane,
    pub caller_commitment: String,
    pub action_root: String,
    pub nullifier: String,
    pub pq_public_key_commitment: String,
    pub pq_signature_root: String,
    pub privacy_proof_root: String,
    pub max_fee_units: u64,
    pub relayer_tip_units: u64,
    pub created_height: u64,
    pub expires_at_height: u64,
    pub status: PrivateFeeIntentStatus,
    pub quote_id: Option<String>,
    pub pool_id: Option<String>,
    pub batch_id: Option<String>,
    pub reject_reason_root: Option<String>,
}

impl PrivateFeeIntent {
    pub fn new(
        lane: PrivateFeeLane,
        caller_commitment: &str,
        action_root: &str,
        nullifier_seed: &str,
        pq_public_key_commitment: &str,
        max_fee_units: u64,
        relayer_tip_units: u64,
        created_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let nullifier = domain_hash(
            "PRIVATE-PAYMASTER-NULLIFIER",
            &[
                HashPart::Str(caller_commitment),
                HashPart::Str(action_root),
                HashPart::Str(nullifier_seed),
            ],
            32,
        );
        let transcript = json!({
            "lane": lane.as_str(),
            "caller_commitment": caller_commitment,
            "action_root": action_root,
            "nullifier": nullifier,
            "pq_public_key_commitment": pq_public_key_commitment,
            "max_fee_units": max_fee_units,
            "relayer_tip_units": relayer_tip_units,
            "created_height": created_height,
        });
        let intent_id = domain_hash(
            "PRIVATE-PAYMASTER-INTENT-ID",
            &[HashPart::Json(&transcript)],
            24,
        );
        Self {
            intent_id,
            lane,
            caller_commitment: caller_commitment.to_string(),
            action_root: action_root.to_string(),
            nullifier,
            pq_public_key_commitment: pq_public_key_commitment.to_string(),
            pq_signature_root: domain_hash(
                "PRIVATE-PAYMASTER-PQ-SIGNATURE",
                &[HashPart::Json(&transcript)],
                32,
            ),
            privacy_proof_root: domain_hash(
                "PRIVATE-PAYMASTER-PRIVACY-PROOF",
                &[HashPart::Json(&transcript)],
                32,
            ),
            max_fee_units,
            relayer_tip_units,
            created_height,
            expires_at_height: created_height.saturating_add(ttl_blocks),
            status: PrivateFeeIntentStatus::Open,
            quote_id: None,
            pool_id: None,
            batch_id: None,
            reject_reason_root: None,
        }
    }

    pub fn quoted(&mut self, quote: &PrivateFeeQuote) {
        self.quote_id = Some(quote.quote_id.clone());
        self.pool_id = Some(quote.pool_id.clone());
        self.status = PrivateFeeIntentStatus::Quoted;
    }

    pub fn admit(&mut self) {
        self.status = PrivateFeeIntentStatus::Admitted;
    }

    pub fn settle(&mut self, batch_id: &str) {
        self.batch_id = Some(batch_id.to_string());
        self.status = PrivateFeeIntentStatus::Settled;
    }

    pub fn expire(&mut self, height: u64) {
        self.status = PrivateFeeIntentStatus::Expired;
        self.reject_reason_root = Some(domain_hash(
            "PRIVATE-PAYMASTER-INTENT-EXPIRED",
            &[
                HashPart::Str(&self.intent_id),
                HashPart::Int(height as i128),
                HashPart::Int(self.expires_at_height as i128),
            ],
            32,
        ));
    }

    pub fn reject(&mut self, reason: &str) {
        self.status = PrivateFeeIntentStatus::Rejected;
        self.reject_reason_root = Some(domain_hash(
            "PRIVATE-PAYMASTER-INTENT-REJECT",
            &[HashPart::Str(&self.intent_id), HashPart::Str(reason)],
            32,
        ));
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
            && !matches!(
                self.status,
                PrivateFeeIntentStatus::Settled | PrivateFeeIntentStatus::Rejected
            )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_fee_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_PAYMASTER_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "lane": self.lane.as_str(),
            "caller_commitment": self.caller_commitment,
            "action_root": self.action_root,
            "nullifier": self.nullifier,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "pq_signature_root": self.pq_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "max_fee_units": self.max_fee_units,
            "relayer_tip_units": self.relayer_tip_units,
            "created_height": self.created_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "quote_id": self.quote_id,
            "pool_id": self.pool_id,
            "batch_id": self.batch_id,
            "reject_reason_root": self.reject_reason_root,
        })
    }

    pub fn intent_root(&self) -> String {
        domain_hash(
            "PRIVATE-PAYMASTER-INTENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivatePaymasterReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub pool_id: String,
    pub lane: PrivateFeeLane,
    pub sponsored_fee_units: u64,
    pub relayer_tip_units: u64,
    pub settled_height: u64,
    pub action_receipt_root: String,
    pub privacy_receipt_root: String,
    pub pq_attestation_root: String,
}

impl PrivatePaymasterReceipt {
    pub fn new(
        intent: &PrivateFeeIntent,
        quote: &PrivateFeeQuote,
        settled_height: u64,
        action_receipt_root: &str,
    ) -> PrivatePaymasterResult<Self> {
        let quote_id = intent
            .quote_id
            .clone()
            .ok_or_else(|| "private fee intent missing quote id".to_string())?;
        let pool_id = intent
            .pool_id
            .clone()
            .ok_or_else(|| "private fee intent missing pool id".to_string())?;
        if quote_id != quote.quote_id || pool_id != quote.pool_id {
            return Err("private paymaster quote does not match intent".to_string());
        }
        let payload = json!({
            "intent_id": intent.intent_id,
            "quote_id": quote.quote_id,
            "pool_id": quote.pool_id,
            "sponsored_fee_units": quote.sponsored_fee_units,
            "relayer_tip_units": quote.relayer_tip_units,
            "settled_height": settled_height,
            "action_receipt_root": action_receipt_root,
        });
        let receipt_id = domain_hash(
            "PRIVATE-PAYMASTER-RECEIPT-ID",
            &[HashPart::Json(&payload)],
            24,
        );
        Ok(Self {
            receipt_id,
            intent_id: intent.intent_id.clone(),
            quote_id,
            pool_id,
            lane: intent.lane,
            sponsored_fee_units: quote.sponsored_fee_units,
            relayer_tip_units: quote.relayer_tip_units,
            settled_height,
            action_receipt_root: action_receipt_root.to_string(),
            privacy_receipt_root: domain_hash(
                "PRIVATE-PAYMASTER-PRIVACY-RECEIPT",
                &[HashPart::Json(&payload)],
                32,
            ),
            pq_attestation_root: domain_hash(
                "PRIVATE-PAYMASTER-PQ-ATTESTATION",
                &[HashPart::Json(&payload)],
                32,
            ),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_paymaster_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_PAYMASTER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "pool_id": self.pool_id,
            "lane": self.lane.as_str(),
            "sponsored_fee_units": self.sponsored_fee_units,
            "relayer_tip_units": self.relayer_tip_units,
            "settled_height": self.settled_height,
            "action_receipt_root": self.action_receipt_root,
            "privacy_receipt_root": self.privacy_receipt_root,
            "pq_attestation_root": self.pq_attestation_root,
        })
    }

    pub fn receipt_root(&self) -> String {
        domain_hash(
            "PRIVATE-PAYMASTER-RECEIPT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivatePaymasterBatch {
    pub batch_id: String,
    pub height: u64,
    pub epoch: u64,
    pub status: PrivatePaymasterBatchStatus,
    pub intent_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub lane_fee_units: BTreeMap<PrivateFeeLane, u64>,
    pub intent_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub pq_batch_root: String,
    pub privacy_batch_root: String,
}

impl PrivatePaymasterBatch {
    pub fn new(
        height: u64,
        epoch: u64,
        intents: &[PrivateFeeIntent],
        receipts: &[PrivatePaymasterReceipt],
    ) -> Self {
        let intent_records = intents
            .iter()
            .map(PrivateFeeIntent::public_record)
            .collect::<Vec<_>>();
        let receipt_records = receipts
            .iter()
            .map(PrivatePaymasterReceipt::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = intents
            .iter()
            .map(|intent| json!({"intent_id": intent.intent_id, "nullifier": intent.nullifier}))
            .collect::<Vec<_>>();
        let intent_root = merkle_root("PRIVATE-PAYMASTER-BATCH-INTENT", &intent_records);
        let receipt_root = merkle_root("PRIVATE-PAYMASTER-BATCH-RECEIPT", &receipt_records);
        let nullifier_root = merkle_root("PRIVATE-PAYMASTER-BATCH-NULLIFIER", &nullifier_records);
        let mut lane_fee_units: BTreeMap<PrivateFeeLane, u64> = BTreeMap::new();
        for receipt in receipts {
            *lane_fee_units.entry(receipt.lane).or_default() += receipt.sponsored_fee_units;
        }
        let batch_payload = json!({
            "height": height,
            "epoch": epoch,
            "intent_root": intent_root,
            "receipt_root": receipt_root,
            "nullifier_root": nullifier_root,
            "receipt_count": receipts.len(),
        });
        let batch_id = domain_hash(
            "PRIVATE-PAYMASTER-BATCH-ID",
            &[HashPart::Json(&batch_payload)],
            24,
        );
        Self {
            batch_id,
            height,
            epoch,
            status: PrivatePaymasterBatchStatus::Sealed,
            intent_ids: intents
                .iter()
                .map(|intent| intent.intent_id.clone())
                .collect(),
            receipt_ids: receipts
                .iter()
                .map(|receipt| receipt.receipt_id.clone())
                .collect(),
            lane_fee_units,
            intent_root,
            receipt_root,
            nullifier_root,
            pq_batch_root: domain_hash(
                "PRIVATE-PAYMASTER-BATCH-PQ",
                &[HashPart::Json(&batch_payload)],
                32,
            ),
            privacy_batch_root: domain_hash(
                "PRIVATE-PAYMASTER-BATCH-PRIVACY",
                &[HashPart::Json(&batch_payload)],
                32,
            ),
        }
    }

    pub fn post(&mut self) {
        self.status = PrivatePaymasterBatchStatus::Posted;
    }

    pub fn finalize(&mut self) {
        self.status = PrivatePaymasterBatchStatus::Finalized;
    }

    pub fn public_record(&self) -> Value {
        let lane_fee_units = self
            .lane_fee_units
            .iter()
            .map(|(lane, units)| json!({"lane": lane.as_str(), "fee_units": units}))
            .collect::<Vec<_>>();
        json!({
            "kind": "private_paymaster_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_PAYMASTER_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "height": self.height,
            "epoch": self.epoch,
            "status": self.status.as_str(),
            "intent_ids": self.intent_ids,
            "receipt_ids": self.receipt_ids,
            "lane_fee_units": lane_fee_units,
            "intent_root": self.intent_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "pq_batch_root": self.pq_batch_root,
            "privacy_batch_root": self.privacy_batch_root,
        })
    }

    pub fn batch_root(&self) -> String {
        domain_hash(
            "PRIVATE-PAYMASTER-BATCH",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivatePaymasterRoots {
    pub pool_root: String,
    pub intent_root: String,
    pub quote_root: String,
    pub receipt_root: String,
    pub batch_root: String,
    pub nullifier_root: String,
    pub policy_root: String,
    pub state_root: String,
}

impl PrivatePaymasterRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_paymaster_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_PAYMASTER_PROTOCOL_VERSION,
            "pool_root": self.pool_root,
            "intent_root": self.intent_root,
            "quote_root": self.quote_root,
            "receipt_root": self.receipt_root,
            "batch_root": self.batch_root,
            "nullifier_root": self.nullifier_root,
            "policy_root": self.policy_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivatePaymasterState {
    pub config: PrivatePaymasterConfig,
    pub height: u64,
    pub pools: BTreeMap<String, PrivateSponsorPool>,
    pub intents: BTreeMap<String, PrivateFeeIntent>,
    pub quotes: BTreeMap<String, PrivateFeeQuote>,
    pub receipts: BTreeMap<String, PrivatePaymasterReceipt>,
    pub batches: BTreeMap<String, PrivatePaymasterBatch>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl PrivatePaymasterState {
    pub fn new(config: PrivatePaymasterConfig) -> Self {
        Self {
            config,
            height: 0,
            pools: BTreeMap::new(),
            intents: BTreeMap::new(),
            quotes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            batches: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> PrivatePaymasterResult<Self> {
        let mut state = Self::new(PrivatePaymasterConfig::devnet());
        let lanes = [
            PrivateFeeLane::WalletTransfer,
            PrivateFeeLane::MoneroBridge,
            PrivateFeeLane::DefiSwap,
            PrivateFeeLane::ContractCall,
            PrivateFeeLane::ProofJob,
            PrivateFeeLane::ExitLiquidity,
        ];
        for (index, lane) in lanes.into_iter().enumerate() {
            let pool = PrivateSponsorPool::new(
                &format!("sponsor-commitment-{index}"),
                "wxmr-devnet",
                lane,
                if index % 2 == 0 {
                    PrivateSponsorMode::ShieldedPool
                } else {
                    PrivateSponsorMode::Hybrid
                },
                256 + (index as u64 * 64),
                0,
            );
            state.insert_pool(pool)?;
        }
        for index in 0..12_u64 {
            let lane = lanes[(index as usize) % lanes.len()];
            let intent = PrivateFeeIntent::new(
                lane,
                &format!("caller-commitment-{index}"),
                &domain_hash(
                    "PRIVATE-PAYMASTER-DEVNET-ACTION",
                    &[HashPart::Int(index as i128), HashPart::Str(lane.as_str())],
                    32,
                ),
                &format!("devnet-nullifier-seed-{index}"),
                &format!("pq-key-commitment-{index}"),
                lane.default_fee_units(),
                index % 2,
                0,
                state.config.default_intent_ttl_blocks,
            );
            let intent_id = state.open_intent(intent)?;
            let quote_id = state.quote_intent(&intent_id)?;
            state.admit_intent(&intent_id, &quote_id)?;
            if index % 3 == 0 {
                let action_receipt_root = domain_hash(
                    "PRIVATE-PAYMASTER-DEVNET-ACTION-RECEIPT",
                    &[HashPart::Str(&intent_id), HashPart::Int(index as i128)],
                    32,
                );
                state.settle_intent(&intent_id, &quote_id, &action_receipt_root)?;
            }
        }
        let _ = state.build_batch("devnet-private-paymaster-bootstrap")?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        let epoch = if self.config.epoch_blocks == 0 {
            0
        } else {
            height / self.config.epoch_blocks
        };
        for pool in self.pools.values_mut() {
            pool.epoch = epoch;
        }
        self.expire_stale_intents();
    }

    pub fn insert_pool(&mut self, pool: PrivateSponsorPool) -> PrivatePaymasterResult<()> {
        if self.pools.contains_key(&pool.pool_id) {
            return Err(format!(
                "private sponsor pool already exists: {}",
                pool.pool_id
            ));
        }
        self.pools.insert(pool.pool_id.clone(), pool);
        Ok(())
    }

    pub fn open_intent(&mut self, intent: PrivateFeeIntent) -> PrivatePaymasterResult<String> {
        if self.spent_nullifiers.contains(&intent.nullifier) {
            return Err("private paymaster nullifier already spent".to_string());
        }
        if self
            .intents
            .values()
            .any(|known| known.nullifier == intent.nullifier)
        {
            return Err("private paymaster nullifier already open".to_string());
        }
        if intent.max_fee_units > self.config.max_fee_units_per_intent {
            return Err("private fee intent exceeds per-intent cap".to_string());
        }
        if intent.max_fee_units == 0 {
            return Err("private fee intent has zero max fee".to_string());
        }
        let intent_id = intent.intent_id.clone();
        self.intents.insert(intent_id.clone(), intent);
        Ok(intent_id)
    }

    pub fn quote_intent(&mut self, intent_id: &str) -> PrivatePaymasterResult<String> {
        let (lane, max_fee_units) = {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("private fee intent not found: {intent_id}"))?;
            if intent.status != PrivateFeeIntentStatus::Open {
                return Err("private fee intent is not open".to_string());
            }
            if intent.expired_at(self.height) {
                return Err("private fee intent expired before quote".to_string());
            }
            (intent.lane, intent.max_fee_units)
        };
        let pool_id = self
            .select_pool(lane, max_fee_units)
            .ok_or_else(|| "no private sponsor pool can cover intent".to_string())?;
        let quote = PrivateFeeQuote::new(
            &pool_id,
            lane,
            max_fee_units,
            lane.default_fee_units()
                .saturating_sub(max_fee_units)
                .min(1),
            self.height
                .saturating_add(self.config.default_intent_ttl_blocks),
            lane.privacy_floor().saturating_mul(100).min(10_000),
        );
        let quote_id = quote.quote_id.clone();
        self.quotes.insert(quote_id.clone(), quote.clone());
        if let Some(intent) = self.intents.get_mut(intent_id) {
            intent.quoted(&quote);
        }
        Ok(quote_id)
    }

    pub fn admit_intent(&mut self, intent_id: &str, quote_id: &str) -> PrivatePaymasterResult<()> {
        let quote = self
            .quotes
            .get(quote_id)
            .cloned()
            .ok_or_else(|| format!("private fee quote not found: {quote_id}"))?;
        if quote.expired_at(self.height) {
            return Err("private fee quote expired".to_string());
        }
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| format!("private fee intent not found: {intent_id}"))?;
        if intent.quote_id.as_deref() != Some(quote_id) {
            return Err("private fee quote is not bound to intent".to_string());
        }
        if intent.status != PrivateFeeIntentStatus::Quoted {
            return Err("private fee intent is not quoted".to_string());
        }
        let pool = self
            .pools
            .get_mut(&quote.pool_id)
            .ok_or_else(|| format!("private sponsor pool not found: {}", quote.pool_id))?;
        pool.commit(quote.sponsored_fee_units)?;
        intent.admit();
        Ok(())
    }

    pub fn settle_intent(
        &mut self,
        intent_id: &str,
        quote_id: &str,
        action_receipt_root: &str,
    ) -> PrivatePaymasterResult<String> {
        let quote = self
            .quotes
            .get(quote_id)
            .cloned()
            .ok_or_else(|| format!("private fee quote not found: {quote_id}"))?;
        let mut intent = self
            .intents
            .get(intent_id)
            .cloned()
            .ok_or_else(|| format!("private fee intent not found: {intent_id}"))?;
        if intent.status != PrivateFeeIntentStatus::Admitted {
            return Err("private fee intent is not admitted".to_string());
        }
        if self.spent_nullifiers.contains(&intent.nullifier) {
            return Err("private fee intent nullifier already spent".to_string());
        }
        let receipt =
            PrivatePaymasterReceipt::new(&intent, &quote, self.height, action_receipt_root)?;
        let receipt_id = receipt.receipt_id.clone();
        let pool = self
            .pools
            .get_mut(&quote.pool_id)
            .ok_or_else(|| format!("private sponsor pool not found: {}", quote.pool_id))?;
        pool.settle(quote.sponsored_fee_units);
        self.spent_nullifiers.insert(intent.nullifier.clone());
        intent.status = PrivateFeeIntentStatus::Settled;
        self.intents.insert(intent_id.to_string(), intent);
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn build_batch(&mut self, label: &str) -> PrivatePaymasterResult<Option<String>> {
        let mut selected_intents = Vec::new();
        let mut selected_receipts = Vec::new();
        for receipt in self.receipts.values() {
            if selected_receipts.len() >= self.config.max_batch_items {
                break;
            }
            if self
                .batches
                .values()
                .any(|batch| batch.receipt_ids.contains(&receipt.receipt_id))
            {
                continue;
            }
            if let Some(intent) = self.intents.get(&receipt.intent_id) {
                selected_intents.push(intent.clone());
                selected_receipts.push(receipt.clone());
            }
        }
        if selected_receipts.is_empty() {
            return Ok(None);
        }
        let epoch = if self.config.epoch_blocks == 0 {
            0
        } else {
            self.height / self.config.epoch_blocks
        };
        let mut batch =
            PrivatePaymasterBatch::new(self.height, epoch, &selected_intents, &selected_receipts);
        let label_root = domain_hash(
            "PRIVATE-PAYMASTER-BATCH-LABEL",
            &[HashPart::Str(label), HashPart::Str(&batch.batch_id)],
            32,
        );
        batch.pq_batch_root = domain_hash(
            "PRIVATE-PAYMASTER-BATCH-PQ-LABELED",
            &[
                HashPart::Str(&batch.pq_batch_root),
                HashPart::Str(&label_root),
            ],
            32,
        );
        batch.post();
        let batch_id = batch.batch_id.clone();
        for intent_id in &batch.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.settle(&batch_id);
            }
        }
        self.batches.insert(batch_id.clone(), batch);
        Ok(Some(batch_id))
    }

    pub fn expire_stale_intents(&mut self) {
        let height = self.height;
        let mut releases = Vec::new();
        for intent in self.intents.values_mut() {
            if intent.expired_at(height) {
                if let (Some(pool_id), Some(quote_id)) =
                    (intent.pool_id.clone(), intent.quote_id.clone())
                {
                    if let Some(quote) = self.quotes.get(&quote_id) {
                        releases.push((pool_id, quote.sponsored_fee_units));
                    }
                }
                intent.expire(height);
            }
        }
        for (pool_id, fee_units) in releases {
            if let Some(pool) = self.pools.get_mut(&pool_id) {
                pool.release(fee_units);
            }
        }
    }

    pub fn select_pool(&self, lane: PrivateFeeLane, fee_units: u64) -> Option<String> {
        self.pools
            .values()
            .filter(|pool| pool.can_sponsor(lane, fee_units))
            .max_by_key(|pool| {
                (
                    pool.reserve_ratio_bps(),
                    pool.available_units(),
                    std::cmp::Reverse(pool.pool_id.clone()),
                )
            })
            .map(|pool| pool.pool_id.clone())
    }

    pub fn pending_intent_count(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| {
                matches!(
                    intent.status,
                    PrivateFeeIntentStatus::Open
                        | PrivateFeeIntentStatus::Quoted
                        | PrivateFeeIntentStatus::Admitted
                )
            })
            .count() as u64
    }

    pub fn settled_intent_count(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| intent.status == PrivateFeeIntentStatus::Settled)
            .count() as u64
    }

    pub fn total_available_units(&self) -> u64 {
        self.pools
            .values()
            .map(PrivateSponsorPool::available_units)
            .sum()
    }

    pub fn lane_available_units(&self) -> BTreeMap<PrivateFeeLane, u64> {
        let mut lanes = BTreeMap::new();
        for pool in self.pools.values() {
            *lanes.entry(pool.lane).or_default() += pool.available_units();
        }
        lanes
    }

    pub fn roots(&self) -> PrivatePaymasterRoots {
        let pool_records = self
            .pools
            .values()
            .map(PrivateSponsorPool::public_record)
            .collect::<Vec<_>>();
        let intent_records = self
            .intents
            .values()
            .map(PrivateFeeIntent::public_record)
            .collect::<Vec<_>>();
        let quote_records = self
            .quotes
            .values()
            .map(PrivateFeeQuote::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(PrivatePaymasterReceipt::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(PrivatePaymasterBatch::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .spent_nullifiers
            .iter()
            .map(|nullifier| json!({"nullifier": nullifier}))
            .collect::<Vec<_>>();
        let pool_root = merkle_root("PRIVATE-PAYMASTER-POOL", &pool_records);
        let intent_root = merkle_root("PRIVATE-PAYMASTER-INTENT", &intent_records);
        let quote_root = merkle_root("PRIVATE-PAYMASTER-QUOTE", &quote_records);
        let receipt_root = merkle_root("PRIVATE-PAYMASTER-RECEIPT", &receipt_records);
        let batch_root = merkle_root("PRIVATE-PAYMASTER-BATCH", &batch_records);
        let nullifier_root = merkle_root("PRIVATE-PAYMASTER-NULLIFIER", &nullifier_records);
        let policy_root = self.config.config_root();
        let state_record = json!({
            "pool_root": pool_root,
            "intent_root": intent_root,
            "quote_root": quote_root,
            "receipt_root": receipt_root,
            "batch_root": batch_root,
            "nullifier_root": nullifier_root,
            "policy_root": policy_root,
            "height": self.height,
        });
        let state_root = private_paymaster_state_root_from_record(&state_record);
        PrivatePaymasterRoots {
            pool_root,
            intent_root,
            quote_root,
            receipt_root,
            batch_root,
            nullifier_root,
            policy_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        private_paymaster_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(map) = &mut record {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        let lane_available_units = self
            .lane_available_units()
            .into_iter()
            .map(|(lane, units)| json!({"lane": lane.as_str(), "available_units": units}))
            .collect::<Vec<_>>();
        json!({
            "kind": "private_paymaster_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_PAYMASTER_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "pool_count": self.pools.len() as u64,
            "intent_count": self.intents.len() as u64,
            "quote_count": self.quotes.len() as u64,
            "receipt_count": self.receipts.len() as u64,
            "batch_count": self.batches.len() as u64,
            "spent_nullifier_count": self.spent_nullifiers.len() as u64,
            "pending_intent_count": self.pending_intent_count(),
            "settled_intent_count": self.settled_intent_count(),
            "total_available_units": self.total_available_units(),
            "lane_available_units": lane_available_units,
            "pool_root": self.roots().pool_root,
            "intent_root": self.roots().intent_root,
            "quote_root": self.roots().quote_root,
            "receipt_root": self.roots().receipt_root,
            "batch_root": self.roots().batch_root,
            "nullifier_root": self.roots().nullifier_root,
        })
    }

    pub fn validate(&self) -> PrivatePaymasterResult<()> {
        for intent in self.intents.values() {
            if intent.max_fee_units == 0 {
                return Err(format!(
                    "private fee intent has zero fee: {}",
                    intent.intent_id
                ));
            }
            if intent.max_fee_units > self.config.max_fee_units_per_intent {
                return Err(format!("private fee intent over cap: {}", intent.intent_id));
            }
            if let Some(quote_id) = &intent.quote_id {
                let quote = self
                    .quotes
                    .get(quote_id)
                    .ok_or_else(|| format!("intent references missing quote: {quote_id}"))?;
                if quote.lane != intent.lane {
                    return Err(format!(
                        "quote lane mismatch for intent {}",
                        intent.intent_id
                    ));
                }
            }
        }
        for receipt in self.receipts.values() {
            if !self.intents.contains_key(&receipt.intent_id) {
                return Err(format!(
                    "receipt references missing intent: {}",
                    receipt.receipt_id
                ));
            }
            if !self.quotes.contains_key(&receipt.quote_id) {
                return Err(format!(
                    "receipt references missing quote: {}",
                    receipt.receipt_id
                ));
            }
            if !self.pools.contains_key(&receipt.pool_id) {
                return Err(format!(
                    "receipt references missing pool: {}",
                    receipt.receipt_id
                ));
            }
        }
        for pool in self.pools.values() {
            if pool.available_units() < self.config.min_pool_reserve_units / 8 && !pool.paused {
                return Err(format!(
                    "private sponsor pool reserve too low: {}",
                    pool.pool_id
                ));
            }
        }
        Ok(())
    }
}

pub fn private_paymaster_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-PAYMASTER-STATE",
        &[
            HashPart::Str(PRIVATE_PAYMASTER_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
