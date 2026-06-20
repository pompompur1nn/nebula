use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateConfidentialStableSwapPoolResult<T> = Result<T, String>;

pub const PRIVATE_CONFIDENTIAL_STABLE_SWAP_POOL_PROTOCOL_VERSION: &str =
    "nebula-private-confidential-stable-swap-pool-v1";

const SCHEMA_VERSION: &str = "private-confidential-stable-swap-pool-state-v1";
const HASH_SUITE: &str = "SHAKE256-domain-separated";
const ZK_INVARIANT_SCHEME: &str = "zk-stableswap-invariant-range-attestation-shake256-v1";
const CONFIDENTIAL_AMOUNT_SCHEME: &str = "pedersen-note-range-commitment-shake256-v1";
const PQ_GOVERNANCE_SCHEME: &str = "ml-dsa-87+slh-dsa-shake-256f-pool-governance-v1";
const RECEIPT_SCHEME: &str = "recursive-private-settlement-receipt-v1";
const DEFAULT_HEIGHT: u64 = 4_096;
const DEFAULT_EPOCH_BLOCKS: u64 = 120;
const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 48;
const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
const DEFAULT_FEE_BPS: u64 = 4;
const DEFAULT_ADMIN_FEE_BPS: u64 = 1;
const DEFAULT_SPONSOR_FEE_BPS: u64 = 3;
const DEFAULT_AMP_FACTOR: u64 = 180;
const DEFAULT_MAX_DEPEG_BPS: u64 = 150;
const DEFAULT_MAX_BALANCE_SKEW_BPS: u64 = 2_500;
const DEFAULT_SETTLEMENT_BATCH_LIMIT: u64 = 512;
const MAX_BPS: u64 = 10_000;
const MAX_POOL_ASSETS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub confidential_amount_scheme: String,
    pub zk_invariant_scheme: String,
    pub pq_governance_scheme: String,
    pub receipt_scheme: String,
    pub epoch_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub default_fee_bps: u64,
    pub default_admin_fee_bps: u64,
    pub default_sponsor_fee_bps: u64,
    pub default_amp_factor: u64,
    pub max_depeg_bps: u64,
    pub max_balance_skew_bps: u64,
    pub settlement_batch_limit: u64,
}

impl Config {
    fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_CONFIDENTIAL_STABLE_SWAP_POOL_PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            confidential_amount_scheme: CONFIDENTIAL_AMOUNT_SCHEME.to_string(),
            zk_invariant_scheme: ZK_INVARIANT_SCHEME.to_string(),
            pq_governance_scheme: PQ_GOVERNANCE_SCHEME.to_string(),
            receipt_scheme: RECEIPT_SCHEME.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            default_fee_bps: DEFAULT_FEE_BPS,
            default_admin_fee_bps: DEFAULT_ADMIN_FEE_BPS,
            default_sponsor_fee_bps: DEFAULT_SPONSOR_FEE_BPS,
            default_amp_factor: DEFAULT_AMP_FACTOR,
            max_depeg_bps: DEFAULT_MAX_DEPEG_BPS,
            max_balance_skew_bps: DEFAULT_MAX_BALANCE_SKEW_BPS,
            settlement_batch_limit: DEFAULT_SETTLEMENT_BATCH_LIMIT,
        }
    }

    fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("private confidential stable-swap config chain id mismatch".to_string());
        }
        if self.protocol_version != PRIVATE_CONFIDENTIAL_STABLE_SWAP_POOL_PROTOCOL_VERSION {
            return Err("private confidential stable-swap protocol version mismatch".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("private confidential stable-swap schema version mismatch".to_string());
        }
        if self.hash_suite.is_empty()
            || self.confidential_amount_scheme.is_empty()
            || self.zk_invariant_scheme.is_empty()
            || self.pq_governance_scheme.is_empty()
            || self.receipt_scheme.is_empty()
        {
            return Err(
                "private confidential stable-swap suite labels must be populated".to_string(),
            );
        }
        if self.epoch_blocks == 0
            || self.challenge_window_blocks == 0
            || self.min_privacy_set_size == 0
            || self.default_amp_factor == 0
            || self.settlement_batch_limit == 0
        {
            return Err(
                "private confidential stable-swap numeric config values must be positive"
                    .to_string(),
            );
        }
        if self.min_pq_security_bits < 192 {
            return Err("private confidential stable-swap pq security floor too low".to_string());
        }
        if self.default_fee_bps > MAX_BPS
            || self.default_admin_fee_bps > MAX_BPS
            || self.default_sponsor_fee_bps > MAX_BPS
            || self.max_depeg_bps > MAX_BPS
            || self.max_balance_skew_bps > MAX_BPS
        {
            return Err("private confidential stable-swap bps config exceeds max".to_string());
        }
        Ok(())
    }

    fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "confidential_amount_scheme": self.confidential_amount_scheme,
            "zk_invariant_scheme": self.zk_invariant_scheme,
            "pq_governance_scheme": self.pq_governance_scheme,
            "receipt_scheme": self.receipt_scheme,
            "epoch_blocks": self.epoch_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "default_fee_bps": self.default_fee_bps,
            "default_admin_fee_bps": self.default_admin_fee_bps,
            "default_sponsor_fee_bps": self.default_sponsor_fee_bps,
            "default_amp_factor": self.default_amp_factor,
            "max_depeg_bps": self.max_depeg_bps,
            "max_balance_skew_bps": self.max_balance_skew_bps,
            "settlement_batch_limit": self.settlement_batch_limit,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub asset_root: String,
    pub pool_root: String,
    pub position_root: String,
    pub swap_root: String,
    pub sponsor_credit_root: String,
    pub invariant_attestation_root: String,
    pub governance_root: String,
    pub settlement_receipt_root: String,
    pub challenge_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub assets: u64,
    pub pools: u64,
    pub lp_positions: u64,
    pub swaps: u64,
    pub sponsor_credits: u64,
    pub invariant_attestations: u64,
    pub governance_actions: u64,
    pub settlement_receipts: u64,
    pub challenges: u64,
    pub open_challenges: u64,
    pub settled_challenges: u64,
    pub spent_nullifiers: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PoolStatus {
    Bootstrapping,
    Active,
    Paused,
    WindDown,
}

impl PoolStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrapping => "bootstrapping",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::WindDown => "wind_down",
        }
    }

    fn allows_swaps(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PositionStatus {
    Opening,
    Active,
    Exiting,
    Closed,
}

impl PositionStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Active => "active",
            Self::Exiting => "exiting",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SwapStatus {
    Committed,
    Proved,
    Settled,
    Challenged,
    Expired,
}

impl SwapStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChallengeStatus {
    Open,
    Answered,
    Upheld,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Answered => "answered",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::Answered)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GovernanceActionKind {
    FeeChange,
    AmpChange,
    PausePool,
    ResumePool,
    SponsorBudgetChange,
    CircuitUpgrade,
}

impl GovernanceActionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::FeeChange => "fee_change",
            Self::AmpChange => "amp_change",
            Self::PausePool => "pause_pool",
            Self::ResumePool => "resume_pool",
            Self::SponsorBudgetChange => "sponsor_budget_change",
            Self::CircuitUpgrade => "circuit_upgrade",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ShieldedAsset {
    asset_id: String,
    symbol_commitment: String,
    decimals: u8,
    peg_reference_commitment: String,
    oracle_committee_root: String,
    risk_weight_bps: u64,
    enabled: bool,
}

impl ShieldedAsset {
    fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "symbol_commitment": self.symbol_commitment,
            "decimals": self.decimals,
            "peg_reference_commitment": self.peg_reference_commitment,
            "oracle_committee_root": self.oracle_committee_root,
            "risk_weight_bps": self.risk_weight_bps,
            "enabled": self.enabled,
        })
    }

    fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        if self.asset_id.is_empty()
            || self.symbol_commitment.is_empty()
            || self.peg_reference_commitment.is_empty()
            || self.oracle_committee_root.is_empty()
        {
            return Err("shielded stable-swap asset identifiers must be populated".to_string());
        }
        if self.risk_weight_bps > MAX_BPS {
            return Err("shielded stable-swap asset risk weight exceeds max bps".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ShieldedPool {
    pool_id: String,
    asset_ids: Vec<String>,
    reserve_commitments: BTreeMap<String, String>,
    reserve_note_roots: BTreeMap<String, String>,
    virtual_balance_commitments: BTreeMap<String, String>,
    amp_factor: u64,
    fee_bps: u64,
    admin_fee_bps: u64,
    sponsor_fee_bps: u64,
    lp_token_commitment: String,
    governance_key_root: String,
    circuit_root: String,
    invariant_root: String,
    status: PoolStatus,
    created_height: u64,
}

impl ShieldedPool {
    fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "asset_ids": self.asset_ids,
            "reserve_commitments": self.reserve_commitments,
            "reserve_note_roots": self.reserve_note_roots,
            "virtual_balance_commitments": self.virtual_balance_commitments,
            "amp_factor": self.amp_factor,
            "fee_bps": self.fee_bps,
            "admin_fee_bps": self.admin_fee_bps,
            "sponsor_fee_bps": self.sponsor_fee_bps,
            "lp_token_commitment": self.lp_token_commitment,
            "governance_key_root": self.governance_key_root,
            "circuit_root": self.circuit_root,
            "invariant_root": self.invariant_root,
            "status": self.status.as_str(),
            "created_height": self.created_height,
        })
    }

    fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        if self.pool_id.is_empty()
            || self.lp_token_commitment.is_empty()
            || self.governance_key_root.is_empty()
            || self.circuit_root.is_empty()
            || self.invariant_root.is_empty()
        {
            return Err("shielded stable-swap pool identifiers must be populated".to_string());
        }
        if self.asset_ids.len() < 2 || self.asset_ids.len() > MAX_POOL_ASSETS {
            return Err("shielded stable-swap pool asset count out of range".to_string());
        }
        let unique_assets = self.asset_ids.iter().collect::<BTreeSet<_>>();
        if unique_assets.len() != self.asset_ids.len() {
            return Err("shielded stable-swap pool assets must be unique".to_string());
        }
        if self.amp_factor == 0 {
            return Err("shielded stable-swap pool amp factor must be positive".to_string());
        }
        if self.fee_bps > MAX_BPS || self.admin_fee_bps > MAX_BPS || self.sponsor_fee_bps > MAX_BPS
        {
            return Err("shielded stable-swap pool fee bps exceeds max".to_string());
        }
        for asset_id in &self.asset_ids {
            if !self.reserve_commitments.contains_key(asset_id)
                || !self.reserve_note_roots.contains_key(asset_id)
                || !self.virtual_balance_commitments.contains_key(asset_id)
            {
                return Err(
                    "shielded stable-swap pool reserve maps must cover every asset".to_string(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ConfidentialLpPosition {
    position_id: String,
    pool_id: String,
    owner_commitment: String,
    lp_amount_commitment: String,
    share_commitment: String,
    entry_invariant_commitment: String,
    deposit_note_root: String,
    withdrawal_nullifier_root: String,
    view_tag_root: String,
    opened_height: u64,
    unlock_height: u64,
    status: PositionStatus,
}

impl ConfidentialLpPosition {
    fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "pool_id": self.pool_id,
            "owner_commitment": self.owner_commitment,
            "lp_amount_commitment": self.lp_amount_commitment,
            "share_commitment": self.share_commitment,
            "entry_invariant_commitment": self.entry_invariant_commitment,
            "deposit_note_root": self.deposit_note_root,
            "withdrawal_nullifier_root": self.withdrawal_nullifier_root,
            "view_tag_root": self.view_tag_root,
            "opened_height": self.opened_height,
            "unlock_height": self.unlock_height,
            "status": self.status.as_str(),
        })
    }

    fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        if self.position_id.is_empty()
            || self.pool_id.is_empty()
            || self.owner_commitment.is_empty()
            || self.lp_amount_commitment.is_empty()
            || self.share_commitment.is_empty()
            || self.entry_invariant_commitment.is_empty()
            || self.deposit_note_root.is_empty()
            || self.withdrawal_nullifier_root.is_empty()
            || self.view_tag_root.is_empty()
        {
            return Err("confidential lp position identifiers must be populated".to_string());
        }
        if self.unlock_height < self.opened_height {
            return Err("confidential lp position unlock height precedes open height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateSwapIntent {
    swap_id: String,
    pool_id: String,
    input_asset_id: String,
    output_asset_id: String,
    trader_commitment: String,
    amount_in_commitment: String,
    min_amount_out_commitment: String,
    fee_commitment: String,
    sponsor_credit_id: String,
    input_nullifier_root: String,
    output_note_root: String,
    encrypted_witness_root: String,
    status: SwapStatus,
    committed_height: u64,
    expiry_height: u64,
}

impl PrivateSwapIntent {
    fn public_record(&self) -> Value {
        json!({
            "swap_id": self.swap_id,
            "pool_id": self.pool_id,
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "trader_commitment": self.trader_commitment,
            "amount_in_commitment": self.amount_in_commitment,
            "min_amount_out_commitment": self.min_amount_out_commitment,
            "fee_commitment": self.fee_commitment,
            "sponsor_credit_id": self.sponsor_credit_id,
            "input_nullifier_root": self.input_nullifier_root,
            "output_note_root": self.output_note_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "status": self.status.as_str(),
            "committed_height": self.committed_height,
            "expiry_height": self.expiry_height,
        })
    }

    fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        if self.swap_id.is_empty()
            || self.pool_id.is_empty()
            || self.input_asset_id.is_empty()
            || self.output_asset_id.is_empty()
            || self.trader_commitment.is_empty()
            || self.amount_in_commitment.is_empty()
            || self.min_amount_out_commitment.is_empty()
            || self.fee_commitment.is_empty()
            || self.input_nullifier_root.is_empty()
            || self.output_note_root.is_empty()
            || self.encrypted_witness_root.is_empty()
        {
            return Err("private stable-swap intent identifiers must be populated".to_string());
        }
        if self.input_asset_id == self.output_asset_id {
            return Err("private stable-swap intent must exchange different assets".to_string());
        }
        if self.expiry_height <= self.committed_height {
            return Err("private stable-swap intent expiry must follow commit height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SponsorCredit {
    credit_id: String,
    sponsor_commitment: String,
    pool_id: String,
    credit_asset_id: String,
    budget_commitment: String,
    spent_commitment: String,
    eligible_trader_root: String,
    max_fee_bps: u64,
    minted_height: u64,
    expiry_height: u64,
    revoked: bool,
}

impl SponsorCredit {
    fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "sponsor_commitment": self.sponsor_commitment,
            "pool_id": self.pool_id,
            "credit_asset_id": self.credit_asset_id,
            "budget_commitment": self.budget_commitment,
            "spent_commitment": self.spent_commitment,
            "eligible_trader_root": self.eligible_trader_root,
            "max_fee_bps": self.max_fee_bps,
            "minted_height": self.minted_height,
            "expiry_height": self.expiry_height,
            "revoked": self.revoked,
        })
    }

    fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        if self.credit_id.is_empty()
            || self.sponsor_commitment.is_empty()
            || self.pool_id.is_empty()
            || self.credit_asset_id.is_empty()
            || self.budget_commitment.is_empty()
            || self.spent_commitment.is_empty()
            || self.eligible_trader_root.is_empty()
        {
            return Err(
                "private stable-swap sponsor credit identifiers must be populated".to_string(),
            );
        }
        if self.max_fee_bps > MAX_BPS {
            return Err("private stable-swap sponsor max fee exceeds max bps".to_string());
        }
        if self.expiry_height <= self.minted_height {
            return Err(
                "private stable-swap sponsor credit expiry must follow mint height".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ZkInvariantAttestation {
    attestation_id: String,
    pool_id: String,
    pre_state_root: String,
    post_state_root: String,
    invariant_commitment: String,
    reserve_delta_root: String,
    fee_delta_root: String,
    proof_public_input_root: String,
    recursive_proof_root: String,
    verifier_key_root: String,
    prover_commitment: String,
    attested_height: u64,
}

impl ZkInvariantAttestation {
    fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "pool_id": self.pool_id,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "invariant_commitment": self.invariant_commitment,
            "reserve_delta_root": self.reserve_delta_root,
            "fee_delta_root": self.fee_delta_root,
            "proof_public_input_root": self.proof_public_input_root,
            "recursive_proof_root": self.recursive_proof_root,
            "verifier_key_root": self.verifier_key_root,
            "prover_commitment": self.prover_commitment,
            "attested_height": self.attested_height,
        })
    }

    fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        if self.attestation_id.is_empty()
            || self.pool_id.is_empty()
            || self.pre_state_root.is_empty()
            || self.post_state_root.is_empty()
            || self.invariant_commitment.is_empty()
            || self.reserve_delta_root.is_empty()
            || self.fee_delta_root.is_empty()
            || self.proof_public_input_root.is_empty()
            || self.recursive_proof_root.is_empty()
            || self.verifier_key_root.is_empty()
            || self.prover_commitment.is_empty()
        {
            return Err(
                "private stable-swap invariant attestation identifiers must be populated"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PqGovernanceAction {
    action_id: String,
    pool_id: String,
    action_kind: GovernanceActionKind,
    proposal_root: String,
    quorum_root: String,
    pq_signature_root: String,
    signer_set_root: String,
    execution_payload_root: String,
    effective_height: u64,
    expires_height: u64,
    executed: bool,
}

impl PqGovernanceAction {
    fn public_record(&self) -> Value {
        json!({
            "action_id": self.action_id,
            "pool_id": self.pool_id,
            "action_kind": self.action_kind.as_str(),
            "proposal_root": self.proposal_root,
            "quorum_root": self.quorum_root,
            "pq_signature_root": self.pq_signature_root,
            "signer_set_root": self.signer_set_root,
            "execution_payload_root": self.execution_payload_root,
            "effective_height": self.effective_height,
            "expires_height": self.expires_height,
            "executed": self.executed,
        })
    }

    fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        if self.action_id.is_empty()
            || self.pool_id.is_empty()
            || self.proposal_root.is_empty()
            || self.quorum_root.is_empty()
            || self.pq_signature_root.is_empty()
            || self.signer_set_root.is_empty()
            || self.execution_payload_root.is_empty()
        {
            return Err("pq stable-swap governance identifiers must be populated".to_string());
        }
        if self.expires_height <= self.effective_height {
            return Err(
                "pq stable-swap governance expiry must follow effective height".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SettlementReceipt {
    receipt_id: String,
    pool_id: String,
    batch_id: String,
    swap_root: String,
    lp_delta_root: String,
    sponsor_credit_root: String,
    nullifier_root: String,
    output_note_root: String,
    invariant_attestation_id: String,
    sequencer_commitment: String,
    settlement_height: u64,
    challenge_deadline_height: u64,
}

impl SettlementReceipt {
    fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "pool_id": self.pool_id,
            "batch_id": self.batch_id,
            "swap_root": self.swap_root,
            "lp_delta_root": self.lp_delta_root,
            "sponsor_credit_root": self.sponsor_credit_root,
            "nullifier_root": self.nullifier_root,
            "output_note_root": self.output_note_root,
            "invariant_attestation_id": self.invariant_attestation_id,
            "sequencer_commitment": self.sequencer_commitment,
            "settlement_height": self.settlement_height,
            "challenge_deadline_height": self.challenge_deadline_height,
        })
    }

    fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        if self.receipt_id.is_empty()
            || self.pool_id.is_empty()
            || self.batch_id.is_empty()
            || self.swap_root.is_empty()
            || self.lp_delta_root.is_empty()
            || self.sponsor_credit_root.is_empty()
            || self.nullifier_root.is_empty()
            || self.output_note_root.is_empty()
            || self.invariant_attestation_id.is_empty()
            || self.sequencer_commitment.is_empty()
        {
            return Err(
                "private stable-swap settlement receipt identifiers must be populated".to_string(),
            );
        }
        if self.challenge_deadline_height <= self.settlement_height {
            return Err(
                "private stable-swap settlement challenge deadline must follow settlement"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ChallengeWindow {
    challenge_id: String,
    subject_id: String,
    subject_root: String,
    challenger_commitment: String,
    evidence_root: String,
    bond_commitment: String,
    response_root: String,
    opened_height: u64,
    deadline_height: u64,
    status: ChallengeStatus,
}

impl ChallengeWindow {
    fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "bond_commitment": self.bond_commitment,
            "response_root": self.response_root,
            "opened_height": self.opened_height,
            "deadline_height": self.deadline_height,
            "status": self.status.as_str(),
        })
    }

    fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        if self.challenge_id.is_empty()
            || self.subject_id.is_empty()
            || self.subject_root.is_empty()
            || self.challenger_commitment.is_empty()
            || self.evidence_root.is_empty()
            || self.bond_commitment.is_empty()
            || self.response_root.is_empty()
        {
            return Err("private stable-swap challenge identifiers must be populated".to_string());
        }
        if self.deadline_height <= self.opened_height {
            return Err(
                "private stable-swap challenge deadline must follow open height".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ConfidentialRiskEnvelope {
    envelope_id: String,
    pool_id: String,
    depeg_guard_root: String,
    balance_skew_root: String,
    liquidity_depth_root: String,
    oracle_freshness_root: String,
    volatility_commitment: String,
    max_depeg_bps: u64,
    max_balance_skew_bps: u64,
    measured_height: u64,
}

impl ConfidentialRiskEnvelope {
    fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "pool_id": self.pool_id,
            "depeg_guard_root": self.depeg_guard_root,
            "balance_skew_root": self.balance_skew_root,
            "liquidity_depth_root": self.liquidity_depth_root,
            "oracle_freshness_root": self.oracle_freshness_root,
            "volatility_commitment": self.volatility_commitment,
            "max_depeg_bps": self.max_depeg_bps,
            "max_balance_skew_bps": self.max_balance_skew_bps,
            "measured_height": self.measured_height,
        })
    }

    fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        if self.envelope_id.is_empty()
            || self.pool_id.is_empty()
            || self.depeg_guard_root.is_empty()
            || self.balance_skew_root.is_empty()
            || self.liquidity_depth_root.is_empty()
            || self.oracle_freshness_root.is_empty()
            || self.volatility_commitment.is_empty()
        {
            return Err(
                "private stable-swap risk envelope identifiers must be populated".to_string(),
            );
        }
        if self.max_depeg_bps > MAX_BPS || self.max_balance_skew_bps > MAX_BPS {
            return Err("private stable-swap risk envelope bps exceeds max".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateRoutingLane {
    lane_id: String,
    pool_id: String,
    source_asset_id: String,
    target_asset_id: String,
    solver_set_root: String,
    latency_commitment: String,
    fee_quote_root: String,
    privacy_budget_root: String,
    priority_score: u64,
    enabled: bool,
}

impl PrivateRoutingLane {
    fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "pool_id": self.pool_id,
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "solver_set_root": self.solver_set_root,
            "latency_commitment": self.latency_commitment,
            "fee_quote_root": self.fee_quote_root,
            "privacy_budget_root": self.privacy_budget_root,
            "priority_score": self.priority_score,
            "enabled": self.enabled,
        })
    }

    fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        if self.lane_id.is_empty()
            || self.pool_id.is_empty()
            || self.source_asset_id.is_empty()
            || self.target_asset_id.is_empty()
            || self.solver_set_root.is_empty()
            || self.latency_commitment.is_empty()
            || self.fee_quote_root.is_empty()
            || self.privacy_budget_root.is_empty()
        {
            return Err(
                "private stable-swap routing lane identifiers must be populated".to_string(),
            );
        }
        if self.source_asset_id == self.target_asset_id {
            return Err(
                "private stable-swap routing lane must connect different assets".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ProofBatchPolicy {
    policy_id: String,
    pool_id: String,
    aggregation_circuit_root: String,
    membership_circuit_root: String,
    range_circuit_root: String,
    settlement_circuit_root: String,
    max_batch_size: u64,
    target_proof_millis: u64,
    recursive_depth: u64,
    enabled: bool,
}

impl ProofBatchPolicy {
    fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "pool_id": self.pool_id,
            "aggregation_circuit_root": self.aggregation_circuit_root,
            "membership_circuit_root": self.membership_circuit_root,
            "range_circuit_root": self.range_circuit_root,
            "settlement_circuit_root": self.settlement_circuit_root,
            "max_batch_size": self.max_batch_size,
            "target_proof_millis": self.target_proof_millis,
            "recursive_depth": self.recursive_depth,
            "enabled": self.enabled,
        })
    }

    fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        if self.policy_id.is_empty()
            || self.pool_id.is_empty()
            || self.aggregation_circuit_root.is_empty()
            || self.membership_circuit_root.is_empty()
            || self.range_circuit_root.is_empty()
            || self.settlement_circuit_root.is_empty()
        {
            return Err(
                "private stable-swap proof batch policy identifiers must be populated".to_string(),
            );
        }
        if self.max_batch_size == 0 || self.target_proof_millis == 0 || self.recursive_depth == 0 {
            return Err(
                "private stable-swap proof batch policy numeric values must be positive"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SelectiveDisclosureAudit {
    audit_id: String,
    pool_id: String,
    auditor_commitment: String,
    disclosure_key_root: String,
    redacted_record_root: String,
    scope_root: String,
    expiry_height: u64,
    issued_height: u64,
    revocation_root: String,
}

impl SelectiveDisclosureAudit {
    fn public_record(&self) -> Value {
        json!({
            "audit_id": self.audit_id,
            "pool_id": self.pool_id,
            "auditor_commitment": self.auditor_commitment,
            "disclosure_key_root": self.disclosure_key_root,
            "redacted_record_root": self.redacted_record_root,
            "scope_root": self.scope_root,
            "expiry_height": self.expiry_height,
            "issued_height": self.issued_height,
            "revocation_root": self.revocation_root,
        })
    }

    fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        if self.audit_id.is_empty()
            || self.pool_id.is_empty()
            || self.auditor_commitment.is_empty()
            || self.disclosure_key_root.is_empty()
            || self.redacted_record_root.is_empty()
            || self.scope_root.is_empty()
            || self.revocation_root.is_empty()
        {
            return Err(
                "private stable-swap selective disclosure audit identifiers must be populated"
                    .to_string(),
            );
        }
        if self.expiry_height <= self.issued_height {
            return Err(
                "private stable-swap selective disclosure audit expiry must follow issue height"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    assets: BTreeMap<String, ShieldedAsset>,
    pools: BTreeMap<String, ShieldedPool>,
    lp_positions: BTreeMap<String, ConfidentialLpPosition>,
    swaps: BTreeMap<String, PrivateSwapIntent>,
    sponsor_credits: BTreeMap<String, SponsorCredit>,
    invariant_attestations: BTreeMap<String, ZkInvariantAttestation>,
    governance_actions: BTreeMap<String, PqGovernanceAction>,
    settlement_receipts: BTreeMap<String, SettlementReceipt>,
    challenges: BTreeMap<String, ChallengeWindow>,
    spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateConfidentialStableSwapPoolResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        let height = DEFAULT_HEIGHT;
        let epoch = height / config.epoch_blocks;

        let dusd = ShieldedAsset {
            asset_id: stable_hash("ASSET-ID", &[HashPart::Str("nebula-usd")]),
            symbol_commitment: stable_hash("SYMBOL", &[HashPart::Str("DUSD")]),
            decimals: 12,
            peg_reference_commitment: stable_hash("PEG", &[HashPart::Str("usd-1")]),
            oracle_committee_root: stable_merkle(
                "ORACLE-COMMITTEE",
                vec![
                    json!("nebula-oracle-alpha"),
                    json!("nebula-oracle-beta"),
                    json!("nebula-oracle-gamma"),
                ],
            ),
            risk_weight_bps: 1_000,
            enabled: true,
        };
        let xusd = ShieldedAsset {
            asset_id: stable_hash("ASSET-ID", &[HashPart::Str("monero-shielded-usd")]),
            symbol_commitment: stable_hash("SYMBOL", &[HashPart::Str("xUSD")]),
            decimals: 12,
            peg_reference_commitment: stable_hash("PEG", &[HashPart::Str("usd-1")]),
            oracle_committee_root: stable_merkle(
                "ORACLE-COMMITTEE",
                vec![
                    json!("monero-oracle-alpha"),
                    json!("monero-oracle-beta"),
                    json!("monero-oracle-gamma"),
                ],
            ),
            risk_weight_bps: 1_100,
            enabled: true,
        };
        let zusd = ShieldedAsset {
            asset_id: stable_hash("ASSET-ID", &[HashPart::Str("zk-usd-note")]),
            symbol_commitment: stable_hash("SYMBOL", &[HashPart::Str("zUSD")]),
            decimals: 12,
            peg_reference_commitment: stable_hash("PEG", &[HashPart::Str("usd-1")]),
            oracle_committee_root: stable_merkle(
                "ORACLE-COMMITTEE",
                vec![
                    json!("zk-oracle-alpha"),
                    json!("zk-oracle-beta"),
                    json!("zk-oracle-gamma"),
                ],
            ),
            risk_weight_bps: 1_050,
            enabled: true,
        };

        let mut assets = BTreeMap::new();
        assets.insert(dusd.asset_id.clone(), dusd.clone());
        assets.insert(xusd.asset_id.clone(), xusd.clone());
        assets.insert(zusd.asset_id.clone(), zusd.clone());

        let pool_asset_ids = vec![
            dusd.asset_id.clone(),
            xusd.asset_id.clone(),
            zusd.asset_id.clone(),
        ];
        let pool_id = stable_hash(
            "POOL-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str("devnet-usd-tricrypto-private-stable"),
                HashPart::Int(height as i128),
            ],
        );
        let reserve_commitments = commitment_map("RESERVE", &pool_id, &pool_asset_ids, 9_000_000);
        let reserve_note_roots = note_root_map("RESERVE-NOTE", &pool_id, &pool_asset_ids);
        let virtual_balance_commitments =
            commitment_map("VIRTUAL-BALANCE", &pool_id, &pool_asset_ids, 9_000_000);
        let invariant_root = stable_hash(
            "POOL-INVARIANT",
            &[
                HashPart::Str(&pool_id),
                HashPart::Int(config.default_amp_factor as i128),
                HashPart::Json(&json!(reserve_commitments)),
                HashPart::Json(&json!(virtual_balance_commitments)),
            ],
        );
        let pool = ShieldedPool {
            pool_id: pool_id.clone(),
            asset_ids: pool_asset_ids.clone(),
            reserve_commitments,
            reserve_note_roots,
            virtual_balance_commitments,
            amp_factor: config.default_amp_factor,
            fee_bps: config.default_fee_bps,
            admin_fee_bps: config.default_admin_fee_bps,
            sponsor_fee_bps: config.default_sponsor_fee_bps,
            lp_token_commitment: stable_hash("LP-TOKEN", &[HashPart::Str(&pool_id)]),
            governance_key_root: stable_merkle(
                "PQ-GOVERNANCE-KEY",
                vec![
                    json!(stable_hash("PQ-GOV-KEY", &[HashPart::Str("council-alpha")])),
                    json!(stable_hash("PQ-GOV-KEY", &[HashPart::Str("council-beta")])),
                    json!(stable_hash("PQ-GOV-KEY", &[HashPart::Str("council-gamma")])),
                ],
            ),
            circuit_root: stable_hash("POOL-CIRCUIT", &[HashPart::Str(ZK_INVARIANT_SCHEME)]),
            invariant_root,
            status: PoolStatus::Active,
            created_height: height,
        };
        let mut pools = BTreeMap::new();
        pools.insert(pool_id.clone(), pool.clone());

        let lp_position = ConfidentialLpPosition {
            position_id: stable_hash(
                "LP-POSITION-ID",
                &[HashPart::Str(&pool_id), HashPart::Str("lp-alpha")],
            ),
            pool_id: pool_id.clone(),
            owner_commitment: stable_hash("LP-OWNER", &[HashPart::Str("lp-alpha-view")]),
            lp_amount_commitment: stable_hash(
                "LP-AMOUNT",
                &[HashPart::Str("lp-alpha"), HashPart::Int(1_000_000)],
            ),
            share_commitment: stable_hash(
                "LP-SHARE",
                &[HashPart::Str("lp-alpha"), HashPart::Int(3_333)],
            ),
            entry_invariant_commitment: pool.invariant_root.clone(),
            deposit_note_root: stable_merkle(
                "LP-DEPOSIT-NOTE",
                pool_asset_ids
                    .iter()
                    .map(|asset_id| json!(asset_id))
                    .collect(),
            ),
            withdrawal_nullifier_root: stable_merkle("LP-WITHDRAWAL-NULLIFIER", Vec::new()),
            view_tag_root: stable_merkle(
                "LP-VIEW-TAG",
                vec![json!(stable_hash("VIEW-TAG", &[HashPart::Str("lp-alpha")]))],
            ),
            opened_height: height,
            unlock_height: height + config.challenge_window_blocks,
            status: PositionStatus::Active,
        };
        let mut lp_positions = BTreeMap::new();
        lp_positions.insert(lp_position.position_id.clone(), lp_position);

        let sponsor_credit = SponsorCredit {
            credit_id: stable_hash(
                "SPONSOR-CREDIT-ID",
                &[HashPart::Str(&pool_id), HashPart::Str("devnet-sponsor")],
            ),
            sponsor_commitment: stable_hash("SPONSOR", &[HashPart::Str("devnet-sponsor-view")]),
            pool_id: pool_id.clone(),
            credit_asset_id: dusd.asset_id.clone(),
            budget_commitment: stable_hash("SPONSOR-BUDGET", &[HashPart::Int(250_000)]),
            spent_commitment: stable_hash("SPONSOR-SPENT", &[HashPart::Int(0)]),
            eligible_trader_root: stable_merkle(
                "SPONSOR-ELIGIBLE-TRADER",
                vec![
                    json!(stable_hash("TRADER", &[HashPart::Str("alice")])),
                    json!(stable_hash("TRADER", &[HashPart::Str("bob")])),
                    json!(stable_hash("TRADER", &[HashPart::Str("carol")])),
                ],
            ),
            max_fee_bps: config.default_sponsor_fee_bps,
            minted_height: height,
            expiry_height: height + config.epoch_blocks * 8,
            revoked: false,
        };
        let mut sponsor_credits = BTreeMap::new();
        sponsor_credits.insert(sponsor_credit.credit_id.clone(), sponsor_credit.clone());

        let swap = PrivateSwapIntent {
            swap_id: stable_hash(
                "SWAP-ID",
                &[HashPart::Str(&pool_id), HashPart::Str("swap-alpha")],
            ),
            pool_id: pool_id.clone(),
            input_asset_id: dusd.asset_id.clone(),
            output_asset_id: xusd.asset_id.clone(),
            trader_commitment: stable_hash("TRADER", &[HashPart::Str("alice")]),
            amount_in_commitment: stable_hash(
                "AMOUNT-IN",
                &[HashPart::Str("swap-alpha"), HashPart::Int(10_000)],
            ),
            min_amount_out_commitment: stable_hash(
                "MIN-OUT",
                &[HashPart::Str("swap-alpha"), HashPart::Int(9_990)],
            ),
            fee_commitment: stable_hash("FEE", &[HashPart::Str("swap-alpha"), HashPart::Int(4)]),
            sponsor_credit_id: sponsor_credit.credit_id.clone(),
            input_nullifier_root: stable_merkle(
                "SWAP-INPUT-NULLIFIER",
                vec![json!(stable_hash(
                    "NULLIFIER",
                    &[HashPart::Str("swap-alpha-input")]
                ))],
            ),
            output_note_root: stable_merkle(
                "SWAP-OUTPUT-NOTE",
                vec![json!(stable_hash(
                    "OUTPUT-NOTE",
                    &[HashPart::Str("swap-alpha-output")]
                ))],
            ),
            encrypted_witness_root: stable_hash(
                "ENCRYPTED-WITNESS",
                &[HashPart::Str("swap-alpha")],
            ),
            status: SwapStatus::Proved,
            committed_height: height,
            expiry_height: height + config.challenge_window_blocks,
        };
        let mut swaps = BTreeMap::new();
        swaps.insert(swap.swap_id.clone(), swap.clone());

        let pre_state_root = stable_hash(
            "PRE-STATE",
            &[HashPart::Str(&pool_id), HashPart::Int(height as i128)],
        );
        let post_state_root = stable_hash(
            "POST-STATE",
            &[HashPart::Str(&pool_id), HashPart::Int(height as i128 + 1)],
        );
        let attestation = ZkInvariantAttestation {
            attestation_id: stable_hash(
                "INVARIANT-ATTESTATION-ID",
                &[HashPart::Str(&swap.swap_id)],
            ),
            pool_id: pool_id.clone(),
            pre_state_root,
            post_state_root,
            invariant_commitment: pool.invariant_root.clone(),
            reserve_delta_root: stable_merkle(
                "RESERVE-DELTA",
                vec![
                    json!({"asset_id": dusd.asset_id, "delta_commitment": stable_hash("DELTA", &[HashPart::Str("dusd-in")])}),
                    json!({"asset_id": xusd.asset_id, "delta_commitment": stable_hash("DELTA", &[HashPart::Str("xusd-out")])}),
                ],
            ),
            fee_delta_root: stable_merkle(
                "FEE-DELTA",
                vec![json!(stable_hash(
                    "FEE-DELTA-COMMITMENT",
                    &[HashPart::Str("swap-alpha")]
                ))],
            ),
            proof_public_input_root: stable_hash(
                "PROOF-PUBLIC-INPUT",
                &[HashPart::Str(&swap.swap_id)],
            ),
            recursive_proof_root: stable_hash("RECURSIVE-PROOF", &[HashPart::Str(&swap.swap_id)]),
            verifier_key_root: stable_hash("VERIFIER-KEY", &[HashPart::Str(ZK_INVARIANT_SCHEME)]),
            prover_commitment: stable_hash("PROVER", &[HashPart::Str("devnet-prover")]),
            attested_height: height + 1,
        };
        let mut invariant_attestations = BTreeMap::new();
        invariant_attestations.insert(attestation.attestation_id.clone(), attestation.clone());

        let governance_action = PqGovernanceAction {
            action_id: stable_hash(
                "GOVERNANCE-ACTION-ID",
                &[HashPart::Str(&pool_id), HashPart::Str("fee-confirm")],
            ),
            pool_id: pool_id.clone(),
            action_kind: GovernanceActionKind::FeeChange,
            proposal_root: stable_hash("GOVERNANCE-PROPOSAL", &[HashPart::Str("keep-low-fees")]),
            quorum_root: stable_hash("GOVERNANCE-QUORUM", &[HashPart::Int(3)]),
            pq_signature_root: stable_merkle(
                "PQ-GOVERNANCE-SIGNATURE",
                vec![
                    json!(stable_hash("PQ-SIGNATURE", &[HashPart::Str("sig-alpha")])),
                    json!(stable_hash("PQ-SIGNATURE", &[HashPart::Str("sig-beta")])),
                    json!(stable_hash("PQ-SIGNATURE", &[HashPart::Str("sig-gamma")])),
                ],
            ),
            signer_set_root: pool.governance_key_root.clone(),
            execution_payload_root: stable_hash(
                "GOVERNANCE-PAYLOAD",
                &[HashPart::Str("fee-bps-4")],
            ),
            effective_height: height,
            expires_height: height + config.epoch_blocks,
            executed: true,
        };
        let mut governance_actions = BTreeMap::new();
        governance_actions.insert(governance_action.action_id.clone(), governance_action);

        let settlement_receipt = SettlementReceipt {
            receipt_id: stable_hash("SETTLEMENT-RECEIPT-ID", &[HashPart::Str(&swap.swap_id)]),
            pool_id: pool_id.clone(),
            batch_id: stable_hash(
                "SETTLEMENT-BATCH-ID",
                &[HashPart::Str(&pool_id), HashPart::Int(epoch as i128)],
            ),
            swap_root: stable_merkle("SETTLEMENT-SWAP", vec![swap.public_record()]),
            lp_delta_root: stable_merkle("SETTLEMENT-LP-DELTA", Vec::new()),
            sponsor_credit_root: stable_merkle(
                "SETTLEMENT-SPONSOR-CREDIT",
                vec![sponsor_credit.public_record()],
            ),
            nullifier_root: swap.input_nullifier_root.clone(),
            output_note_root: swap.output_note_root.clone(),
            invariant_attestation_id: attestation.attestation_id.clone(),
            sequencer_commitment: stable_hash("SEQUENCER", &[HashPart::Str("devnet-sequencer")]),
            settlement_height: height + 2,
            challenge_deadline_height: height + 2 + config.challenge_window_blocks,
        };
        let mut settlement_receipts = BTreeMap::new();
        settlement_receipts.insert(
            settlement_receipt.receipt_id.clone(),
            settlement_receipt.clone(),
        );

        let challenge = ChallengeWindow {
            challenge_id: stable_hash(
                "CHALLENGE-ID",
                &[HashPart::Str(&settlement_receipt.receipt_id)],
            ),
            subject_id: settlement_receipt.receipt_id.clone(),
            subject_root: root_from_record(&settlement_receipt.public_record()),
            challenger_commitment: stable_hash("CHALLENGER", &[HashPart::Str("watchtower-alpha")]),
            evidence_root: stable_merkle(
                "CHALLENGE-EVIDENCE",
                vec![json!(stable_hash(
                    "EVIDENCE",
                    &[HashPart::Str("latency-sample")]
                ))],
            ),
            bond_commitment: stable_hash("CHALLENGE-BOND", &[HashPart::Int(1_000)]),
            response_root: stable_hash("CHALLENGE-RESPONSE", &[HashPart::Str("pending")]),
            opened_height: height + 3,
            deadline_height: height + 3 + config.challenge_window_blocks,
            status: ChallengeStatus::Open,
        };
        let mut challenges = BTreeMap::new();
        challenges.insert(challenge.challenge_id.clone(), challenge);

        let mut spent_nullifiers = BTreeSet::new();
        spent_nullifiers.insert(stable_hash(
            "NULLIFIER",
            &[HashPart::Str("swap-alpha-input")],
        ));

        let state = Self {
            config,
            height,
            epoch,
            assets,
            pools,
            lp_positions,
            swaps,
            sponsor_credits,
            invariant_attestations,
            governance_actions,
            settlement_receipts,
            challenges,
            spent_nullifiers,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PrivateConfidentialStableSwapPoolResult<()> {
        self.config.validate()?;
        if self.epoch != self.height / self.config.epoch_blocks {
            return Err("private confidential stable-swap epoch does not match height".to_string());
        }
        if self.assets.is_empty() {
            return Err(
                "private confidential stable-swap state requires at least one asset".to_string(),
            );
        }
        if self.pools.is_empty() {
            return Err(
                "private confidential stable-swap state requires at least one pool".to_string(),
            );
        }
        for (asset_id, asset) in &self.assets {
            asset.validate()?;
            if asset_id != &asset.asset_id {
                return Err("private confidential stable-swap asset map key mismatch".to_string());
            }
        }
        for (pool_id, pool) in &self.pools {
            pool.validate()?;
            if pool_id != &pool.pool_id {
                return Err("private confidential stable-swap pool map key mismatch".to_string());
            }
            for asset_id in &pool.asset_ids {
                match self.assets.get(asset_id) {
                    Some(asset) if asset.enabled => {}
                    Some(_) => {
                        return Err(
                            "private confidential stable-swap pool references disabled asset"
                                .to_string(),
                        );
                    }
                    None => {
                        return Err(
                            "private confidential stable-swap pool references unknown asset"
                                .to_string(),
                        );
                    }
                }
            }
        }
        for (position_id, position) in &self.lp_positions {
            position.validate()?;
            if position_id != &position.position_id {
                return Err(
                    "private confidential stable-swap lp position map key mismatch".to_string(),
                );
            }
            if !self.pools.contains_key(&position.pool_id) {
                return Err(
                    "private confidential stable-swap lp position references unknown pool"
                        .to_string(),
                );
            }
        }
        for (swap_id, swap) in &self.swaps {
            swap.validate()?;
            if swap_id != &swap.swap_id {
                return Err("private confidential stable-swap swap map key mismatch".to_string());
            }
            let pool = match self.pools.get(&swap.pool_id) {
                Some(pool) => pool,
                None => {
                    return Err(
                        "private confidential stable-swap swap references unknown pool".to_string(),
                    )
                }
            };
            if !pool.status.allows_swaps()
                && matches!(swap.status, SwapStatus::Committed | SwapStatus::Proved)
            {
                return Err(
                    "private confidential stable-swap active swap references inactive pool"
                        .to_string(),
                );
            }
            if !pool.asset_ids.contains(&swap.input_asset_id)
                || !pool.asset_ids.contains(&swap.output_asset_id)
            {
                return Err(
                    "private confidential stable-swap swap references asset outside pool"
                        .to_string(),
                );
            }
            if !swap.sponsor_credit_id.is_empty()
                && !self.sponsor_credits.contains_key(&swap.sponsor_credit_id)
            {
                return Err(
                    "private confidential stable-swap swap references unknown sponsor credit"
                        .to_string(),
                );
            }
        }
        for (credit_id, credit) in &self.sponsor_credits {
            credit.validate()?;
            if credit_id != &credit.credit_id {
                return Err(
                    "private confidential stable-swap sponsor credit map key mismatch".to_string(),
                );
            }
            if !self.pools.contains_key(&credit.pool_id) {
                return Err(
                    "private confidential stable-swap sponsor credit references unknown pool"
                        .to_string(),
                );
            }
            if !self.assets.contains_key(&credit.credit_asset_id) {
                return Err(
                    "private confidential stable-swap sponsor credit references unknown asset"
                        .to_string(),
                );
            }
        }
        for (attestation_id, attestation) in &self.invariant_attestations {
            attestation.validate()?;
            if attestation_id != &attestation.attestation_id {
                return Err(
                    "private confidential stable-swap attestation map key mismatch".to_string(),
                );
            }
            if !self.pools.contains_key(&attestation.pool_id) {
                return Err(
                    "private confidential stable-swap attestation references unknown pool"
                        .to_string(),
                );
            }
        }
        for (action_id, action) in &self.governance_actions {
            action.validate()?;
            if action_id != &action.action_id {
                return Err(
                    "private confidential stable-swap governance map key mismatch".to_string(),
                );
            }
            if !self.pools.contains_key(&action.pool_id) {
                return Err(
                    "private confidential stable-swap governance action references unknown pool"
                        .to_string(),
                );
            }
        }
        for (receipt_id, receipt) in &self.settlement_receipts {
            receipt.validate()?;
            if receipt_id != &receipt.receipt_id {
                return Err("private confidential stable-swap receipt map key mismatch".to_string());
            }
            if !self.pools.contains_key(&receipt.pool_id) {
                return Err(
                    "private confidential stable-swap receipt references unknown pool".to_string(),
                );
            }
            if !self
                .invariant_attestations
                .contains_key(&receipt.invariant_attestation_id)
            {
                return Err(
                    "private confidential stable-swap receipt references unknown attestation"
                        .to_string(),
                );
            }
        }
        for (challenge_id, challenge) in &self.challenges {
            challenge.validate()?;
            if challenge_id != &challenge.challenge_id {
                return Err(
                    "private confidential stable-swap challenge map key mismatch".to_string(),
                );
            }
            if !self.settlement_receipts.contains_key(&challenge.subject_id)
                && !self.swaps.contains_key(&challenge.subject_id)
                && !self.governance_actions.contains_key(&challenge.subject_id)
            {
                return Err(
                    "private confidential stable-swap challenge references unknown subject"
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PrivateConfidentialStableSwapPoolResult<()> {
        self.height = height;
        self.epoch = height / self.config.epoch_blocks;
        self.refresh_time_dependent_statuses();
        self.validate()
    }

    pub fn update_height(
        &mut self,
        height_delta: u64,
    ) -> PrivateConfidentialStableSwapPoolResult<()> {
        let next_height = self
            .height
            .checked_add(height_delta)
            .ok_or_else(|| "private confidential stable-swap height overflow".to_string())?;
        self.set_height(next_height)
    }

    pub fn roots(&self) -> Roots {
        let config_record = self.config.public_record();
        let asset_records =
            self.record_values(self.assets.values().map(ShieldedAsset::public_record));
        let pool_records = self.record_values(self.pools.values().map(ShieldedPool::public_record));
        let position_records = self.record_values(
            self.lp_positions
                .values()
                .map(ConfidentialLpPosition::public_record),
        );
        let swap_records =
            self.record_values(self.swaps.values().map(PrivateSwapIntent::public_record));
        let sponsor_records = self.record_values(
            self.sponsor_credits
                .values()
                .map(SponsorCredit::public_record),
        );
        let attestation_records = self.record_values(
            self.invariant_attestations
                .values()
                .map(ZkInvariantAttestation::public_record),
        );
        let governance_records = self.record_values(
            self.governance_actions
                .values()
                .map(PqGovernanceAction::public_record),
        );
        let receipt_records = self.record_values(
            self.settlement_receipts
                .values()
                .map(SettlementReceipt::public_record),
        );
        let challenge_records =
            self.record_values(self.challenges.values().map(ChallengeWindow::public_record));
        let nullifier_records = self
            .spent_nullifiers
            .iter()
            .map(|nullifier| json!(nullifier))
            .collect::<Vec<_>>();

        let config_root = stable_hash("CONFIG-ROOT", &[HashPart::Json(&config_record)]);
        let asset_root = stable_merkle("ASSET", asset_records);
        let pool_root = stable_merkle("POOL", pool_records);
        let position_root = stable_merkle("LP-POSITION", position_records);
        let swap_root = stable_merkle("SWAP", swap_records);
        let sponsor_credit_root = stable_merkle("SPONSOR-CREDIT", sponsor_records);
        let invariant_attestation_root =
            stable_merkle("INVARIANT-ATTESTATION", attestation_records);
        let governance_root = stable_merkle("PQ-GOVERNANCE", governance_records);
        let settlement_receipt_root = stable_merkle("SETTLEMENT-RECEIPT", receipt_records);
        let challenge_root = stable_merkle("CHALLENGE", challenge_records);
        let nullifier_root = stable_merkle("NULLIFIER", nullifier_records);
        let public_record = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONFIDENTIAL_STABLE_SWAP_POOL_PROTOCOL_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "config_root": config_root,
            "asset_root": asset_root,
            "pool_root": pool_root,
            "position_root": position_root,
            "swap_root": swap_root,
            "sponsor_credit_root": sponsor_credit_root,
            "invariant_attestation_root": invariant_attestation_root,
            "governance_root": governance_root,
            "settlement_receipt_root": settlement_receipt_root,
            "challenge_root": challenge_root,
            "nullifier_root": nullifier_root,
        });
        let state_root = root_from_record(&public_record);
        Roots {
            config_root,
            asset_root,
            pool_root,
            position_root,
            swap_root,
            sponsor_credit_root,
            invariant_attestation_root,
            governance_root,
            settlement_receipt_root,
            challenge_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        let open_challenges = self
            .challenges
            .values()
            .filter(|challenge| challenge.status.is_open())
            .count() as u64;
        let settled_challenges = self.challenges.len() as u64 - open_challenges;
        Counters {
            assets: self.assets.len() as u64,
            pools: self.pools.len() as u64,
            lp_positions: self.lp_positions.len() as u64,
            swaps: self.swaps.len() as u64,
            sponsor_credits: self.sponsor_credits.len() as u64,
            invariant_attestations: self.invariant_attestations.len() as u64,
            governance_actions: self.governance_actions.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            challenges: self.challenges.len() as u64,
            open_challenges,
            settled_challenges,
            spent_nullifiers: self.spent_nullifiers.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONFIDENTIAL_STABLE_SWAP_POOL_PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "roots": {
                "config_root": roots.config_root,
                "asset_root": roots.asset_root,
                "pool_root": roots.pool_root,
                "position_root": roots.position_root,
                "swap_root": roots.swap_root,
                "sponsor_credit_root": roots.sponsor_credit_root,
                "invariant_attestation_root": roots.invariant_attestation_root,
                "governance_root": roots.governance_root,
                "settlement_receipt_root": roots.settlement_receipt_root,
                "challenge_root": roots.challenge_root,
                "nullifier_root": roots.nullifier_root,
                "state_root": roots.state_root,
            },
            "counters": {
                "assets": counters.assets,
                "pools": counters.pools,
                "lp_positions": counters.lp_positions,
                "swaps": counters.swaps,
                "sponsor_credits": counters.sponsor_credits,
                "invariant_attestations": counters.invariant_attestations,
                "governance_actions": counters.governance_actions,
                "settlement_receipts": counters.settlement_receipts,
                "challenges": counters.challenges,
                "open_challenges": counters.open_challenges,
                "settled_challenges": counters.settled_challenges,
                "spent_nullifiers": counters.spent_nullifiers,
            },
            "privacy": {
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "confidential_amount_scheme": self.config.confidential_amount_scheme,
                "zk_invariant_scheme": self.config.zk_invariant_scheme,
                "receipt_scheme": self.config.receipt_scheme,
            },
            "quantum_resistance": {
                "pq_governance_scheme": self.config.pq_governance_scheme,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "governance_root": roots.governance_root,
            },
            "low_fee": {
                "default_fee_bps": self.config.default_fee_bps,
                "default_admin_fee_bps": self.config.default_admin_fee_bps,
                "default_sponsor_fee_bps": self.config.default_sponsor_fee_bps,
                "sponsor_credit_root": roots.sponsor_credit_root,
            },
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn refresh_time_dependent_statuses(&mut self) {
        for swap in self.swaps.values_mut() {
            if self.height >= swap.expiry_height
                && matches!(swap.status, SwapStatus::Committed | SwapStatus::Proved)
            {
                swap.status = SwapStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if self.height >= challenge.deadline_height && challenge.status.is_open() {
                challenge.status = ChallengeStatus::Expired;
            }
        }
    }

    fn record_values<I>(&self, records: I) -> Vec<Value>
    where
        I: IntoIterator<Item = Value>,
    {
        records.into_iter().collect()
    }
}

pub fn root_from_record(record: &Value) -> String {
    stable_hash("RECORD-ROOT", &[HashPart::Json(record)])
}

pub fn devnet() -> PrivateConfidentialStableSwapPoolResult<State> {
    State::devnet()
}

fn commitment_map(
    domain: &str,
    pool_id: &str,
    asset_ids: &[String],
    base_units: u64,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (index, asset_id) in asset_ids.iter().enumerate() {
        let amount = base_units.saturating_add((index as u64).saturating_mul(10_000));
        map.insert(
            asset_id.clone(),
            stable_hash(
                domain,
                &[
                    HashPart::Str(pool_id),
                    HashPart::Str(asset_id),
                    HashPart::Int(amount as i128),
                ],
            ),
        );
    }
    map
}

fn note_root_map(domain: &str, pool_id: &str, asset_ids: &[String]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for asset_id in asset_ids {
        map.insert(
            asset_id.clone(),
            stable_merkle(
                domain,
                vec![
                    json!(stable_hash(
                        domain,
                        &[
                            HashPart::Str(pool_id),
                            HashPart::Str(asset_id),
                            HashPart::Int(0)
                        ]
                    )),
                    json!(stable_hash(
                        domain,
                        &[
                            HashPart::Str(pool_id),
                            HashPart::Str(asset_id),
                            HashPart::Int(1)
                        ]
                    )),
                ],
            ),
        );
    }
    map
}

fn stable_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    let scoped_domain = format!("PRIVATE-CONFIDENTIAL-STABLE-SWAP-POOL:{domain}");
    domain_hash(&scoped_domain, parts, 32)
}

fn stable_merkle(domain: &str, leaves: Vec<Value>) -> String {
    let scoped_domain = format!("PRIVATE-CONFIDENTIAL-STABLE-SWAP-POOL:{domain}");
    merkle_root(&scoped_domain, &leaves)
}
