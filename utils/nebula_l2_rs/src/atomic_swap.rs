use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type AtomicSwapResult<T> = Result<T, String>;

pub const ATOMIC_SWAP_PROTOCOL_VERSION: &str = "nebula-atomic-swap-v1";
pub const ATOMIC_SWAP_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const ATOMIC_SWAP_DEVNET_WXMR_ASSET_ID: &str = "asset:wxmr";
pub const ATOMIC_SWAP_DEVNET_STABLE_ASSET_ID: &str = "asset:usdd";
pub const ATOMIC_SWAP_DEVNET_SWAP_COORDINATOR: &str = "devnet-swap-coordinator";
pub const ATOMIC_SWAP_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const ATOMIC_SWAP_RECOVERY_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const ATOMIC_SWAP_STATUS_OPEN: &str = "open";
pub const ATOMIC_SWAP_STATUS_LOCKED: &str = "locked";
pub const ATOMIC_SWAP_STATUS_SETTLED: &str = "settled";
pub const ATOMIC_SWAP_STATUS_REFUNDED: &str = "refunded";
pub const ATOMIC_SWAP_STATUS_EXPIRED: &str = "expired";
pub const ATOMIC_SWAP_STATUS_CHALLENGED: &str = "challenged";
pub const ATOMIC_SWAP_DEFAULT_LOCK_BLOCKS: u64 = 72;
pub const ATOMIC_SWAP_DEFAULT_REFUND_DELAY_BLOCKS: u64 = 18;
pub const ATOMIC_SWAP_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 24;
pub const ATOMIC_SWAP_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 48;
pub const ATOMIC_SWAP_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 288;
pub const ATOMIC_SWAP_DEFAULT_MAX_PACKET_BYTES: u64 = 1_536;
pub const ATOMIC_SWAP_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_000;
pub const ATOMIC_SWAP_DEFAULT_MAX_SLIPPAGE_BPS: u64 = 150;
pub const ATOMIC_SWAP_MAX_BPS: u64 = 10_000;
pub const ATOMIC_SWAP_MAX_QUOTES: usize = 512;
pub const ATOMIC_SWAP_MAX_INTENTS: usize = 512;
pub const ATOMIC_SWAP_MAX_ATTESTATIONS: usize = 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicSwapDirection {
    MoneroToL2,
    L2ToMonero,
}

impl AtomicSwapDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroToL2 => "monero_to_l2",
            Self::L2ToMonero => "l2_to_monero",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicSwapLockKind {
    HashTimeLocked,
    AdaptorSignature,
    ViewKeyObserved,
    ThresholdCoordinator,
    HybridRecovery,
}

impl AtomicSwapLockKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HashTimeLocked => "hash_time_locked",
            Self::AdaptorSignature => "adaptor_signature",
            Self::ViewKeyObserved => "view_key_observed",
            Self::ThresholdCoordinator => "threshold_coordinator",
            Self::HybridRecovery => "hybrid_recovery",
        }
    }

    pub fn requires_monero_evidence(self) -> bool {
        matches!(
            self,
            Self::ViewKeyObserved | Self::AdaptorSignature | Self::HybridRecovery
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicSwapPhase {
    Quoted,
    IntentSubmitted,
    MoneroLocked,
    L2Escrowed,
    BothLocked,
    Settled,
    Refunding,
    Refunded,
    Challenged,
    Expired,
}

impl AtomicSwapPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::IntentSubmitted => "intent_submitted",
            Self::MoneroLocked => "monero_locked",
            Self::L2Escrowed => "l2_escrowed",
            Self::BothLocked => "both_locked",
            Self::Settled => "settled",
            Self::Refunding => "refunding",
            Self::Refunded => "refunded",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicSwapAttestationRole {
    Coordinator,
    MoneroWatcher,
    L2Sequencer,
    LiquidityProvider,
    Watchtower,
}

impl AtomicSwapAttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Coordinator => "coordinator",
            Self::MoneroWatcher => "monero_watcher",
            Self::L2Sequencer => "l2_sequencer",
            Self::LiquidityProvider => "liquidity_provider",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicSwapChallengeKind {
    MissingLockEvidence,
    InvalidAdaptorRoot,
    PriceSlippageExceeded,
    RefundTooEarly,
    DoubleSettlement,
    WatcherEquivocation,
}

impl AtomicSwapChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingLockEvidence => "missing_lock_evidence",
            Self::InvalidAdaptorRoot => "invalid_adaptor_root",
            Self::PriceSlippageExceeded => "price_slippage_exceeded",
            Self::RefundTooEarly => "refund_too_early",
            Self::DoubleSettlement => "double_settlement",
            Self::WatcherEquivocation => "watcher_equivocation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicSwapConfig {
    pub config_id: String,
    pub monero_network: String,
    pub wxmr_asset_id: String,
    pub stable_asset_id: String,
    pub default_quote_ttl_blocks: u64,
    pub default_lock_blocks: u64,
    pub default_refund_delay_blocks: u64,
    pub default_challenge_window_blocks: u64,
    pub max_slippage_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub max_packet_bytes: u64,
    pub require_payload_roots_only: bool,
    pub pq_signature_scheme: String,
    pub recovery_signature_scheme: String,
}

impl Default for AtomicSwapConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            monero_network: ATOMIC_SWAP_DEVNET_MONERO_NETWORK.to_string(),
            wxmr_asset_id: ATOMIC_SWAP_DEVNET_WXMR_ASSET_ID.to_string(),
            stable_asset_id: ATOMIC_SWAP_DEVNET_STABLE_ASSET_ID.to_string(),
            default_quote_ttl_blocks: ATOMIC_SWAP_DEFAULT_QUOTE_TTL_BLOCKS,
            default_lock_blocks: ATOMIC_SWAP_DEFAULT_LOCK_BLOCKS,
            default_refund_delay_blocks: ATOMIC_SWAP_DEFAULT_REFUND_DELAY_BLOCKS,
            default_challenge_window_blocks: ATOMIC_SWAP_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_slippage_bps: ATOMIC_SWAP_DEFAULT_MAX_SLIPPAGE_BPS,
            low_fee_rebate_bps: ATOMIC_SWAP_DEFAULT_LOW_FEE_REBATE_BPS,
            max_packet_bytes: ATOMIC_SWAP_DEFAULT_MAX_PACKET_BYTES,
            require_payload_roots_only: true,
            pq_signature_scheme: ATOMIC_SWAP_PQ_SIGNATURE_SCHEME.to_string(),
            recovery_signature_scheme: ATOMIC_SWAP_RECOVERY_SIGNATURE_SCHEME.to_string(),
        };
        config.config_id = atomic_swap_config_id(&config.identity_record());
        config
    }
}

impl AtomicSwapConfig {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "atomic_swap_config",
            "chain_id": CHAIN_ID,
            "protocol_version": ATOMIC_SWAP_PROTOCOL_VERSION,
            "monero_network": self.monero_network,
            "wxmr_asset_id": self.wxmr_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "default_quote_ttl_blocks": self.default_quote_ttl_blocks,
            "default_lock_blocks": self.default_lock_blocks,
            "default_refund_delay_blocks": self.default_refund_delay_blocks,
            "default_challenge_window_blocks": self.default_challenge_window_blocks,
            "max_slippage_bps": self.max_slippage_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_packet_bytes": self.max_packet_bytes,
            "require_payload_roots_only": self.require_payload_roots_only,
            "pq_signature_scheme": self.pq_signature_scheme,
            "recovery_signature_scheme": self.recovery_signature_scheme,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("atomic swap config public record object");
        object.insert(
            "config_id".to_string(),
            Value::String(self.config_id.clone()),
        );
        object.insert("config_root".to_string(), Value::String(self.config_root()));
        record
    }

    pub fn config_root(&self) -> String {
        atomic_swap_payload_root("ATOMIC-SWAP-CONFIG", &self.identity_record())
    }

    pub fn validate(&self) -> AtomicSwapResult<String> {
        ensure_non_empty(&self.config_id, "atomic swap config id")?;
        ensure_non_empty(&self.monero_network, "atomic swap monero network")?;
        ensure_non_empty(&self.wxmr_asset_id, "atomic swap wxmr asset id")?;
        ensure_non_empty(&self.stable_asset_id, "atomic swap stable asset id")?;
        ensure_positive(self.default_quote_ttl_blocks, "atomic swap quote ttl")?;
        ensure_positive(self.default_lock_blocks, "atomic swap lock blocks")?;
        ensure_positive(self.default_refund_delay_blocks, "atomic swap refund delay")?;
        ensure_positive(
            self.default_challenge_window_blocks,
            "atomic swap challenge window",
        )?;
        validate_bps(self.max_slippage_bps, "atomic swap max slippage")?;
        validate_bps(self.low_fee_rebate_bps, "atomic swap low fee rebate")?;
        ensure_positive(self.max_packet_bytes, "atomic swap packet bytes")?;
        ensure_non_empty(&self.pq_signature_scheme, "atomic swap pq signature")?;
        ensure_non_empty(
            &self.recovery_signature_scheme,
            "atomic swap recovery signature",
        )?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicSwapQuote {
    pub quote_id: String,
    pub maker_commitment: String,
    pub direction: AtomicSwapDirection,
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub source_amount_units: u64,
    pub target_amount_units: u64,
    pub fee_units: u64,
    pub max_slippage_bps: u64,
    pub lock_kind: AtomicSwapLockKind,
    pub route_root: String,
    pub price_root: String,
    pub low_fee_eligible: bool,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl AtomicSwapQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maker_commitment: impl Into<String>,
        direction: AtomicSwapDirection,
        source_asset_id: impl Into<String>,
        target_asset_id: impl Into<String>,
        source_amount_units: u64,
        target_amount_units: u64,
        fee_units: u64,
        max_slippage_bps: u64,
        lock_kind: AtomicSwapLockKind,
        route_root: impl Into<String>,
        price_root: impl Into<String>,
        low_fee_eligible: bool,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> AtomicSwapResult<Self> {
        let maker_commitment = maker_commitment.into();
        let source_asset_id = source_asset_id.into();
        let target_asset_id = target_asset_id.into();
        let route_root = route_root.into();
        let price_root = price_root.into();
        ensure_non_empty(&maker_commitment, "atomic quote maker")?;
        ensure_non_empty(&source_asset_id, "atomic quote source asset")?;
        ensure_non_empty(&target_asset_id, "atomic quote target asset")?;
        ensure_positive(source_amount_units, "atomic quote source amount")?;
        ensure_positive(target_amount_units, "atomic quote target amount")?;
        validate_bps(max_slippage_bps, "atomic quote max slippage")?;
        ensure_non_empty(&route_root, "atomic quote route root")?;
        ensure_non_empty(&price_root, "atomic quote price root")?;
        if expires_at_height <= created_at_height {
            return Err("atomic quote expiry must follow creation".to_string());
        }
        let quote_id = atomic_swap_quote_id(
            &maker_commitment,
            direction,
            &source_asset_id,
            &target_asset_id,
            source_amount_units,
            target_amount_units,
            fee_units,
            max_slippage_bps,
            lock_kind,
            &route_root,
            &price_root,
            created_at_height,
            expires_at_height,
        );
        Ok(Self {
            quote_id,
            maker_commitment,
            direction,
            source_asset_id,
            target_asset_id,
            source_amount_units,
            target_amount_units,
            fee_units,
            max_slippage_bps,
            lock_kind,
            route_root,
            price_root,
            low_fee_eligible,
            created_at_height,
            expires_at_height,
            status: ATOMIC_SWAP_STATUS_OPEN.to_string(),
        })
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "atomic_swap_quote",
            "chain_id": CHAIN_ID,
            "protocol_version": ATOMIC_SWAP_PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "maker_commitment": self.maker_commitment,
            "direction": self.direction.as_str(),
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "source_amount_units": self.source_amount_units,
            "target_amount_units": self.target_amount_units,
            "fee_units": self.fee_units,
            "max_slippage_bps": self.max_slippage_bps,
            "lock_kind": self.lock_kind.as_str(),
            "route_root": self.route_root,
            "price_root": self.price_root,
            "low_fee_eligible": self.low_fee_eligible,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn quote_root(&self) -> String {
        atomic_swap_payload_root("ATOMIC-SWAP-QUOTE", &self.public_record())
    }

    pub fn validate(&self) -> AtomicSwapResult<String> {
        ensure_non_empty(&self.quote_id, "atomic quote id")?;
        ensure_non_empty(&self.maker_commitment, "atomic quote maker")?;
        ensure_non_empty(&self.source_asset_id, "atomic quote source asset")?;
        ensure_non_empty(&self.target_asset_id, "atomic quote target asset")?;
        ensure_positive(self.source_amount_units, "atomic quote source amount")?;
        ensure_positive(self.target_amount_units, "atomic quote target amount")?;
        validate_bps(self.max_slippage_bps, "atomic quote max slippage")?;
        ensure_non_empty(&self.route_root, "atomic quote route root")?;
        ensure_non_empty(&self.price_root, "atomic quote price root")?;
        if self.expires_at_height <= self.created_at_height {
            return Err("atomic quote expiry must follow creation".to_string());
        }
        Ok(self.quote_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroLockEvidence {
    pub evidence_id: String,
    pub swap_id: String,
    pub monero_network: String,
    pub txid_root: String,
    pub output_commitment_root: String,
    pub key_image_root: String,
    pub view_tag_root: String,
    pub amount_bucket: u64,
    pub confirmation_height: u64,
    pub observed_by_commitment: String,
    pub lock_expires_at_height: u64,
    pub status: String,
}

impl MoneroLockEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        swap_id: impl Into<String>,
        monero_network: impl Into<String>,
        txid_root: impl Into<String>,
        output_commitment_root: impl Into<String>,
        key_image_root: impl Into<String>,
        view_tag_root: impl Into<String>,
        amount_bucket: u64,
        confirmation_height: u64,
        observed_by_commitment: impl Into<String>,
        lock_expires_at_height: u64,
    ) -> AtomicSwapResult<Self> {
        let swap_id = swap_id.into();
        let monero_network = monero_network.into();
        let txid_root = txid_root.into();
        let output_commitment_root = output_commitment_root.into();
        let key_image_root = key_image_root.into();
        let view_tag_root = view_tag_root.into();
        let observed_by_commitment = observed_by_commitment.into();
        ensure_non_empty(&swap_id, "monero lock swap id")?;
        ensure_non_empty(&monero_network, "monero lock network")?;
        ensure_non_empty(&txid_root, "monero lock txid root")?;
        ensure_non_empty(&output_commitment_root, "monero lock output root")?;
        ensure_non_empty(&key_image_root, "monero lock key image root")?;
        ensure_non_empty(&view_tag_root, "monero lock view tag root")?;
        ensure_positive(amount_bucket, "monero lock amount bucket")?;
        ensure_non_empty(&observed_by_commitment, "monero lock observer")?;
        if lock_expires_at_height <= confirmation_height {
            return Err("monero lock expiry must follow confirmation".to_string());
        }
        let evidence_id = monero_lock_evidence_id(
            &swap_id,
            &monero_network,
            &txid_root,
            &output_commitment_root,
            &key_image_root,
            &view_tag_root,
            amount_bucket,
            confirmation_height,
            &observed_by_commitment,
            lock_expires_at_height,
        );
        Ok(Self {
            evidence_id,
            swap_id,
            monero_network,
            txid_root,
            output_commitment_root,
            key_image_root,
            view_tag_root,
            amount_bucket,
            confirmation_height,
            observed_by_commitment,
            lock_expires_at_height,
            status: ATOMIC_SWAP_STATUS_LOCKED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_lock_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": ATOMIC_SWAP_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "swap_id": self.swap_id,
            "monero_network": self.monero_network,
            "txid_root": self.txid_root,
            "output_commitment_root": self.output_commitment_root,
            "key_image_root": self.key_image_root,
            "view_tag_root": self.view_tag_root,
            "amount_bucket": self.amount_bucket,
            "confirmation_height": self.confirmation_height,
            "observed_by_commitment": self.observed_by_commitment,
            "lock_expires_at_height": self.lock_expires_at_height,
            "status": self.status,
        })
    }

    pub fn evidence_root(&self) -> String {
        atomic_swap_payload_root("MONERO-LOCK-EVIDENCE", &self.public_record())
    }

    pub fn validate(&self) -> AtomicSwapResult<String> {
        ensure_non_empty(&self.evidence_id, "monero evidence id")?;
        ensure_non_empty(&self.swap_id, "monero evidence swap id")?;
        ensure_non_empty(&self.monero_network, "monero evidence network")?;
        ensure_non_empty(&self.txid_root, "monero evidence txid root")?;
        ensure_non_empty(&self.output_commitment_root, "monero evidence output root")?;
        ensure_non_empty(&self.key_image_root, "monero evidence key image root")?;
        ensure_non_empty(&self.view_tag_root, "monero evidence view tag root")?;
        ensure_positive(self.amount_bucket, "monero evidence amount bucket")?;
        ensure_non_empty(&self.observed_by_commitment, "monero evidence observer")?;
        if self.lock_expires_at_height <= self.confirmation_height {
            return Err("monero evidence expiry must follow confirmation".to_string());
        }
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct L2EscrowLock {
    pub escrow_id: String,
    pub swap_id: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub amount_units: u64,
    pub contract_root: String,
    pub nullifier_root: String,
    pub refund_commitment_root: String,
    pub locked_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl L2EscrowLock {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        swap_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        asset_id: impl Into<String>,
        amount_units: u64,
        contract_root: impl Into<String>,
        nullifier_root: impl Into<String>,
        refund_commitment_root: impl Into<String>,
        locked_at_height: u64,
        expires_at_height: u64,
    ) -> AtomicSwapResult<Self> {
        let swap_id = swap_id.into();
        let owner_commitment = owner_commitment.into();
        let asset_id = asset_id.into();
        let contract_root = contract_root.into();
        let nullifier_root = nullifier_root.into();
        let refund_commitment_root = refund_commitment_root.into();
        ensure_non_empty(&swap_id, "l2 escrow swap id")?;
        ensure_non_empty(&owner_commitment, "l2 escrow owner")?;
        ensure_non_empty(&asset_id, "l2 escrow asset")?;
        ensure_positive(amount_units, "l2 escrow amount")?;
        ensure_non_empty(&contract_root, "l2 escrow contract root")?;
        ensure_non_empty(&nullifier_root, "l2 escrow nullifier root")?;
        ensure_non_empty(&refund_commitment_root, "l2 escrow refund root")?;
        if expires_at_height <= locked_at_height {
            return Err("l2 escrow expiry must follow lock height".to_string());
        }
        let escrow_id = l2_escrow_lock_id(
            &swap_id,
            &owner_commitment,
            &asset_id,
            amount_units,
            &contract_root,
            &nullifier_root,
            &refund_commitment_root,
            locked_at_height,
            expires_at_height,
        );
        Ok(Self {
            escrow_id,
            swap_id,
            owner_commitment,
            asset_id,
            amount_units,
            contract_root,
            nullifier_root,
            refund_commitment_root,
            locked_at_height,
            expires_at_height,
            status: ATOMIC_SWAP_STATUS_LOCKED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "l2_escrow_lock",
            "chain_id": CHAIN_ID,
            "protocol_version": ATOMIC_SWAP_PROTOCOL_VERSION,
            "escrow_id": self.escrow_id,
            "swap_id": self.swap_id,
            "owner_commitment": self.owner_commitment,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "contract_root": self.contract_root,
            "nullifier_root": self.nullifier_root,
            "refund_commitment_root": self.refund_commitment_root,
            "locked_at_height": self.locked_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn escrow_root(&self) -> String {
        atomic_swap_payload_root("L2-ESCROW-LOCK", &self.public_record())
    }

    pub fn validate(&self) -> AtomicSwapResult<String> {
        ensure_non_empty(&self.escrow_id, "l2 escrow id")?;
        ensure_non_empty(&self.swap_id, "l2 escrow swap id")?;
        ensure_non_empty(&self.owner_commitment, "l2 escrow owner")?;
        ensure_non_empty(&self.asset_id, "l2 escrow asset")?;
        ensure_positive(self.amount_units, "l2 escrow amount")?;
        ensure_non_empty(&self.contract_root, "l2 escrow contract")?;
        ensure_non_empty(&self.nullifier_root, "l2 escrow nullifier")?;
        ensure_non_empty(&self.refund_commitment_root, "l2 escrow refund")?;
        if self.expires_at_height <= self.locked_at_height {
            return Err("l2 escrow expiry must follow lock height".to_string());
        }
        Ok(self.escrow_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicSwapIntent {
    pub swap_id: String,
    pub quote_id: String,
    pub taker_commitment: String,
    pub maker_commitment: String,
    pub direction: AtomicSwapDirection,
    pub lock_kind: AtomicSwapLockKind,
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub source_amount_units: u64,
    pub target_amount_units: u64,
    pub adaptor_root: String,
    pub secret_hash_root: String,
    pub encrypted_payload_root: String,
    pub public_metadata_root: String,
    pub monero_evidence_id: Option<String>,
    pub l2_escrow_id: Option<String>,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub refund_available_at_height: u64,
    pub phase: AtomicSwapPhase,
}

impl AtomicSwapIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn from_quote(
        quote: &AtomicSwapQuote,
        taker_commitment: impl Into<String>,
        adaptor_root: impl Into<String>,
        secret_hash_root: impl Into<String>,
        encrypted_payload_root: impl Into<String>,
        public_metadata_root: impl Into<String>,
        submitted_at_height: u64,
        lock_blocks: u64,
        refund_delay_blocks: u64,
    ) -> AtomicSwapResult<Self> {
        quote.validate()?;
        let taker_commitment = taker_commitment.into();
        let adaptor_root = adaptor_root.into();
        let secret_hash_root = secret_hash_root.into();
        let encrypted_payload_root = encrypted_payload_root.into();
        let public_metadata_root = public_metadata_root.into();
        ensure_non_empty(&taker_commitment, "swap taker commitment")?;
        ensure_non_empty(&adaptor_root, "swap adaptor root")?;
        ensure_non_empty(&secret_hash_root, "swap secret hash root")?;
        ensure_non_empty(&encrypted_payload_root, "swap encrypted payload root")?;
        ensure_non_empty(&public_metadata_root, "swap public metadata root")?;
        ensure_positive(lock_blocks, "swap lock blocks")?;
        ensure_positive(refund_delay_blocks, "swap refund delay")?;
        if submitted_at_height >= quote.expires_at_height {
            return Err("swap intent cannot use expired quote".to_string());
        }
        let expires_at_height = submitted_at_height.saturating_add(lock_blocks);
        let refund_available_at_height = expires_at_height.saturating_add(refund_delay_blocks);
        let swap_id = atomic_swap_intent_id(
            &quote.quote_id,
            &taker_commitment,
            &quote.maker_commitment,
            quote.direction,
            quote.lock_kind,
            &quote.source_asset_id,
            &quote.target_asset_id,
            quote.source_amount_units,
            quote.target_amount_units,
            &adaptor_root,
            &secret_hash_root,
            &encrypted_payload_root,
            submitted_at_height,
            expires_at_height,
        );
        Ok(Self {
            swap_id,
            quote_id: quote.quote_id.clone(),
            taker_commitment,
            maker_commitment: quote.maker_commitment.clone(),
            direction: quote.direction,
            lock_kind: quote.lock_kind,
            source_asset_id: quote.source_asset_id.clone(),
            target_asset_id: quote.target_asset_id.clone(),
            source_amount_units: quote.source_amount_units,
            target_amount_units: quote.target_amount_units,
            adaptor_root,
            secret_hash_root,
            encrypted_payload_root,
            public_metadata_root,
            monero_evidence_id: None,
            l2_escrow_id: None,
            submitted_at_height,
            expires_at_height,
            refund_available_at_height,
            phase: AtomicSwapPhase::IntentSubmitted,
        })
    }

    pub fn both_locked(&self) -> bool {
        self.monero_evidence_id.is_some() && self.l2_escrow_id.is_some()
    }

    pub fn set_monero_lock(&mut self, evidence_id: impl Into<String>) {
        self.monero_evidence_id = Some(evidence_id.into());
        self.phase = if self.l2_escrow_id.is_some() {
            AtomicSwapPhase::BothLocked
        } else {
            AtomicSwapPhase::MoneroLocked
        };
    }

    pub fn set_l2_escrow(&mut self, escrow_id: impl Into<String>) {
        self.l2_escrow_id = Some(escrow_id.into());
        self.phase = if self.monero_evidence_id.is_some() {
            AtomicSwapPhase::BothLocked
        } else {
            AtomicSwapPhase::L2Escrowed
        };
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height
            && !matches!(
                self.phase,
                AtomicSwapPhase::Settled | AtomicSwapPhase::Refunded
            )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "atomic_swap_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": ATOMIC_SWAP_PROTOCOL_VERSION,
            "swap_id": self.swap_id,
            "quote_id": self.quote_id,
            "taker_commitment": self.taker_commitment,
            "maker_commitment": self.maker_commitment,
            "direction": self.direction.as_str(),
            "lock_kind": self.lock_kind.as_str(),
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "source_amount_units": self.source_amount_units,
            "target_amount_units": self.target_amount_units,
            "adaptor_root": self.adaptor_root,
            "secret_hash_root": self.secret_hash_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "public_metadata_root": self.public_metadata_root,
            "monero_evidence_id": self.monero_evidence_id,
            "l2_escrow_id": self.l2_escrow_id,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "refund_available_at_height": self.refund_available_at_height,
            "phase": self.phase.as_str(),
        })
    }

    pub fn intent_root(&self) -> String {
        atomic_swap_payload_root("ATOMIC-SWAP-INTENT", &self.public_record())
    }

    pub fn validate(&self) -> AtomicSwapResult<String> {
        ensure_non_empty(&self.swap_id, "swap id")?;
        ensure_non_empty(&self.quote_id, "swap quote id")?;
        ensure_non_empty(&self.taker_commitment, "swap taker")?;
        ensure_non_empty(&self.maker_commitment, "swap maker")?;
        ensure_non_empty(&self.source_asset_id, "swap source asset")?;
        ensure_non_empty(&self.target_asset_id, "swap target asset")?;
        ensure_positive(self.source_amount_units, "swap source amount")?;
        ensure_positive(self.target_amount_units, "swap target amount")?;
        ensure_non_empty(&self.adaptor_root, "swap adaptor root")?;
        ensure_non_empty(&self.secret_hash_root, "swap secret hash root")?;
        ensure_non_empty(&self.encrypted_payload_root, "swap encrypted payload root")?;
        ensure_non_empty(&self.public_metadata_root, "swap public metadata root")?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err("swap expiry must follow submission".to_string());
        }
        if self.refund_available_at_height <= self.expires_at_height {
            return Err("swap refund must follow expiry".to_string());
        }
        Ok(self.intent_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapExecutionPlan {
    pub plan_id: String,
    pub swap_id: String,
    pub monero_evidence_root: String,
    pub l2_escrow_root: String,
    pub adaptor_root: String,
    pub settlement_call_root: String,
    pub low_fee_lane_root: String,
    pub pq_attestation_root: String,
    pub planned_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl SwapExecutionPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent: &AtomicSwapIntent,
        monero_evidence_root: impl Into<String>,
        l2_escrow_root: impl Into<String>,
        settlement_call_root: impl Into<String>,
        low_fee_lane_root: impl Into<String>,
        pq_attestation_root: impl Into<String>,
        planned_at_height: u64,
        ttl_blocks: u64,
    ) -> AtomicSwapResult<Self> {
        intent.validate()?;
        if !intent.both_locked() {
            return Err("swap execution plan requires both locks".to_string());
        }
        let monero_evidence_root = monero_evidence_root.into();
        let l2_escrow_root = l2_escrow_root.into();
        let settlement_call_root = settlement_call_root.into();
        let low_fee_lane_root = low_fee_lane_root.into();
        let pq_attestation_root = pq_attestation_root.into();
        ensure_non_empty(&monero_evidence_root, "swap plan monero evidence root")?;
        ensure_non_empty(&l2_escrow_root, "swap plan l2 escrow root")?;
        ensure_non_empty(&settlement_call_root, "swap plan settlement root")?;
        ensure_non_empty(&low_fee_lane_root, "swap plan low fee root")?;
        ensure_non_empty(&pq_attestation_root, "swap plan pq root")?;
        ensure_positive(ttl_blocks, "swap plan ttl")?;
        let expires_at_height = planned_at_height.saturating_add(ttl_blocks);
        let plan_id = swap_execution_plan_id(
            &intent.swap_id,
            &monero_evidence_root,
            &l2_escrow_root,
            &intent.adaptor_root,
            &settlement_call_root,
            &low_fee_lane_root,
            &pq_attestation_root,
            planned_at_height,
            expires_at_height,
        );
        Ok(Self {
            plan_id,
            swap_id: intent.swap_id.clone(),
            monero_evidence_root,
            l2_escrow_root,
            adaptor_root: intent.adaptor_root.clone(),
            settlement_call_root,
            low_fee_lane_root,
            pq_attestation_root,
            planned_at_height,
            expires_at_height,
            status: ATOMIC_SWAP_STATUS_OPEN.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "swap_execution_plan",
            "chain_id": CHAIN_ID,
            "protocol_version": ATOMIC_SWAP_PROTOCOL_VERSION,
            "plan_id": self.plan_id,
            "swap_id": self.swap_id,
            "monero_evidence_root": self.monero_evidence_root,
            "l2_escrow_root": self.l2_escrow_root,
            "adaptor_root": self.adaptor_root,
            "settlement_call_root": self.settlement_call_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "pq_attestation_root": self.pq_attestation_root,
            "planned_at_height": self.planned_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn plan_root(&self) -> String {
        atomic_swap_payload_root("SWAP-EXECUTION-PLAN", &self.public_record())
    }

    pub fn validate(&self) -> AtomicSwapResult<String> {
        ensure_non_empty(&self.plan_id, "swap plan id")?;
        ensure_non_empty(&self.swap_id, "swap plan swap id")?;
        ensure_non_empty(&self.monero_evidence_root, "swap plan monero root")?;
        ensure_non_empty(&self.l2_escrow_root, "swap plan l2 root")?;
        ensure_non_empty(&self.adaptor_root, "swap plan adaptor root")?;
        ensure_non_empty(&self.settlement_call_root, "swap plan settlement root")?;
        ensure_non_empty(&self.low_fee_lane_root, "swap plan low fee root")?;
        ensure_non_empty(&self.pq_attestation_root, "swap plan pq root")?;
        if self.expires_at_height <= self.planned_at_height {
            return Err("swap plan expiry must follow planning".to_string());
        }
        Ok(self.plan_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapLiquidityPool {
    pub pool_id: String,
    pub operator_commitment: String,
    pub monero_reserve_root: String,
    pub l2_reserve_root: String,
    pub wxmr_capacity_units: u64,
    pub stable_capacity_units: u64,
    pub max_single_swap_units: u64,
    pub fee_bps: u64,
    pub active_quote_root: String,
    pub opened_at_height: u64,
    pub status: String,
}

impl SwapLiquidityPool {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_commitment: impl Into<String>,
        monero_reserve_root: impl Into<String>,
        l2_reserve_root: impl Into<String>,
        wxmr_capacity_units: u64,
        stable_capacity_units: u64,
        max_single_swap_units: u64,
        fee_bps: u64,
        active_quote_root: impl Into<String>,
        opened_at_height: u64,
    ) -> AtomicSwapResult<Self> {
        let operator_commitment = operator_commitment.into();
        let monero_reserve_root = monero_reserve_root.into();
        let l2_reserve_root = l2_reserve_root.into();
        let active_quote_root = active_quote_root.into();
        ensure_non_empty(&operator_commitment, "swap pool operator")?;
        ensure_non_empty(&monero_reserve_root, "swap pool monero reserve")?;
        ensure_non_empty(&l2_reserve_root, "swap pool l2 reserve")?;
        ensure_positive(wxmr_capacity_units, "swap pool wxmr capacity")?;
        ensure_positive(stable_capacity_units, "swap pool stable capacity")?;
        ensure_positive(max_single_swap_units, "swap pool max single swap")?;
        validate_bps(fee_bps, "swap pool fee")?;
        ensure_non_empty(&active_quote_root, "swap pool quote root")?;
        let pool_id = swap_liquidity_pool_id(
            &operator_commitment,
            &monero_reserve_root,
            &l2_reserve_root,
            wxmr_capacity_units,
            stable_capacity_units,
            max_single_swap_units,
            fee_bps,
            &active_quote_root,
            opened_at_height,
        );
        Ok(Self {
            pool_id,
            operator_commitment,
            monero_reserve_root,
            l2_reserve_root,
            wxmr_capacity_units,
            stable_capacity_units,
            max_single_swap_units,
            fee_bps,
            active_quote_root,
            opened_at_height,
            status: ATOMIC_SWAP_STATUS_OPEN.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "swap_liquidity_pool",
            "chain_id": CHAIN_ID,
            "protocol_version": ATOMIC_SWAP_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "operator_commitment": self.operator_commitment,
            "monero_reserve_root": self.monero_reserve_root,
            "l2_reserve_root": self.l2_reserve_root,
            "wxmr_capacity_units": self.wxmr_capacity_units,
            "stable_capacity_units": self.stable_capacity_units,
            "max_single_swap_units": self.max_single_swap_units,
            "fee_bps": self.fee_bps,
            "active_quote_root": self.active_quote_root,
            "opened_at_height": self.opened_at_height,
            "status": self.status,
        })
    }

    pub fn pool_root(&self) -> String {
        atomic_swap_payload_root("SWAP-LIQUIDITY-POOL", &self.public_record())
    }

    pub fn validate(&self) -> AtomicSwapResult<String> {
        ensure_non_empty(&self.pool_id, "swap pool id")?;
        ensure_non_empty(&self.operator_commitment, "swap pool operator")?;
        ensure_non_empty(&self.monero_reserve_root, "swap pool monero root")?;
        ensure_non_empty(&self.l2_reserve_root, "swap pool l2 root")?;
        ensure_positive(self.wxmr_capacity_units, "swap pool wxmr capacity")?;
        ensure_positive(self.stable_capacity_units, "swap pool stable capacity")?;
        ensure_positive(self.max_single_swap_units, "swap pool max swap")?;
        validate_bps(self.fee_bps, "swap pool fee")?;
        ensure_non_empty(&self.active_quote_root, "swap pool quote root")?;
        Ok(self.pool_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub direction: AtomicSwapDirection,
    pub asset_id: String,
    pub total_budget_units: u64,
    pub spent_budget_units: u64,
    pub min_amount_units: u64,
    pub max_rebate_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl SwapSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: impl Into<String>,
        direction: AtomicSwapDirection,
        asset_id: impl Into<String>,
        total_budget_units: u64,
        min_amount_units: u64,
        max_rebate_bps: u64,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> AtomicSwapResult<Self> {
        let sponsor_commitment = sponsor_commitment.into();
        let asset_id = asset_id.into();
        ensure_non_empty(&sponsor_commitment, "swap sponsor")?;
        ensure_non_empty(&asset_id, "swap sponsorship asset")?;
        ensure_positive(total_budget_units, "swap sponsorship budget")?;
        ensure_positive(min_amount_units, "swap sponsorship min amount")?;
        validate_bps(max_rebate_bps, "swap sponsorship max rebate")?;
        if expires_at_height <= opened_at_height {
            return Err("swap sponsorship expiry must follow open".to_string());
        }
        let sponsorship_id = swap_sponsorship_id(
            &sponsor_commitment,
            direction,
            &asset_id,
            total_budget_units,
            min_amount_units,
            max_rebate_bps,
            opened_at_height,
            expires_at_height,
        );
        Ok(Self {
            sponsorship_id,
            sponsor_commitment,
            direction,
            asset_id,
            total_budget_units,
            spent_budget_units: 0,
            min_amount_units,
            max_rebate_bps,
            opened_at_height,
            expires_at_height,
            status: ATOMIC_SWAP_STATUS_OPEN.to_string(),
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status == ATOMIC_SWAP_STATUS_OPEN {
            self.status = ATOMIC_SWAP_STATUS_EXPIRED.to_string();
        }
    }

    pub fn available_units(&self, height: u64) -> u64 {
        if height >= self.expires_at_height || self.status != ATOMIC_SWAP_STATUS_OPEN {
            0
        } else {
            self.total_budget_units
                .saturating_sub(self.spent_budget_units)
        }
    }

    pub fn can_sponsor(&self, quote: &AtomicSwapQuote, height: u64) -> bool {
        self.available_units(height) > 0
            && quote.direction == self.direction
            && quote.source_asset_id == self.asset_id
            && quote.source_amount_units >= self.min_amount_units
            && quote.low_fee_eligible
    }

    pub fn charge(&mut self, units: u64, height: u64) -> AtomicSwapResult<()> {
        if self.available_units(height) < units {
            return Err("swap sponsorship budget insufficient".to_string());
        }
        self.spent_budget_units = self.spent_budget_units.saturating_add(units);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "swap_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": ATOMIC_SWAP_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "direction": self.direction.as_str(),
            "asset_id": self.asset_id,
            "total_budget_units": self.total_budget_units,
            "spent_budget_units": self.spent_budget_units,
            "remaining_budget_units": self.total_budget_units.saturating_sub(self.spent_budget_units),
            "min_amount_units": self.min_amount_units,
            "max_rebate_bps": self.max_rebate_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        atomic_swap_payload_root("SWAP-SPONSORSHIP", &self.public_record())
    }

    pub fn validate(&self) -> AtomicSwapResult<String> {
        ensure_non_empty(&self.sponsorship_id, "swap sponsorship id")?;
        ensure_non_empty(&self.sponsor_commitment, "swap sponsorship sponsor")?;
        ensure_non_empty(&self.asset_id, "swap sponsorship asset")?;
        ensure_positive(self.total_budget_units, "swap sponsorship budget")?;
        if self.spent_budget_units > self.total_budget_units {
            return Err("swap sponsorship spent exceeds budget".to_string());
        }
        ensure_positive(self.min_amount_units, "swap sponsorship min amount")?;
        validate_bps(self.max_rebate_bps, "swap sponsorship max rebate")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("swap sponsorship expiry must follow open".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSwapAttestation {
    pub attestation_id: String,
    pub role: AtomicSwapAttestationRole,
    pub signer_commitment: String,
    pub subject_id: String,
    pub subject_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PqSwapAttestation {
    pub fn sign(
        role: AtomicSwapAttestationRole,
        signer_label: &str,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        signed_at_height: u64,
        ttl_blocks: u64,
    ) -> AtomicSwapResult<Self> {
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        ensure_non_empty(signer_label, "swap attestation signer")?;
        ensure_non_empty(&subject_id, "swap attestation subject id")?;
        ensure_non_empty(&subject_root, "swap attestation subject root")?;
        ensure_positive(ttl_blocks, "swap attestation ttl")?;
        let signer_commitment = atomic_swap_string_root("SWAP-ATTESTATION-SIGNER", signer_label);
        let transcript_root = atomic_swap_payload_root(
            "SWAP-ATTESTATION-TRANSCRIPT",
            &json!({
                "role": role.as_str(),
                "subject_id": subject_id,
                "subject_root": subject_root,
                "signed_at_height": signed_at_height,
            }),
        );
        let signature_root = atomic_swap_signature_root(signer_label, &transcript_root);
        let expires_at_height = signed_at_height.saturating_add(ttl_blocks);
        let attestation_id = pq_swap_attestation_id(
            role,
            &signer_commitment,
            &subject_id,
            &subject_root,
            &transcript_root,
            &signature_root,
            signed_at_height,
            expires_at_height,
        );
        Ok(Self {
            attestation_id,
            role,
            signer_commitment,
            subject_id,
            subject_root,
            transcript_root,
            signature_root,
            signed_at_height,
            expires_at_height,
            status: ATOMIC_SWAP_STATUS_OPEN.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_swap_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": ATOMIC_SWAP_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "role": self.role.as_str(),
            "signer_commitment": self.signer_commitment,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn attestation_root(&self) -> String {
        atomic_swap_payload_root("PQ-SWAP-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> AtomicSwapResult<String> {
        ensure_non_empty(&self.attestation_id, "swap attestation id")?;
        ensure_non_empty(&self.signer_commitment, "swap attestation signer")?;
        ensure_non_empty(&self.subject_id, "swap attestation subject")?;
        ensure_non_empty(&self.subject_root, "swap attestation subject root")?;
        ensure_non_empty(&self.transcript_root, "swap attestation transcript")?;
        ensure_non_empty(&self.signature_root, "swap attestation signature")?;
        if self.expires_at_height <= self.signed_at_height {
            return Err("swap attestation expiry must follow signing".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapSettlementReceipt {
    pub receipt_id: String,
    pub swap_id: String,
    pub plan_id: String,
    pub monero_release_root: String,
    pub l2_release_root: String,
    pub fee_receipt_root: String,
    pub secret_reveal_root: String,
    pub attestation_root: String,
    pub settled_at_height: u64,
    pub status: String,
}

impl SwapSettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan: &SwapExecutionPlan,
        monero_release_root: impl Into<String>,
        l2_release_root: impl Into<String>,
        fee_receipt_root: impl Into<String>,
        secret_reveal_root: impl Into<String>,
        attestation_root: impl Into<String>,
        settled_at_height: u64,
    ) -> AtomicSwapResult<Self> {
        plan.validate()?;
        let monero_release_root = monero_release_root.into();
        let l2_release_root = l2_release_root.into();
        let fee_receipt_root = fee_receipt_root.into();
        let secret_reveal_root = secret_reveal_root.into();
        let attestation_root = attestation_root.into();
        ensure_non_empty(&monero_release_root, "swap settlement monero release")?;
        ensure_non_empty(&l2_release_root, "swap settlement l2 release")?;
        ensure_non_empty(&fee_receipt_root, "swap settlement fee receipt")?;
        ensure_non_empty(&secret_reveal_root, "swap settlement secret root")?;
        ensure_non_empty(&attestation_root, "swap settlement attestation root")?;
        let receipt_id = swap_settlement_receipt_id(
            &plan.swap_id,
            &plan.plan_id,
            &monero_release_root,
            &l2_release_root,
            &fee_receipt_root,
            &secret_reveal_root,
            &attestation_root,
            settled_at_height,
        );
        Ok(Self {
            receipt_id,
            swap_id: plan.swap_id.clone(),
            plan_id: plan.plan_id.clone(),
            monero_release_root,
            l2_release_root,
            fee_receipt_root,
            secret_reveal_root,
            attestation_root,
            settled_at_height,
            status: ATOMIC_SWAP_STATUS_SETTLED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "swap_settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": ATOMIC_SWAP_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "swap_id": self.swap_id,
            "plan_id": self.plan_id,
            "monero_release_root": self.monero_release_root,
            "l2_release_root": self.l2_release_root,
            "fee_receipt_root": self.fee_receipt_root,
            "secret_reveal_root": self.secret_reveal_root,
            "attestation_root": self.attestation_root,
            "settled_at_height": self.settled_at_height,
            "status": self.status,
        })
    }

    pub fn receipt_root(&self) -> String {
        atomic_swap_payload_root("SWAP-SETTLEMENT-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> AtomicSwapResult<String> {
        ensure_non_empty(&self.receipt_id, "swap settlement receipt id")?;
        ensure_non_empty(&self.swap_id, "swap settlement swap id")?;
        ensure_non_empty(&self.plan_id, "swap settlement plan id")?;
        ensure_non_empty(&self.monero_release_root, "swap settlement monero root")?;
        ensure_non_empty(&self.l2_release_root, "swap settlement l2 root")?;
        ensure_non_empty(&self.fee_receipt_root, "swap settlement fee root")?;
        ensure_non_empty(&self.secret_reveal_root, "swap settlement secret root")?;
        ensure_non_empty(&self.attestation_root, "swap settlement attestation")?;
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapRefundEnvelope {
    pub refund_id: String,
    pub swap_id: String,
    pub refund_side: AtomicSwapDirection,
    pub refund_commitment_root: String,
    pub timeout_evidence_root: String,
    pub refund_fee_root: String,
    pub pq_attestation_root: String,
    pub requested_at_height: u64,
    pub executable_at_height: u64,
    pub status: String,
}

impl SwapRefundEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent: &AtomicSwapIntent,
        refund_commitment_root: impl Into<String>,
        timeout_evidence_root: impl Into<String>,
        refund_fee_root: impl Into<String>,
        pq_attestation_root: impl Into<String>,
        requested_at_height: u64,
    ) -> AtomicSwapResult<Self> {
        intent.validate()?;
        let refund_commitment_root = refund_commitment_root.into();
        let timeout_evidence_root = timeout_evidence_root.into();
        let refund_fee_root = refund_fee_root.into();
        let pq_attestation_root = pq_attestation_root.into();
        ensure_non_empty(&refund_commitment_root, "swap refund commitment")?;
        ensure_non_empty(&timeout_evidence_root, "swap refund timeout evidence")?;
        ensure_non_empty(&refund_fee_root, "swap refund fee root")?;
        ensure_non_empty(&pq_attestation_root, "swap refund pq root")?;
        if requested_at_height < intent.refund_available_at_height {
            return Err("swap refund requested before refund height".to_string());
        }
        let refund_id = swap_refund_envelope_id(
            &intent.swap_id,
            intent.direction,
            &refund_commitment_root,
            &timeout_evidence_root,
            &refund_fee_root,
            &pq_attestation_root,
            requested_at_height,
            intent.refund_available_at_height,
        );
        Ok(Self {
            refund_id,
            swap_id: intent.swap_id.clone(),
            refund_side: intent.direction,
            refund_commitment_root,
            timeout_evidence_root,
            refund_fee_root,
            pq_attestation_root,
            requested_at_height,
            executable_at_height: intent.refund_available_at_height,
            status: ATOMIC_SWAP_STATUS_REFUNDED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "swap_refund_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": ATOMIC_SWAP_PROTOCOL_VERSION,
            "refund_id": self.refund_id,
            "swap_id": self.swap_id,
            "refund_side": self.refund_side.as_str(),
            "refund_commitment_root": self.refund_commitment_root,
            "timeout_evidence_root": self.timeout_evidence_root,
            "refund_fee_root": self.refund_fee_root,
            "pq_attestation_root": self.pq_attestation_root,
            "requested_at_height": self.requested_at_height,
            "executable_at_height": self.executable_at_height,
            "status": self.status,
        })
    }

    pub fn refund_root(&self) -> String {
        atomic_swap_payload_root("SWAP-REFUND-ENVELOPE", &self.public_record())
    }

    pub fn validate(&self) -> AtomicSwapResult<String> {
        ensure_non_empty(&self.refund_id, "swap refund id")?;
        ensure_non_empty(&self.swap_id, "swap refund swap id")?;
        ensure_non_empty(&self.refund_commitment_root, "swap refund commitment")?;
        ensure_non_empty(&self.timeout_evidence_root, "swap refund timeout")?;
        ensure_non_empty(&self.refund_fee_root, "swap refund fee root")?;
        ensure_non_empty(&self.pq_attestation_root, "swap refund pq root")?;
        if self.requested_at_height < self.executable_at_height {
            return Err("swap refund requested too early".to_string());
        }
        Ok(self.refund_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapChallenge {
    pub challenge_id: String,
    pub swap_id: String,
    pub challenge_kind: AtomicSwapChallengeKind,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub disputed_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub bond_units: u64,
    pub status: String,
}

impl SwapChallenge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        swap_id: impl Into<String>,
        challenge_kind: AtomicSwapChallengeKind,
        challenger_commitment: impl Into<String>,
        evidence_root: impl Into<String>,
        disputed_root: impl Into<String>,
        opened_at_height: u64,
        ttl_blocks: u64,
        bond_units: u64,
    ) -> AtomicSwapResult<Self> {
        let swap_id = swap_id.into();
        let challenger_commitment = challenger_commitment.into();
        let evidence_root = evidence_root.into();
        let disputed_root = disputed_root.into();
        ensure_non_empty(&swap_id, "swap challenge swap id")?;
        ensure_non_empty(&challenger_commitment, "swap challenge challenger")?;
        ensure_non_empty(&evidence_root, "swap challenge evidence")?;
        ensure_non_empty(&disputed_root, "swap challenge disputed root")?;
        ensure_positive(ttl_blocks, "swap challenge ttl")?;
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let challenge_id = swap_challenge_id(
            &swap_id,
            challenge_kind,
            &challenger_commitment,
            &evidence_root,
            &disputed_root,
            opened_at_height,
            expires_at_height,
            bond_units,
        );
        Ok(Self {
            challenge_id,
            swap_id,
            challenge_kind,
            challenger_commitment,
            evidence_root,
            disputed_root,
            opened_at_height,
            expires_at_height,
            bond_units,
            status: ATOMIC_SWAP_STATUS_CHALLENGED.to_string(),
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status == ATOMIC_SWAP_STATUS_CHALLENGED {
            self.status = ATOMIC_SWAP_STATUS_EXPIRED.to_string();
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "swap_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": ATOMIC_SWAP_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "swap_id": self.swap_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "disputed_root": self.disputed_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "bond_units": self.bond_units,
            "status": self.status,
        })
    }

    pub fn challenge_root(&self) -> String {
        atomic_swap_payload_root("SWAP-CHALLENGE", &self.public_record())
    }

    pub fn validate(&self) -> AtomicSwapResult<String> {
        ensure_non_empty(&self.challenge_id, "swap challenge id")?;
        ensure_non_empty(&self.swap_id, "swap challenge swap id")?;
        ensure_non_empty(&self.challenger_commitment, "swap challenge challenger")?;
        ensure_non_empty(&self.evidence_root, "swap challenge evidence")?;
        ensure_non_empty(&self.disputed_root, "swap challenge disputed root")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("swap challenge expiry must follow open".to_string());
        }
        Ok(self.challenge_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicSwapRoots {
    pub config_root: String,
    pub quote_root: String,
    pub intent_root: String,
    pub monero_evidence_root: String,
    pub l2_escrow_root: String,
    pub execution_plan_root: String,
    pub liquidity_pool_root: String,
    pub sponsorship_root: String,
    pub pq_attestation_root: String,
    pub settlement_receipt_root: String,
    pub refund_root: String,
    pub challenge_root: String,
}

impl AtomicSwapRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "atomic_swap_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": ATOMIC_SWAP_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "quote_root": self.quote_root,
            "intent_root": self.intent_root,
            "monero_evidence_root": self.monero_evidence_root,
            "l2_escrow_root": self.l2_escrow_root,
            "execution_plan_root": self.execution_plan_root,
            "liquidity_pool_root": self.liquidity_pool_root,
            "sponsorship_root": self.sponsorship_root,
            "pq_attestation_root": self.pq_attestation_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "refund_root": self.refund_root,
            "challenge_root": self.challenge_root,
        })
    }

    pub fn roots_root(&self) -> String {
        atomic_swap_payload_root("ATOMIC-SWAP-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicSwapState {
    pub height: u64,
    pub config: AtomicSwapConfig,
    pub quotes: BTreeMap<String, AtomicSwapQuote>,
    pub intents: BTreeMap<String, AtomicSwapIntent>,
    pub monero_evidence: BTreeMap<String, MoneroLockEvidence>,
    pub l2_escrows: BTreeMap<String, L2EscrowLock>,
    pub execution_plans: BTreeMap<String, SwapExecutionPlan>,
    pub liquidity_pools: BTreeMap<String, SwapLiquidityPool>,
    pub sponsorships: BTreeMap<String, SwapSponsorship>,
    pub attestations: BTreeMap<String, PqSwapAttestation>,
    pub settlements: BTreeMap<String, SwapSettlementReceipt>,
    pub refunds: BTreeMap<String, SwapRefundEnvelope>,
    pub challenges: BTreeMap<String, SwapChallenge>,
}

impl Default for AtomicSwapState {
    fn default() -> Self {
        Self {
            height: 0,
            config: AtomicSwapConfig::default(),
            quotes: BTreeMap::new(),
            intents: BTreeMap::new(),
            monero_evidence: BTreeMap::new(),
            l2_escrows: BTreeMap::new(),
            execution_plans: BTreeMap::new(),
            liquidity_pools: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            refunds: BTreeMap::new(),
            challenges: BTreeMap::new(),
        }
    }
}

impl AtomicSwapState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet(operator_label: &str) -> AtomicSwapResult<Self> {
        ensure_non_empty(operator_label, "atomic swap operator label")?;
        let mut state = Self::new();
        state.set_height(16);
        let maker = atomic_swap_string_root("ATOMIC-SWAP-DEVNET-MAKER", operator_label);
        let taker = atomic_swap_string_root("ATOMIC-SWAP-DEVNET-TAKER", "alice");
        let route_root = atomic_swap_payload_root(
            "ATOMIC-SWAP-DEVNET-ROUTE",
            &json!({
                "monero_network": state.config.monero_network,
                "l2_asset": state.config.wxmr_asset_id,
                "privacy": "roots_only",
            }),
        );
        let price_root = atomic_swap_payload_root(
            "ATOMIC-SWAP-DEVNET-PRICE",
            &json!({"wxmr_usdd": 178_000_000_000_u64, "decimals": 8_u64}),
        );
        let quote = AtomicSwapQuote::new(
            maker.clone(),
            AtomicSwapDirection::MoneroToL2,
            state.config.wxmr_asset_id.clone(),
            state.config.stable_asset_id.clone(),
            1_000_000_000_000,
            178_000_000_000,
            45_000,
            state.config.max_slippage_bps,
            AtomicSwapLockKind::AdaptorSignature,
            route_root.clone(),
            price_root,
            true,
            state.height,
            state
                .height
                .saturating_add(state.config.default_quote_ttl_blocks),
        )?;
        let quote_id = state.insert_quote(quote.clone())?;
        let sponsorship = SwapSponsorship::new(
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-SPONSOR", "foundation"),
            AtomicSwapDirection::MoneroToL2,
            state.config.wxmr_asset_id.clone(),
            500_000,
            1_000_000_000,
            state.config.low_fee_rebate_bps,
            state.height,
            state
                .height
                .saturating_add(ATOMIC_SWAP_DEFAULT_SPONSOR_TTL_BLOCKS),
        )?;
        let sponsorship_id = state.insert_sponsorship(sponsorship)?;
        let pool = SwapLiquidityPool::new(
            maker.clone(),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-MONERO-RESERVE", "reserve-wallet"),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-L2-RESERVE", "l2-vault"),
            25_000_000_000_000,
            4_500_000_000_000,
            2_500_000_000_000,
            35,
            state.quote_root(),
            state.height,
        )?;
        state.insert_liquidity_pool(pool)?;
        let mut intent = AtomicSwapIntent::from_quote(
            &quote,
            taker.clone(),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-ADAPTOR", "alice"),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-SECRET", "alice"),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-ENCRYPTED-PAYLOAD", "alice"),
            atomic_swap_payload_root(
                "ATOMIC-SWAP-DEVNET-METADATA",
                &json!({"quote_id": quote_id, "wallet": "alice"}),
            ),
            state.height,
            state.config.default_lock_blocks,
            state.config.default_refund_delay_blocks,
        )?;
        let swap_id = intent.swap_id.clone();
        let evidence = MoneroLockEvidence::new(
            swap_id.clone(),
            state.config.monero_network.clone(),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-MONERO-TXID", "tx-a"),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-MONERO-OUTPUT", "output-a"),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-MONERO-KEY-IMAGE", "unspent-a"),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-VIEW-TAG", "view-a"),
            1_000_000_000_000,
            state.height.saturating_add(3),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-WATCHER", "watcher-a"),
            state
                .height
                .saturating_add(state.config.default_lock_blocks),
        )?;
        intent.set_monero_lock(evidence.evidence_id.clone());
        let escrow = L2EscrowLock::new(
            swap_id.clone(),
            maker.clone(),
            state.config.stable_asset_id.clone(),
            178_000_000_000,
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-CONTRACT", "swap-escrow"),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-NULLIFIER", "escrow-a"),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-REFUND", "maker-refund"),
            state.height.saturating_add(2),
            state
                .height
                .saturating_add(state.config.default_lock_blocks),
        )?;
        intent.set_l2_escrow(escrow.escrow_id.clone());
        state.insert_intent(intent.clone())?;
        state.insert_monero_evidence(evidence.clone())?;
        state.insert_l2_escrow(escrow.clone())?;
        let coordinator_attestation = PqSwapAttestation::sign(
            AtomicSwapAttestationRole::Coordinator,
            ATOMIC_SWAP_DEVNET_SWAP_COORDINATOR,
            swap_id.clone(),
            intent.intent_root(),
            state.height,
            state.config.default_challenge_window_blocks,
        )?;
        let attestation_root = coordinator_attestation.attestation_root();
        state.insert_attestation(coordinator_attestation)?;
        let plan = SwapExecutionPlan::new(
            &intent,
            evidence.evidence_root(),
            escrow.escrow_root(),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-SETTLEMENT-CALL", "settle-a"),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-LOW-FEE-LANE", &sponsorship_id),
            attestation_root.clone(),
            state.height.saturating_add(4),
            state.config.default_challenge_window_blocks,
        )?;
        let plan_id = state.insert_execution_plan(plan.clone())?;
        state.apply_sponsorship(&quote_id, &sponsorship_id)?;
        let settlement_attestation = PqSwapAttestation::sign(
            AtomicSwapAttestationRole::L2Sequencer,
            operator_label,
            plan_id,
            plan.plan_root(),
            state.height.saturating_add(5),
            state.config.default_challenge_window_blocks,
        )?;
        let settlement_attestation_root = settlement_attestation.attestation_root();
        state.insert_attestation(settlement_attestation)?;
        let receipt = SwapSettlementReceipt::new(
            &plan,
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-MONERO-RELEASE", "release-a"),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-L2-RELEASE", "release-a"),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-FEE-RECEIPT", "fee-a"),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-SECRET-REVEAL", "secret-a"),
            settlement_attestation_root,
            state.height.saturating_add(6),
        )?;
        state.insert_settlement(receipt)?;
        let challenge = SwapChallenge::new(
            swap_id,
            AtomicSwapChallengeKind::WatcherEquivocation,
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-CHALLENGER", "watchtower"),
            atomic_swap_string_root("ATOMIC-SWAP-DEVNET-CHALLENGE-EVIDENCE", "watcher-sample"),
            state.monero_evidence_root(),
            state.height.saturating_add(7),
            state.config.default_challenge_window_blocks,
            25_000,
        )?;
        state.insert_challenge(challenge)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for quote in self.quotes.values_mut() {
            if quote.status == ATOMIC_SWAP_STATUS_OPEN && quote.is_expired_at(height) {
                quote.status = ATOMIC_SWAP_STATUS_EXPIRED.to_string();
            }
        }
        for intent in self.intents.values_mut() {
            if intent.is_expired_at(height) {
                intent.phase = AtomicSwapPhase::Expired;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            sponsorship.set_height(height);
        }
        for challenge in self.challenges.values_mut() {
            challenge.set_height(height);
        }
    }

    pub fn insert_quote(&mut self, quote: AtomicSwapQuote) -> AtomicSwapResult<String> {
        if self.quotes.len() >= ATOMIC_SWAP_MAX_QUOTES && !self.quotes.contains_key(&quote.quote_id)
        {
            return Err("atomic swap quote limit exceeded".to_string());
        }
        quote.validate()?;
        let quote_id = quote.quote_id.clone();
        self.quotes.insert(quote_id.clone(), quote);
        Ok(quote_id)
    }

    pub fn insert_intent(&mut self, intent: AtomicSwapIntent) -> AtomicSwapResult<String> {
        if self.intents.len() >= ATOMIC_SWAP_MAX_INTENTS
            && !self.intents.contains_key(&intent.swap_id)
        {
            return Err("atomic swap intent limit exceeded".to_string());
        }
        intent.validate()?;
        if !self.quotes.contains_key(&intent.quote_id) {
            return Err("swap intent references unknown quote".to_string());
        }
        let swap_id = intent.swap_id.clone();
        self.intents.insert(swap_id.clone(), intent);
        Ok(swap_id)
    }

    pub fn insert_monero_evidence(
        &mut self,
        evidence: MoneroLockEvidence,
    ) -> AtomicSwapResult<String> {
        evidence.validate()?;
        if let Some(intent) = self.intents.get_mut(&evidence.swap_id) {
            intent.set_monero_lock(evidence.evidence_id.clone());
        }
        let evidence_id = evidence.evidence_id.clone();
        self.monero_evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn insert_l2_escrow(&mut self, escrow: L2EscrowLock) -> AtomicSwapResult<String> {
        escrow.validate()?;
        if let Some(intent) = self.intents.get_mut(&escrow.swap_id) {
            intent.set_l2_escrow(escrow.escrow_id.clone());
        }
        let escrow_id = escrow.escrow_id.clone();
        self.l2_escrows.insert(escrow_id.clone(), escrow);
        Ok(escrow_id)
    }

    pub fn insert_execution_plan(&mut self, plan: SwapExecutionPlan) -> AtomicSwapResult<String> {
        plan.validate()?;
        if !self.intents.contains_key(&plan.swap_id) {
            return Err("swap plan references unknown intent".to_string());
        }
        let plan_id = plan.plan_id.clone();
        self.execution_plans.insert(plan_id.clone(), plan);
        Ok(plan_id)
    }

    pub fn insert_liquidity_pool(&mut self, pool: SwapLiquidityPool) -> AtomicSwapResult<String> {
        pool.validate()?;
        let pool_id = pool.pool_id.clone();
        self.liquidity_pools.insert(pool_id.clone(), pool);
        Ok(pool_id)
    }

    pub fn insert_sponsorship(&mut self, sponsorship: SwapSponsorship) -> AtomicSwapResult<String> {
        sponsorship.validate()?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        Ok(sponsorship_id)
    }

    pub fn insert_attestation(
        &mut self,
        attestation: PqSwapAttestation,
    ) -> AtomicSwapResult<String> {
        if self.attestations.len() >= ATOMIC_SWAP_MAX_ATTESTATIONS
            && !self.attestations.contains_key(&attestation.attestation_id)
        {
            return Err("swap attestation limit exceeded".to_string());
        }
        attestation.validate()?;
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn insert_settlement(
        &mut self,
        receipt: SwapSettlementReceipt,
    ) -> AtomicSwapResult<String> {
        receipt.validate()?;
        if let Some(intent) = self.intents.get_mut(&receipt.swap_id) {
            intent.phase = AtomicSwapPhase::Settled;
        }
        let receipt_id = receipt.receipt_id.clone();
        self.settlements.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn insert_refund(&mut self, refund: SwapRefundEnvelope) -> AtomicSwapResult<String> {
        refund.validate()?;
        if let Some(intent) = self.intents.get_mut(&refund.swap_id) {
            intent.phase = AtomicSwapPhase::Refunded;
        }
        let refund_id = refund.refund_id.clone();
        self.refunds.insert(refund_id.clone(), refund);
        Ok(refund_id)
    }

    pub fn insert_challenge(&mut self, challenge: SwapChallenge) -> AtomicSwapResult<String> {
        challenge.validate()?;
        if let Some(intent) = self.intents.get_mut(&challenge.swap_id) {
            if !matches!(
                intent.phase,
                AtomicSwapPhase::Settled | AtomicSwapPhase::Refunded
            ) {
                intent.phase = AtomicSwapPhase::Challenged;
            }
        }
        let challenge_id = challenge.challenge_id.clone();
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn apply_sponsorship(
        &mut self,
        quote_id: &str,
        sponsorship_id: &str,
    ) -> AtomicSwapResult<u64> {
        let quote = self
            .quotes
            .get(quote_id)
            .ok_or_else(|| "swap sponsorship quote unknown".to_string())?;
        let sponsorship = self
            .sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "swap sponsorship unknown".to_string())?;
        if !sponsorship.can_sponsor(quote, self.height) {
            return Err("swap quote is not eligible for sponsorship".to_string());
        }
        let rebate = quote
            .fee_units
            .saturating_mul(sponsorship.max_rebate_bps)
            .saturating_div(ATOMIC_SWAP_MAX_BPS)
            .min(sponsorship.available_units(self.height));
        sponsorship.charge(rebate, self.height)?;
        Ok(rebate)
    }

    pub fn roots(&self) -> AtomicSwapRoots {
        AtomicSwapRoots {
            config_root: self.config.config_root(),
            quote_root: self.quote_root(),
            intent_root: self.intent_root(),
            monero_evidence_root: self.monero_evidence_root(),
            l2_escrow_root: self.l2_escrow_root(),
            execution_plan_root: self.execution_plan_root(),
            liquidity_pool_root: self.liquidity_pool_root(),
            sponsorship_root: self.sponsorship_root(),
            pq_attestation_root: self.pq_attestation_root(),
            settlement_receipt_root: self.settlement_receipt_root(),
            refund_root: self.refund_root(),
            challenge_root: self.challenge_root(),
        }
    }

    pub fn quote_root(&self) -> String {
        atomic_swap_quote_collection_root(&self.quotes.values().cloned().collect::<Vec<_>>())
    }

    pub fn intent_root(&self) -> String {
        atomic_swap_intent_collection_root(&self.intents.values().cloned().collect::<Vec<_>>())
    }

    pub fn monero_evidence_root(&self) -> String {
        monero_lock_evidence_collection_root(
            &self.monero_evidence.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn l2_escrow_root(&self) -> String {
        l2_escrow_collection_root(&self.l2_escrows.values().cloned().collect::<Vec<_>>())
    }

    pub fn execution_plan_root(&self) -> String {
        swap_execution_plan_collection_root(
            &self.execution_plans.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn liquidity_pool_root(&self) -> String {
        swap_liquidity_pool_collection_root(
            &self.liquidity_pools.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn sponsorship_root(&self) -> String {
        swap_sponsorship_collection_root(&self.sponsorships.values().cloned().collect::<Vec<_>>())
    }

    pub fn pq_attestation_root(&self) -> String {
        pq_swap_attestation_collection_root(
            &self.attestations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn settlement_receipt_root(&self) -> String {
        swap_settlement_collection_root(&self.settlements.values().cloned().collect::<Vec<_>>())
    }

    pub fn refund_root(&self) -> String {
        swap_refund_collection_root(&self.refunds.values().cloned().collect::<Vec<_>>())
    }

    pub fn challenge_root(&self) -> String {
        swap_challenge_collection_root(&self.challenges.values().cloned().collect::<Vec<_>>())
    }

    pub fn open_swap_count(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| {
                !matches!(
                    intent.phase,
                    AtomicSwapPhase::Settled | AtomicSwapPhase::Refunded | AtomicSwapPhase::Expired
                )
            })
            .count() as u64
    }

    pub fn settled_swap_count(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| intent.phase == AtomicSwapPhase::Settled)
            .count() as u64
    }

    pub fn available_sponsorship_units(&self) -> u64 {
        self.sponsorships
            .values()
            .map(|sponsorship| sponsorship.available_units(self.height))
            .sum()
    }

    pub fn state_root(&self) -> String {
        atomic_swap_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("atomic swap state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "atomic_swap_state",
            "chain_id": CHAIN_ID,
            "protocol_version": ATOMIC_SWAP_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "quote_count": self.quotes.len() as u64,
            "intent_count": self.intents.len() as u64,
            "open_swap_count": self.open_swap_count(),
            "settled_swap_count": self.settled_swap_count(),
            "monero_evidence_count": self.monero_evidence.len() as u64,
            "l2_escrow_count": self.l2_escrows.len() as u64,
            "execution_plan_count": self.execution_plans.len() as u64,
            "liquidity_pool_count": self.liquidity_pools.len() as u64,
            "sponsorship_count": self.sponsorships.len() as u64,
            "available_sponsorship_units": self.available_sponsorship_units(),
            "attestation_count": self.attestations.len() as u64,
            "settlement_count": self.settlements.len() as u64,
            "refund_count": self.refunds.len() as u64,
            "challenge_count": self.challenges.len() as u64,
        })
    }

    pub fn validate(&self) -> AtomicSwapResult<String> {
        self.config.validate()?;
        for quote in self.quotes.values() {
            quote.validate()?;
        }
        for intent in self.intents.values() {
            intent.validate()?;
            if !self.quotes.contains_key(&intent.quote_id) {
                return Err("swap intent references unknown quote".to_string());
            }
            if let Some(evidence_id) = &intent.monero_evidence_id {
                if !self.monero_evidence.contains_key(evidence_id) {
                    return Err("swap intent references unknown monero evidence".to_string());
                }
            }
            if let Some(escrow_id) = &intent.l2_escrow_id {
                if !self.l2_escrows.contains_key(escrow_id) {
                    return Err("swap intent references unknown l2 escrow".to_string());
                }
            }
        }
        for evidence in self.monero_evidence.values() {
            evidence.validate()?;
        }
        for escrow in self.l2_escrows.values() {
            escrow.validate()?;
        }
        for plan in self.execution_plans.values() {
            plan.validate()?;
            if !self.intents.contains_key(&plan.swap_id) {
                return Err("swap plan references unknown intent".to_string());
            }
        }
        for pool in self.liquidity_pools.values() {
            pool.validate()?;
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
        }
        for settlement in self.settlements.values() {
            settlement.validate()?;
            if !self.intents.contains_key(&settlement.swap_id) {
                return Err("swap settlement references unknown intent".to_string());
            }
        }
        for refund in self.refunds.values() {
            refund.validate()?;
            if !self.intents.contains_key(&refund.swap_id) {
                return Err("swap refund references unknown intent".to_string());
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn atomic_swap_config_id(payload: &Value) -> String {
    atomic_swap_payload_root("ATOMIC-SWAP-CONFIG-ID", payload)
}

#[allow(clippy::too_many_arguments)]
pub fn atomic_swap_quote_id(
    maker_commitment: &str,
    direction: AtomicSwapDirection,
    source_asset_id: &str,
    target_asset_id: &str,
    source_amount_units: u64,
    target_amount_units: u64,
    fee_units: u64,
    max_slippage_bps: u64,
    lock_kind: AtomicSwapLockKind,
    route_root: &str,
    price_root: &str,
    created_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "ATOMIC-SWAP-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(maker_commitment),
            HashPart::Str(direction.as_str()),
            HashPart::Str(source_asset_id),
            HashPart::Str(target_asset_id),
            HashPart::Int(source_amount_units as i128),
            HashPart::Int(target_amount_units as i128),
            HashPart::Int(fee_units as i128),
            HashPart::Int(max_slippage_bps as i128),
            HashPart::Str(lock_kind.as_str()),
            HashPart::Str(route_root),
            HashPart::Str(price_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn atomic_swap_intent_id(
    quote_id: &str,
    taker_commitment: &str,
    maker_commitment: &str,
    direction: AtomicSwapDirection,
    lock_kind: AtomicSwapLockKind,
    source_asset_id: &str,
    target_asset_id: &str,
    source_amount_units: u64,
    target_amount_units: u64,
    adaptor_root: &str,
    secret_hash_root: &str,
    encrypted_payload_root: &str,
    submitted_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "ATOMIC-SWAP-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(quote_id),
            HashPart::Str(taker_commitment),
            HashPart::Str(maker_commitment),
            HashPart::Str(direction.as_str()),
            HashPart::Str(lock_kind.as_str()),
            HashPart::Str(source_asset_id),
            HashPart::Str(target_asset_id),
            HashPart::Int(source_amount_units as i128),
            HashPart::Int(target_amount_units as i128),
            HashPart::Str(adaptor_root),
            HashPart::Str(secret_hash_root),
            HashPart::Str(encrypted_payload_root),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn monero_lock_evidence_id(
    swap_id: &str,
    monero_network: &str,
    txid_root: &str,
    output_commitment_root: &str,
    key_image_root: &str,
    view_tag_root: &str,
    amount_bucket: u64,
    confirmation_height: u64,
    observed_by_commitment: &str,
    lock_expires_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-LOCK-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(swap_id),
            HashPart::Str(monero_network),
            HashPart::Str(txid_root),
            HashPart::Str(output_commitment_root),
            HashPart::Str(key_image_root),
            HashPart::Str(view_tag_root),
            HashPart::Int(amount_bucket as i128),
            HashPart::Int(confirmation_height as i128),
            HashPart::Str(observed_by_commitment),
            HashPart::Int(lock_expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn l2_escrow_lock_id(
    swap_id: &str,
    owner_commitment: &str,
    asset_id: &str,
    amount_units: u64,
    contract_root: &str,
    nullifier_root: &str,
    refund_commitment_root: &str,
    locked_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "L2-ESCROW-LOCK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(swap_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(asset_id),
            HashPart::Int(amount_units as i128),
            HashPart::Str(contract_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(refund_commitment_root),
            HashPart::Int(locked_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn swap_execution_plan_id(
    swap_id: &str,
    monero_evidence_root: &str,
    l2_escrow_root: &str,
    adaptor_root: &str,
    settlement_call_root: &str,
    low_fee_lane_root: &str,
    pq_attestation_root: &str,
    planned_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "SWAP-EXECUTION-PLAN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(swap_id),
            HashPart::Str(monero_evidence_root),
            HashPart::Str(l2_escrow_root),
            HashPart::Str(adaptor_root),
            HashPart::Str(settlement_call_root),
            HashPart::Str(low_fee_lane_root),
            HashPart::Str(pq_attestation_root),
            HashPart::Int(planned_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn swap_liquidity_pool_id(
    operator_commitment: &str,
    monero_reserve_root: &str,
    l2_reserve_root: &str,
    wxmr_capacity_units: u64,
    stable_capacity_units: u64,
    max_single_swap_units: u64,
    fee_bps: u64,
    active_quote_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "SWAP-LIQUIDITY-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::Str(monero_reserve_root),
            HashPart::Str(l2_reserve_root),
            HashPart::Int(wxmr_capacity_units as i128),
            HashPart::Int(stable_capacity_units as i128),
            HashPart::Int(max_single_swap_units as i128),
            HashPart::Int(fee_bps as i128),
            HashPart::Str(active_quote_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn swap_sponsorship_id(
    sponsor_commitment: &str,
    direction: AtomicSwapDirection,
    asset_id: &str,
    total_budget_units: u64,
    min_amount_units: u64,
    max_rebate_bps: u64,
    opened_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "SWAP-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(direction.as_str()),
            HashPart::Str(asset_id),
            HashPart::Int(total_budget_units as i128),
            HashPart::Int(min_amount_units as i128),
            HashPart::Int(max_rebate_bps as i128),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn pq_swap_attestation_id(
    role: AtomicSwapAttestationRole,
    signer_commitment: &str,
    subject_id: &str,
    subject_root: &str,
    transcript_root: &str,
    signature_root: &str,
    signed_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "PQ-SWAP-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(role.as_str()),
            HashPart::Str(signer_commitment),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(transcript_root),
            HashPart::Str(signature_root),
            HashPart::Int(signed_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn swap_settlement_receipt_id(
    swap_id: &str,
    plan_id: &str,
    monero_release_root: &str,
    l2_release_root: &str,
    fee_receipt_root: &str,
    secret_reveal_root: &str,
    attestation_root: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "SWAP-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(swap_id),
            HashPart::Str(plan_id),
            HashPart::Str(monero_release_root),
            HashPart::Str(l2_release_root),
            HashPart::Str(fee_receipt_root),
            HashPart::Str(secret_reveal_root),
            HashPart::Str(attestation_root),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn swap_refund_envelope_id(
    swap_id: &str,
    refund_side: AtomicSwapDirection,
    refund_commitment_root: &str,
    timeout_evidence_root: &str,
    refund_fee_root: &str,
    pq_attestation_root: &str,
    requested_at_height: u64,
    executable_at_height: u64,
) -> String {
    domain_hash(
        "SWAP-REFUND-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(swap_id),
            HashPart::Str(refund_side.as_str()),
            HashPart::Str(refund_commitment_root),
            HashPart::Str(timeout_evidence_root),
            HashPart::Str(refund_fee_root),
            HashPart::Str(pq_attestation_root),
            HashPart::Int(requested_at_height as i128),
            HashPart::Int(executable_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn swap_challenge_id(
    swap_id: &str,
    challenge_kind: AtomicSwapChallengeKind,
    challenger_commitment: &str,
    evidence_root: &str,
    disputed_root: &str,
    opened_at_height: u64,
    expires_at_height: u64,
    bond_units: u64,
) -> String {
    domain_hash(
        "SWAP-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(swap_id),
            HashPart::Str(challenge_kind.as_str()),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
            HashPart::Str(disputed_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Int(bond_units as i128),
        ],
        32,
    )
}

pub fn atomic_swap_quote_collection_root(quotes: &[AtomicSwapQuote]) -> String {
    merkle_root(
        "ATOMIC-SWAP-QUOTE-COLLECTION",
        &quotes
            .iter()
            .map(AtomicSwapQuote::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn atomic_swap_intent_collection_root(intents: &[AtomicSwapIntent]) -> String {
    merkle_root(
        "ATOMIC-SWAP-INTENT-COLLECTION",
        &intents
            .iter()
            .map(AtomicSwapIntent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn monero_lock_evidence_collection_root(evidence: &[MoneroLockEvidence]) -> String {
    merkle_root(
        "MONERO-LOCK-EVIDENCE-COLLECTION",
        &evidence
            .iter()
            .map(MoneroLockEvidence::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn l2_escrow_collection_root(escrows: &[L2EscrowLock]) -> String {
    merkle_root(
        "L2-ESCROW-COLLECTION",
        &escrows
            .iter()
            .map(L2EscrowLock::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn swap_execution_plan_collection_root(plans: &[SwapExecutionPlan]) -> String {
    merkle_root(
        "SWAP-EXECUTION-PLAN-COLLECTION",
        &plans
            .iter()
            .map(SwapExecutionPlan::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn swap_liquidity_pool_collection_root(pools: &[SwapLiquidityPool]) -> String {
    merkle_root(
        "SWAP-LIQUIDITY-POOL-COLLECTION",
        &pools
            .iter()
            .map(SwapLiquidityPool::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn swap_sponsorship_collection_root(sponsorships: &[SwapSponsorship]) -> String {
    merkle_root(
        "SWAP-SPONSORSHIP-COLLECTION",
        &sponsorships
            .iter()
            .map(SwapSponsorship::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_swap_attestation_collection_root(attestations: &[PqSwapAttestation]) -> String {
    merkle_root(
        "PQ-SWAP-ATTESTATION-COLLECTION",
        &attestations
            .iter()
            .map(PqSwapAttestation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn swap_settlement_collection_root(receipts: &[SwapSettlementReceipt]) -> String {
    merkle_root(
        "SWAP-SETTLEMENT-COLLECTION",
        &receipts
            .iter()
            .map(SwapSettlementReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn swap_refund_collection_root(refunds: &[SwapRefundEnvelope]) -> String {
    merkle_root(
        "SWAP-REFUND-COLLECTION",
        &refunds
            .iter()
            .map(SwapRefundEnvelope::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn swap_challenge_collection_root(challenges: &[SwapChallenge]) -> String {
    merkle_root(
        "SWAP-CHALLENGE-COLLECTION",
        &challenges
            .iter()
            .map(SwapChallenge::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn atomic_swap_state_root_from_record(record: &Value) -> String {
    atomic_swap_payload_root("ATOMIC-SWAP-STATE", record)
}

pub fn atomic_swap_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn atomic_swap_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn atomic_swap_string_set_root(domain: &str, values: &[String]) -> String {
    let records = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn atomic_swap_signature_root(signer_label: &str, transcript_root: &str) -> String {
    domain_hash(
        "ATOMIC-SWAP-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(signer_label),
            HashPart::Str(transcript_root),
            HashPart::Str(ATOMIC_SWAP_PQ_SIGNATURE_SCHEME),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> AtomicSwapResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> AtomicSwapResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn validate_bps(value: u64, label: &str) -> AtomicSwapResult<()> {
    if value > ATOMIC_SWAP_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

#[allow(dead_code)]
fn ensure_unique_strings(values: &[String], label: &str) -> AtomicSwapResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicates"));
        }
    }
    Ok(())
}
