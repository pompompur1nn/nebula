use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateOrderflowResult<T> = Result<T, String>;

pub const PRIVATE_ORDERFLOW_PROTOCOL_VERSION: u64 = 1;
pub const PRIVATE_ORDERFLOW_ENCRYPTION_SCHEME: &str = "devnet-mock-intent-envelope-v1";
pub const PRIVATE_ORDERFLOW_COMMITMENT_SCHEME: &str = "devnet-shake256-commitment-v1";
pub const PRIVATE_ORDERFLOW_ORDERING_POLICY: &str = "commit-reveal-batch-auction";
pub const PRIVATE_ORDERFLOW_DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 8;
pub const PRIVATE_ORDERFLOW_DEFAULT_REVEAL_DELAY_BLOCKS: u64 = 2;
pub const PRIVATE_ORDERFLOW_DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 6;
pub const PRIVATE_ORDERFLOW_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 12;
pub const PRIVATE_ORDERFLOW_DEFAULT_PRIVACY_BUDGET_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_ORDERFLOW_DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 250_000;
pub const PRIVATE_ORDERFLOW_DEFAULT_INTENT_TTL_BLOCKS: u64 = 32;
pub const PRIVATE_ORDERFLOW_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_ORDERFLOW_MAX_BATCH_INTENTS: usize = 512;
pub const PRIVATE_ORDERFLOW_STATUS_ACTIVE: &str = "active";
pub const PRIVATE_ORDERFLOW_STATUS_COLLECTING: &str = "collecting";
pub const PRIVATE_ORDERFLOW_STATUS_REVEALING: &str = "revealing";
pub const PRIVATE_ORDERFLOW_STATUS_SETTLED: &str = "settled";
pub const PRIVATE_ORDERFLOW_STATUS_EXPIRED: &str = "expired";
pub const PRIVATE_ORDERFLOW_STATUS_CONSUMED: &str = "consumed";
pub const PRIVATE_ORDERFLOW_STATUS_RELEASED: &str = "released";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedIntentEnvelope {
    pub intent_id: String,
    pub owner_commitment: String,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub amount_commitment: String,
    pub limit_price_commitment: String,
    pub max_slippage_bps: u16,
    pub deadline_height: u64,
    pub submitted_at_height: u64,
    pub nonce: u64,
    pub encrypted_payload_root: String,
    pub encryption_scheme: String,
    pub privacy_budget_id: String,
    pub route_hint_root: String,
    pub public_metadata_root: String,
    pub status: String,
}

impl EncryptedIntentEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: &str,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in: u64,
        limit_price_numerator: u64,
        limit_price_denominator: u64,
        max_slippage_bps: u16,
        deadline_height: u64,
        submitted_at_height: u64,
        nonce: u64,
        encrypted_payload: &Value,
        privacy_budget_id: impl Into<String>,
        route_hint_root: impl Into<String>,
        public_metadata: &Value,
    ) -> PrivateOrderflowResult<Self> {
        ensure_non_empty(owner_label, "encrypted intent owner_label")?;
        ensure_non_empty(asset_in_id, "encrypted intent asset_in_id")?;
        ensure_non_empty(asset_out_id, "encrypted intent asset_out_id")?;
        if amount_in == 0 {
            return Err("encrypted intent amount must be positive".to_string());
        }
        if limit_price_denominator == 0 {
            return Err("encrypted intent limit price denominator cannot be zero".to_string());
        }
        if max_slippage_bps > 10_000 {
            return Err("encrypted intent max slippage exceeds 10000 bps".to_string());
        }
        if deadline_height <= submitted_at_height {
            return Err("encrypted intent deadline must be after submission".to_string());
        }
        let privacy_budget_id = privacy_budget_id.into();
        let route_hint_root = route_hint_root.into();
        ensure_non_empty(&privacy_budget_id, "encrypted intent privacy_budget_id")?;
        ensure_non_empty(&route_hint_root, "encrypted intent route_hint_root")?;

        let owner_commitment = private_orderflow_owner_commitment(owner_label);
        let asset_in_commitment = private_orderflow_asset_commitment(asset_in_id);
        let asset_out_commitment = private_orderflow_asset_commitment(asset_out_id);
        let amount_commitment = private_orderflow_amount_commitment(
            amount_in,
            &private_orderflow_intent_blinding(owner_label, nonce, "amount"),
        );
        let limit_price_commitment = private_orderflow_price_commitment(
            limit_price_numerator,
            limit_price_denominator,
            &private_orderflow_intent_blinding(owner_label, nonce, "limit_price"),
        );
        let encrypted_payload_root =
            private_orderflow_payload_root("intent_envelope", encrypted_payload);
        let public_metadata_root =
            private_orderflow_payload_root("intent_metadata", public_metadata);
        let intent_id = private_orderflow_intent_id(
            &owner_commitment,
            &asset_in_commitment,
            &asset_out_commitment,
            &amount_commitment,
            &limit_price_commitment,
            &route_hint_root,
            deadline_height,
            nonce,
        );
        let intent = Self {
            intent_id,
            owner_commitment,
            asset_in_commitment,
            asset_out_commitment,
            amount_commitment,
            limit_price_commitment,
            max_slippage_bps,
            deadline_height,
            submitted_at_height,
            nonce,
            encrypted_payload_root,
            encryption_scheme: PRIVATE_ORDERFLOW_ENCRYPTION_SCHEME.to_string(),
            privacy_budget_id,
            route_hint_root,
            public_metadata_root,
            status: PRIVATE_ORDERFLOW_STATUS_ACTIVE.to_string(),
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "private_orderflow_encrypted_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "asset_in_commitment": self.asset_in_commitment,
            "asset_out_commitment": self.asset_out_commitment,
            "amount_commitment": self.amount_commitment,
            "limit_price_commitment": self.limit_price_commitment,
            "max_slippage_bps": self.max_slippage_bps,
            "deadline_height": self.deadline_height,
            "submitted_at_height": self.submitted_at_height,
            "nonce": self.nonce,
            "encrypted_payload_root": self.encrypted_payload_root,
            "encryption_scheme": self.encryption_scheme,
            "commitment_scheme": PRIVATE_ORDERFLOW_COMMITMENT_SCHEME,
            "privacy_budget_id": self.privacy_budget_id,
            "route_hint_root": self.route_hint_root,
            "public_metadata_root": self.public_metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("encrypted intent public record object")
            .insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> PrivateOrderflowResult<String> {
        ensure_non_empty(&self.intent_id, "encrypted intent id")?;
        ensure_non_empty(&self.owner_commitment, "encrypted intent owner commitment")?;
        ensure_non_empty(
            &self.asset_in_commitment,
            "encrypted intent asset in commitment",
        )?;
        ensure_non_empty(
            &self.asset_out_commitment,
            "encrypted intent asset out commitment",
        )?;
        ensure_non_empty(
            &self.amount_commitment,
            "encrypted intent amount commitment",
        )?;
        ensure_non_empty(
            &self.limit_price_commitment,
            "encrypted intent limit price commitment",
        )?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "encrypted intent payload root",
        )?;
        ensure_non_empty(&self.privacy_budget_id, "encrypted intent budget id")?;
        ensure_non_empty(&self.route_hint_root, "encrypted intent route hint root")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_ORDERFLOW_STATUS_ACTIVE,
                PRIVATE_ORDERFLOW_STATUS_SETTLED,
                PRIVATE_ORDERFLOW_STATUS_EXPIRED,
            ],
        )?;
        if self.deadline_height <= self.submitted_at_height {
            return Err("encrypted intent deadline must be after submission".to_string());
        }
        if self.max_slippage_bps > 10_000 {
            return Err("encrypted intent max slippage exceeds 10000 bps".to_string());
        }
        let expected_id = private_orderflow_intent_id(
            &self.owner_commitment,
            &self.asset_in_commitment,
            &self.asset_out_commitment,
            &self.amount_commitment,
            &self.limit_price_commitment,
            &self.route_hint_root,
            self.deadline_height,
            self.nonce,
        );
        if self.intent_id != expected_id {
            return Err("encrypted intent id mismatch".to_string());
        }
        Ok(self.intent_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialRouteHint {
    pub hint_id: String,
    pub intent_id: String,
    pub venue_commitment: String,
    pub hop_commitment_root: String,
    pub route_ciphertext_root: String,
    pub disclosure_policy_root: String,
    pub max_hops: u16,
    pub created_at_height: u64,
    pub expires_height: u64,
    pub status: String,
}

impl ConfidentialRouteHint {
    pub fn new(
        intent_id: impl Into<String>,
        venue_label: &str,
        route_steps: &[Value],
        disclosure_policy: &Value,
        max_hops: u16,
        created_at_height: u64,
        expires_height: u64,
    ) -> PrivateOrderflowResult<Self> {
        let intent_id = intent_id.into();
        ensure_non_empty(&intent_id, "route hint intent_id")?;
        ensure_non_empty(venue_label, "route hint venue_label")?;
        if route_steps.is_empty() {
            return Err("route hint requires at least one route step".to_string());
        }
        if max_hops == 0 || route_steps.len() > max_hops as usize {
            return Err("route hint max_hops does not cover route steps".to_string());
        }
        if expires_height <= created_at_height {
            return Err("route hint expiry must be after creation".to_string());
        }
        let venue_commitment = private_orderflow_string_root("route_venue", venue_label);
        let hop_commitment_root = private_orderflow_route_step_root(route_steps);
        let route_ciphertext_root = private_orderflow_payload_root(
            "route_hint_ciphertext",
            &Value::Array(route_steps.to_vec()),
        );
        let disclosure_policy_root =
            private_orderflow_payload_root("route_disclosure_policy", disclosure_policy);
        let hint_id = private_orderflow_route_hint_id(
            &intent_id,
            &venue_commitment,
            &hop_commitment_root,
            &route_ciphertext_root,
            expires_height,
        );
        let hint = Self {
            hint_id,
            intent_id,
            venue_commitment,
            hop_commitment_root,
            route_ciphertext_root,
            disclosure_policy_root,
            max_hops,
            created_at_height,
            expires_height,
            status: PRIVATE_ORDERFLOW_STATUS_ACTIVE.to_string(),
        };
        hint.validate()?;
        Ok(hint)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_orderflow_confidential_route_hint",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "hint_id": self.hint_id,
            "intent_id": self.intent_id,
            "venue_commitment": self.venue_commitment,
            "hop_commitment_root": self.hop_commitment_root,
            "route_ciphertext_root": self.route_ciphertext_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "max_hops": self.max_hops,
            "created_at_height": self.created_at_height,
            "expires_height": self.expires_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateOrderflowResult<String> {
        ensure_non_empty(&self.hint_id, "route hint id")?;
        ensure_non_empty(&self.intent_id, "route hint intent id")?;
        ensure_non_empty(&self.venue_commitment, "route hint venue commitment")?;
        ensure_non_empty(&self.hop_commitment_root, "route hint hop root")?;
        ensure_non_empty(&self.route_ciphertext_root, "route hint ciphertext root")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_ORDERFLOW_STATUS_ACTIVE,
                PRIVATE_ORDERFLOW_STATUS_EXPIRED,
            ],
        )?;
        if self.max_hops == 0 {
            return Err("route hint max_hops cannot be zero".to_string());
        }
        if self.expires_height <= self.created_at_height {
            return Err("route hint expiry must be after creation".to_string());
        }
        let expected_id = private_orderflow_route_hint_id(
            &self.intent_id,
            &self.venue_commitment,
            &self.hop_commitment_root,
            &self.route_ciphertext_root,
            self.expires_height,
        );
        if self.hint_id != expected_id {
            return Err("route hint id mismatch".to_string());
        }
        Ok(self.hint_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetAccount {
    pub budget_id: String,
    pub owner_commitment: String,
    pub epoch: u64,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub total_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub released_units: u64,
    pub status: String,
}

impl PrivacyBudgetAccount {
    pub fn new(
        owner_label: &str,
        epoch: u64,
        epoch_start_height: u64,
        epoch_end_height: u64,
        total_units: u64,
    ) -> PrivateOrderflowResult<Self> {
        ensure_non_empty(owner_label, "privacy budget owner_label")?;
        if epoch_end_height <= epoch_start_height {
            return Err("privacy budget epoch end must be after start".to_string());
        }
        if total_units == 0 {
            return Err("privacy budget total units must be positive".to_string());
        }
        let owner_commitment = private_orderflow_owner_commitment(owner_label);
        let budget_id = private_orderflow_budget_id(
            &owner_commitment,
            epoch,
            epoch_start_height,
            epoch_end_height,
            total_units,
        );
        Ok(Self {
            budget_id,
            owner_commitment,
            epoch,
            epoch_start_height,
            epoch_end_height,
            total_units,
            reserved_units: 0,
            consumed_units: 0,
            released_units: 0,
            status: PRIVATE_ORDERFLOW_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn available_units(&self) -> u64 {
        self.total_units
            .saturating_sub(self.reserved_units.saturating_add(self.consumed_units))
    }

    pub fn reserve(&mut self, units: u64) -> PrivateOrderflowResult<()> {
        if units == 0 {
            return Err("privacy budget reservation units must be positive".to_string());
        }
        if self.available_units() < units {
            return Err("privacy budget insufficient available units".to_string());
        }
        self.reserved_units = self
            .reserved_units
            .checked_add(units)
            .ok_or_else(|| "privacy budget reserved unit overflow".to_string())?;
        Ok(())
    }

    pub fn consume_reserved(&mut self, units: u64) -> PrivateOrderflowResult<()> {
        if units == 0 {
            return Err("privacy budget consumed units must be positive".to_string());
        }
        if self.reserved_units < units {
            return Err("privacy budget consumed units exceed reserved units".to_string());
        }
        self.reserved_units -= units;
        self.consumed_units = self
            .consumed_units
            .checked_add(units)
            .ok_or_else(|| "privacy budget consumed unit overflow".to_string())?;
        Ok(())
    }

    pub fn release_reserved(&mut self, units: u64) -> PrivateOrderflowResult<()> {
        if units == 0 {
            return Err("privacy budget released units must be positive".to_string());
        }
        if self.reserved_units < units {
            return Err("privacy budget released units exceed reserved units".to_string());
        }
        self.reserved_units -= units;
        self.released_units = self
            .released_units
            .checked_add(units)
            .ok_or_else(|| "privacy budget released unit overflow".to_string())?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_orderflow_privacy_budget",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "epoch": self.epoch,
            "epoch_start_height": self.epoch_start_height,
            "epoch_end_height": self.epoch_end_height,
            "total_units": self.total_units,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "released_units": self.released_units,
            "available_units": self.available_units(),
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateOrderflowResult<String> {
        ensure_non_empty(&self.budget_id, "privacy budget id")?;
        ensure_non_empty(&self.owner_commitment, "privacy budget owner commitment")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_ORDERFLOW_STATUS_ACTIVE,
                PRIVATE_ORDERFLOW_STATUS_EXPIRED,
            ],
        )?;
        if self.total_units == 0 {
            return Err("privacy budget total units must be positive".to_string());
        }
        if self.epoch_end_height <= self.epoch_start_height {
            return Err("privacy budget epoch end must be after start".to_string());
        }
        if self.reserved_units.saturating_add(self.consumed_units) > self.total_units {
            return Err("privacy budget reserved and consumed units exceed total".to_string());
        }
        let expected_id = private_orderflow_budget_id(
            &self.owner_commitment,
            self.epoch,
            self.epoch_start_height,
            self.epoch_end_height,
            self.total_units,
        );
        if self.budget_id != expected_id {
            return Err("privacy budget id mismatch".to_string());
        }
        Ok(self.budget_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetReservation {
    pub reservation_id: String,
    pub budget_id: String,
    pub object_kind: String,
    pub object_id: String,
    pub units: u64,
    pub reserved_at_height: u64,
    pub expires_height: u64,
    pub consumed_at_height: u64,
    pub released_at_height: u64,
    pub status: String,
}

impl PrivacyBudgetReservation {
    pub fn new(
        budget_id: impl Into<String>,
        object_kind: impl Into<String>,
        object_id: impl Into<String>,
        units: u64,
        reserved_at_height: u64,
        expires_height: u64,
    ) -> PrivateOrderflowResult<Self> {
        let budget_id = budget_id.into();
        let object_kind = object_kind.into();
        let object_id = object_id.into();
        ensure_non_empty(&budget_id, "budget reservation budget_id")?;
        ensure_non_empty(&object_kind, "budget reservation object_kind")?;
        ensure_non_empty(&object_id, "budget reservation object_id")?;
        if units == 0 {
            return Err("budget reservation units must be positive".to_string());
        }
        if expires_height <= reserved_at_height {
            return Err("budget reservation expiry must be after reservation".to_string());
        }
        let reservation_id = private_orderflow_budget_reservation_id(
            &budget_id,
            &object_kind,
            &object_id,
            units,
            reserved_at_height,
            expires_height,
        );
        Ok(Self {
            reservation_id,
            budget_id,
            object_kind,
            object_id,
            units,
            reserved_at_height,
            expires_height,
            consumed_at_height: 0,
            released_at_height: 0,
            status: PRIVATE_ORDERFLOW_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn mark_consumed(&mut self, height: u64) -> PrivateOrderflowResult<()> {
        if self.status != PRIVATE_ORDERFLOW_STATUS_ACTIVE {
            return Err("budget reservation is not active".to_string());
        }
        if height < self.reserved_at_height {
            return Err("budget reservation consumed before reservation".to_string());
        }
        self.consumed_at_height = height;
        self.status = PRIVATE_ORDERFLOW_STATUS_CONSUMED.to_string();
        Ok(())
    }

    pub fn mark_released(&mut self, height: u64) -> PrivateOrderflowResult<()> {
        if self.status != PRIVATE_ORDERFLOW_STATUS_ACTIVE {
            return Err("budget reservation is not active".to_string());
        }
        if height < self.reserved_at_height {
            return Err("budget reservation released before reservation".to_string());
        }
        self.released_at_height = height;
        self.status = PRIVATE_ORDERFLOW_STATUS_RELEASED.to_string();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_orderflow_privacy_budget_reservation",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "reservation_id": self.reservation_id,
            "budget_id": self.budget_id,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "units": self.units,
            "reserved_at_height": self.reserved_at_height,
            "expires_height": self.expires_height,
            "consumed_at_height": self.consumed_at_height,
            "released_at_height": self.released_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateOrderflowResult<String> {
        ensure_non_empty(&self.reservation_id, "budget reservation id")?;
        ensure_non_empty(&self.budget_id, "budget reservation budget id")?;
        ensure_non_empty(&self.object_kind, "budget reservation object kind")?;
        ensure_non_empty(&self.object_id, "budget reservation object id")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_ORDERFLOW_STATUS_ACTIVE,
                PRIVATE_ORDERFLOW_STATUS_CONSUMED,
                PRIVATE_ORDERFLOW_STATUS_RELEASED,
                PRIVATE_ORDERFLOW_STATUS_EXPIRED,
            ],
        )?;
        if self.units == 0 {
            return Err("budget reservation units must be positive".to_string());
        }
        if self.expires_height <= self.reserved_at_height {
            return Err("budget reservation expiry must be after reservation".to_string());
        }
        if self.status == PRIVATE_ORDERFLOW_STATUS_CONSUMED && self.consumed_at_height == 0 {
            return Err("consumed budget reservation missing consumed height".to_string());
        }
        if self.status == PRIVATE_ORDERFLOW_STATUS_RELEASED && self.released_at_height == 0 {
            return Err("released budget reservation missing released height".to_string());
        }
        let expected_id = private_orderflow_budget_reservation_id(
            &self.budget_id,
            &self.object_kind,
            &self.object_id,
            self.units,
            self.reserved_at_height,
            self.expires_height,
        );
        if self.reservation_id != expected_id {
            return Err("budget reservation id mismatch".to_string());
        }
        Ok(self.reservation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealWindow {
    pub window_id: String,
    pub auction_id: String,
    pub commit_start_height: u64,
    pub commit_end_height: u64,
    pub reveal_start_height: u64,
    pub reveal_end_height: u64,
    pub challenge_end_height: u64,
    pub min_reveals: u16,
    pub status: String,
}

impl RevealWindow {
    pub fn new(
        auction_id: impl Into<String>,
        commit_start_height: u64,
        commit_end_height: u64,
        reveal_start_height: u64,
        reveal_end_height: u64,
        challenge_end_height: u64,
        min_reveals: u16,
    ) -> PrivateOrderflowResult<Self> {
        let auction_id = auction_id.into();
        ensure_non_empty(&auction_id, "reveal window auction_id")?;
        if commit_end_height <= commit_start_height {
            return Err("reveal window commit end must be after start".to_string());
        }
        if reveal_start_height < commit_end_height {
            return Err("reveal window reveal start cannot precede commit end".to_string());
        }
        if reveal_end_height <= reveal_start_height {
            return Err("reveal window reveal end must be after reveal start".to_string());
        }
        if challenge_end_height < reveal_end_height {
            return Err("reveal window challenge end cannot precede reveal end".to_string());
        }
        let window_id = private_orderflow_reveal_window_id(
            &auction_id,
            commit_start_height,
            commit_end_height,
            reveal_start_height,
            reveal_end_height,
            challenge_end_height,
        );
        Ok(Self {
            window_id,
            auction_id,
            commit_start_height,
            commit_end_height,
            reveal_start_height,
            reveal_end_height,
            challenge_end_height,
            min_reveals,
            status: PRIVATE_ORDERFLOW_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn phase_at(&self, height: u64) -> String {
        if height < self.commit_start_height {
            "pending".to_string()
        } else if height <= self.commit_end_height {
            "commit".to_string()
        } else if height < self.reveal_start_height {
            "sealed".to_string()
        } else if height <= self.reveal_end_height {
            "reveal".to_string()
        } else if height <= self.challenge_end_height {
            "challenge".to_string()
        } else {
            "closed".to_string()
        }
    }

    pub fn accepts_commit_at(&self, height: u64) -> bool {
        height >= self.commit_start_height && height <= self.commit_end_height
    }

    pub fn accepts_reveal_at(&self, height: u64) -> bool {
        height >= self.reveal_start_height && height <= self.reveal_end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_orderflow_reveal_window",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "auction_id": self.auction_id,
            "commit_start_height": self.commit_start_height,
            "commit_end_height": self.commit_end_height,
            "reveal_start_height": self.reveal_start_height,
            "reveal_end_height": self.reveal_end_height,
            "challenge_end_height": self.challenge_end_height,
            "min_reveals": self.min_reveals,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateOrderflowResult<String> {
        ensure_non_empty(&self.window_id, "reveal window id")?;
        ensure_non_empty(&self.auction_id, "reveal window auction id")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_ORDERFLOW_STATUS_ACTIVE,
                PRIVATE_ORDERFLOW_STATUS_EXPIRED,
            ],
        )?;
        if self.commit_end_height <= self.commit_start_height {
            return Err("reveal window commit end must be after start".to_string());
        }
        if self.reveal_start_height < self.commit_end_height {
            return Err("reveal window reveal start cannot precede commit end".to_string());
        }
        if self.reveal_end_height <= self.reveal_start_height {
            return Err("reveal window reveal end must be after reveal start".to_string());
        }
        if self.challenge_end_height < self.reveal_end_height {
            return Err("reveal window challenge end cannot precede reveal end".to_string());
        }
        let expected_id = private_orderflow_reveal_window_id(
            &self.auction_id,
            self.commit_start_height,
            self.commit_end_height,
            self.reveal_start_height,
            self.reveal_end_height,
            self.challenge_end_height,
        );
        if self.window_id != expected_id {
            return Err("reveal window id mismatch".to_string());
        }
        Ok(self.window_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedAuction {
    pub auction_id: String,
    pub market_id: String,
    pub pair_commitment: String,
    pub encrypted_intent_root: String,
    pub route_hint_root: String,
    pub budget_reservation_root: String,
    pub commit_start_height: u64,
    pub commit_end_height: u64,
    pub reveal_window_id: String,
    pub solver_commitment_root: String,
    pub ordering_seed: String,
    pub status: String,
}

impl SealedAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        pair_commitment: impl Into<String>,
        encrypted_intent_root: impl Into<String>,
        route_hint_root: impl Into<String>,
        budget_reservation_root: impl Into<String>,
        commit_start_height: u64,
        commit_end_height: u64,
        reveal_window_id: impl Into<String>,
        solver_commitment_root: impl Into<String>,
        ordering_seed: impl Into<String>,
    ) -> PrivateOrderflowResult<Self> {
        let market_id = market_id.into();
        let pair_commitment = pair_commitment.into();
        let encrypted_intent_root = encrypted_intent_root.into();
        let route_hint_root = route_hint_root.into();
        let budget_reservation_root = budget_reservation_root.into();
        let reveal_window_id = reveal_window_id.into();
        let solver_commitment_root = solver_commitment_root.into();
        let ordering_seed = ordering_seed.into();
        ensure_non_empty(&market_id, "sealed auction market_id")?;
        ensure_non_empty(&pair_commitment, "sealed auction pair commitment")?;
        ensure_non_empty(&encrypted_intent_root, "sealed auction intent root")?;
        ensure_non_empty(&route_hint_root, "sealed auction route hint root")?;
        ensure_non_empty(
            &budget_reservation_root,
            "sealed auction budget reservation root",
        )?;
        ensure_non_empty(&solver_commitment_root, "sealed auction solver root")?;
        ensure_non_empty(&ordering_seed, "sealed auction ordering seed")?;
        if commit_end_height <= commit_start_height {
            return Err("sealed auction commit end must be after start".to_string());
        }
        let auction_id = private_orderflow_auction_id(
            &market_id,
            &pair_commitment,
            &encrypted_intent_root,
            commit_start_height,
            commit_end_height,
            &ordering_seed,
        );
        let auction = Self {
            auction_id,
            market_id,
            pair_commitment,
            encrypted_intent_root,
            route_hint_root,
            budget_reservation_root,
            commit_start_height,
            commit_end_height,
            reveal_window_id,
            solver_commitment_root,
            ordering_seed,
            status: PRIVATE_ORDERFLOW_STATUS_COLLECTING.to_string(),
        };
        auction.validate()?;
        Ok(auction)
    }

    pub fn with_reveal_window(mut self, reveal_window_id: impl Into<String>) -> Self {
        self.reveal_window_id = reveal_window_id.into();
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_orderflow_sealed_auction",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "market_id": self.market_id,
            "pair_commitment": self.pair_commitment,
            "encrypted_intent_root": self.encrypted_intent_root,
            "route_hint_root": self.route_hint_root,
            "budget_reservation_root": self.budget_reservation_root,
            "commit_start_height": self.commit_start_height,
            "commit_end_height": self.commit_end_height,
            "reveal_window_id": self.reveal_window_id,
            "solver_commitment_root": self.solver_commitment_root,
            "ordering_seed": self.ordering_seed,
            "ordering_policy": PRIVATE_ORDERFLOW_ORDERING_POLICY,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateOrderflowResult<String> {
        ensure_non_empty(&self.auction_id, "sealed auction id")?;
        ensure_non_empty(&self.market_id, "sealed auction market id")?;
        ensure_non_empty(&self.pair_commitment, "sealed auction pair commitment")?;
        ensure_non_empty(&self.encrypted_intent_root, "sealed auction intent root")?;
        ensure_non_empty(&self.route_hint_root, "sealed auction route root")?;
        ensure_non_empty(&self.solver_commitment_root, "sealed auction solver root")?;
        ensure_non_empty(&self.ordering_seed, "sealed auction ordering seed")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_ORDERFLOW_STATUS_COLLECTING,
                PRIVATE_ORDERFLOW_STATUS_REVEALING,
                PRIVATE_ORDERFLOW_STATUS_SETTLED,
                PRIVATE_ORDERFLOW_STATUS_EXPIRED,
            ],
        )?;
        if self.commit_end_height <= self.commit_start_height {
            return Err("sealed auction commit end must be after start".to_string());
        }
        let expected_id = private_orderflow_auction_id(
            &self.market_id,
            &self.pair_commitment,
            &self.encrypted_intent_root,
            self.commit_start_height,
            self.commit_end_height,
            &self.ordering_seed,
        );
        if self.auction_id != expected_id {
            return Err("sealed auction id mismatch".to_string());
        }
        Ok(self.auction_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteCommitment {
    pub quote_id: String,
    pub auction_id: String,
    pub solver_commitment_id: String,
    pub solver_commitment: String,
    pub quote_commitment: String,
    pub asset_pair_commitment: String,
    pub amount_in_commitment: String,
    pub amount_out_commitment: String,
    pub clearing_price_commitment: String,
    pub solver_fee_commitment: String,
    pub valid_until_height: u64,
    pub status: String,
}

impl QuoteCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: impl Into<String>,
        solver_label: &str,
        solver_commitment_id: impl Into<String>,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in: u64,
        amount_out: u64,
        clearing_price_numerator: u64,
        clearing_price_denominator: u64,
        solver_fee: u64,
        quote_secret: &str,
        valid_until_height: u64,
    ) -> PrivateOrderflowResult<Self> {
        let auction_id = auction_id.into();
        let solver_commitment_id = solver_commitment_id.into();
        ensure_non_empty(&auction_id, "quote commitment auction_id")?;
        ensure_non_empty(solver_label, "quote commitment solver_label")?;
        ensure_non_empty(asset_in_id, "quote commitment asset_in_id")?;
        ensure_non_empty(asset_out_id, "quote commitment asset_out_id")?;
        ensure_non_empty(quote_secret, "quote commitment secret")?;
        if amount_in == 0 || amount_out == 0 {
            return Err("quote commitment amounts must be positive".to_string());
        }
        if clearing_price_denominator == 0 {
            return Err("quote commitment price denominator cannot be zero".to_string());
        }
        let solver_commitment = private_orderflow_solver_commitment(solver_label);
        let asset_pair_commitment =
            private_orderflow_asset_pair_commitment(asset_in_id, asset_out_id);
        let amount_in_commitment = private_orderflow_amount_commitment(amount_in, quote_secret);
        let amount_out_commitment = private_orderflow_amount_commitment(amount_out, quote_secret);
        let clearing_price_commitment = private_orderflow_price_commitment(
            clearing_price_numerator,
            clearing_price_denominator,
            quote_secret,
        );
        let solver_fee_commitment = private_orderflow_amount_commitment(solver_fee, quote_secret);
        let quote_commitment = private_orderflow_quote_commitment_hash(
            &auction_id,
            &solver_commitment,
            &asset_pair_commitment,
            &amount_in_commitment,
            &amount_out_commitment,
            &clearing_price_commitment,
            &solver_fee_commitment,
            quote_secret,
        );
        let quote_id = private_orderflow_quote_id(
            &auction_id,
            &solver_commitment,
            &quote_commitment,
            valid_until_height,
        );
        let quote = Self {
            quote_id,
            auction_id,
            solver_commitment_id,
            solver_commitment,
            quote_commitment,
            asset_pair_commitment,
            amount_in_commitment,
            amount_out_commitment,
            clearing_price_commitment,
            solver_fee_commitment,
            valid_until_height,
            status: PRIVATE_ORDERFLOW_STATUS_ACTIVE.to_string(),
        };
        quote.validate()?;
        Ok(quote)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_orderflow_quote_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "auction_id": self.auction_id,
            "solver_commitment_id": self.solver_commitment_id,
            "solver_commitment": self.solver_commitment,
            "quote_commitment": self.quote_commitment,
            "asset_pair_commitment": self.asset_pair_commitment,
            "amount_in_commitment": self.amount_in_commitment,
            "amount_out_commitment": self.amount_out_commitment,
            "clearing_price_commitment": self.clearing_price_commitment,
            "solver_fee_commitment": self.solver_fee_commitment,
            "valid_until_height": self.valid_until_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateOrderflowResult<String> {
        ensure_non_empty(&self.quote_id, "quote id")?;
        ensure_non_empty(&self.auction_id, "quote auction id")?;
        ensure_non_empty(&self.solver_commitment, "quote solver commitment")?;
        ensure_non_empty(&self.quote_commitment, "quote commitment")?;
        ensure_non_empty(&self.asset_pair_commitment, "quote asset pair commitment")?;
        ensure_non_empty(&self.amount_in_commitment, "quote amount in commitment")?;
        ensure_non_empty(&self.amount_out_commitment, "quote amount out commitment")?;
        ensure_non_empty(
            &self.clearing_price_commitment,
            "quote clearing price commitment",
        )?;
        ensure_non_empty(&self.solver_fee_commitment, "quote solver fee commitment")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_ORDERFLOW_STATUS_ACTIVE,
                PRIVATE_ORDERFLOW_STATUS_SETTLED,
                PRIVATE_ORDERFLOW_STATUS_EXPIRED,
            ],
        )?;
        let expected_id = private_orderflow_quote_id(
            &self.auction_id,
            &self.solver_commitment,
            &self.quote_commitment,
            self.valid_until_height,
        );
        if self.quote_id != expected_id {
            return Err("quote id mismatch".to_string());
        }
        Ok(self.quote_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCommitment {
    pub commitment_id: String,
    pub auction_id: String,
    pub solver_commitment: String,
    pub quote_commitment_root: String,
    pub route_plan_commitment: String,
    pub batch_order_commitment: String,
    pub bonded_amount: u64,
    pub committed_at_height: u64,
    pub reveal_deadline_height: u64,
    pub status: String,
}

impl SolverCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: impl Into<String>,
        solver_label: &str,
        quote_commitment_root: impl Into<String>,
        route_plan: &Value,
        batch_order_commitment: impl Into<String>,
        bonded_amount: u64,
        committed_at_height: u64,
        reveal_deadline_height: u64,
    ) -> PrivateOrderflowResult<Self> {
        let auction_id = auction_id.into();
        let quote_commitment_root = quote_commitment_root.into();
        let batch_order_commitment = batch_order_commitment.into();
        ensure_non_empty(&auction_id, "solver commitment auction_id")?;
        ensure_non_empty(solver_label, "solver commitment solver_label")?;
        ensure_non_empty(&quote_commitment_root, "solver commitment quote root")?;
        ensure_non_empty(
            &batch_order_commitment,
            "solver commitment batch order commitment",
        )?;
        if reveal_deadline_height <= committed_at_height {
            return Err("solver commitment reveal deadline must be after commit".to_string());
        }
        let solver_commitment = private_orderflow_solver_commitment(solver_label);
        let route_plan_commitment = private_orderflow_payload_root("solver_route_plan", route_plan);
        let commitment_id = private_orderflow_solver_commitment_id(
            &auction_id,
            &solver_commitment,
            &quote_commitment_root,
            &route_plan_commitment,
            committed_at_height,
            reveal_deadline_height,
        );
        let commitment = Self {
            commitment_id,
            auction_id,
            solver_commitment,
            quote_commitment_root,
            route_plan_commitment,
            batch_order_commitment,
            bonded_amount,
            committed_at_height,
            reveal_deadline_height,
            status: PRIVATE_ORDERFLOW_STATUS_ACTIVE.to_string(),
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_orderflow_solver_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "auction_id": self.auction_id,
            "solver_commitment": self.solver_commitment,
            "quote_commitment_root": self.quote_commitment_root,
            "route_plan_commitment": self.route_plan_commitment,
            "batch_order_commitment": self.batch_order_commitment,
            "bonded_amount": self.bonded_amount,
            "committed_at_height": self.committed_at_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateOrderflowResult<String> {
        ensure_non_empty(&self.commitment_id, "solver commitment id")?;
        ensure_non_empty(&self.auction_id, "solver commitment auction id")?;
        ensure_non_empty(&self.solver_commitment, "solver commitment")?;
        ensure_non_empty(&self.quote_commitment_root, "solver quote root")?;
        ensure_non_empty(&self.route_plan_commitment, "solver route plan commitment")?;
        ensure_non_empty(
            &self.batch_order_commitment,
            "solver batch order commitment",
        )?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_ORDERFLOW_STATUS_ACTIVE,
                PRIVATE_ORDERFLOW_STATUS_SETTLED,
                PRIVATE_ORDERFLOW_STATUS_EXPIRED,
            ],
        )?;
        if self.reveal_deadline_height <= self.committed_at_height {
            return Err("solver commitment reveal deadline must be after commit".to_string());
        }
        let expected_id = private_orderflow_solver_commitment_id(
            &self.auction_id,
            &self.solver_commitment,
            &self.quote_commitment_root,
            &self.route_plan_commitment,
            self.committed_at_height,
            self.reveal_deadline_height,
        );
        if self.commitment_id != expected_id {
            return Err("solver commitment id mismatch".to_string());
        }
        Ok(self.commitment_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteReveal {
    pub reveal_id: String,
    pub quote_id: String,
    pub solver_commitment_id: String,
    pub quote_commitment: String,
    pub revealed_amount_in: u64,
    pub revealed_amount_out: u64,
    pub solver_fee: u64,
    pub clearing_price_numerator: u64,
    pub clearing_price_denominator: u64,
    pub route_plan_root: String,
    pub reveal_secret_hash: String,
    pub revealed_at_height: u64,
    pub status: String,
}

impl QuoteReveal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        quote: &QuoteCommitment,
        solver_commitment_id: impl Into<String>,
        amount_in: u64,
        amount_out: u64,
        solver_fee: u64,
        clearing_price_numerator: u64,
        clearing_price_denominator: u64,
        route_plan: &Value,
        reveal_secret: &str,
        revealed_at_height: u64,
    ) -> PrivateOrderflowResult<Self> {
        let solver_commitment_id = solver_commitment_id.into();
        quote.validate()?;
        ensure_non_empty(&solver_commitment_id, "quote reveal solver commitment id")?;
        ensure_non_empty(reveal_secret, "quote reveal secret")?;
        if amount_in == 0 || amount_out == 0 {
            return Err("quote reveal amounts must be positive".to_string());
        }
        if clearing_price_denominator == 0 {
            return Err("quote reveal price denominator cannot be zero".to_string());
        }
        let route_plan_root = private_orderflow_payload_root("quote_reveal_route_plan", route_plan);
        let reveal_secret_hash =
            private_orderflow_string_root("quote_reveal_secret", reveal_secret);
        let reveal_id = private_orderflow_quote_reveal_id(
            &quote.quote_id,
            &solver_commitment_id,
            &quote.quote_commitment,
            &route_plan_root,
            revealed_at_height,
        );
        let reveal = Self {
            reveal_id,
            quote_id: quote.quote_id.clone(),
            solver_commitment_id,
            quote_commitment: quote.quote_commitment.clone(),
            revealed_amount_in: amount_in,
            revealed_amount_out: amount_out,
            solver_fee,
            clearing_price_numerator,
            clearing_price_denominator,
            route_plan_root,
            reveal_secret_hash,
            revealed_at_height,
            status: PRIVATE_ORDERFLOW_STATUS_ACTIVE.to_string(),
        };
        reveal.validate()?;
        Ok(reveal)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_orderflow_quote_reveal",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "reveal_id": self.reveal_id,
            "quote_id": self.quote_id,
            "solver_commitment_id": self.solver_commitment_id,
            "quote_commitment": self.quote_commitment,
            "revealed_amount_in": self.revealed_amount_in,
            "revealed_amount_out": self.revealed_amount_out,
            "solver_fee": self.solver_fee,
            "clearing_price_numerator": self.clearing_price_numerator,
            "clearing_price_denominator": self.clearing_price_denominator,
            "route_plan_root": self.route_plan_root,
            "reveal_secret_hash": self.reveal_secret_hash,
            "revealed_at_height": self.revealed_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateOrderflowResult<String> {
        ensure_non_empty(&self.reveal_id, "quote reveal id")?;
        ensure_non_empty(&self.quote_id, "quote reveal quote id")?;
        ensure_non_empty(
            &self.solver_commitment_id,
            "quote reveal solver commitment id",
        )?;
        ensure_non_empty(&self.quote_commitment, "quote reveal quote commitment")?;
        ensure_non_empty(&self.route_plan_root, "quote reveal route root")?;
        ensure_non_empty(&self.reveal_secret_hash, "quote reveal secret hash")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_ORDERFLOW_STATUS_ACTIVE,
                PRIVATE_ORDERFLOW_STATUS_SETTLED,
            ],
        )?;
        if self.revealed_amount_in == 0 || self.revealed_amount_out == 0 {
            return Err("quote reveal amounts must be positive".to_string());
        }
        if self.clearing_price_denominator == 0 {
            return Err("quote reveal price denominator cannot be zero".to_string());
        }
        let expected_id = private_orderflow_quote_reveal_id(
            &self.quote_id,
            &self.solver_commitment_id,
            &self.quote_commitment,
            &self.route_plan_root,
            self.revealed_at_height,
        );
        if self.reveal_id != expected_id {
            return Err("quote reveal id mismatch".to_string());
        }
        Ok(self.reveal_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBatchOrder {
    pub batch_order_id: String,
    pub auction_id: String,
    pub batch_height: u64,
    pub ordering_seed: String,
    pub ordered_intent_ids: Vec<String>,
    pub ordered_solver_commitment_ids: Vec<String>,
    pub ordered_quote_ids: Vec<String>,
    pub intent_order_root: String,
    pub solver_order_root: String,
    pub quote_order_root: String,
    pub fairness_policy: String,
    pub tie_breaker_root: String,
    pub status: String,
}

impl PrivateBatchOrder {
    pub fn new(
        auction_id: impl Into<String>,
        batch_height: u64,
        ordering_seed: impl Into<String>,
        intent_ids: &[String],
        solver_commitment_ids: &[String],
        quote_ids: &[String],
    ) -> PrivateOrderflowResult<Self> {
        let auction_id = auction_id.into();
        let ordering_seed = ordering_seed.into();
        ensure_non_empty(&auction_id, "batch order auction_id")?;
        ensure_non_empty(&ordering_seed, "batch order ordering_seed")?;
        if intent_ids.len() > PRIVATE_ORDERFLOW_MAX_BATCH_INTENTS {
            return Err("batch order intent limit exceeded".to_string());
        }
        let ordered_intent_ids =
            private_orderflow_mev_resistant_order(&auction_id, &ordering_seed, intent_ids);
        let ordered_solver_commitment_ids = private_orderflow_mev_resistant_order(
            &auction_id,
            &ordering_seed,
            solver_commitment_ids,
        );
        let ordered_quote_ids =
            private_orderflow_mev_resistant_order(&auction_id, &ordering_seed, quote_ids);
        let intent_order_root =
            private_orderflow_string_set_root("batch_intent_order", &ordered_intent_ids);
        let solver_order_root =
            private_orderflow_string_set_root("batch_solver_order", &ordered_solver_commitment_ids);
        let quote_order_root =
            private_orderflow_string_set_root("batch_quote_order", &ordered_quote_ids);
        let tie_breaker_root = private_orderflow_tie_breaker_root(
            &auction_id,
            &ordering_seed,
            &ordered_intent_ids,
            &ordered_solver_commitment_ids,
            &ordered_quote_ids,
        );
        let batch_order_id = private_orderflow_batch_order_id(
            &auction_id,
            batch_height,
            &ordering_seed,
            &intent_order_root,
            &solver_order_root,
            &quote_order_root,
        );
        let order = Self {
            batch_order_id,
            auction_id,
            batch_height,
            ordering_seed,
            ordered_intent_ids,
            ordered_solver_commitment_ids,
            ordered_quote_ids,
            intent_order_root,
            solver_order_root,
            quote_order_root,
            fairness_policy: PRIVATE_ORDERFLOW_ORDERING_POLICY.to_string(),
            tie_breaker_root,
            status: PRIVATE_ORDERFLOW_STATUS_ACTIVE.to_string(),
        };
        order.validate()?;
        Ok(order)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_orderflow_batch_order",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "batch_order_id": self.batch_order_id,
            "auction_id": self.auction_id,
            "batch_height": self.batch_height,
            "ordering_seed": self.ordering_seed,
            "ordered_intent_ids": self.ordered_intent_ids,
            "ordered_solver_commitment_ids": self.ordered_solver_commitment_ids,
            "ordered_quote_ids": self.ordered_quote_ids,
            "intent_order_root": self.intent_order_root,
            "solver_order_root": self.solver_order_root,
            "quote_order_root": self.quote_order_root,
            "fairness_policy": self.fairness_policy,
            "tie_breaker_root": self.tie_breaker_root,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateOrderflowResult<String> {
        ensure_non_empty(&self.batch_order_id, "batch order id")?;
        ensure_non_empty(&self.auction_id, "batch order auction id")?;
        ensure_non_empty(&self.ordering_seed, "batch order ordering seed")?;
        ensure_non_empty(&self.intent_order_root, "batch intent order root")?;
        ensure_non_empty(&self.solver_order_root, "batch solver order root")?;
        ensure_non_empty(&self.quote_order_root, "batch quote order root")?;
        ensure_non_empty(&self.tie_breaker_root, "batch tie breaker root")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_ORDERFLOW_STATUS_ACTIVE,
                PRIVATE_ORDERFLOW_STATUS_SETTLED,
            ],
        )?;
        ensure_distinct_strings(&self.ordered_intent_ids, "ordered intent ids")?;
        ensure_distinct_strings(
            &self.ordered_solver_commitment_ids,
            "ordered solver commitment ids",
        )?;
        ensure_distinct_strings(&self.ordered_quote_ids, "ordered quote ids")?;
        let expected_id = private_orderflow_batch_order_id(
            &self.auction_id,
            self.batch_height,
            &self.ordering_seed,
            &self.intent_order_root,
            &self.solver_order_root,
            &self.quote_order_root,
        );
        if self.batch_order_id != expected_id {
            return Err("batch order id mismatch".to_string());
        }
        Ok(self.batch_order_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementManifestFill {
    pub fill_id: String,
    pub intent_id: String,
    pub quote_id: String,
    pub solver_commitment_id: String,
    pub input_nullifier_commitment: String,
    pub output_commitment: String,
    pub refund_commitment: String,
    pub fee_commitment: String,
    pub route_hint_id: String,
    pub status: String,
}

impl SettlementManifestFill {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: impl Into<String>,
        quote_id: impl Into<String>,
        solver_commitment_id: impl Into<String>,
        input_nullifier: &str,
        output_note: &str,
        refund_note: &str,
        fee_amount: u64,
        fee_blinding: &str,
        route_hint_id: impl Into<String>,
    ) -> PrivateOrderflowResult<Self> {
        let intent_id = intent_id.into();
        let quote_id = quote_id.into();
        let solver_commitment_id = solver_commitment_id.into();
        let route_hint_id = route_hint_id.into();
        ensure_non_empty(&intent_id, "settlement fill intent_id")?;
        ensure_non_empty(&quote_id, "settlement fill quote_id")?;
        ensure_non_empty(
            &solver_commitment_id,
            "settlement fill solver commitment id",
        )?;
        ensure_non_empty(input_nullifier, "settlement fill input nullifier")?;
        ensure_non_empty(output_note, "settlement fill output note")?;
        ensure_non_empty(fee_blinding, "settlement fill fee blinding")?;
        ensure_non_empty(&route_hint_id, "settlement fill route hint id")?;
        let input_nullifier_commitment =
            private_orderflow_string_root("settlement_nullifier", input_nullifier);
        let output_commitment = private_orderflow_string_root("settlement_output", output_note);
        let refund_commitment = if refund_note.is_empty() {
            private_orderflow_string_root("settlement_refund", "none")
        } else {
            private_orderflow_string_root("settlement_refund", refund_note)
        };
        let fee_commitment = private_orderflow_amount_commitment(fee_amount, fee_blinding);
        let fill_id = private_orderflow_settlement_fill_id(
            &intent_id,
            &quote_id,
            &solver_commitment_id,
            &input_nullifier_commitment,
            &output_commitment,
            &refund_commitment,
            &fee_commitment,
        );
        let fill = Self {
            fill_id,
            intent_id,
            quote_id,
            solver_commitment_id,
            input_nullifier_commitment,
            output_commitment,
            refund_commitment,
            fee_commitment,
            route_hint_id,
            status: PRIVATE_ORDERFLOW_STATUS_ACTIVE.to_string(),
        };
        fill.validate()?;
        Ok(fill)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_orderflow_settlement_manifest_fill",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "fill_id": self.fill_id,
            "intent_id": self.intent_id,
            "quote_id": self.quote_id,
            "solver_commitment_id": self.solver_commitment_id,
            "input_nullifier_commitment": self.input_nullifier_commitment,
            "output_commitment": self.output_commitment,
            "refund_commitment": self.refund_commitment,
            "fee_commitment": self.fee_commitment,
            "route_hint_id": self.route_hint_id,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateOrderflowResult<String> {
        ensure_non_empty(&self.fill_id, "settlement fill id")?;
        ensure_non_empty(&self.intent_id, "settlement fill intent id")?;
        ensure_non_empty(&self.quote_id, "settlement fill quote id")?;
        ensure_non_empty(
            &self.solver_commitment_id,
            "settlement fill solver commitment id",
        )?;
        ensure_non_empty(
            &self.input_nullifier_commitment,
            "settlement fill nullifier commitment",
        )?;
        ensure_non_empty(&self.output_commitment, "settlement fill output commitment")?;
        ensure_non_empty(&self.refund_commitment, "settlement fill refund commitment")?;
        ensure_non_empty(&self.fee_commitment, "settlement fill fee commitment")?;
        ensure_non_empty(&self.route_hint_id, "settlement fill route hint id")?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_ORDERFLOW_STATUS_ACTIVE,
                PRIVATE_ORDERFLOW_STATUS_SETTLED,
            ],
        )?;
        let expected_id = private_orderflow_settlement_fill_id(
            &self.intent_id,
            &self.quote_id,
            &self.solver_commitment_id,
            &self.input_nullifier_commitment,
            &self.output_commitment,
            &self.refund_commitment,
            &self.fee_commitment,
        );
        if self.fill_id != expected_id {
            return Err("settlement fill id mismatch".to_string());
        }
        Ok(self.fill_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementManifest {
    pub manifest_id: String,
    pub auction_id: String,
    pub batch_order_id: String,
    pub winning_solver_commitment_id: String,
    pub quote_id: String,
    pub fill_root: String,
    pub route_hint_root: String,
    pub quote_commitment_root: String,
    pub privacy_budget_reservation_root: String,
    pub public_output_root: String,
    pub surplus_commitment_root: String,
    pub settlement_height: u64,
    pub challenge_end_height: u64,
    pub status: String,
}

impl SettlementManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: impl Into<String>,
        batch_order_id: impl Into<String>,
        winning_solver_commitment_id: impl Into<String>,
        quote_id: impl Into<String>,
        fills: &[SettlementManifestFill],
        route_hint_root: impl Into<String>,
        quote_commitment_root: impl Into<String>,
        privacy_budget_reservation_root: impl Into<String>,
        public_outputs: &[Value],
        surplus_commitments: &[String],
        settlement_height: u64,
        challenge_end_height: u64,
    ) -> PrivateOrderflowResult<Self> {
        let auction_id = auction_id.into();
        let batch_order_id = batch_order_id.into();
        let winning_solver_commitment_id = winning_solver_commitment_id.into();
        let quote_id = quote_id.into();
        let route_hint_root = route_hint_root.into();
        let quote_commitment_root = quote_commitment_root.into();
        let privacy_budget_reservation_root = privacy_budget_reservation_root.into();
        ensure_non_empty(&auction_id, "settlement manifest auction_id")?;
        ensure_non_empty(&batch_order_id, "settlement manifest batch_order_id")?;
        ensure_non_empty(
            &winning_solver_commitment_id,
            "settlement manifest winning solver id",
        )?;
        ensure_non_empty(&quote_id, "settlement manifest quote id")?;
        ensure_non_empty(&route_hint_root, "settlement manifest route root")?;
        ensure_non_empty(&quote_commitment_root, "settlement manifest quote root")?;
        ensure_non_empty(
            &privacy_budget_reservation_root,
            "settlement manifest budget reservation root",
        )?;
        if fills.is_empty() {
            return Err("settlement manifest requires fills".to_string());
        }
        if challenge_end_height < settlement_height {
            return Err("settlement manifest challenge end cannot precede settlement".to_string());
        }
        for fill in fills {
            fill.validate()?;
        }
        let fill_root = private_orderflow_settlement_fill_root(fills);
        let public_output_root = merkle_root("PRIVATE-ORDERFLOW-PUBLIC-OUTPUT", public_outputs);
        let surplus_commitment_root =
            private_orderflow_string_set_root("settlement_surplus", surplus_commitments);
        let manifest_id = private_orderflow_settlement_manifest_id(
            &auction_id,
            &batch_order_id,
            &winning_solver_commitment_id,
            &quote_id,
            &fill_root,
            settlement_height,
        );
        let manifest = Self {
            manifest_id,
            auction_id,
            batch_order_id,
            winning_solver_commitment_id,
            quote_id,
            fill_root,
            route_hint_root,
            quote_commitment_root,
            privacy_budget_reservation_root,
            public_output_root,
            surplus_commitment_root,
            settlement_height,
            challenge_end_height,
            status: PRIVATE_ORDERFLOW_STATUS_SETTLED.to_string(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_orderflow_settlement_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "auction_id": self.auction_id,
            "batch_order_id": self.batch_order_id,
            "winning_solver_commitment_id": self.winning_solver_commitment_id,
            "quote_id": self.quote_id,
            "fill_root": self.fill_root,
            "route_hint_root": self.route_hint_root,
            "quote_commitment_root": self.quote_commitment_root,
            "privacy_budget_reservation_root": self.privacy_budget_reservation_root,
            "public_output_root": self.public_output_root,
            "surplus_commitment_root": self.surplus_commitment_root,
            "settlement_height": self.settlement_height,
            "challenge_end_height": self.challenge_end_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateOrderflowResult<String> {
        ensure_non_empty(&self.manifest_id, "settlement manifest id")?;
        ensure_non_empty(&self.auction_id, "settlement manifest auction id")?;
        ensure_non_empty(&self.batch_order_id, "settlement manifest batch order id")?;
        ensure_non_empty(
            &self.winning_solver_commitment_id,
            "settlement manifest winning solver id",
        )?;
        ensure_non_empty(&self.quote_id, "settlement manifest quote id")?;
        ensure_non_empty(&self.fill_root, "settlement manifest fill root")?;
        ensure_non_empty(&self.route_hint_root, "settlement manifest route root")?;
        ensure_non_empty(
            &self.quote_commitment_root,
            "settlement manifest quote root",
        )?;
        ensure_non_empty(
            &self.privacy_budget_reservation_root,
            "settlement manifest budget reservation root",
        )?;
        ensure_non_empty(&self.public_output_root, "settlement manifest output root")?;
        ensure_non_empty(
            &self.surplus_commitment_root,
            "settlement manifest surplus root",
        )?;
        ensure_status(
            &self.status,
            &[
                PRIVATE_ORDERFLOW_STATUS_SETTLED,
                PRIVATE_ORDERFLOW_STATUS_EXPIRED,
            ],
        )?;
        if self.challenge_end_height < self.settlement_height {
            return Err("settlement manifest challenge end cannot precede settlement".to_string());
        }
        let expected_id = private_orderflow_settlement_manifest_id(
            &self.auction_id,
            &self.batch_order_id,
            &self.winning_solver_commitment_id,
            &self.quote_id,
            &self.fill_root,
            self.settlement_height,
        );
        if self.manifest_id != expected_id {
            return Err("settlement manifest id mismatch".to_string());
        }
        Ok(self.manifest_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOrderflowPublicRecord {
    pub record_id: String,
    pub object_kind: String,
    pub object_id: String,
    pub record_root: String,
    pub recorded_at_height: u64,
}

impl PrivateOrderflowPublicRecord {
    pub fn new(
        object_kind: impl Into<String>,
        object_id: impl Into<String>,
        record: &Value,
        recorded_at_height: u64,
    ) -> PrivateOrderflowResult<Self> {
        let object_kind = object_kind.into();
        let object_id = object_id.into();
        ensure_non_empty(&object_kind, "public record object kind")?;
        ensure_non_empty(&object_id, "public record object id")?;
        let record_root = private_orderflow_public_record_root(record);
        let record_id = private_orderflow_public_record_id(
            &object_kind,
            &object_id,
            &record_root,
            recorded_at_height,
        );
        Ok(Self {
            record_id,
            object_kind,
            object_id,
            record_root,
            recorded_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_orderflow_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "record_root": self.record_root,
            "recorded_at_height": self.recorded_at_height,
        })
    }

    pub fn validate(&self) -> PrivateOrderflowResult<String> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.object_kind, "public record object kind")?;
        ensure_non_empty(&self.object_id, "public record object id")?;
        ensure_non_empty(&self.record_root, "public record root")?;
        let expected_id = private_orderflow_public_record_id(
            &self.object_kind,
            &self.object_id,
            &self.record_root,
            self.recorded_at_height,
        );
        if self.record_id != expected_id {
            return Err("public record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOrderflowStateRoots {
    pub encrypted_intent_root: String,
    pub route_hint_root: String,
    pub privacy_budget_root: String,
    pub budget_reservation_root: String,
    pub auction_root: String,
    pub reveal_window_root: String,
    pub solver_commitment_root: String,
    pub quote_commitment_root: String,
    pub quote_reveal_root: String,
    pub batch_order_root: String,
    pub settlement_manifest_root: String,
    pub public_record_root: String,
}

impl PrivateOrderflowStateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_orderflow_state_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "encrypted_intent_root": self.encrypted_intent_root,
            "route_hint_root": self.route_hint_root,
            "privacy_budget_root": self.privacy_budget_root,
            "budget_reservation_root": self.budget_reservation_root,
            "auction_root": self.auction_root,
            "reveal_window_root": self.reveal_window_root,
            "solver_commitment_root": self.solver_commitment_root,
            "quote_commitment_root": self.quote_commitment_root,
            "quote_reveal_root": self.quote_reveal_root,
            "batch_order_root": self.batch_order_root,
            "settlement_manifest_root": self.settlement_manifest_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_orderflow_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOrderflowState {
    pub encrypted_intents: BTreeMap<String, EncryptedIntentEnvelope>,
    pub route_hints: BTreeMap<String, ConfidentialRouteHint>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudgetAccount>,
    pub budget_reservations: BTreeMap<String, PrivacyBudgetReservation>,
    pub sealed_auctions: BTreeMap<String, SealedAuction>,
    pub reveal_windows: BTreeMap<String, RevealWindow>,
    pub solver_commitments: BTreeMap<String, SolverCommitment>,
    pub quote_commitments: BTreeMap<String, QuoteCommitment>,
    pub quote_reveals: BTreeMap<String, QuoteReveal>,
    pub batch_orders: BTreeMap<String, PrivateBatchOrder>,
    pub settlement_manifests: BTreeMap<String, SettlementManifest>,
    pub public_records: BTreeMap<String, PrivateOrderflowPublicRecord>,
    pub height: u64,
    pub nonce: u64,
}

impl PrivateOrderflowState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet() -> PrivateOrderflowResult<Self> {
        let mut state = Self::new();
        state.height = 1;

        let budget = PrivacyBudgetAccount::new(
            "devnet-alice",
            0,
            0,
            PRIVATE_ORDERFLOW_DEFAULT_PRIVACY_BUDGET_EPOCH_BLOCKS,
            PRIVATE_ORDERFLOW_DEFAULT_PRIVACY_BUDGET_UNITS,
        )?;
        let budget_id = budget.budget_id.clone();
        state.insert_privacy_budget(budget)?;

        let route_steps = vec![
            json!({
                "venue": "devnet-amm-a",
                "pool_commitment": private_orderflow_string_root("devnet_pool", "xmr-usdd"),
                "asset_in": private_orderflow_asset_commitment("XMR"),
                "asset_out": private_orderflow_asset_commitment("USDD"),
                "max_hops": 1,
            }),
            json!({
                "venue": "devnet-settlement",
                "pool_commitment": private_orderflow_string_root("devnet_pool", "settlement-vault"),
                "asset_in": private_orderflow_asset_commitment("USDD"),
                "asset_out": private_orderflow_asset_commitment("USDD"),
                "max_hops": 1,
            }),
        ];
        let route_payload_root = private_orderflow_payload_root(
            "devnet_route_payload",
            &Value::Array(route_steps.clone()),
        );
        let encrypted_payload = json!({
            "intent": "swap",
            "asset_in": "XMR",
            "asset_out": "USDD",
            "amount_in": 42_000_000_u64,
            "limit_price": "180000000/1",
            "recipient": "devnet-alice-shielded-output",
        });
        let intent = EncryptedIntentEnvelope::new(
            "devnet-alice",
            "XMR",
            "USDD",
            42_000_000,
            180_000_000,
            1,
            50,
            state.height + PRIVATE_ORDERFLOW_DEFAULT_INTENT_TTL_BLOCKS,
            state.height,
            1,
            &encrypted_payload,
            &budget_id,
            route_payload_root,
            &json!({"lane": "devnet-private-orderflow"}),
        )?;
        let intent_id = intent.intent_id.clone();
        state.insert_encrypted_intent(intent)?;

        let route_hint = ConfidentialRouteHint::new(
            &intent_id,
            "devnet-private-router",
            &route_steps,
            &json!({"auditor": "devnet-view-key-policy", "release": "settlement_only"}),
            4,
            state.height,
            state.height + PRIVATE_ORDERFLOW_DEFAULT_INTENT_TTL_BLOCKS,
        )?;
        let route_hint_id = route_hint.hint_id.clone();
        state.insert_route_hint(route_hint)?;

        let reservation = state.reserve_privacy_budget(
            &budget_id,
            "encrypted_intent",
            &intent_id,
            25_000,
            state.height + PRIVATE_ORDERFLOW_DEFAULT_INTENT_TTL_BLOCKS,
        )?;

        let pair_commitment = private_orderflow_asset_pair_commitment("XMR", "USDD");
        let ordering_seed = private_orderflow_ordering_seed(
            "devnet-private-market",
            state.height,
            &state.encrypted_intent_root(),
        );
        let mut auction = SealedAuction::new(
            "devnet-private-market",
            &pair_commitment,
            state.encrypted_intent_root(),
            state.route_hint_root(),
            state.budget_reservation_root(),
            state.height,
            state.height + PRIVATE_ORDERFLOW_DEFAULT_AUCTION_WINDOW_BLOCKS,
            "",
            private_orderflow_solver_commitment_root(&[]),
            ordering_seed,
        )?;
        let auction_id = auction.auction_id.clone();
        let reveal_window = RevealWindow::new(
            &auction_id,
            auction.commit_start_height,
            auction.commit_end_height,
            auction.commit_end_height + PRIVATE_ORDERFLOW_DEFAULT_REVEAL_DELAY_BLOCKS,
            auction.commit_end_height
                + PRIVATE_ORDERFLOW_DEFAULT_REVEAL_DELAY_BLOCKS
                + PRIVATE_ORDERFLOW_DEFAULT_REVEAL_WINDOW_BLOCKS,
            auction.commit_end_height
                + PRIVATE_ORDERFLOW_DEFAULT_REVEAL_DELAY_BLOCKS
                + PRIVATE_ORDERFLOW_DEFAULT_REVEAL_WINDOW_BLOCKS
                + PRIVATE_ORDERFLOW_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            1,
        )?;
        auction.reveal_window_id = reveal_window.window_id.clone();
        state.insert_reveal_window(reveal_window)?;

        let mut quote = QuoteCommitment::new(
            &auction_id,
            "devnet-solver-1",
            "",
            "XMR",
            "USDD",
            42_000_000,
            7_560_000_000,
            180_000_000,
            1,
            15_000,
            "devnet-quote-secret-1",
            auction.commit_end_height,
        )?;
        let quote_root =
            private_orderflow_quote_commitment_string_root(std::slice::from_ref(&quote));
        let solver = SolverCommitment::new(
            &auction_id,
            "devnet-solver-1",
            &quote_root,
            &json!({"route": "devnet-xmr-usdd-direct", "settlement": "atomic"}),
            private_orderflow_string_root("devnet_batch_order_commitment", "solver-1"),
            1_000_000,
            state.height + 1,
            state.height + PRIVATE_ORDERFLOW_DEFAULT_AUCTION_WINDOW_BLOCKS,
        )?;
        quote.solver_commitment_id = solver.commitment_id.clone();
        let solver_id = solver.commitment_id.clone();
        let quote_id = quote.quote_id.clone();
        state.insert_quote_commitment(quote.clone())?;
        state.insert_solver_commitment(solver)?;
        auction.solver_commitment_root = state.solver_commitment_root();
        state.insert_sealed_auction(auction)?;

        let reveal = QuoteReveal::new(
            &quote,
            &solver_id,
            42_000_000,
            7_560_000_000,
            15_000,
            180_000_000,
            1,
            &json!({"route": "devnet-xmr-usdd-direct", "settlement": "atomic"}),
            "devnet-quote-secret-1",
            state.height
                + PRIVATE_ORDERFLOW_DEFAULT_AUCTION_WINDOW_BLOCKS
                + PRIVATE_ORDERFLOW_DEFAULT_REVEAL_DELAY_BLOCKS,
        )?;
        state.insert_quote_reveal(reveal)?;

        let batch_order = PrivateBatchOrder::new(
            &auction_id,
            state.height + PRIVATE_ORDERFLOW_DEFAULT_AUCTION_WINDOW_BLOCKS + 1,
            private_orderflow_ordering_seed("devnet-batch", state.height, &auction_id),
            std::slice::from_ref(&intent_id),
            std::slice::from_ref(&solver_id),
            std::slice::from_ref(&quote_id),
        )?;
        let batch_order_id = batch_order.batch_order_id.clone();
        state.insert_batch_order(batch_order)?;

        let fill = SettlementManifestFill::new(
            &intent_id,
            &quote_id,
            &solver_id,
            "devnet-nullifier-1",
            "devnet-output-note-1",
            "",
            15_000,
            "devnet-fee-blinding",
            &route_hint_id,
        )?;
        let settlement_height = state.height + PRIVATE_ORDERFLOW_DEFAULT_AUCTION_WINDOW_BLOCKS + 2;
        state.consume_privacy_budget(&reservation.reservation_id, settlement_height)?;
        let manifest = SettlementManifest::new(
            &auction_id,
            &batch_order_id,
            &solver_id,
            &quote_id,
            std::slice::from_ref(&fill),
            state.route_hint_root(),
            state.quote_commitment_root(),
            state.budget_reservation_root(),
            &[json!({"output_commitment": fill.output_commitment.clone()})],
            &[private_orderflow_amount_commitment(2_000, "devnet-surplus")],
            settlement_height,
            state.height
                + PRIVATE_ORDERFLOW_DEFAULT_AUCTION_WINDOW_BLOCKS
                + PRIVATE_ORDERFLOW_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
        )?;
        state.insert_settlement_manifest(manifest)?;

        for (object_kind, object_id, record) in [
            (
                "encrypted_intent",
                intent_id.as_str(),
                state.encrypted_intents[&intent_id].public_record(),
            ),
            (
                "sealed_auction",
                auction_id.as_str(),
                state.sealed_auctions[&auction_id].public_record(),
            ),
            (
                "solver_commitment",
                solver_id.as_str(),
                state.solver_commitments[&solver_id].public_record(),
            ),
            (
                "quote_commitment",
                quote_id.as_str(),
                state.quote_commitments[&quote_id].public_record(),
            ),
        ] {
            state.publish_public_record(object_kind, object_id, &record)?;
        }

        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn advance_height(&mut self, blocks: u64) -> PrivateOrderflowResult<u64> {
        self.height = self
            .height
            .checked_add(blocks)
            .ok_or_else(|| "private orderflow height overflow".to_string())?;
        Ok(self.height)
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce += 1;
        self.nonce
    }

    pub fn insert_encrypted_intent(
        &mut self,
        intent: EncryptedIntentEnvelope,
    ) -> PrivateOrderflowResult<()> {
        intent.validate()?;
        self.encrypted_intents
            .insert(intent.intent_id.clone(), intent);
        Ok(())
    }

    pub fn insert_route_hint(&mut self, hint: ConfidentialRouteHint) -> PrivateOrderflowResult<()> {
        hint.validate()?;
        if !self.encrypted_intents.contains_key(&hint.intent_id) {
            return Err("route hint references unknown intent".to_string());
        }
        self.route_hints.insert(hint.hint_id.clone(), hint);
        Ok(())
    }

    pub fn insert_privacy_budget(
        &mut self,
        budget: PrivacyBudgetAccount,
    ) -> PrivateOrderflowResult<()> {
        budget.validate()?;
        self.privacy_budgets
            .insert(budget.budget_id.clone(), budget);
        Ok(())
    }

    pub fn insert_budget_reservation(
        &mut self,
        reservation: PrivacyBudgetReservation,
    ) -> PrivateOrderflowResult<()> {
        reservation.validate()?;
        if !self.privacy_budgets.contains_key(&reservation.budget_id) {
            return Err("budget reservation references unknown budget".to_string());
        }
        self.budget_reservations
            .insert(reservation.reservation_id.clone(), reservation);
        Ok(())
    }

    pub fn reserve_privacy_budget(
        &mut self,
        budget_id: &str,
        object_kind: &str,
        object_id: &str,
        units: u64,
        expires_height: u64,
    ) -> PrivateOrderflowResult<PrivacyBudgetReservation> {
        let budget = self
            .privacy_budgets
            .get_mut(budget_id)
            .ok_or_else(|| "unknown privacy budget".to_string())?;
        budget.reserve(units)?;
        let reservation = PrivacyBudgetReservation::new(
            budget_id,
            object_kind,
            object_id,
            units,
            self.height,
            expires_height,
        )?;
        self.insert_budget_reservation(reservation.clone())?;
        Ok(reservation)
    }

    pub fn consume_privacy_budget(
        &mut self,
        reservation_id: &str,
        height: u64,
    ) -> PrivateOrderflowResult<()> {
        let reservation = self
            .budget_reservations
            .get_mut(reservation_id)
            .ok_or_else(|| "unknown budget reservation".to_string())?;
        let budget = self
            .privacy_budgets
            .get_mut(&reservation.budget_id)
            .ok_or_else(|| "unknown privacy budget".to_string())?;
        budget.consume_reserved(reservation.units)?;
        reservation.mark_consumed(height)
    }

    pub fn release_privacy_budget(
        &mut self,
        reservation_id: &str,
        height: u64,
    ) -> PrivateOrderflowResult<()> {
        let reservation = self
            .budget_reservations
            .get_mut(reservation_id)
            .ok_or_else(|| "unknown budget reservation".to_string())?;
        let budget = self
            .privacy_budgets
            .get_mut(&reservation.budget_id)
            .ok_or_else(|| "unknown privacy budget".to_string())?;
        budget.release_reserved(reservation.units)?;
        reservation.mark_released(height)
    }

    pub fn insert_sealed_auction(&mut self, auction: SealedAuction) -> PrivateOrderflowResult<()> {
        auction.validate()?;
        self.sealed_auctions
            .insert(auction.auction_id.clone(), auction);
        Ok(())
    }

    pub fn insert_reveal_window(&mut self, window: RevealWindow) -> PrivateOrderflowResult<()> {
        window.validate()?;
        self.reveal_windows.insert(window.window_id.clone(), window);
        Ok(())
    }

    pub fn insert_solver_commitment(
        &mut self,
        commitment: SolverCommitment,
    ) -> PrivateOrderflowResult<()> {
        commitment.validate()?;
        if !self.sealed_auctions.is_empty()
            && !self.sealed_auctions.contains_key(&commitment.auction_id)
        {
            return Err("solver commitment references unknown auction".to_string());
        }
        self.solver_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(())
    }

    pub fn insert_quote_commitment(
        &mut self,
        quote: QuoteCommitment,
    ) -> PrivateOrderflowResult<()> {
        quote.validate()?;
        if !self.sealed_auctions.is_empty() && !self.sealed_auctions.contains_key(&quote.auction_id)
        {
            return Err("quote commitment references unknown auction".to_string());
        }
        self.quote_commitments.insert(quote.quote_id.clone(), quote);
        Ok(())
    }

    pub fn insert_quote_reveal(&mut self, reveal: QuoteReveal) -> PrivateOrderflowResult<()> {
        reveal.validate()?;
        if !self.quote_commitments.contains_key(&reveal.quote_id) {
            return Err("quote reveal references unknown quote".to_string());
        }
        if !self
            .solver_commitments
            .contains_key(&reveal.solver_commitment_id)
        {
            return Err("quote reveal references unknown solver commitment".to_string());
        }
        self.quote_reveals.insert(reveal.reveal_id.clone(), reveal);
        Ok(())
    }

    pub fn insert_batch_order(&mut self, order: PrivateBatchOrder) -> PrivateOrderflowResult<()> {
        order.validate()?;
        if !self.sealed_auctions.contains_key(&order.auction_id) {
            return Err("batch order references unknown auction".to_string());
        }
        self.batch_orders
            .insert(order.batch_order_id.clone(), order);
        Ok(())
    }

    pub fn insert_settlement_manifest(
        &mut self,
        manifest: SettlementManifest,
    ) -> PrivateOrderflowResult<()> {
        manifest.validate()?;
        if !self.sealed_auctions.contains_key(&manifest.auction_id) {
            return Err("settlement manifest references unknown auction".to_string());
        }
        self.settlement_manifests
            .insert(manifest.manifest_id.clone(), manifest);
        Ok(())
    }

    pub fn publish_public_record(
        &mut self,
        object_kind: &str,
        object_id: &str,
        record: &Value,
    ) -> PrivateOrderflowResult<PrivateOrderflowPublicRecord> {
        let public_record =
            PrivateOrderflowPublicRecord::new(object_kind, object_id, record, self.height)?;
        self.public_records
            .insert(public_record.record_id.clone(), public_record.clone());
        Ok(public_record)
    }

    pub fn encrypted_intent_root(&self) -> String {
        private_orderflow_encrypted_intent_root(
            &self.encrypted_intents.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn route_hint_root(&self) -> String {
        private_orderflow_route_hint_root(&self.route_hints.values().cloned().collect::<Vec<_>>())
    }

    pub fn privacy_budget_root(&self) -> String {
        private_orderflow_privacy_budget_root(
            &self.privacy_budgets.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn budget_reservation_root(&self) -> String {
        private_orderflow_budget_reservation_root(
            &self
                .budget_reservations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn auction_root(&self) -> String {
        private_orderflow_auction_root(&self.sealed_auctions.values().cloned().collect::<Vec<_>>())
    }

    pub fn reveal_window_root(&self) -> String {
        private_orderflow_reveal_window_root(
            &self.reveal_windows.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn solver_commitment_root(&self) -> String {
        private_orderflow_solver_commitment_root(
            &self
                .solver_commitments
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn quote_commitment_root(&self) -> String {
        private_orderflow_quote_commitment_root(
            &self.quote_commitments.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn quote_reveal_root(&self) -> String {
        private_orderflow_quote_reveal_root(
            &self.quote_reveals.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn batch_order_root(&self) -> String {
        private_orderflow_batch_order_root(&self.batch_orders.values().cloned().collect::<Vec<_>>())
    }

    pub fn settlement_manifest_root(&self) -> String {
        private_orderflow_settlement_manifest_root(
            &self
                .settlement_manifests
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        private_orderflow_public_record_set_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> PrivateOrderflowStateRoots {
        PrivateOrderflowStateRoots {
            encrypted_intent_root: self.encrypted_intent_root(),
            route_hint_root: self.route_hint_root(),
            privacy_budget_root: self.privacy_budget_root(),
            budget_reservation_root: self.budget_reservation_root(),
            auction_root: self.auction_root(),
            reveal_window_root: self.reveal_window_root(),
            solver_commitment_root: self.solver_commitment_root(),
            quote_commitment_root: self.quote_commitment_root(),
            quote_reveal_root: self.quote_reveal_root(),
            batch_order_root: self.batch_order_root(),
            settlement_manifest_root: self.settlement_manifest_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn state_root(&self) -> String {
        private_orderflow_state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_orderflow_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ORDERFLOW_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "encrypted_intent_count": self.encrypted_intents.len(),
            "route_hint_count": self.route_hints.len(),
            "privacy_budget_count": self.privacy_budgets.len(),
            "budget_reservation_count": self.budget_reservations.len(),
            "auction_count": self.sealed_auctions.len(),
            "reveal_window_count": self.reveal_windows.len(),
            "solver_commitment_count": self.solver_commitments.len(),
            "quote_commitment_count": self.quote_commitments.len(),
            "quote_reveal_count": self.quote_reveals.len(),
            "batch_order_count": self.batch_orders.len(),
            "settlement_manifest_count": self.settlement_manifests.len(),
            "public_record_count": self.public_records.len(),
            "roots": roots.public_record(),
            "state_root": roots.state_root(),
        })
    }
}

pub fn private_orderflow_owner_commitment(owner_label: &str) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-OWNER",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(owner_label)],
        32,
    )
}

pub fn private_orderflow_solver_commitment(solver_label: &str) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-SOLVER",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(solver_label)],
        32,
    )
}

pub fn private_orderflow_asset_commitment(asset_id: &str) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-ASSET",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(asset_id)],
        32,
    )
}

pub fn private_orderflow_asset_pair_commitment(asset_in_id: &str, asset_out_id: &str) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-ASSET-PAIR",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(asset_in_id),
            HashPart::Str(asset_out_id),
        ],
        32,
    )
}

pub fn private_orderflow_amount_commitment(amount: u64, blinding: &str) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-AMOUNT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(amount as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn private_orderflow_price_commitment(
    numerator: u64,
    denominator: u64,
    blinding: &str,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-PRICE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(numerator as i128),
            HashPart::Int(denominator as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn private_orderflow_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-STRING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn private_orderflow_payload_root(kind: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_orderflow_public_record_root(record: &Value) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-PUBLIC-RECORD",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn private_orderflow_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn private_orderflow_intent_blinding(owner_label: &str, nonce: u64, field: &str) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-INTENT-BLINDING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_label),
            HashPart::Int(nonce as i128),
            HashPart::Str(field),
        ],
        32,
    )
}

pub fn private_orderflow_intent_id(
    owner_commitment: &str,
    asset_in_commitment: &str,
    asset_out_commitment: &str,
    amount_commitment: &str,
    limit_price_commitment: &str,
    route_hint_root: &str,
    deadline_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(asset_in_commitment),
            HashPart::Str(asset_out_commitment),
            HashPart::Str(amount_commitment),
            HashPart::Str(limit_price_commitment),
            HashPart::Str(route_hint_root),
            HashPart::Int(deadline_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_orderflow_route_hint_id(
    intent_id: &str,
    venue_commitment: &str,
    hop_commitment_root: &str,
    route_ciphertext_root: &str,
    expires_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-ROUTE-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(venue_commitment),
            HashPart::Str(hop_commitment_root),
            HashPart::Str(route_ciphertext_root),
            HashPart::Int(expires_height as i128),
        ],
        32,
    )
}

pub fn private_orderflow_route_step_root(route_steps: &[Value]) -> String {
    let leaves = route_steps
        .iter()
        .map(|step| {
            Value::String(domain_hash(
                "PRIVATE-ORDERFLOW-ROUTE-STEP",
                &[HashPart::Str(CHAIN_ID), HashPart::Json(step)],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-ORDERFLOW-ROUTE-STEP", &leaves)
}

pub fn private_orderflow_budget_id(
    owner_commitment: &str,
    epoch: u64,
    epoch_start_height: u64,
    epoch_end_height: u64,
    total_units: u64,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Int(epoch as i128),
            HashPart::Int(epoch_start_height as i128),
            HashPart::Int(epoch_end_height as i128),
            HashPart::Int(total_units as i128),
        ],
        32,
    )
}

pub fn private_orderflow_budget_reservation_id(
    budget_id: &str,
    object_kind: &str,
    object_id: &str,
    units: u64,
    reserved_at_height: u64,
    expires_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-BUDGET-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(budget_id),
            HashPart::Str(object_kind),
            HashPart::Str(object_id),
            HashPart::Int(units as i128),
            HashPart::Int(reserved_at_height as i128),
            HashPart::Int(expires_height as i128),
        ],
        32,
    )
}

pub fn private_orderflow_reveal_window_id(
    auction_id: &str,
    commit_start_height: u64,
    commit_end_height: u64,
    reveal_start_height: u64,
    reveal_end_height: u64,
    challenge_end_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-REVEAL-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Int(commit_start_height as i128),
            HashPart::Int(commit_end_height as i128),
            HashPart::Int(reveal_start_height as i128),
            HashPart::Int(reveal_end_height as i128),
            HashPart::Int(challenge_end_height as i128),
        ],
        32,
    )
}

pub fn private_orderflow_auction_id(
    market_id: &str,
    pair_commitment: &str,
    encrypted_intent_root: &str,
    commit_start_height: u64,
    commit_end_height: u64,
    ordering_seed: &str,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(pair_commitment),
            HashPart::Str(encrypted_intent_root),
            HashPart::Int(commit_start_height as i128),
            HashPart::Int(commit_end_height as i128),
            HashPart::Str(ordering_seed),
        ],
        32,
    )
}

pub fn private_orderflow_ordering_seed(context: &str, height: u64, root: &str) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-ORDERING-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(context),
            HashPart::Int(height as i128),
            HashPart::Str(root),
        ],
        32,
    )
}

pub fn private_orderflow_quote_commitment_hash(
    auction_id: &str,
    solver_commitment: &str,
    asset_pair_commitment: &str,
    amount_in_commitment: &str,
    amount_out_commitment: &str,
    clearing_price_commitment: &str,
    solver_fee_commitment: &str,
    quote_secret: &str,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-QUOTE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(asset_pair_commitment),
            HashPart::Str(amount_in_commitment),
            HashPart::Str(amount_out_commitment),
            HashPart::Str(clearing_price_commitment),
            HashPart::Str(solver_fee_commitment),
            HashPart::Str(quote_secret),
        ],
        32,
    )
}

pub fn private_orderflow_quote_id(
    auction_id: &str,
    solver_commitment: &str,
    quote_commitment: &str,
    valid_until_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(quote_commitment),
            HashPart::Int(valid_until_height as i128),
        ],
        32,
    )
}

pub fn private_orderflow_solver_commitment_id(
    auction_id: &str,
    solver_commitment: &str,
    quote_commitment_root: &str,
    route_plan_commitment: &str,
    committed_at_height: u64,
    reveal_deadline_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-SOLVER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(quote_commitment_root),
            HashPart::Str(route_plan_commitment),
            HashPart::Int(committed_at_height as i128),
            HashPart::Int(reveal_deadline_height as i128),
        ],
        32,
    )
}

pub fn private_orderflow_quote_reveal_id(
    quote_id: &str,
    solver_commitment_id: &str,
    quote_commitment: &str,
    route_plan_root: &str,
    revealed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-QUOTE-REVEAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(quote_id),
            HashPart::Str(solver_commitment_id),
            HashPart::Str(quote_commitment),
            HashPart::Str(route_plan_root),
            HashPart::Int(revealed_at_height as i128),
        ],
        32,
    )
}

pub fn private_orderflow_mev_order_key(
    auction_id: &str,
    ordering_seed: &str,
    object_id: &str,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-MEV-ORDER-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(ordering_seed),
            HashPart::Str(object_id),
        ],
        32,
    )
}

pub fn private_orderflow_mev_resistant_order(
    auction_id: &str,
    ordering_seed: &str,
    object_ids: &[String],
) -> Vec<String> {
    let mut keyed = object_ids
        .iter()
        .map(|object_id| {
            (
                private_orderflow_mev_order_key(auction_id, ordering_seed, object_id),
                object_id.clone(),
            )
        })
        .collect::<Vec<_>>();
    keyed.sort();
    keyed.into_iter().map(|(_, object_id)| object_id).collect()
}

pub fn private_orderflow_tie_breaker_root(
    auction_id: &str,
    ordering_seed: &str,
    intent_ids: &[String],
    solver_commitment_ids: &[String],
    quote_ids: &[String],
) -> String {
    let mut leaves = Vec::new();
    for object_id in intent_ids {
        leaves.push(json!({
            "object_kind": "intent",
            "object_id": object_id,
            "order_key": private_orderflow_mev_order_key(auction_id, ordering_seed, object_id),
        }));
    }
    for object_id in solver_commitment_ids {
        leaves.push(json!({
            "object_kind": "solver_commitment",
            "object_id": object_id,
            "order_key": private_orderflow_mev_order_key(auction_id, ordering_seed, object_id),
        }));
    }
    for object_id in quote_ids {
        leaves.push(json!({
            "object_kind": "quote",
            "object_id": object_id,
            "order_key": private_orderflow_mev_order_key(auction_id, ordering_seed, object_id),
        }));
    }
    merkle_root("PRIVATE-ORDERFLOW-TIE-BREAKER", &leaves)
}

pub fn private_orderflow_batch_order_id(
    auction_id: &str,
    batch_height: u64,
    ordering_seed: &str,
    intent_order_root: &str,
    solver_order_root: &str,
    quote_order_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-BATCH-ORDER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Int(batch_height as i128),
            HashPart::Str(ordering_seed),
            HashPart::Str(intent_order_root),
            HashPart::Str(solver_order_root),
            HashPart::Str(quote_order_root),
        ],
        32,
    )
}

pub fn private_orderflow_settlement_fill_id(
    intent_id: &str,
    quote_id: &str,
    solver_commitment_id: &str,
    input_nullifier_commitment: &str,
    output_commitment: &str,
    refund_commitment: &str,
    fee_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-SETTLEMENT-FILL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(quote_id),
            HashPart::Str(solver_commitment_id),
            HashPart::Str(input_nullifier_commitment),
            HashPart::Str(output_commitment),
            HashPart::Str(refund_commitment),
            HashPart::Str(fee_commitment),
        ],
        32,
    )
}

pub fn private_orderflow_settlement_manifest_id(
    auction_id: &str,
    batch_order_id: &str,
    winning_solver_commitment_id: &str,
    quote_id: &str,
    fill_root: &str,
    settlement_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-SETTLEMENT-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(batch_order_id),
            HashPart::Str(winning_solver_commitment_id),
            HashPart::Str(quote_id),
            HashPart::Str(fill_root),
            HashPart::Int(settlement_height as i128),
        ],
        32,
    )
}

pub fn private_orderflow_public_record_id(
    object_kind: &str,
    object_id: &str,
    record_root: &str,
    recorded_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-ORDERFLOW-PUBLIC-RECORD-ID",
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

pub fn private_orderflow_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-ORDERFLOW-{}", domain.to_ascii_uppercase()),
        &leaves,
    )
}

pub fn private_orderflow_quote_commitment_string_root(quotes: &[QuoteCommitment]) -> String {
    let leaves = quotes
        .iter()
        .map(|quote| Value::String(quote.quote_commitment.clone()))
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-ORDERFLOW-QUOTE-COMMITMENT-STRING", &leaves)
}

pub fn private_orderflow_encrypted_intent_root(intents: &[EncryptedIntentEnvelope]) -> String {
    merkle_root(
        "PRIVATE-ORDERFLOW-ENCRYPTED-INTENT",
        &intents
            .iter()
            .map(EncryptedIntentEnvelope::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_orderflow_route_hint_root(hints: &[ConfidentialRouteHint]) -> String {
    merkle_root(
        "PRIVATE-ORDERFLOW-ROUTE-HINT",
        &hints
            .iter()
            .map(ConfidentialRouteHint::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_orderflow_privacy_budget_root(budgets: &[PrivacyBudgetAccount]) -> String {
    merkle_root(
        "PRIVATE-ORDERFLOW-PRIVACY-BUDGET",
        &budgets
            .iter()
            .map(PrivacyBudgetAccount::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_orderflow_budget_reservation_root(
    reservations: &[PrivacyBudgetReservation],
) -> String {
    merkle_root(
        "PRIVATE-ORDERFLOW-BUDGET-RESERVATION",
        &reservations
            .iter()
            .map(PrivacyBudgetReservation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_orderflow_auction_root(auctions: &[SealedAuction]) -> String {
    merkle_root(
        "PRIVATE-ORDERFLOW-AUCTION",
        &auctions
            .iter()
            .map(SealedAuction::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_orderflow_reveal_window_root(windows: &[RevealWindow]) -> String {
    merkle_root(
        "PRIVATE-ORDERFLOW-REVEAL-WINDOW",
        &windows
            .iter()
            .map(RevealWindow::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_orderflow_solver_commitment_root(commitments: &[SolverCommitment]) -> String {
    merkle_root(
        "PRIVATE-ORDERFLOW-SOLVER-COMMITMENT",
        &commitments
            .iter()
            .map(SolverCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_orderflow_quote_commitment_root(quotes: &[QuoteCommitment]) -> String {
    merkle_root(
        "PRIVATE-ORDERFLOW-QUOTE-COMMITMENT",
        &quotes
            .iter()
            .map(QuoteCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_orderflow_quote_reveal_root(reveals: &[QuoteReveal]) -> String {
    merkle_root(
        "PRIVATE-ORDERFLOW-QUOTE-REVEAL",
        &reveals
            .iter()
            .map(QuoteReveal::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_orderflow_batch_order_root(orders: &[PrivateBatchOrder]) -> String {
    merkle_root(
        "PRIVATE-ORDERFLOW-BATCH-ORDER",
        &orders
            .iter()
            .map(PrivateBatchOrder::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_orderflow_settlement_fill_root(fills: &[SettlementManifestFill]) -> String {
    merkle_root(
        "PRIVATE-ORDERFLOW-SETTLEMENT-FILL",
        &fills
            .iter()
            .map(SettlementManifestFill::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_orderflow_settlement_manifest_root(manifests: &[SettlementManifest]) -> String {
    merkle_root(
        "PRIVATE-ORDERFLOW-SETTLEMENT-MANIFEST",
        &manifests
            .iter()
            .map(SettlementManifest::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_orderflow_public_record_set_root(
    records: &[PrivateOrderflowPublicRecord],
) -> String {
    merkle_root(
        "PRIVATE-ORDERFLOW-PUBLIC-RECORD-SET",
        &records
            .iter()
            .map(PrivateOrderflowPublicRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

fn ensure_non_empty(value: &str, field: &str) -> PrivateOrderflowResult<()> {
    if value.is_empty() {
        return Err(format!("{field} is required"));
    }
    Ok(())
}

fn ensure_status(status: &str, allowed: &[&str]) -> PrivateOrderflowResult<()> {
    if allowed.iter().any(|allowed| allowed == &status) {
        Ok(())
    } else {
        Err(format!("status {status} is invalid"))
    }
}

fn ensure_distinct_strings(values: &[String], field: &str) -> PrivateOrderflowResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value"));
        }
    }
    Ok(())
}
