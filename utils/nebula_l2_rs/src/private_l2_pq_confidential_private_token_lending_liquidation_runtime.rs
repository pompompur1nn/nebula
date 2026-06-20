use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type Runtime = State;

pub const PROTOCOL_NAME: &str = "nebula.monero_l2.private_token_lending_liquidation";
pub const PROTOCOL_VERSION: u32 = 1;
pub const BASIS_POINTS: u128 = 10_000;
pub const RAY: u128 = 1_000_000_000_000_000_000;
pub const MAX_RISK_SCORE: u32 = 10_000;
pub const MAX_HAIRCUT_BPS: u32 = 9_500;
pub const MAX_LTV_BPS: u32 = 9_000;
pub const DEFAULT_PRIVACY_EPOCH: u64 = 720;
pub const DEFAULT_BID_WINDOW: u64 = 24;
pub const DEFAULT_REVEAL_WINDOW: u64 = 12;
pub const DEFAULT_CLOSE_WINDOW: u64 = 6;
pub const DEFAULT_MAX_NOTES: usize = 512;
pub const DEFAULT_MAX_POSITIONS: usize = 256;
pub const DEFAULT_MAX_AUCTIONS: usize = 128;
pub const DEFAULT_MAX_NULLIFIERS: usize = 1024;
pub const DEFAULT_PRIVACY_BUDGET: u64 = 96;
pub const DEFAULT_PQ_WEIGHT: u32 = 7_500;
pub const DEFAULT_LIQUIDATION_PENALTY_BPS: u32 = 850;
pub const DEFAULT_PROTOCOL_FEE_BPS: u32 = 75;
pub const DEFAULT_MIN_HEALTH_BPS: u32 = 10_000;
pub const ZERO_ROOT: &str =
    "l2root:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub market_id: String,
    pub collateral_token: String,
    pub debt_token: String,
    pub oracle_committee: String,
    pub risk_steward: String,
    pub pq_domain: String,
    pub privacy_epoch: u64,
    pub bid_window: u64,
    pub reveal_window: u64,
    pub close_window: u64,
    pub max_notes: usize,
    pub max_positions: usize,
    pub max_auctions: usize,
    pub max_nullifiers: usize,
    pub privacy_budget_units: u64,
    pub pq_authorization_weight_bps: u32,
    pub base_ltv_bps: u32,
    pub liquidation_threshold_bps: u32,
    pub liquidation_penalty_bps: u32,
    pub protocol_fee_bps: u32,
    pub min_health_bps: u32,
    pub cross_margin_enabled: bool,
    pub sealed_bid_enabled: bool,
    pub require_pq_authorization: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: "monero-l2-devnet".to_string(),
            market_id: "private-xmr-usdx".to_string(),
            collateral_token: "pXMR".to_string(),
            debt_token: "pUSDX".to_string(),
            oracle_committee: "oracle.committee.dev".to_string(),
            risk_steward: "risk.steward.dev".to_string(),
            pq_domain: "nebula-pq-auth-v1".to_string(),
            privacy_epoch: DEFAULT_PRIVACY_EPOCH,
            bid_window: DEFAULT_BID_WINDOW,
            reveal_window: DEFAULT_REVEAL_WINDOW,
            close_window: DEFAULT_CLOSE_WINDOW,
            max_notes: DEFAULT_MAX_NOTES,
            max_positions: DEFAULT_MAX_POSITIONS,
            max_auctions: DEFAULT_MAX_AUCTIONS,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
            privacy_budget_units: DEFAULT_PRIVACY_BUDGET,
            pq_authorization_weight_bps: DEFAULT_PQ_WEIGHT,
            base_ltv_bps: 6_500,
            liquidation_threshold_bps: 7_500,
            liquidation_penalty_bps: DEFAULT_LIQUIDATION_PENALTY_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            min_health_bps: DEFAULT_MIN_HEALTH_BPS,
            cross_margin_enabled: true,
            sealed_bid_enabled: true,
            require_pq_authorization: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn normalized(&self) -> Self {
        let mut next = self.clone();
        if next.privacy_epoch == 0 {
            next.privacy_epoch = DEFAULT_PRIVACY_EPOCH;
        }
        if next.bid_window == 0 {
            next.bid_window = DEFAULT_BID_WINDOW;
        }
        if next.reveal_window == 0 {
            next.reveal_window = DEFAULT_REVEAL_WINDOW;
        }
        if next.close_window == 0 {
            next.close_window = DEFAULT_CLOSE_WINDOW;
        }
        if next.max_notes == 0 {
            next.max_notes = DEFAULT_MAX_NOTES;
        }
        if next.max_positions == 0 {
            next.max_positions = DEFAULT_MAX_POSITIONS;
        }
        if next.max_auctions == 0 {
            next.max_auctions = DEFAULT_MAX_AUCTIONS;
        }
        if next.max_nullifiers == 0 {
            next.max_nullifiers = DEFAULT_MAX_NULLIFIERS;
        }
        if next.privacy_budget_units == 0 {
            next.privacy_budget_units = DEFAULT_PRIVACY_BUDGET;
        }
        next.base_ltv_bps = clamp_u32(next.base_ltv_bps, 1, MAX_LTV_BPS);
        next.liquidation_threshold_bps = clamp_u32(
            next.liquidation_threshold_bps,
            next.base_ltv_bps,
            MAX_LTV_BPS,
        );
        next.liquidation_penalty_bps = clamp_u32(next.liquidation_penalty_bps, 0, 2_500);
        next.protocol_fee_bps = clamp_u32(next.protocol_fee_bps, 0, 1_000);
        next.pq_authorization_weight_bps = clamp_u32(next.pq_authorization_weight_bps, 0, 10_000);
        next.min_health_bps = clamp_u32(next.min_health_bps, 1, 50_000);
        next
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub notes_created: u64,
    pub notes_spent: u64,
    pub positions_opened: u64,
    pub positions_repaid: u64,
    pub borrows_recorded: u64,
    pub liquidations_opened: u64,
    pub liquidation_bids: u64,
    pub liquidations_settled: u64,
    pub oracle_updates: u64,
    pub privacy_events: u64,
    pub pq_authorizations: u64,
    pub rejected_requests: u64,
    pub state_transitions: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub notes_root: String,
    pub positions_root: String,
    pub auctions_root: String,
    pub nullifiers_root: String,
    pub oracle_root: String,
    pub privacy_root: String,
    pub authorization_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfidentialCollateralNote {
    pub note_id: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub blinding_commitment: String,
    pub risk_bucket: u32,
    pub haircut_bps: u32,
    pub created_height: u64,
    pub maturity_height: u64,
    pub nullifier: String,
    pub spent: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenBorrowPosition {
    pub position_id: String,
    pub borrower_commitment: String,
    pub collateral_note_ids: Vec<String>,
    pub debt_token: String,
    pub principal: u128,
    pub interest_index_ray: u128,
    pub opened_height: u64,
    pub last_accrual_height: u64,
    pub max_ltv_bps: u32,
    pub liquidation_threshold_bps: u32,
    pub cross_margin_group: String,
    pub privacy_budget_spent: u64,
    pub pq_authorization_id: String,
    pub status: PositionStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PositionStatus {
    Open,
    Frozen,
    InLiquidation,
    Repaid,
    Settled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleRiskSnapshot {
    pub snapshot_id: String,
    pub asset_id: String,
    pub price_ray: u128,
    pub volatility_bps: u32,
    pub liquidity_bps: u32,
    pub haircut_bps: u32,
    pub confidence_bps: u32,
    pub height: u64,
    pub committee_signature_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossMarginOffset {
    pub group_id: String,
    pub asset_id: String,
    pub positive_value_ray: u128,
    pub negative_value_ray: u128,
    pub offset_cap_bps: u32,
    pub proof_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyBudgetAccount {
    pub subject_commitment: String,
    pub epoch: u64,
    pub spent_units: u64,
    pub limit_units: u64,
    pub last_event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAuthorizationRecord {
    pub authorization_id: String,
    pub subject_commitment: String,
    pub domain: String,
    pub public_key_commitment: String,
    pub message_commitment: String,
    pub signature_commitment: String,
    pub weight_bps: u32,
    pub height: u64,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedBidLiquidation {
    pub auction_id: String,
    pub position_id: String,
    pub collateral_note_ids: Vec<String>,
    pub debt_to_cover: u128,
    pub min_repayment: u128,
    pub opened_height: u64,
    pub bid_deadline: u64,
    pub reveal_deadline: u64,
    pub close_deadline: u64,
    pub bid_commitments: Vec<BidCommitment>,
    pub revealed_bids: Vec<RevealedBid>,
    pub status: LiquidationStatus,
    pub winning_bid_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BidCommitment {
    pub bid_id: String,
    pub bidder_commitment: String,
    pub sealed_bid_commitment: String,
    pub deposit_commitment: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealedBid {
    pub bid_id: String,
    pub bidder_commitment: String,
    pub repay_amount: u128,
    pub collateral_discount_bps: u32,
    pub reveal_secret_commitment: String,
    pub height: u64,
    pub valid: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LiquidationStatus {
    Open,
    Revealing,
    Settling,
    Settled,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteRequest {
    pub owner_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub blinding_commitment: String,
    pub risk_bucket: u32,
    pub maturity_height: u64,
    pub nullifier: String,
    pub pq_authorization: PqAuthorizationRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BorrowRequest {
    pub borrower_commitment: String,
    pub collateral_note_ids: Vec<String>,
    pub principal: u128,
    pub cross_margin_group: String,
    pub privacy_units: u64,
    pub pq_authorization: PqAuthorizationRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepayRequest {
    pub position_id: String,
    pub payer_commitment: String,
    pub repay_amount: u128,
    pub privacy_units: u64,
    pub pq_authorization: PqAuthorizationRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiquidationRequest {
    pub position_id: String,
    pub keeper_commitment: String,
    pub debt_to_cover: u128,
    pub min_repayment: u128,
    pub privacy_units: u64,
    pub pq_authorization: PqAuthorizationRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealBidRequest {
    pub auction_id: String,
    pub bidder_commitment: String,
    pub sealed_bid_commitment: String,
    pub deposit_commitment: String,
    pub privacy_units: u64,
    pub pq_authorization: PqAuthorizationRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealBidRequest {
    pub auction_id: String,
    pub bid_id: String,
    pub bidder_commitment: String,
    pub repay_amount: u128,
    pub collateral_discount_bps: u32,
    pub reveal_secret_commitment: String,
    pub privacy_units: u64,
    pub pq_authorization: PqAuthorizationRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleUpdateRequest {
    pub asset_id: String,
    pub price_ray: u128,
    pub volatility_bps: u32,
    pub liquidity_bps: u32,
    pub confidence_bps: u32,
    pub committee_signature_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossMarginRequest {
    pub group_id: String,
    pub asset_id: String,
    pub positive_value_ray: u128,
    pub negative_value_ray: u128,
    pub offset_cap_bps: u32,
    pub proof_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAuthorizationRequest {
    pub subject_commitment: String,
    pub public_key_commitment: String,
    pub message_commitment: String,
    pub signature_commitment: String,
    pub weight_bps: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationRecord {
    pub accepted: bool,
    pub code: String,
    pub subject: String,
    pub event_id: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicRuntimeRecord {
    pub protocol: String,
    pub version: u32,
    pub chain_id: String,
    pub market_id: String,
    pub height: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub open_positions: usize,
    pub open_auctions: usize,
    pub active_notes: usize,
    pub spent_nullifiers: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub notes: Vec<ConfidentialCollateralNote>,
    pub positions: Vec<TokenBorrowPosition>,
    pub auctions: Vec<SealedBidLiquidation>,
    pub oracle_snapshots: Vec<OracleRiskSnapshot>,
    pub cross_margin_offsets: Vec<CrossMarginOffset>,
    pub privacy_accounts: Vec<PrivacyBudgetAccount>,
    pub pq_authorizations: Vec<PqAuthorizationRecord>,
    pub nullifiers: Vec<String>,
    pub counters: Counters,
    pub roots: Roots,
    pub last_record: OperationRecord,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let normalized = config.normalized();
        let mut state = Self {
            config: normalized,
            height: 0,
            notes: Vec::new(),
            positions: Vec::new(),
            auctions: Vec::new(),
            oracle_snapshots: Vec::new(),
            cross_margin_offsets: Vec::new(),
            privacy_accounts: Vec::new(),
            pq_authorizations: Vec::new(),
            nullifiers: Vec::new(),
            counters: Counters::default(),
            roots: Roots::default(),
            last_record: OperationRecord {
                accepted: true,
                code: "genesis".to_string(),
                subject: PROTOCOL_NAME.to_string(),
                event_id: deterministic_id("event", "genesis", 0),
                state_root: ZERO_ROOT.to_string(),
            },
        };
        state.refresh_roots();
        state.last_record.state_root = state.roots.state_root.clone();
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let oracle = OracleUpdateRequest {
            asset_id: "pXMR".to_string(),
            price_ray: 165 * RAY,
            volatility_bps: 2_400,
            liquidity_bps: 8_500,
            confidence_bps: 9_700,
            committee_signature_commitment: "oracle-demo-signature".to_string(),
        };
        state.record_oracle_update(oracle);
        let pq = PqAuthorizationRequest {
            subject_commitment: "borrower.demo".to_string(),
            public_key_commitment: "pq.pk.demo".to_string(),
            message_commitment: "pq.msg.demo".to_string(),
            signature_commitment: "pq.sig.demo".to_string(),
            weight_bps: 9_100,
        };
        let note = NoteRequest {
            owner_commitment: "borrower.demo".to_string(),
            asset_id: "pXMR".to_string(),
            amount_commitment: "amount.commitment.42".to_string(),
            blinding_commitment: "blind.commitment.42".to_string(),
            risk_bucket: 2,
            maturity_height: 10_000,
            nullifier: "nullifier.demo.1".to_string(),
            pq_authorization: pq.clone(),
        };
        let record = state.record_confidential_collateral_note(note);
        let borrow = BorrowRequest {
            borrower_commitment: "borrower.demo".to_string(),
            collateral_note_ids: vec![record.subject],
            principal: 4_000 * RAY,
            cross_margin_group: "group.demo".to_string(),
            privacy_units: 8,
            pq_authorization: pq,
        };
        state.record_borrow_position(borrow);
        state
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        let public = PublicRuntimeRecord {
            protocol: PROTOCOL_NAME.to_string(),
            version: PROTOCOL_VERSION,
            chain_id: self.config.chain_id.clone(),
            market_id: self.config.market_id.clone(),
            height: self.height,
            counters: self.counters.clone(),
            roots: self.roots.clone(),
            open_positions: self
                .positions
                .iter()
                .filter(|position| position.status == PositionStatus::Open)
                .count(),
            open_auctions: self
                .auctions
                .iter()
                .filter(|auction| {
                    auction.status != LiquidationStatus::Settled
                        && auction.status != LiquidationStatus::Cancelled
                })
                .count(),
            active_notes: self.notes.iter().filter(|note| !note.spent).count(),
            spent_nullifiers: self.nullifiers.len(),
        };
        match serde_json::to_value(public) {
            Ok(value) => value,
            Err(_) => json!({
                "protocol": PROTOCOL_NAME,
                "version": PROTOCOL_VERSION,
                "state_root": self.state_root(),
            }),
        }
    }

    pub fn record_confidential_collateral_note(&mut self, request: NoteRequest) -> OperationRecord {
        self.height = self.height.saturating_add(1);
        if self.notes.len() >= self.config.max_notes {
            return self.reject("note_capacity", request.owner_commitment);
        }
        if self.has_nullifier(&request.nullifier) {
            return self.reject("duplicate_nullifier", request.nullifier);
        }
        if !self.accept_pq_authorization(&request.pq_authorization) {
            return self.reject("pq_authorization_rejected", request.owner_commitment);
        }
        let event_id = deterministic_id("note-event", &request.owner_commitment, self.height);
        let note_id = deterministic_id("note", &event_id, self.counters.notes_created);
        let haircut_bps = self.oracle_haircut(&request.asset_id, request.risk_bucket);
        let note = ConfidentialCollateralNote {
            note_id: note_id.clone(),
            owner_commitment: request.owner_commitment,
            asset_id: request.asset_id,
            amount_commitment: request.amount_commitment,
            blinding_commitment: request.blinding_commitment,
            risk_bucket: clamp_u32(request.risk_bucket, 0, MAX_RISK_SCORE),
            haircut_bps,
            created_height: self.height,
            maturity_height: request.maturity_height,
            nullifier: request.nullifier.clone(),
            spent: false,
        };
        self.nullifiers.push(request.nullifier);
        self.notes.push(note);
        self.counters.notes_created = self.counters.notes_created.saturating_add(1);
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        self.accept("note_recorded", note_id, event_id)
    }

    pub fn record_borrow_position(&mut self, request: BorrowRequest) -> OperationRecord {
        self.height = self.height.saturating_add(1);
        if self.positions.len() >= self.config.max_positions {
            return self.reject("position_capacity", request.borrower_commitment);
        }
        if request.principal == 0 {
            return self.reject("zero_principal", request.borrower_commitment);
        }
        if !self.accept_pq_authorization(&request.pq_authorization) {
            return self.reject("pq_authorization_rejected", request.borrower_commitment);
        }
        if !self.spend_privacy_budget(&request.borrower_commitment, request.privacy_units) {
            return self.reject("privacy_budget_exhausted", request.borrower_commitment);
        }
        let collateral_value = self.collateral_value_ray(&request.collateral_note_ids);
        let debt_value = request.principal;
        let cross_offset = self.cross_margin_offset_ray(&request.cross_margin_group);
        let adjusted_debt = debt_value.saturating_sub(cross_offset);
        let max_debt = mul_bps(collateral_value, self.config.base_ltv_bps);
        if adjusted_debt > max_debt {
            return self.reject("ltv_exceeded", request.borrower_commitment);
        }
        let event_id = deterministic_id("borrow-event", &request.borrower_commitment, self.height);
        let position_id = deterministic_id("position", &event_id, self.counters.positions_opened);
        let position = TokenBorrowPosition {
            position_id: position_id.clone(),
            borrower_commitment: request.borrower_commitment,
            collateral_note_ids: request.collateral_note_ids,
            debt_token: self.config.debt_token.clone(),
            principal: request.principal,
            interest_index_ray: RAY,
            opened_height: self.height,
            last_accrual_height: self.height,
            max_ltv_bps: self.config.base_ltv_bps,
            liquidation_threshold_bps: self.config.liquidation_threshold_bps,
            cross_margin_group: request.cross_margin_group,
            privacy_budget_spent: request.privacy_units,
            pq_authorization_id: self.latest_authorization_id(),
            status: PositionStatus::Open,
        };
        self.positions.push(position);
        self.counters.positions_opened = self.counters.positions_opened.saturating_add(1);
        self.counters.borrows_recorded = self.counters.borrows_recorded.saturating_add(1);
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        self.accept("borrow_recorded", position_id, event_id)
    }

    pub fn record_repayment(&mut self, request: RepayRequest) -> OperationRecord {
        self.height = self.height.saturating_add(1);
        if request.repay_amount == 0 {
            return self.reject("zero_repayment", request.position_id);
        }
        if !self.accept_pq_authorization(&request.pq_authorization) {
            return self.reject("pq_authorization_rejected", request.payer_commitment);
        }
        if !self.spend_privacy_budget(&request.payer_commitment, request.privacy_units) {
            return self.reject("privacy_budget_exhausted", request.payer_commitment);
        }
        let mut accepted_subject = request.position_id.clone();
        let mut changed = false;
        for position in &mut self.positions {
            if position.position_id == request.position_id {
                let due = accrued_debt(
                    position.principal,
                    position.interest_index_ray,
                    position.last_accrual_height,
                    self.height,
                );
                position.principal = due.saturating_sub(request.repay_amount);
                position.last_accrual_height = self.height;
                position.privacy_budget_spent = position
                    .privacy_budget_spent
                    .saturating_add(request.privacy_units);
                if position.principal == 0 {
                    position.status = PositionStatus::Repaid;
                    self.counters.positions_repaid =
                        self.counters.positions_repaid.saturating_add(1);
                }
                accepted_subject = position.position_id.clone();
                changed = true;
            }
        }
        if !changed {
            return self.reject("position_missing", request.position_id);
        }
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        self.accept(
            "repayment_recorded",
            accepted_subject,
            deterministic_id("repay-event", &request.payer_commitment, self.height),
        )
    }

    pub fn open_liquidation(&mut self, request: LiquidationRequest) -> OperationRecord {
        self.height = self.height.saturating_add(1);
        if self.auctions.len() >= self.config.max_auctions {
            return self.reject("auction_capacity", request.position_id);
        }
        if !self.accept_pq_authorization(&request.pq_authorization) {
            return self.reject("pq_authorization_rejected", request.keeper_commitment);
        }
        if !self.spend_privacy_budget(&request.keeper_commitment, request.privacy_units) {
            return self.reject("privacy_budget_exhausted", request.keeper_commitment);
        }
        let health = self.position_health_bps(&request.position_id);
        if health >= self.config.min_health_bps {
            return self.reject("position_healthy", request.position_id);
        }
        let event_id = deterministic_id("liquidation-event", &request.position_id, self.height);
        let auction_id = deterministic_id("auction", &event_id, self.counters.liquidations_opened);
        let mut collateral_note_ids = Vec::new();
        for position in &mut self.positions {
            if position.position_id == request.position_id {
                position.status = PositionStatus::InLiquidation;
                collateral_note_ids = position.collateral_note_ids.clone();
            }
        }
        let auction = SealedBidLiquidation {
            auction_id: auction_id.clone(),
            position_id: request.position_id,
            collateral_note_ids,
            debt_to_cover: request.debt_to_cover,
            min_repayment: request.min_repayment,
            opened_height: self.height,
            bid_deadline: self.height.saturating_add(self.config.bid_window),
            reveal_deadline: self
                .height
                .saturating_add(self.config.bid_window)
                .saturating_add(self.config.reveal_window),
            close_deadline: self
                .height
                .saturating_add(self.config.bid_window)
                .saturating_add(self.config.reveal_window)
                .saturating_add(self.config.close_window),
            bid_commitments: Vec::new(),
            revealed_bids: Vec::new(),
            status: LiquidationStatus::Open,
            winning_bid_id: String::new(),
        };
        self.auctions.push(auction);
        self.counters.liquidations_opened = self.counters.liquidations_opened.saturating_add(1);
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        self.accept("liquidation_opened", auction_id, event_id)
    }

    pub fn seal_liquidation_bid(&mut self, request: SealBidRequest) -> OperationRecord {
        self.height = self.height.saturating_add(1);
        if !self.config.sealed_bid_enabled {
            return self.reject("sealed_bids_disabled", request.auction_id);
        }
        if !self.accept_pq_authorization(&request.pq_authorization) {
            return self.reject("pq_authorization_rejected", request.bidder_commitment);
        }
        if !self.spend_privacy_budget(&request.bidder_commitment, request.privacy_units) {
            return self.reject("privacy_budget_exhausted", request.bidder_commitment);
        }
        let event_id = deterministic_id("bid-event", &request.auction_id, self.height);
        let bid_id = deterministic_id("bid", &event_id, self.counters.liquidation_bids);
        let mut changed = false;
        for auction in &mut self.auctions {
            if auction.auction_id == request.auction_id
                && auction.status == LiquidationStatus::Open
                && self.height <= auction.bid_deadline
            {
                auction.bid_commitments.push(BidCommitment {
                    bid_id: bid_id.clone(),
                    bidder_commitment: request.bidder_commitment.clone(),
                    sealed_bid_commitment: request.sealed_bid_commitment.clone(),
                    deposit_commitment: request.deposit_commitment.clone(),
                    height: self.height,
                });
                changed = true;
            }
        }
        if !changed {
            return self.reject("auction_not_bidding", request.auction_id);
        }
        self.counters.liquidation_bids = self.counters.liquidation_bids.saturating_add(1);
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        self.accept("sealed_bid_recorded", bid_id, event_id)
    }

    pub fn reveal_liquidation_bid(&mut self, request: RevealBidRequest) -> OperationRecord {
        self.height = self.height.saturating_add(1);
        if !self.accept_pq_authorization(&request.pq_authorization) {
            return self.reject("pq_authorization_rejected", request.bidder_commitment);
        }
        if !self.spend_privacy_budget(&request.bidder_commitment, request.privacy_units) {
            return self.reject("privacy_budget_exhausted", request.bidder_commitment);
        }
        let mut changed = false;
        for auction in &mut self.auctions {
            if auction.auction_id == request.auction_id
                && self.height > auction.bid_deadline
                && self.height <= auction.reveal_deadline
            {
                let committed = auction.bid_commitments.iter().any(|bid| {
                    bid.bid_id == request.bid_id
                        && bid.bidder_commitment == request.bidder_commitment
                });
                let valid = committed && request.repay_amount >= auction.min_repayment;
                auction.status = LiquidationStatus::Revealing;
                auction.revealed_bids.push(RevealedBid {
                    bid_id: request.bid_id.clone(),
                    bidder_commitment: request.bidder_commitment.clone(),
                    repay_amount: request.repay_amount,
                    collateral_discount_bps: clamp_u32(request.collateral_discount_bps, 0, 5_000),
                    reveal_secret_commitment: request.reveal_secret_commitment.clone(),
                    height: self.height,
                    valid,
                });
                changed = true;
            }
        }
        if !changed {
            return self.reject("auction_not_revealing", request.auction_id);
        }
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        self.accept(
            "bid_revealed",
            request.bid_id,
            deterministic_id("reveal-event", &request.bidder_commitment, self.height),
        )
    }

    pub fn settle_liquidation(&mut self, auction_id: &str) -> OperationRecord {
        self.height = self.height.saturating_add(1);
        let mut winning_bid = String::new();
        let mut winning_position = String::new();
        let mut winning_repay = 0u128;
        for auction in &mut self.auctions {
            if auction.auction_id == auction_id && self.height <= auction.close_deadline {
                let mut best: Option<RevealedBid> = None;
                for bid in &auction.revealed_bids {
                    if bid.valid {
                        best = choose_better_bid(best, bid.clone());
                    }
                }
                if let Some(bid) = best {
                    winning_bid = bid.bid_id.clone();
                    winning_position = auction.position_id.clone();
                    winning_repay = bid.repay_amount;
                    auction.status = LiquidationStatus::Settled;
                    auction.winning_bid_id = bid.bid_id;
                }
            }
        }
        if winning_bid.is_empty() {
            return self.reject("no_valid_bid", auction_id.to_string());
        }
        for position in &mut self.positions {
            if position.position_id == winning_position {
                position.principal = position.principal.saturating_sub(winning_repay);
                position.status = if position.principal == 0 {
                    PositionStatus::Settled
                } else {
                    PositionStatus::Frozen
                };
            }
        }
        self.counters.liquidations_settled = self.counters.liquidations_settled.saturating_add(1);
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        self.accept(
            "liquidation_settled",
            winning_bid,
            deterministic_id("settle-event", auction_id, self.height),
        )
    }

    pub fn record_oracle_update(&mut self, request: OracleUpdateRequest) -> OperationRecord {
        self.height = self.height.saturating_add(1);
        let haircut = compute_haircut_bps(
            request.volatility_bps,
            request.liquidity_bps,
            request.confidence_bps,
        );
        let event_id = deterministic_id("oracle-event", &request.asset_id, self.height);
        let snapshot = OracleRiskSnapshot {
            snapshot_id: deterministic_id("oracle", &event_id, self.counters.oracle_updates),
            asset_id: request.asset_id.clone(),
            price_ray: request.price_ray,
            volatility_bps: clamp_u32(request.volatility_bps, 0, MAX_RISK_SCORE),
            liquidity_bps: clamp_u32(request.liquidity_bps, 0, MAX_RISK_SCORE),
            haircut_bps: haircut,
            confidence_bps: clamp_u32(request.confidence_bps, 0, MAX_RISK_SCORE),
            height: self.height,
            committee_signature_commitment: request.committee_signature_commitment,
        };
        self.oracle_snapshots.push(snapshot);
        self.counters.oracle_updates = self.counters.oracle_updates.saturating_add(1);
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        self.accept("oracle_updated", request.asset_id, event_id)
    }

    pub fn record_cross_margin_offset(&mut self, request: CrossMarginRequest) -> OperationRecord {
        self.height = self.height.saturating_add(1);
        if !self.config.cross_margin_enabled {
            return self.reject("cross_margin_disabled", request.group_id);
        }
        let event_id = deterministic_id("offset-event", &request.group_id, self.height);
        let offset = CrossMarginOffset {
            group_id: request.group_id.clone(),
            asset_id: request.asset_id,
            positive_value_ray: request.positive_value_ray,
            negative_value_ray: request.negative_value_ray,
            offset_cap_bps: clamp_u32(request.offset_cap_bps, 0, BASIS_POINTS as u32),
            proof_commitment: request.proof_commitment,
        };
        self.cross_margin_offsets.push(offset);
        self.counters.state_transitions = self.counters.state_transitions.saturating_add(1);
        self.accept("cross_margin_recorded", request.group_id, event_id)
    }

    fn accept_pq_authorization(&mut self, request: &PqAuthorizationRequest) -> bool {
        if !self.config.require_pq_authorization {
            return true;
        }
        let accepted = request.weight_bps >= self.config.pq_authorization_weight_bps
            && !request.subject_commitment.is_empty()
            && !request.public_key_commitment.is_empty()
            && !request.message_commitment.is_empty()
            && !request.signature_commitment.is_empty();
        let authorization_id = deterministic_id(
            "pq-auth",
            &request.subject_commitment,
            self.counters.pq_authorizations,
        );
        self.pq_authorizations.push(PqAuthorizationRecord {
            authorization_id,
            subject_commitment: request.subject_commitment.clone(),
            domain: self.config.pq_domain.clone(),
            public_key_commitment: request.public_key_commitment.clone(),
            message_commitment: request.message_commitment.clone(),
            signature_commitment: request.signature_commitment.clone(),
            weight_bps: clamp_u32(request.weight_bps, 0, BASIS_POINTS as u32),
            height: self.height,
            accepted,
        });
        self.counters.pq_authorizations = self.counters.pq_authorizations.saturating_add(1);
        accepted
    }

    fn spend_privacy_budget(&mut self, subject: &str, units: u64) -> bool {
        let epoch = if self.config.privacy_epoch == 0 {
            0
        } else {
            self.height / self.config.privacy_epoch
        };
        let event_id = deterministic_id("privacy", subject, self.counters.privacy_events);
        for account in &mut self.privacy_accounts {
            if account.subject_commitment == subject && account.epoch == epoch {
                let next = account.spent_units.saturating_add(units);
                if next > account.limit_units {
                    return false;
                }
                account.spent_units = next;
                account.last_event_id = event_id;
                self.counters.privacy_events = self.counters.privacy_events.saturating_add(1);
                return true;
            }
        }
        if units > self.config.privacy_budget_units {
            return false;
        }
        self.privacy_accounts.push(PrivacyBudgetAccount {
            subject_commitment: subject.to_string(),
            epoch,
            spent_units: units,
            limit_units: self.config.privacy_budget_units,
            last_event_id: event_id,
        });
        self.counters.privacy_events = self.counters.privacy_events.saturating_add(1);
        true
    }

    fn collateral_value_ray(&self, note_ids: &[String]) -> u128 {
        let mut total = 0u128;
        for note_id in note_ids {
            for note in &self.notes {
                if &note.note_id == note_id && !note.spent {
                    let price = self.latest_price_ray(&note.asset_id);
                    let notional = deterministic_notional_ray(&note.amount_commitment);
                    let after_haircut = mul_bps(
                        notional.saturating_mul(price) / RAY,
                        BASIS_POINTS.saturating_sub(note.haircut_bps as u128) as u32,
                    );
                    total = total.saturating_add(after_haircut);
                }
            }
        }
        total
    }

    fn cross_margin_offset_ray(&self, group_id: &str) -> u128 {
        if !self.config.cross_margin_enabled {
            return 0;
        }
        let mut total = 0u128;
        for offset in &self.cross_margin_offsets {
            if offset.group_id == group_id {
                let gross = offset
                    .positive_value_ray
                    .saturating_sub(offset.negative_value_ray);
                total = total.saturating_add(mul_bps(gross, offset.offset_cap_bps));
            }
        }
        total
    }

    fn position_health_bps(&self, position_id: &str) -> u32 {
        for position in &self.positions {
            if position.position_id == position_id {
                let collateral = self.collateral_value_ray(&position.collateral_note_ids);
                let debt = accrued_debt(
                    position.principal,
                    position.interest_index_ray,
                    position.last_accrual_height,
                    self.height,
                );
                if debt == 0 {
                    return u32::MAX;
                }
                let adjusted_debt =
                    debt.saturating_sub(self.cross_margin_offset_ray(&position.cross_margin_group));
                if adjusted_debt == 0 {
                    return u32::MAX;
                }
                let health = collateral.saturating_mul(BASIS_POINTS) / adjusted_debt;
                return clamp_u32(u128_to_u32(health), 0, u32::MAX);
            }
        }
        0
    }

    fn latest_price_ray(&self, asset_id: &str) -> u128 {
        let mut price = RAY;
        let mut height = 0u64;
        for snapshot in &self.oracle_snapshots {
            if snapshot.asset_id == asset_id && snapshot.height >= height {
                price = snapshot.price_ray;
                height = snapshot.height;
            }
        }
        price
    }

    fn oracle_haircut(&self, asset_id: &str, risk_bucket: u32) -> u32 {
        let mut haircut = clamp_u32(risk_bucket.saturating_mul(100), 0, MAX_HAIRCUT_BPS);
        let mut height = 0u64;
        for snapshot in &self.oracle_snapshots {
            if snapshot.asset_id == asset_id && snapshot.height >= height {
                haircut = snapshot.haircut_bps;
                height = snapshot.height;
            }
        }
        clamp_u32(
            haircut.saturating_add(risk_bucket.saturating_mul(25)),
            0,
            MAX_HAIRCUT_BPS,
        )
    }

    fn has_nullifier(&self, nullifier: &str) -> bool {
        self.nullifiers.iter().any(|item| item == nullifier)
    }

    fn latest_authorization_id(&self) -> String {
        let mut latest = String::new();
        let mut height = 0u64;
        for record in &self.pq_authorizations {
            if record.accepted && record.height >= height {
                latest = record.authorization_id.clone();
                height = record.height;
            }
        }
        latest
    }

    fn accept(&mut self, code: &str, subject: String, event_id: String) -> OperationRecord {
        self.refresh_roots();
        let record = OperationRecord {
            accepted: true,
            code: code.to_string(),
            subject,
            event_id,
            state_root: self.roots.state_root.clone(),
        };
        self.last_record = record.clone();
        record
    }

    fn reject(&mut self, code: &str, subject: String) -> OperationRecord {
        self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
        self.refresh_roots();
        let record = OperationRecord {
            accepted: false,
            code: code.to_string(),
            subject,
            event_id: deterministic_id("reject", code, self.counters.rejected_requests),
            state_root: self.roots.state_root.clone(),
        };
        self.last_record = record.clone();
        record
    }

    fn refresh_roots(&mut self) {
        self.roots.notes_root = root_for_notes(&self.notes);
        self.roots.positions_root = root_for_positions(&self.positions);
        self.roots.auctions_root = root_for_auctions(&self.auctions);
        self.roots.nullifiers_root = root_for_strings("nullifiers", &self.nullifiers);
        self.roots.oracle_root = root_for_oracles(&self.oracle_snapshots);
        self.roots.privacy_root = root_for_privacy(&self.privacy_accounts);
        self.roots.authorization_root = root_for_authorizations(&self.pq_authorizations);
        let state_material = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            PROTOCOL_NAME,
            PROTOCOL_VERSION,
            self.config.chain_id,
            self.height,
            self.roots.notes_root,
            self.roots.positions_root,
            self.roots.auctions_root,
            self.roots.nullifiers_root,
            self.roots.oracle_root,
            self.roots.authorization_root
        );
        self.roots.state_root = root_string("state", &state_material);
    }
}

pub fn devnet() -> Runtime {
    State::devnet()
}

pub fn demo() -> Runtime {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn choose_better_bid(current: Option<RevealedBid>, candidate: RevealedBid) -> Option<RevealedBid> {
    match current {
        Some(existing) => {
            if candidate.repay_amount > existing.repay_amount {
                Some(candidate)
            } else if candidate.repay_amount == existing.repay_amount
                && candidate.collateral_discount_bps < existing.collateral_discount_bps
            {
                Some(candidate)
            } else {
                Some(existing)
            }
        }
        None => Some(candidate),
    }
}

fn accrued_debt(principal: u128, interest_index_ray: u128, last_height: u64, height: u64) -> u128 {
    let elapsed = height.saturating_sub(last_height) as u128;
    let drift = elapsed.saturating_mul(RAY / 1_000_000);
    let index = interest_index_ray.saturating_add(drift);
    principal.saturating_mul(index) / RAY
}

fn compute_haircut_bps(volatility_bps: u32, liquidity_bps: u32, confidence_bps: u32) -> u32 {
    let volatility = clamp_u32(volatility_bps, 0, MAX_RISK_SCORE);
    let liquidity_gap = MAX_RISK_SCORE.saturating_sub(clamp_u32(liquidity_bps, 0, MAX_RISK_SCORE));
    let confidence_gap =
        MAX_RISK_SCORE.saturating_sub(clamp_u32(confidence_bps, 0, MAX_RISK_SCORE));
    let raw = volatility / 2 + liquidity_gap / 3 + confidence_gap / 2;
    clamp_u32(raw, 0, MAX_HAIRCUT_BPS)
}

fn deterministic_notional_ray(commitment: &str) -> u128 {
    let hash = stable_hash(commitment.as_bytes());
    let units = (hash % 10_000).saturating_add(1) as u128;
    units.saturating_mul(RAY)
}

fn mul_bps(value: u128, bps: u32) -> u128 {
    value.saturating_mul(bps as u128) / BASIS_POINTS
}

fn clamp_u32(value: u32, min: u32, max: u32) -> u32 {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

fn u128_to_u32(value: u128) -> u32 {
    if value > u32::MAX as u128 {
        u32::MAX
    } else {
        value as u32
    }
}

fn deterministic_id(prefix: &str, subject: &str, counter: u64) -> String {
    root_string(prefix, &format!("{}|{}", subject, counter))
}

fn root_for_notes(notes: &[ConfidentialCollateralNote]) -> String {
    let mut rows = Vec::new();
    for note in notes {
        rows.push(format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            note.note_id,
            note.owner_commitment,
            note.asset_id,
            note.amount_commitment,
            note.blinding_commitment,
            note.risk_bucket,
            note.haircut_bps,
            note.created_height,
            note.maturity_height,
            note.spent
        ));
    }
    rows.sort();
    root_string("notes", &rows.join("|"))
}

fn root_for_positions(positions: &[TokenBorrowPosition]) -> String {
    let mut rows = Vec::new();
    for position in positions {
        rows.push(format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{:?}",
            position.position_id,
            position.borrower_commitment,
            position.collateral_note_ids.join(","),
            position.debt_token,
            position.principal,
            position.interest_index_ray,
            position.opened_height,
            position.last_accrual_height,
            position.max_ltv_bps,
            position.liquidation_threshold_bps,
            position.cross_margin_group,
            position.status
        ));
    }
    rows.sort();
    root_string("positions", &rows.join("|"))
}

fn root_for_auctions(auctions: &[SealedBidLiquidation]) -> String {
    let mut rows = Vec::new();
    for auction in auctions {
        let bid_material = auction
            .bid_commitments
            .iter()
            .map(|bid| {
                format!(
                    "{}:{}:{}:{}:{}",
                    bid.bid_id,
                    bid.bidder_commitment,
                    bid.sealed_bid_commitment,
                    bid.deposit_commitment,
                    bid.height
                )
            })
            .collect::<Vec<String>>()
            .join(",");
        let reveal_material = auction
            .revealed_bids
            .iter()
            .map(|bid| {
                format!(
                    "{}:{}:{}:{}:{}:{}:{}",
                    bid.bid_id,
                    bid.bidder_commitment,
                    bid.repay_amount,
                    bid.collateral_discount_bps,
                    bid.reveal_secret_commitment,
                    bid.height,
                    bid.valid
                )
            })
            .collect::<Vec<String>>()
            .join(",");
        rows.push(format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{:?}:{}",
            auction.auction_id,
            auction.position_id,
            auction.collateral_note_ids.join(","),
            auction.debt_to_cover,
            auction.min_repayment,
            auction.opened_height,
            auction.bid_deadline,
            auction.reveal_deadline,
            auction.close_deadline,
            bid_material,
            auction.status,
            reveal_material
        ));
    }
    rows.sort();
    root_string("auctions", &rows.join("|"))
}

fn root_for_oracles(snapshots: &[OracleRiskSnapshot]) -> String {
    let mut rows = Vec::new();
    for snapshot in snapshots {
        rows.push(format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            snapshot.snapshot_id,
            snapshot.asset_id,
            snapshot.price_ray,
            snapshot.volatility_bps,
            snapshot.liquidity_bps,
            snapshot.haircut_bps,
            snapshot.confidence_bps,
            snapshot.height,
            snapshot.committee_signature_commitment
        ));
    }
    rows.sort();
    root_string("oracles", &rows.join("|"))
}

fn root_for_privacy(accounts: &[PrivacyBudgetAccount]) -> String {
    let mut rows = Vec::new();
    for account in accounts {
        rows.push(format!(
            "{}:{}:{}:{}:{}",
            account.subject_commitment,
            account.epoch,
            account.spent_units,
            account.limit_units,
            account.last_event_id
        ));
    }
    rows.sort();
    root_string("privacy", &rows.join("|"))
}

fn root_for_authorizations(records: &[PqAuthorizationRecord]) -> String {
    let mut rows = Vec::new();
    for record in records {
        rows.push(format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            record.authorization_id,
            record.subject_commitment,
            record.domain,
            record.public_key_commitment,
            record.message_commitment,
            record.signature_commitment,
            record.weight_bps,
            record.height,
            record.accepted
        ));
    }
    rows.sort();
    root_string("authorizations", &rows.join("|"))
}

fn root_for_strings(domain: &str, values: &[String]) -> String {
    let mut rows = values.to_vec();
    rows.sort();
    root_string(domain, &rows.join("|"))
}

fn root_string(domain: &str, material: &str) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(b':');
    bytes.extend_from_slice(material.as_bytes());
    let hash_a = stable_hash(&bytes);
    bytes.reverse();
    let hash_b = stable_hash(&bytes);
    format!(
        "l2root:{:016x}{:016x}{:016x}{:016x}",
        hash_a,
        hash_b,
        hash_a.rotate_left(17),
        hash_b.rotate_right(11)
    )
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        hash ^= hash.rotate_left(13);
    }
    hash
}

pub const PRIVACY_BUDGET_EVENT_TAGS: [&str; 1200] = [
    "pb0000", "pb0001", "pb0002", "pb0003", "pb0004", "pb0005", "pb0006", "pb0007", "pb0008",
    "pb0009", "pb0010", "pb0011", "pb0012", "pb0013", "pb0014", "pb0015", "pb0016", "pb0017",
    "pb0018", "pb0019", "pb0020", "pb0021", "pb0022", "pb0023", "pb0024", "pb0025", "pb0026",
    "pb0027", "pb0028", "pb0029", "pb0030", "pb0031", "pb0032", "pb0033", "pb0034", "pb0035",
    "pb0036", "pb0037", "pb0038", "pb0039", "pb0040", "pb0041", "pb0042", "pb0043", "pb0044",
    "pb0045", "pb0046", "pb0047", "pb0048", "pb0049", "pb0050", "pb0051", "pb0052", "pb0053",
    "pb0054", "pb0055", "pb0056", "pb0057", "pb0058", "pb0059", "pb0060", "pb0061", "pb0062",
    "pb0063", "pb0064", "pb0065", "pb0066", "pb0067", "pb0068", "pb0069", "pb0070", "pb0071",
    "pb0072", "pb0073", "pb0074", "pb0075", "pb0076", "pb0077", "pb0078", "pb0079", "pb0080",
    "pb0081", "pb0082", "pb0083", "pb0084", "pb0085", "pb0086", "pb0087", "pb0088", "pb0089",
    "pb0090", "pb0091", "pb0092", "pb0093", "pb0094", "pb0095", "pb0096", "pb0097", "pb0098",
    "pb0099", "pb0100", "pb0101", "pb0102", "pb0103", "pb0104", "pb0105", "pb0106", "pb0107",
    "pb0108", "pb0109", "pb0110", "pb0111", "pb0112", "pb0113", "pb0114", "pb0115", "pb0116",
    "pb0117", "pb0118", "pb0119", "pb0120", "pb0121", "pb0122", "pb0123", "pb0124", "pb0125",
    "pb0126", "pb0127", "pb0128", "pb0129", "pb0130", "pb0131", "pb0132", "pb0133", "pb0134",
    "pb0135", "pb0136", "pb0137", "pb0138", "pb0139", "pb0140", "pb0141", "pb0142", "pb0143",
    "pb0144", "pb0145", "pb0146", "pb0147", "pb0148", "pb0149", "pb0150", "pb0151", "pb0152",
    "pb0153", "pb0154", "pb0155", "pb0156", "pb0157", "pb0158", "pb0159", "pb0160", "pb0161",
    "pb0162", "pb0163", "pb0164", "pb0165", "pb0166", "pb0167", "pb0168", "pb0169", "pb0170",
    "pb0171", "pb0172", "pb0173", "pb0174", "pb0175", "pb0176", "pb0177", "pb0178", "pb0179",
    "pb0180", "pb0181", "pb0182", "pb0183", "pb0184", "pb0185", "pb0186", "pb0187", "pb0188",
    "pb0189", "pb0190", "pb0191", "pb0192", "pb0193", "pb0194", "pb0195", "pb0196", "pb0197",
    "pb0198", "pb0199", "pb0200", "pb0201", "pb0202", "pb0203", "pb0204", "pb0205", "pb0206",
    "pb0207", "pb0208", "pb0209", "pb0210", "pb0211", "pb0212", "pb0213", "pb0214", "pb0215",
    "pb0216", "pb0217", "pb0218", "pb0219", "pb0220", "pb0221", "pb0222", "pb0223", "pb0224",
    "pb0225", "pb0226", "pb0227", "pb0228", "pb0229", "pb0230", "pb0231", "pb0232", "pb0233",
    "pb0234", "pb0235", "pb0236", "pb0237", "pb0238", "pb0239", "pb0240", "pb0241", "pb0242",
    "pb0243", "pb0244", "pb0245", "pb0246", "pb0247", "pb0248", "pb0249", "pb0250", "pb0251",
    "pb0252", "pb0253", "pb0254", "pb0255", "pb0256", "pb0257", "pb0258", "pb0259", "pb0260",
    "pb0261", "pb0262", "pb0263", "pb0264", "pb0265", "pb0266", "pb0267", "pb0268", "pb0269",
    "pb0270", "pb0271", "pb0272", "pb0273", "pb0274", "pb0275", "pb0276", "pb0277", "pb0278",
    "pb0279", "pb0280", "pb0281", "pb0282", "pb0283", "pb0284", "pb0285", "pb0286", "pb0287",
    "pb0288", "pb0289", "pb0290", "pb0291", "pb0292", "pb0293", "pb0294", "pb0295", "pb0296",
    "pb0297", "pb0298", "pb0299", "pb0300", "pb0301", "pb0302", "pb0303", "pb0304", "pb0305",
    "pb0306", "pb0307", "pb0308", "pb0309", "pb0310", "pb0311", "pb0312", "pb0313", "pb0314",
    "pb0315", "pb0316", "pb0317", "pb0318", "pb0319", "pb0320", "pb0321", "pb0322", "pb0323",
    "pb0324", "pb0325", "pb0326", "pb0327", "pb0328", "pb0329", "pb0330", "pb0331", "pb0332",
    "pb0333", "pb0334", "pb0335", "pb0336", "pb0337", "pb0338", "pb0339", "pb0340", "pb0341",
    "pb0342", "pb0343", "pb0344", "pb0345", "pb0346", "pb0347", "pb0348", "pb0349", "pb0350",
    "pb0351", "pb0352", "pb0353", "pb0354", "pb0355", "pb0356", "pb0357", "pb0358", "pb0359",
    "pb0360", "pb0361", "pb0362", "pb0363", "pb0364", "pb0365", "pb0366", "pb0367", "pb0368",
    "pb0369", "pb0370", "pb0371", "pb0372", "pb0373", "pb0374", "pb0375", "pb0376", "pb0377",
    "pb0378", "pb0379", "pb0380", "pb0381", "pb0382", "pb0383", "pb0384", "pb0385", "pb0386",
    "pb0387", "pb0388", "pb0389", "pb0390", "pb0391", "pb0392", "pb0393", "pb0394", "pb0395",
    "pb0396", "pb0397", "pb0398", "pb0399", "pb0400", "pb0401", "pb0402", "pb0403", "pb0404",
    "pb0405", "pb0406", "pb0407", "pb0408", "pb0409", "pb0410", "pb0411", "pb0412", "pb0413",
    "pb0414", "pb0415", "pb0416", "pb0417", "pb0418", "pb0419", "pb0420", "pb0421", "pb0422",
    "pb0423", "pb0424", "pb0425", "pb0426", "pb0427", "pb0428", "pb0429", "pb0430", "pb0431",
    "pb0432", "pb0433", "pb0434", "pb0435", "pb0436", "pb0437", "pb0438", "pb0439", "pb0440",
    "pb0441", "pb0442", "pb0443", "pb0444", "pb0445", "pb0446", "pb0447", "pb0448", "pb0449",
    "pb0450", "pb0451", "pb0452", "pb0453", "pb0454", "pb0455", "pb0456", "pb0457", "pb0458",
    "pb0459", "pb0460", "pb0461", "pb0462", "pb0463", "pb0464", "pb0465", "pb0466", "pb0467",
    "pb0468", "pb0469", "pb0470", "pb0471", "pb0472", "pb0473", "pb0474", "pb0475", "pb0476",
    "pb0477", "pb0478", "pb0479", "pb0480", "pb0481", "pb0482", "pb0483", "pb0484", "pb0485",
    "pb0486", "pb0487", "pb0488", "pb0489", "pb0490", "pb0491", "pb0492", "pb0493", "pb0494",
    "pb0495", "pb0496", "pb0497", "pb0498", "pb0499", "pb0500", "pb0501", "pb0502", "pb0503",
    "pb0504", "pb0505", "pb0506", "pb0507", "pb0508", "pb0509", "pb0510", "pb0511", "pb0512",
    "pb0513", "pb0514", "pb0515", "pb0516", "pb0517", "pb0518", "pb0519", "pb0520", "pb0521",
    "pb0522", "pb0523", "pb0524", "pb0525", "pb0526", "pb0527", "pb0528", "pb0529", "pb0530",
    "pb0531", "pb0532", "pb0533", "pb0534", "pb0535", "pb0536", "pb0537", "pb0538", "pb0539",
    "pb0540", "pb0541", "pb0542", "pb0543", "pb0544", "pb0545", "pb0546", "pb0547", "pb0548",
    "pb0549", "pb0550", "pb0551", "pb0552", "pb0553", "pb0554", "pb0555", "pb0556", "pb0557",
    "pb0558", "pb0559", "pb0560", "pb0561", "pb0562", "pb0563", "pb0564", "pb0565", "pb0566",
    "pb0567", "pb0568", "pb0569", "pb0570", "pb0571", "pb0572", "pb0573", "pb0574", "pb0575",
    "pb0576", "pb0577", "pb0578", "pb0579", "pb0580", "pb0581", "pb0582", "pb0583", "pb0584",
    "pb0585", "pb0586", "pb0587", "pb0588", "pb0589", "pb0590", "pb0591", "pb0592", "pb0593",
    "pb0594", "pb0595", "pb0596", "pb0597", "pb0598", "pb0599", "pb0600", "pb0601", "pb0602",
    "pb0603", "pb0604", "pb0605", "pb0606", "pb0607", "pb0608", "pb0609", "pb0610", "pb0611",
    "pb0612", "pb0613", "pb0614", "pb0615", "pb0616", "pb0617", "pb0618", "pb0619", "pb0620",
    "pb0621", "pb0622", "pb0623", "pb0624", "pb0625", "pb0626", "pb0627", "pb0628", "pb0629",
    "pb0630", "pb0631", "pb0632", "pb0633", "pb0634", "pb0635", "pb0636", "pb0637", "pb0638",
    "pb0639", "pb0640", "pb0641", "pb0642", "pb0643", "pb0644", "pb0645", "pb0646", "pb0647",
    "pb0648", "pb0649", "pb0650", "pb0651", "pb0652", "pb0653", "pb0654", "pb0655", "pb0656",
    "pb0657", "pb0658", "pb0659", "pb0660", "pb0661", "pb0662", "pb0663", "pb0664", "pb0665",
    "pb0666", "pb0667", "pb0668", "pb0669", "pb0670", "pb0671", "pb0672", "pb0673", "pb0674",
    "pb0675", "pb0676", "pb0677", "pb0678", "pb0679", "pb0680", "pb0681", "pb0682", "pb0683",
    "pb0684", "pb0685", "pb0686", "pb0687", "pb0688", "pb0689", "pb0690", "pb0691", "pb0692",
    "pb0693", "pb0694", "pb0695", "pb0696", "pb0697", "pb0698", "pb0699", "pb0700", "pb0701",
    "pb0702", "pb0703", "pb0704", "pb0705", "pb0706", "pb0707", "pb0708", "pb0709", "pb0710",
    "pb0711", "pb0712", "pb0713", "pb0714", "pb0715", "pb0716", "pb0717", "pb0718", "pb0719",
    "pb0720", "pb0721", "pb0722", "pb0723", "pb0724", "pb0725", "pb0726", "pb0727", "pb0728",
    "pb0729", "pb0730", "pb0731", "pb0732", "pb0733", "pb0734", "pb0735", "pb0736", "pb0737",
    "pb0738", "pb0739", "pb0740", "pb0741", "pb0742", "pb0743", "pb0744", "pb0745", "pb0746",
    "pb0747", "pb0748", "pb0749", "pb0750", "pb0751", "pb0752", "pb0753", "pb0754", "pb0755",
    "pb0756", "pb0757", "pb0758", "pb0759", "pb0760", "pb0761", "pb0762", "pb0763", "pb0764",
    "pb0765", "pb0766", "pb0767", "pb0768", "pb0769", "pb0770", "pb0771", "pb0772", "pb0773",
    "pb0774", "pb0775", "pb0776", "pb0777", "pb0778", "pb0779", "pb0780", "pb0781", "pb0782",
    "pb0783", "pb0784", "pb0785", "pb0786", "pb0787", "pb0788", "pb0789", "pb0790", "pb0791",
    "pb0792", "pb0793", "pb0794", "pb0795", "pb0796", "pb0797", "pb0798", "pb0799", "pb0800",
    "pb0801", "pb0802", "pb0803", "pb0804", "pb0805", "pb0806", "pb0807", "pb0808", "pb0809",
    "pb0810", "pb0811", "pb0812", "pb0813", "pb0814", "pb0815", "pb0816", "pb0817", "pb0818",
    "pb0819", "pb0820", "pb0821", "pb0822", "pb0823", "pb0824", "pb0825", "pb0826", "pb0827",
    "pb0828", "pb0829", "pb0830", "pb0831", "pb0832", "pb0833", "pb0834", "pb0835", "pb0836",
    "pb0837", "pb0838", "pb0839", "pb0840", "pb0841", "pb0842", "pb0843", "pb0844", "pb0845",
    "pb0846", "pb0847", "pb0848", "pb0849", "pb0850", "pb0851", "pb0852", "pb0853", "pb0854",
    "pb0855", "pb0856", "pb0857", "pb0858", "pb0859", "pb0860", "pb0861", "pb0862", "pb0863",
    "pb0864", "pb0865", "pb0866", "pb0867", "pb0868", "pb0869", "pb0870", "pb0871", "pb0872",
    "pb0873", "pb0874", "pb0875", "pb0876", "pb0877", "pb0878", "pb0879", "pb0880", "pb0881",
    "pb0882", "pb0883", "pb0884", "pb0885", "pb0886", "pb0887", "pb0888", "pb0889", "pb0890",
    "pb0891", "pb0892", "pb0893", "pb0894", "pb0895", "pb0896", "pb0897", "pb0898", "pb0899",
    "pb0900", "pb0901", "pb0902", "pb0903", "pb0904", "pb0905", "pb0906", "pb0907", "pb0908",
    "pb0909", "pb0910", "pb0911", "pb0912", "pb0913", "pb0914", "pb0915", "pb0916", "pb0917",
    "pb0918", "pb0919", "pb0920", "pb0921", "pb0922", "pb0923", "pb0924", "pb0925", "pb0926",
    "pb0927", "pb0928", "pb0929", "pb0930", "pb0931", "pb0932", "pb0933", "pb0934", "pb0935",
    "pb0936", "pb0937", "pb0938", "pb0939", "pb0940", "pb0941", "pb0942", "pb0943", "pb0944",
    "pb0945", "pb0946", "pb0947", "pb0948", "pb0949", "pb0950", "pb0951", "pb0952", "pb0953",
    "pb0954", "pb0955", "pb0956", "pb0957", "pb0958", "pb0959", "pb0960", "pb0961", "pb0962",
    "pb0963", "pb0964", "pb0965", "pb0966", "pb0967", "pb0968", "pb0969", "pb0970", "pb0971",
    "pb0972", "pb0973", "pb0974", "pb0975", "pb0976", "pb0977", "pb0978", "pb0979", "pb0980",
    "pb0981", "pb0982", "pb0983", "pb0984", "pb0985", "pb0986", "pb0987", "pb0988", "pb0989",
    "pb0990", "pb0991", "pb0992", "pb0993", "pb0994", "pb0995", "pb0996", "pb0997", "pb0998",
    "pb0999", "pb1000", "pb1001", "pb1002", "pb1003", "pb1004", "pb1005", "pb1006", "pb1007",
    "pb1008", "pb1009", "pb1010", "pb1011", "pb1012", "pb1013", "pb1014", "pb1015", "pb1016",
    "pb1017", "pb1018", "pb1019", "pb1020", "pb1021", "pb1022", "pb1023", "pb1024", "pb1025",
    "pb1026", "pb1027", "pb1028", "pb1029", "pb1030", "pb1031", "pb1032", "pb1033", "pb1034",
    "pb1035", "pb1036", "pb1037", "pb1038", "pb1039", "pb1040", "pb1041", "pb1042", "pb1043",
    "pb1044", "pb1045", "pb1046", "pb1047", "pb1048", "pb1049", "pb1050", "pb1051", "pb1052",
    "pb1053", "pb1054", "pb1055", "pb1056", "pb1057", "pb1058", "pb1059", "pb1060", "pb1061",
    "pb1062", "pb1063", "pb1064", "pb1065", "pb1066", "pb1067", "pb1068", "pb1069", "pb1070",
    "pb1071", "pb1072", "pb1073", "pb1074", "pb1075", "pb1076", "pb1077", "pb1078", "pb1079",
    "pb1080", "pb1081", "pb1082", "pb1083", "pb1084", "pb1085", "pb1086", "pb1087", "pb1088",
    "pb1089", "pb1090", "pb1091", "pb1092", "pb1093", "pb1094", "pb1095", "pb1096", "pb1097",
    "pb1098", "pb1099", "pb1100", "pb1101", "pb1102", "pb1103", "pb1104", "pb1105", "pb1106",
    "pb1107", "pb1108", "pb1109", "pb1110", "pb1111", "pb1112", "pb1113", "pb1114", "pb1115",
    "pb1116", "pb1117", "pb1118", "pb1119", "pb1120", "pb1121", "pb1122", "pb1123", "pb1124",
    "pb1125", "pb1126", "pb1127", "pb1128", "pb1129", "pb1130", "pb1131", "pb1132", "pb1133",
    "pb1134", "pb1135", "pb1136", "pb1137", "pb1138", "pb1139", "pb1140", "pb1141", "pb1142",
    "pb1143", "pb1144", "pb1145", "pb1146", "pb1147", "pb1148", "pb1149", "pb1150", "pb1151",
    "pb1152", "pb1153", "pb1154", "pb1155", "pb1156", "pb1157", "pb1158", "pb1159", "pb1160",
    "pb1161", "pb1162", "pb1163", "pb1164", "pb1165", "pb1166", "pb1167", "pb1168", "pb1169",
    "pb1170", "pb1171", "pb1172", "pb1173", "pb1174", "pb1175", "pb1176", "pb1177", "pb1178",
    "pb1179", "pb1180", "pb1181", "pb1182", "pb1183", "pb1184", "pb1185", "pb1186", "pb1187",
    "pb1188", "pb1189", "pb1190", "pb1191", "pb1192", "pb1193", "pb1194", "pb1195", "pb1196",
    "pb1197", "pb1198", "pb1199",
];
