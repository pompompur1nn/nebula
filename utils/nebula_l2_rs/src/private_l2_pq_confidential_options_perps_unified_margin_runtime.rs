use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const PROTOCOL_NAME: &str = "nebula-l2-pq-confidential-options-perps-unified-margin";
pub const PROTOCOL_VERSION: u32 = 1;
pub const BASIS_POINTS: u128 = 10_000;
pub const PRICE_SCALE: u128 = 1_000_000;
pub const QUANTITY_SCALE: u128 = 1_000_000;
pub const ROOT_DOMAIN: &str = "nebula.private.l2.unified.margin.runtime";
pub const MAX_COLLATERAL_ASSETS: usize = 16;
pub const MAX_OPTIONS_VAULTS: usize = 32;
pub const MAX_PERP_MARKETS: usize = 32;
pub const MAX_AUCTIONS: usize = 64;
pub const DEFAULT_INITIAL_MARGIN_BPS: u32 = 1_250;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u32 = 750;
pub const DEFAULT_LIQUIDATION_PENALTY_BPS: u32 = 350;
pub const DEFAULT_BRIDGE_HAIRCUT_BPS: u32 = 150;
pub const DEFAULT_CONFIDENTIALITY_FEE_BPS: u32 = 8;
pub const DEFAULT_CIRCUIT_BREAKER_BPS: u32 = 1_200;
pub const DEFAULT_RISK_OFFSET_CAP_BPS: u32 = 6_000;
pub const DEFAULT_SETTLEMENT_DELAY_SLOTS: u64 = 12;
pub const DEFAULT_AUCTION_DURATION_SLOTS: u64 = 24;
pub const DEFAULT_ORACLE_STALE_AFTER_SLOTS: u64 = 30;
pub const DEFAULT_WITHDRAWAL_FEE_BPS: u32 = 5;
pub const DEFAULT_TOKEN_COLLATERAL_FACTOR_BPS: u32 = 8_500;
pub const DEFAULT_STABLE_COLLATERAL_FACTOR_BPS: u32 = 9_500;
pub const DEFAULT_VOL_SHOCK_BPS: u32 = 2_000;
pub const DEFAULT_FUNDING_CLAMP_BPS: i64 = 75;
pub const DEFAULT_SETTLEMENT_BATCH_LIMIT: u32 = 512;
pub const EMPTY_ROOT: &str = "r0000000000000000";
pub const EVENT_DEPOSIT: u32 = 1;
pub const EVENT_WITHDRAWAL: u32 = 2;
pub const EVENT_OPTION_MINT: u32 = 3;
pub const EVENT_OPTION_EXERCISE: u32 = 4;
pub const EVENT_PERP_OPEN: u32 = 5;
pub const EVENT_PERP_CLOSE: u32 = 6;
pub const EVENT_RISK_OFFSET: u32 = 7;
pub const EVENT_AUCTION_SEALED: u32 = 8;
pub const EVENT_AUCTION_SETTLED: u32 = 9;
pub const EVENT_ORACLE_BREAKER: u32 = 10;
pub const EVENT_BRIDGE_HAIRCUT: u32 = 11;
pub const EVENT_PRIVATE_SETTLEMENT: u32 = 12;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: u64,
    pub market_id: String,
    pub initial_margin_bps: u32,
    pub maintenance_margin_bps: u32,
    pub liquidation_penalty_bps: u32,
    pub bridge_haircut_bps: u32,
    pub confidentiality_fee_bps: u32,
    pub circuit_breaker_bps: u32,
    pub risk_offset_cap_bps: u32,
    pub settlement_delay_slots: u64,
    pub auction_duration_slots: u64,
    pub oracle_stale_after_slots: u64,
    pub withdrawal_fee_bps: u32,
    pub token_collateral_factor_bps: u32,
    pub stable_collateral_factor_bps: u32,
    pub vol_shock_bps: u32,
    pub funding_clamp_bps: i64,
    pub settlement_batch_limit: u32,
    pub allow_bridge_collateral: bool,
    pub allow_portfolio_offsets: bool,
    pub allow_private_settlement: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub deposits: u64,
    pub withdrawals: u64,
    pub option_vaults: u64,
    pub option_mints: u64,
    pub option_exercises: u64,
    pub perp_positions: u64,
    pub perp_updates: u64,
    pub risk_offsets: u64,
    pub sealed_auctions: u64,
    pub oracle_updates: u64,
    pub oracle_breakers: u64,
    pub bridge_haircuts: u64,
    pub private_settlements: u64,
    pub rejected_requests: u64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub collateral_root: String,
    pub options_root: String,
    pub perps_root: String,
    pub risk_root: String,
    pub auctions_root: String,
    pub oracle_root: String,
    pub settlement_root: String,
    pub bridge_root: String,
    pub state_root: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenCollateral {
    pub account: String,
    pub token: String,
    pub shielded_commitment: String,
    pub amount: u128,
    pub collateral_factor_bps: u32,
    pub bridge_domain: String,
    pub bridge_haircut_bps: u32,
    pub locked: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OptionsVault {
    pub vault_id: String,
    pub owner: String,
    pub underlying: String,
    pub quote: String,
    pub strike_price: u128,
    pub expiry_slot: u64,
    pub is_call: bool,
    pub short_contracts: i128,
    pub long_contracts: i128,
    pub margin_locked: u128,
    pub premium_collected: u128,
    pub sealed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerpetualPosition {
    pub position_id: String,
    pub owner: String,
    pub market: String,
    pub base_quantity: i128,
    pub entry_price: u128,
    pub mark_price: u128,
    pub funding_index: i128,
    pub realized_pnl: i128,
    pub margin_locked: u128,
    pub reduce_only: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskOffset {
    pub offset_id: String,
    pub owner: String,
    pub option_vault_id: String,
    pub perp_position_id: String,
    pub delta_offset: i128,
    pub vega_offset: i128,
    pub margin_credit: u128,
    pub cap_bps: u32,
    pub active: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedLiquidationAuction {
    pub auction_id: String,
    pub account: String,
    pub sealed_bid_root: String,
    pub collateral_lot: u128,
    pub debt_lot: u128,
    pub start_slot: u64,
    pub end_slot: u64,
    pub min_recovery_bps: u32,
    pub settled: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleCircuitBreaker {
    pub market: String,
    pub last_price: u128,
    pub current_price: u128,
    pub max_move_bps: u32,
    pub stale_after_slots: u64,
    pub last_update_slot: u64,
    pub tripped: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateSettlement {
    pub settlement_id: String,
    pub account: String,
    pub net_amount: i128,
    pub asset: String,
    pub proof_commitment: String,
    pub release_slot: u64,
    pub batch_index: u32,
    pub finalized: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositRequest {
    pub account: String,
    pub token: String,
    pub amount: u128,
    pub bridge_domain: String,
    pub shielded_commitment: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    pub account: String,
    pub token: String,
    pub amount: u128,
    pub destination_commitment: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OptionsVaultRequest {
    pub owner: String,
    pub underlying: String,
    pub quote: String,
    pub strike_price: u128,
    pub expiry_slot: u64,
    pub is_call: bool,
    pub short_contracts: i128,
    pub long_contracts: i128,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerpetualPositionRequest {
    pub owner: String,
    pub market: String,
    pub base_quantity: i128,
    pub price: u128,
    pub reduce_only: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskOffsetRequest {
    pub owner: String,
    pub option_vault_id: String,
    pub perp_position_id: String,
    pub delta_offset: i128,
    pub vega_offset: i128,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedAuctionRequest {
    pub account: String,
    pub sealed_bid_root: String,
    pub collateral_lot: u128,
    pub debt_lot: u128,
    pub start_slot: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleUpdateRequest {
    pub market: String,
    pub price: u128,
    pub slot: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateSettlementRequest {
    pub account: String,
    pub net_amount: i128,
    pub asset: String,
    pub proof_commitment: String,
    pub current_slot: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeRecord {
    pub accepted: bool,
    pub event_code: u32,
    pub label: String,
    pub subject: String,
    pub amount: i128,
    pub root: String,
    pub note: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub collateral: Vec<TokenCollateral>,
    pub options_vaults: Vec<OptionsVault>,
    pub perpetual_positions: Vec<PerpetualPosition>,
    pub risk_offsets: Vec<RiskOffset>,
    pub sealed_auctions: Vec<SealedLiquidationAuction>,
    pub oracle_breakers: Vec<OracleCircuitBreaker>,
    pub settlements: Vec<PrivateSettlement>,
    pub records: Vec<RuntimeRecord>,
}
pub type Runtime = State;

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: 2026,
            market_id: "nebula-devnet-unified-margin".to_string(),
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            liquidation_penalty_bps: DEFAULT_LIQUIDATION_PENALTY_BPS,
            bridge_haircut_bps: DEFAULT_BRIDGE_HAIRCUT_BPS,
            confidentiality_fee_bps: DEFAULT_CONFIDENTIALITY_FEE_BPS,
            circuit_breaker_bps: DEFAULT_CIRCUIT_BREAKER_BPS,
            risk_offset_cap_bps: DEFAULT_RISK_OFFSET_CAP_BPS,
            settlement_delay_slots: DEFAULT_SETTLEMENT_DELAY_SLOTS,
            auction_duration_slots: DEFAULT_AUCTION_DURATION_SLOTS,
            oracle_stale_after_slots: DEFAULT_ORACLE_STALE_AFTER_SLOTS,
            withdrawal_fee_bps: DEFAULT_WITHDRAWAL_FEE_BPS,
            token_collateral_factor_bps: DEFAULT_TOKEN_COLLATERAL_FACTOR_BPS,
            stable_collateral_factor_bps: DEFAULT_STABLE_COLLATERAL_FACTOR_BPS,
            vol_shock_bps: DEFAULT_VOL_SHOCK_BPS,
            funding_clamp_bps: DEFAULT_FUNDING_CLAMP_BPS,
            settlement_batch_limit: DEFAULT_SETTLEMENT_BATCH_LIMIT,
            allow_bridge_collateral: true,
            allow_portfolio_offsets: true,
            allow_private_settlement: true,
        }
    }
}
impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            collateral: Vec::new(),
            options_vaults: Vec::new(),
            perpetual_positions: Vec::new(),
            risk_offsets: Vec::new(),
            sealed_auctions: Vec::new(),
            oracle_breakers: Vec::new(),
            settlements: Vec::new(),
            records: Vec::new(),
        };
        state.refresh_roots();
        state
    }
}
impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            ..Self::default()
        };
        state.refresh_roots();
        state
    }
    pub fn record_deposit(&mut self, request: DepositRequest) -> RuntimeRecord {
        if request.amount == 0 || self.collateral.len() >= MAX_COLLATERAL_ASSETS {
            return self.reject(
                EVENT_DEPOSIT,
                "deposit",
                &request.account,
                "invalid deposit request",
            );
        }
        let factor = if request.token.contains("USD") {
            self.config.stable_collateral_factor_bps
        } else {
            self.config.token_collateral_factor_bps
        };
        let bridge_haircut_bps = if request.bridge_domain == "native" {
            0
        } else {
            self.config.bridge_haircut_bps
        };
        self.collateral.push(TokenCollateral {
            account: request.account.clone(),
            token: request.token.clone(),
            shielded_commitment: request.shielded_commitment,
            amount: request.amount,
            collateral_factor_bps: factor,
            bridge_domain: request.bridge_domain,
            bridge_haircut_bps,
            locked: false,
        });
        self.counters.deposits = self.counters.deposits.saturating_add(1);
        if bridge_haircut_bps > 0 {
            self.counters.bridge_haircuts = self.counters.bridge_haircuts.saturating_add(1);
        }
        self.refresh_roots();
        self.accept(
            EVENT_DEPOSIT,
            "deposit",
            &request.account,
            request.amount as i128,
            "collateral accepted",
        )
    }
    pub fn record_withdrawal(&mut self, request: WithdrawalRequest) -> RuntimeRecord {
        let available = self.available_collateral_value(&request.account, &request.token);
        let fee = mul_bps(request.amount, self.config.withdrawal_fee_bps);
        let total = request.amount.saturating_add(fee);
        if request.amount == 0 || available < total {
            return self.reject(
                EVENT_WITHDRAWAL,
                "withdrawal",
                &request.account,
                "insufficient unlocked collateral",
            );
        }
        let mut remaining = total;
        for item in &mut self.collateral {
            if item.account == request.account
                && item.token == request.token
                && !item.locked
                && remaining > 0
            {
                let debit = min_u128(item.amount, remaining);
                item.amount = item.amount.saturating_sub(debit);
                remaining = remaining.saturating_sub(debit);
            }
        }
        self.counters.withdrawals = self.counters.withdrawals.saturating_add(1);
        self.refresh_roots();
        self.accept(
            EVENT_WITHDRAWAL,
            "withdrawal",
            &request.account,
            request.amount as i128,
            "private withdrawal queued",
        )
    }
    pub fn record_options_vault(&mut self, request: OptionsVaultRequest) -> RuntimeRecord {
        if self.options_vaults.len() >= MAX_OPTIONS_VAULTS || request.expiry_slot == 0 {
            return self.reject(
                EVENT_OPTION_MINT,
                "options_vault",
                &request.owner,
                "invalid options vault request",
            );
        }
        let notional = request
            .strike_price
            .saturating_mul(abs_i128(request.short_contracts) as u128)
            / QUANTITY_SCALE;
        let margin = mul_bps(notional, self.config.initial_margin_bps)
            .saturating_add(mul_bps(notional, self.config.vol_shock_bps));
        if self.total_account_collateral_value(&request.owner) < margin {
            return self.reject(
                EVENT_OPTION_MINT,
                "options_vault",
                &request.owner,
                "insufficient margin for option vault",
            );
        }
        let vault_id = deterministic_id(
            "opt",
            self.counters.option_vaults.saturating_add(1),
            &request.owner,
            &request.underlying,
        );
        self.options_vaults.push(OptionsVault {
            vault_id: vault_id.clone(),
            owner: request.owner,
            underlying: request.underlying,
            quote: request.quote,
            strike_price: request.strike_price,
            expiry_slot: request.expiry_slot,
            is_call: request.is_call,
            short_contracts: request.short_contracts,
            long_contracts: request.long_contracts,
            margin_locked: margin,
            premium_collected: mul_bps(notional, 250),
            sealed: true,
        });
        self.counters.option_vaults = self.counters.option_vaults.saturating_add(1);
        self.counters.option_mints = self.counters.option_mints.saturating_add(1);
        self.refresh_roots();
        self.accept(
            EVENT_OPTION_MINT,
            "options_vault",
            &vault_id,
            margin as i128,
            "confidential option vault opened",
        )
    }
    pub fn record_perpetual_position(
        &mut self,
        request: PerpetualPositionRequest,
    ) -> RuntimeRecord {
        if self.perpetual_positions.len() >= MAX_PERP_MARKETS
            || request.price == 0
            || request.base_quantity == 0
        {
            return self.reject(
                EVENT_PERP_OPEN,
                "perpetual_position",
                &request.owner,
                "invalid perpetual request",
            );
        }
        let notional = request
            .price
            .saturating_mul(abs_i128(request.base_quantity) as u128)
            / QUANTITY_SCALE;
        let margin = mul_bps(notional, self.config.initial_margin_bps);
        if self.total_account_collateral_value(&request.owner) < margin {
            return self.reject(
                EVENT_PERP_OPEN,
                "perpetual_position",
                &request.owner,
                "insufficient margin for perpetual",
            );
        }
        let position_id = deterministic_id(
            "perp",
            self.counters.perp_positions.saturating_add(1),
            &request.owner,
            &request.market,
        );
        self.perpetual_positions.push(PerpetualPosition {
            position_id: position_id.clone(),
            owner: request.owner,
            market: request.market,
            base_quantity: request.base_quantity,
            entry_price: request.price,
            mark_price: request.price,
            funding_index: 0,
            realized_pnl: 0,
            margin_locked: margin,
            reduce_only: request.reduce_only,
        });
        self.counters.perp_positions = self.counters.perp_positions.saturating_add(1);
        self.counters.perp_updates = self.counters.perp_updates.saturating_add(1);
        self.refresh_roots();
        self.accept(
            EVENT_PERP_OPEN,
            "perpetual_position",
            &position_id,
            margin as i128,
            "confidential perpetual position opened",
        )
    }
    pub fn record_risk_offset(&mut self, request: RiskOffsetRequest) -> RuntimeRecord {
        if !self.config.allow_portfolio_offsets {
            return self.reject(
                EVENT_RISK_OFFSET,
                "risk_offset",
                &request.owner,
                "portfolio offsets disabled",
            );
        }
        let option_margin = self
            .options_vaults
            .iter()
            .find(|v| v.vault_id == request.option_vault_id && v.owner == request.owner)
            .map(|v| v.margin_locked)
            .unwrap_or(0_u128);
        let perp_margin = self
            .perpetual_positions
            .iter()
            .find(|p| p.position_id == request.perp_position_id && p.owner == request.owner)
            .map(|p| p.margin_locked)
            .unwrap_or(0_u128);
        if option_margin == 0 || perp_margin == 0 {
            return self.reject(
                EVENT_RISK_OFFSET,
                "risk_offset",
                &request.owner,
                "missing offset legs",
            );
        }
        let credit = mul_bps(
            min_u128(option_margin, perp_margin),
            self.config.risk_offset_cap_bps,
        );
        let offset_id = deterministic_id(
            "risk",
            self.counters.risk_offsets.saturating_add(1),
            &request.owner,
            &request.option_vault_id,
        );
        self.risk_offsets.push(RiskOffset {
            offset_id: offset_id.clone(),
            owner: request.owner,
            option_vault_id: request.option_vault_id,
            perp_position_id: request.perp_position_id,
            delta_offset: request.delta_offset,
            vega_offset: request.vega_offset,
            margin_credit: credit,
            cap_bps: self.config.risk_offset_cap_bps,
            active: true,
        });
        self.counters.risk_offsets = self.counters.risk_offsets.saturating_add(1);
        self.refresh_roots();
        self.accept(
            EVENT_RISK_OFFSET,
            "risk_offset",
            &offset_id,
            credit as i128,
            "portfolio margin offset recorded",
        )
    }
    pub fn record_sealed_auction(&mut self, request: SealedAuctionRequest) -> RuntimeRecord {
        if self.sealed_auctions.len() >= MAX_AUCTIONS
            || request.collateral_lot == 0
            || request.debt_lot == 0
        {
            return self.reject(
                EVENT_AUCTION_SEALED,
                "sealed_auction",
                &request.account,
                "invalid liquidation auction",
            );
        }
        let auction_id = deterministic_id(
            "auc",
            self.counters.sealed_auctions.saturating_add(1),
            &request.account,
            &request.sealed_bid_root,
        );
        self.sealed_auctions.push(SealedLiquidationAuction {
            auction_id: auction_id.clone(),
            account: request.account,
            sealed_bid_root: request.sealed_bid_root,
            collateral_lot: request.collateral_lot,
            debt_lot: request.debt_lot,
            start_slot: request.start_slot,
            end_slot: request
                .start_slot
                .saturating_add(self.config.auction_duration_slots),
            min_recovery_bps: BASIS_POINTS as u32 - self.config.liquidation_penalty_bps,
            settled: false,
        });
        self.counters.sealed_auctions = self.counters.sealed_auctions.saturating_add(1);
        self.refresh_roots();
        self.accept(
            EVENT_AUCTION_SEALED,
            "sealed_auction",
            &auction_id,
            request.debt_lot as i128,
            "sealed liquidation auction opened",
        )
    }
    pub fn record_oracle_update(&mut self, request: OracleUpdateRequest) -> RuntimeRecord {
        if request.price == 0 {
            return self.reject(
                EVENT_ORACLE_BREAKER,
                "oracle",
                &request.market,
                "zero oracle price",
            );
        }
        match self
            .oracle_breakers
            .iter_mut()
            .find(|o| o.market == request.market)
        {
            Some(oracle) => {
                let move_bps = price_move_bps(oracle.current_price, request.price);
                oracle.last_price = oracle.current_price;
                oracle.current_price = request.price;
                oracle.last_update_slot = request.slot;
                oracle.tripped = move_bps > oracle.max_move_bps;
                if oracle.tripped {
                    self.counters.oracle_breakers = self.counters.oracle_breakers.saturating_add(1);
                }
            }
            None => self.oracle_breakers.push(OracleCircuitBreaker {
                market: request.market.clone(),
                last_price: request.price,
                current_price: request.price,
                max_move_bps: self.config.circuit_breaker_bps,
                stale_after_slots: self.config.oracle_stale_after_slots,
                last_update_slot: request.slot,
                tripped: false,
            }),
        }
        self.counters.oracle_updates = self.counters.oracle_updates.saturating_add(1);
        self.refresh_roots();
        self.accept(
            EVENT_ORACLE_BREAKER,
            "oracle",
            &request.market,
            request.price as i128,
            "oracle circuit breaker evaluated",
        )
    }
    pub fn record_private_settlement(
        &mut self,
        request: PrivateSettlementRequest,
    ) -> RuntimeRecord {
        if !self.config.allow_private_settlement
            || self.settlements.len() as u32 >= self.config.settlement_batch_limit
        {
            return self.reject(
                EVENT_PRIVATE_SETTLEMENT,
                "private_settlement",
                &request.account,
                "private settlement unavailable",
            );
        }
        let settlement_id = deterministic_id(
            "set",
            self.counters.private_settlements.saturating_add(1),
            &request.account,
            &request.asset,
        );
        let batch_index = self.settlements.len() as u32;
        self.settlements.push(PrivateSettlement {
            settlement_id: settlement_id.clone(),
            account: request.account,
            net_amount: request.net_amount,
            asset: request.asset,
            proof_commitment: request.proof_commitment,
            release_slot: request
                .current_slot
                .saturating_add(self.config.settlement_delay_slots),
            batch_index,
            finalized: false,
        });
        self.counters.private_settlements = self.counters.private_settlements.saturating_add(1);
        self.refresh_roots();
        self.accept(
            EVENT_PRIVATE_SETTLEMENT,
            "private_settlement",
            &settlement_id,
            request.net_amount,
            "private settlement committed",
        )
    }
    pub fn total_account_collateral_value(&self, account: &str) -> u128 {
        self.collateral
            .iter()
            .filter(|c| c.account == account)
            .map(adjusted_collateral_value)
            .fold(0_u128, u128::saturating_add)
    }
    pub fn available_collateral_value(&self, account: &str, token: &str) -> u128 {
        self.collateral
            .iter()
            .filter(|c| c.account == account && c.token == token && !c.locked)
            .map(|c| c.amount)
            .fold(0_u128, u128::saturating_add)
    }
    pub fn margin_requirement(&self, account: &str) -> u128 {
        let option_margin = self
            .options_vaults
            .iter()
            .filter(|v| v.owner == account)
            .map(|v| v.margin_locked)
            .fold(0_u128, u128::saturating_add);
        let perp_margin = self
            .perpetual_positions
            .iter()
            .filter(|p| p.owner == account)
            .map(|p| p.margin_locked)
            .fold(0_u128, u128::saturating_add);
        let offset_credit = self
            .risk_offsets
            .iter()
            .filter(|r| r.owner == account && r.active)
            .map(|r| r.margin_credit)
            .fold(0_u128, u128::saturating_add);
        option_margin
            .saturating_add(perp_margin)
            .saturating_sub(offset_credit)
    }
    pub fn account_health_bps(&self, account: &str) -> u128 {
        let requirement = self.margin_requirement(account);
        if requirement == 0 {
            return BASIS_POINTS;
        }
        self.total_account_collateral_value(account)
            .saturating_mul(BASIS_POINTS)
            / requirement
    }
    pub fn public_record(&self) -> Value {
        json!({ "protocol": PROTOCOL_NAME, "version": PROTOCOL_VERSION, "config": self.config, "counters": self.counters, "roots": self.roots, "collateral_count": self.collateral.len(), "options_vault_count": self.options_vaults.len(), "perpetual_position_count": self.perpetual_positions.len(), "risk_offset_count": self.risk_offsets.len(), "sealed_auction_count": self.sealed_auctions.len(), "oracle_count": self.oracle_breakers.len(), "settlement_count": self.settlements.len(), "records": self.records })
    }
    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
    pub fn refresh_roots(&mut self) {
        self.roots.collateral_root = root_for("collateral", &self.collateral);
        self.roots.options_root = root_for("options", &self.options_vaults);
        self.roots.perps_root = root_for("perps", &self.perpetual_positions);
        self.roots.risk_root = root_for("risk", &self.risk_offsets);
        self.roots.auctions_root = root_for("auctions", &self.sealed_auctions);
        self.roots.oracle_root = root_for("oracle", &self.oracle_breakers);
        self.roots.settlement_root = root_for("settlement", &self.settlements);
        self.roots.bridge_root = root_for(
            "bridge",
            &self
                .collateral
                .iter()
                .map(|c| (&c.bridge_domain, c.bridge_haircut_bps))
                .collect::<Vec<_>>(),
        );
        self.roots.state_root = deterministic_root(&[
            ROOT_DOMAIN,
            &self.roots.collateral_root,
            &self.roots.options_root,
            &self.roots.perps_root,
            &self.roots.risk_root,
            &self.roots.auctions_root,
            &self.roots.oracle_root,
            &self.roots.settlement_root,
            &self.roots.bridge_root,
        ]);
    }
    fn accept(
        &mut self,
        event_code: u32,
        label: &str,
        subject: &str,
        amount: i128,
        note: &str,
    ) -> RuntimeRecord {
        let record = RuntimeRecord {
            accepted: true,
            event_code,
            label: label.to_string(),
            subject: subject.to_string(),
            amount,
            root: self.roots.state_root.clone(),
            note: note.to_string(),
        };
        self.records.push(record.clone());
        record
    }
    fn reject(&mut self, event_code: u32, label: &str, subject: &str, note: &str) -> RuntimeRecord {
        self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
        self.refresh_roots();
        let record = RuntimeRecord {
            accepted: false,
            event_code,
            label: label.to_string(),
            subject: subject.to_string(),
            amount: 0,
            root: self.roots.state_root.clone(),
            note: note.to_string(),
        };
        self.records.push(record.clone());
        record
    }
}

pub fn devnet() -> Runtime {
    State::default()
}
pub fn demo() -> Runtime {
    let mut state = devnet();
    let _ = state.record_deposit(DepositRequest {
        account: "alice".to_string(),
        token: "dUSD".to_string(),
        amount: 20_000_000_000,
        bridge_domain: "native".to_string(),
        shielded_commitment: "cm_alice_dusd_0001".to_string(),
    });
    let _ = state.record_deposit(DepositRequest {
        account: "alice".to_string(),
        token: "wETH".to_string(),
        amount: 4_000_000_000,
        bridge_domain: "l1-mainnet".to_string(),
        shielded_commitment: "cm_alice_weth_0001".to_string(),
    });
    let _ = state.record_options_vault(OptionsVaultRequest {
        owner: "alice".to_string(),
        underlying: "ETH".to_string(),
        quote: "dUSD".to_string(),
        strike_price: 3_200 * PRICE_SCALE,
        expiry_slot: 88_000,
        is_call: true,
        short_contracts: 2 * QUANTITY_SCALE as i128,
        long_contracts: 0,
    });
    let _ = state.record_perpetual_position(PerpetualPositionRequest {
        owner: "alice".to_string(),
        market: "ETH-PERP".to_string(),
        base_quantity: -1_500_000,
        price: 3_050 * PRICE_SCALE,
        reduce_only: false,
    });
    let option_id = match state.options_vaults.get(0) {
        Some(vault) => vault.vault_id.clone(),
        None => String::new(),
    };
    let perp_id = match state.perpetual_positions.get(0) {
        Some(position) => position.position_id.clone(),
        None => String::new(),
    };
    let _ = state.record_risk_offset(RiskOffsetRequest {
        owner: "alice".to_string(),
        option_vault_id: option_id,
        perp_position_id: perp_id,
        delta_offset: -900_000,
        vega_offset: 120_000,
    });
    let _ = state.record_oracle_update(OracleUpdateRequest {
        market: "ETH-PERP".to_string(),
        price: 3_070 * PRICE_SCALE,
        slot: 44,
    });
    let _ = state.record_sealed_auction(SealedAuctionRequest {
        account: "alice".to_string(),
        sealed_bid_root: "sealed_bid_root_demo_0001".to_string(),
        collateral_lot: 1_000_000_000,
        debt_lot: 950_000_000,
        start_slot: 45,
    });
    let _ = state.record_private_settlement(PrivateSettlementRequest {
        account: "alice".to_string(),
        net_amount: 125_000_000,
        asset: "dUSD".to_string(),
        proof_commitment: "settle_proof_demo_0001".to_string(),
        current_slot: 46,
    });
    state.refresh_roots();
    state
}
pub fn public_record() -> Value {
    demo().public_record()
}
pub fn state_root() -> String {
    demo().state_root()
}
fn adjusted_collateral_value(item: &TokenCollateral) -> u128 {
    let after_factor = mul_bps(item.amount, item.collateral_factor_bps);
    after_factor.saturating_sub(mul_bps(after_factor, item.bridge_haircut_bps))
}
fn mul_bps(value: u128, bps: u32) -> u128 {
    value.saturating_mul(bps as u128) / BASIS_POINTS
}
fn min_u128(a: u128, b: u128) -> u128 {
    if a < b {
        a
    } else {
        b
    }
}
fn abs_i128(value: i128) -> i128 {
    if value < 0 {
        value.saturating_neg()
    } else {
        value
    }
}
fn price_move_bps(previous: u128, current: u128) -> u32 {
    if previous == 0 {
        return 0;
    }
    let diff = if current > previous {
        current - previous
    } else {
        previous - current
    };
    let bps = diff.saturating_mul(BASIS_POINTS) / previous;
    if bps > u32::MAX as u128 {
        u32::MAX
    } else {
        bps as u32
    }
}
fn deterministic_id(prefix: &str, index: u64, owner: &str, subject: &str) -> String {
    let root = deterministic_root(&[prefix, &index.to_string(), owner, subject]);
    format!("{}-{}", prefix, &root[1..17])
}
fn root_for<T: Serialize>(domain: &str, value: &T) -> String {
    match serde_json::to_string(value) {
        Ok(serialized) => deterministic_root(&[ROOT_DOMAIN, domain, &serialized]),
        Err(_) => deterministic_root(&[ROOT_DOMAIN, domain, EMPTY_ROOT]),
    }
}
fn deterministic_root(parts: &[&str]) -> String {
    let mut hash: u128 = 0x9e37_79b9_7f4a_7c15_6a09_e667_f3bc_c909;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= *byte as u128;
            hash = hash.wrapping_mul(0x1000_0000_01b3);
            hash ^= hash.rotate_left(29);
        }
        hash ^= 0xff;
        hash = hash.rotate_left(17);
    }
    format!("r{:032x}", hash)
}

pub const RISK_BUCKET_001_MAX_NOTIONAL: u128 = 1u128 * 1_000_000_000;
pub const RISK_BUCKET_001_OPTION_WEIGHT_BPS: u32 = 525;
pub const RISK_BUCKET_001_PERP_WEIGHT_BPS: u32 = 670;
pub const RISK_BUCKET_001_BRIDGE_WEIGHT_BPS: u32 = 55;
pub fn risk_bucket_001_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_001_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_001_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_001_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_001_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_002_MAX_NOTIONAL: u128 = 2u128 * 1_000_000_000;
pub const RISK_BUCKET_002_OPTION_WEIGHT_BPS: u32 = 550;
pub const RISK_BUCKET_002_PERP_WEIGHT_BPS: u32 = 690;
pub const RISK_BUCKET_002_BRIDGE_WEIGHT_BPS: u32 = 60;
pub fn risk_bucket_002_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_002_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_002_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_002_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_002_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_003_MAX_NOTIONAL: u128 = 3u128 * 1_000_000_000;
pub const RISK_BUCKET_003_OPTION_WEIGHT_BPS: u32 = 575;
pub const RISK_BUCKET_003_PERP_WEIGHT_BPS: u32 = 710;
pub const RISK_BUCKET_003_BRIDGE_WEIGHT_BPS: u32 = 65;
pub fn risk_bucket_003_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_003_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_003_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_003_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_003_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_004_MAX_NOTIONAL: u128 = 4u128 * 1_000_000_000;
pub const RISK_BUCKET_004_OPTION_WEIGHT_BPS: u32 = 600;
pub const RISK_BUCKET_004_PERP_WEIGHT_BPS: u32 = 730;
pub const RISK_BUCKET_004_BRIDGE_WEIGHT_BPS: u32 = 70;
pub fn risk_bucket_004_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_004_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_004_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_004_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_004_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_005_MAX_NOTIONAL: u128 = 5u128 * 1_000_000_000;
pub const RISK_BUCKET_005_OPTION_WEIGHT_BPS: u32 = 625;
pub const RISK_BUCKET_005_PERP_WEIGHT_BPS: u32 = 750;
pub const RISK_BUCKET_005_BRIDGE_WEIGHT_BPS: u32 = 75;
pub fn risk_bucket_005_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_005_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_005_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_005_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_005_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_006_MAX_NOTIONAL: u128 = 6u128 * 1_000_000_000;
pub const RISK_BUCKET_006_OPTION_WEIGHT_BPS: u32 = 650;
pub const RISK_BUCKET_006_PERP_WEIGHT_BPS: u32 = 770;
pub const RISK_BUCKET_006_BRIDGE_WEIGHT_BPS: u32 = 80;
pub fn risk_bucket_006_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_006_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_006_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_006_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_006_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_007_MAX_NOTIONAL: u128 = 7u128 * 1_000_000_000;
pub const RISK_BUCKET_007_OPTION_WEIGHT_BPS: u32 = 675;
pub const RISK_BUCKET_007_PERP_WEIGHT_BPS: u32 = 790;
pub const RISK_BUCKET_007_BRIDGE_WEIGHT_BPS: u32 = 85;
pub fn risk_bucket_007_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_007_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_007_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_007_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_007_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_008_MAX_NOTIONAL: u128 = 8u128 * 1_000_000_000;
pub const RISK_BUCKET_008_OPTION_WEIGHT_BPS: u32 = 700;
pub const RISK_BUCKET_008_PERP_WEIGHT_BPS: u32 = 810;
pub const RISK_BUCKET_008_BRIDGE_WEIGHT_BPS: u32 = 90;
pub fn risk_bucket_008_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_008_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_008_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_008_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_008_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_009_MAX_NOTIONAL: u128 = 9u128 * 1_000_000_000;
pub const RISK_BUCKET_009_OPTION_WEIGHT_BPS: u32 = 725;
pub const RISK_BUCKET_009_PERP_WEIGHT_BPS: u32 = 830;
pub const RISK_BUCKET_009_BRIDGE_WEIGHT_BPS: u32 = 95;
pub fn risk_bucket_009_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_009_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_009_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_009_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_009_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_010_MAX_NOTIONAL: u128 = 10u128 * 1_000_000_000;
pub const RISK_BUCKET_010_OPTION_WEIGHT_BPS: u32 = 750;
pub const RISK_BUCKET_010_PERP_WEIGHT_BPS: u32 = 850;
pub const RISK_BUCKET_010_BRIDGE_WEIGHT_BPS: u32 = 100;
pub fn risk_bucket_010_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_010_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_010_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_010_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_010_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_011_MAX_NOTIONAL: u128 = 11u128 * 1_000_000_000;
pub const RISK_BUCKET_011_OPTION_WEIGHT_BPS: u32 = 775;
pub const RISK_BUCKET_011_PERP_WEIGHT_BPS: u32 = 870;
pub const RISK_BUCKET_011_BRIDGE_WEIGHT_BPS: u32 = 105;
pub fn risk_bucket_011_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_011_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_011_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_011_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_011_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_012_MAX_NOTIONAL: u128 = 12u128 * 1_000_000_000;
pub const RISK_BUCKET_012_OPTION_WEIGHT_BPS: u32 = 800;
pub const RISK_BUCKET_012_PERP_WEIGHT_BPS: u32 = 890;
pub const RISK_BUCKET_012_BRIDGE_WEIGHT_BPS: u32 = 110;
pub fn risk_bucket_012_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_012_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_012_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_012_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_012_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_013_MAX_NOTIONAL: u128 = 13u128 * 1_000_000_000;
pub const RISK_BUCKET_013_OPTION_WEIGHT_BPS: u32 = 825;
pub const RISK_BUCKET_013_PERP_WEIGHT_BPS: u32 = 910;
pub const RISK_BUCKET_013_BRIDGE_WEIGHT_BPS: u32 = 115;
pub fn risk_bucket_013_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_013_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_013_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_013_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_013_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_014_MAX_NOTIONAL: u128 = 14u128 * 1_000_000_000;
pub const RISK_BUCKET_014_OPTION_WEIGHT_BPS: u32 = 850;
pub const RISK_BUCKET_014_PERP_WEIGHT_BPS: u32 = 930;
pub const RISK_BUCKET_014_BRIDGE_WEIGHT_BPS: u32 = 120;
pub fn risk_bucket_014_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_014_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_014_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_014_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_014_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_015_MAX_NOTIONAL: u128 = 15u128 * 1_000_000_000;
pub const RISK_BUCKET_015_OPTION_WEIGHT_BPS: u32 = 875;
pub const RISK_BUCKET_015_PERP_WEIGHT_BPS: u32 = 950;
pub const RISK_BUCKET_015_BRIDGE_WEIGHT_BPS: u32 = 125;
pub fn risk_bucket_015_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_015_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_015_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_015_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_015_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_016_MAX_NOTIONAL: u128 = 16u128 * 1_000_000_000;
pub const RISK_BUCKET_016_OPTION_WEIGHT_BPS: u32 = 900;
pub const RISK_BUCKET_016_PERP_WEIGHT_BPS: u32 = 970;
pub const RISK_BUCKET_016_BRIDGE_WEIGHT_BPS: u32 = 130;
pub fn risk_bucket_016_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_016_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_016_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_016_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_016_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_017_MAX_NOTIONAL: u128 = 17u128 * 1_000_000_000;
pub const RISK_BUCKET_017_OPTION_WEIGHT_BPS: u32 = 925;
pub const RISK_BUCKET_017_PERP_WEIGHT_BPS: u32 = 990;
pub const RISK_BUCKET_017_BRIDGE_WEIGHT_BPS: u32 = 135;
pub fn risk_bucket_017_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_017_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_017_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_017_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_017_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_018_MAX_NOTIONAL: u128 = 18u128 * 1_000_000_000;
pub const RISK_BUCKET_018_OPTION_WEIGHT_BPS: u32 = 950;
pub const RISK_BUCKET_018_PERP_WEIGHT_BPS: u32 = 1010;
pub const RISK_BUCKET_018_BRIDGE_WEIGHT_BPS: u32 = 140;
pub fn risk_bucket_018_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_018_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_018_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_018_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_018_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_019_MAX_NOTIONAL: u128 = 19u128 * 1_000_000_000;
pub const RISK_BUCKET_019_OPTION_WEIGHT_BPS: u32 = 975;
pub const RISK_BUCKET_019_PERP_WEIGHT_BPS: u32 = 1030;
pub const RISK_BUCKET_019_BRIDGE_WEIGHT_BPS: u32 = 145;
pub fn risk_bucket_019_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_019_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_019_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_019_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_019_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_020_MAX_NOTIONAL: u128 = 20u128 * 1_000_000_000;
pub const RISK_BUCKET_020_OPTION_WEIGHT_BPS: u32 = 1000;
pub const RISK_BUCKET_020_PERP_WEIGHT_BPS: u32 = 1050;
pub const RISK_BUCKET_020_BRIDGE_WEIGHT_BPS: u32 = 150;
pub fn risk_bucket_020_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_020_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_020_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_020_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_020_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_021_MAX_NOTIONAL: u128 = 21u128 * 1_000_000_000;
pub const RISK_BUCKET_021_OPTION_WEIGHT_BPS: u32 = 1025;
pub const RISK_BUCKET_021_PERP_WEIGHT_BPS: u32 = 1070;
pub const RISK_BUCKET_021_BRIDGE_WEIGHT_BPS: u32 = 155;
pub fn risk_bucket_021_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_021_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_021_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_021_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_021_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_022_MAX_NOTIONAL: u128 = 22u128 * 1_000_000_000;
pub const RISK_BUCKET_022_OPTION_WEIGHT_BPS: u32 = 1050;
pub const RISK_BUCKET_022_PERP_WEIGHT_BPS: u32 = 1090;
pub const RISK_BUCKET_022_BRIDGE_WEIGHT_BPS: u32 = 160;
pub fn risk_bucket_022_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_022_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_022_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_022_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_022_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_023_MAX_NOTIONAL: u128 = 23u128 * 1_000_000_000;
pub const RISK_BUCKET_023_OPTION_WEIGHT_BPS: u32 = 1075;
pub const RISK_BUCKET_023_PERP_WEIGHT_BPS: u32 = 1110;
pub const RISK_BUCKET_023_BRIDGE_WEIGHT_BPS: u32 = 165;
pub fn risk_bucket_023_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_023_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_023_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_023_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_023_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_024_MAX_NOTIONAL: u128 = 24u128 * 1_000_000_000;
pub const RISK_BUCKET_024_OPTION_WEIGHT_BPS: u32 = 1100;
pub const RISK_BUCKET_024_PERP_WEIGHT_BPS: u32 = 1130;
pub const RISK_BUCKET_024_BRIDGE_WEIGHT_BPS: u32 = 170;
pub fn risk_bucket_024_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_024_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_024_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_024_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_024_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_025_MAX_NOTIONAL: u128 = 25u128 * 1_000_000_000;
pub const RISK_BUCKET_025_OPTION_WEIGHT_BPS: u32 = 1125;
pub const RISK_BUCKET_025_PERP_WEIGHT_BPS: u32 = 1150;
pub const RISK_BUCKET_025_BRIDGE_WEIGHT_BPS: u32 = 175;
pub fn risk_bucket_025_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_025_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_025_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_025_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_025_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_026_MAX_NOTIONAL: u128 = 26u128 * 1_000_000_000;
pub const RISK_BUCKET_026_OPTION_WEIGHT_BPS: u32 = 1150;
pub const RISK_BUCKET_026_PERP_WEIGHT_BPS: u32 = 1170;
pub const RISK_BUCKET_026_BRIDGE_WEIGHT_BPS: u32 = 180;
pub fn risk_bucket_026_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_026_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_026_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_026_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_026_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_027_MAX_NOTIONAL: u128 = 27u128 * 1_000_000_000;
pub const RISK_BUCKET_027_OPTION_WEIGHT_BPS: u32 = 1175;
pub const RISK_BUCKET_027_PERP_WEIGHT_BPS: u32 = 1190;
pub const RISK_BUCKET_027_BRIDGE_WEIGHT_BPS: u32 = 185;
pub fn risk_bucket_027_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_027_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_027_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_027_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_027_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_028_MAX_NOTIONAL: u128 = 28u128 * 1_000_000_000;
pub const RISK_BUCKET_028_OPTION_WEIGHT_BPS: u32 = 1200;
pub const RISK_BUCKET_028_PERP_WEIGHT_BPS: u32 = 1210;
pub const RISK_BUCKET_028_BRIDGE_WEIGHT_BPS: u32 = 190;
pub fn risk_bucket_028_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_028_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_028_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_028_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_028_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_029_MAX_NOTIONAL: u128 = 29u128 * 1_000_000_000;
pub const RISK_BUCKET_029_OPTION_WEIGHT_BPS: u32 = 1225;
pub const RISK_BUCKET_029_PERP_WEIGHT_BPS: u32 = 1230;
pub const RISK_BUCKET_029_BRIDGE_WEIGHT_BPS: u32 = 50;
pub fn risk_bucket_029_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_029_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_029_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_029_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_029_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_030_MAX_NOTIONAL: u128 = 30u128 * 1_000_000_000;
pub const RISK_BUCKET_030_OPTION_WEIGHT_BPS: u32 = 1250;
pub const RISK_BUCKET_030_PERP_WEIGHT_BPS: u32 = 1250;
pub const RISK_BUCKET_030_BRIDGE_WEIGHT_BPS: u32 = 55;
pub fn risk_bucket_030_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_030_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_030_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_030_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_030_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_031_MAX_NOTIONAL: u128 = 31u128 * 1_000_000_000;
pub const RISK_BUCKET_031_OPTION_WEIGHT_BPS: u32 = 1275;
pub const RISK_BUCKET_031_PERP_WEIGHT_BPS: u32 = 1270;
pub const RISK_BUCKET_031_BRIDGE_WEIGHT_BPS: u32 = 60;
pub fn risk_bucket_031_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_031_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_031_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_031_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_031_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_032_MAX_NOTIONAL: u128 = 32u128 * 1_000_000_000;
pub const RISK_BUCKET_032_OPTION_WEIGHT_BPS: u32 = 1300;
pub const RISK_BUCKET_032_PERP_WEIGHT_BPS: u32 = 1290;
pub const RISK_BUCKET_032_BRIDGE_WEIGHT_BPS: u32 = 65;
pub fn risk_bucket_032_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_032_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_032_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_032_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_032_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_033_MAX_NOTIONAL: u128 = 33u128 * 1_000_000_000;
pub const RISK_BUCKET_033_OPTION_WEIGHT_BPS: u32 = 1325;
pub const RISK_BUCKET_033_PERP_WEIGHT_BPS: u32 = 1310;
pub const RISK_BUCKET_033_BRIDGE_WEIGHT_BPS: u32 = 70;
pub fn risk_bucket_033_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_033_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_033_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_033_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_033_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_034_MAX_NOTIONAL: u128 = 34u128 * 1_000_000_000;
pub const RISK_BUCKET_034_OPTION_WEIGHT_BPS: u32 = 1350;
pub const RISK_BUCKET_034_PERP_WEIGHT_BPS: u32 = 1330;
pub const RISK_BUCKET_034_BRIDGE_WEIGHT_BPS: u32 = 75;
pub fn risk_bucket_034_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_034_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_034_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_034_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_034_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_035_MAX_NOTIONAL: u128 = 35u128 * 1_000_000_000;
pub const RISK_BUCKET_035_OPTION_WEIGHT_BPS: u32 = 1375;
pub const RISK_BUCKET_035_PERP_WEIGHT_BPS: u32 = 1350;
pub const RISK_BUCKET_035_BRIDGE_WEIGHT_BPS: u32 = 80;
pub fn risk_bucket_035_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_035_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_035_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_035_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_035_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_036_MAX_NOTIONAL: u128 = 36u128 * 1_000_000_000;
pub const RISK_BUCKET_036_OPTION_WEIGHT_BPS: u32 = 1400;
pub const RISK_BUCKET_036_PERP_WEIGHT_BPS: u32 = 1370;
pub const RISK_BUCKET_036_BRIDGE_WEIGHT_BPS: u32 = 85;
pub fn risk_bucket_036_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_036_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_036_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_036_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_036_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_037_MAX_NOTIONAL: u128 = 37u128 * 1_000_000_000;
pub const RISK_BUCKET_037_OPTION_WEIGHT_BPS: u32 = 500;
pub const RISK_BUCKET_037_PERP_WEIGHT_BPS: u32 = 1390;
pub const RISK_BUCKET_037_BRIDGE_WEIGHT_BPS: u32 = 90;
pub fn risk_bucket_037_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_037_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_037_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_037_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_037_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_038_MAX_NOTIONAL: u128 = 38u128 * 1_000_000_000;
pub const RISK_BUCKET_038_OPTION_WEIGHT_BPS: u32 = 525;
pub const RISK_BUCKET_038_PERP_WEIGHT_BPS: u32 = 1410;
pub const RISK_BUCKET_038_BRIDGE_WEIGHT_BPS: u32 = 95;
pub fn risk_bucket_038_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_038_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_038_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_038_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_038_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_039_MAX_NOTIONAL: u128 = 39u128 * 1_000_000_000;
pub const RISK_BUCKET_039_OPTION_WEIGHT_BPS: u32 = 550;
pub const RISK_BUCKET_039_PERP_WEIGHT_BPS: u32 = 1430;
pub const RISK_BUCKET_039_BRIDGE_WEIGHT_BPS: u32 = 100;
pub fn risk_bucket_039_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_039_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_039_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_039_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_039_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_040_MAX_NOTIONAL: u128 = 40u128 * 1_000_000_000;
pub const RISK_BUCKET_040_OPTION_WEIGHT_BPS: u32 = 575;
pub const RISK_BUCKET_040_PERP_WEIGHT_BPS: u32 = 1450;
pub const RISK_BUCKET_040_BRIDGE_WEIGHT_BPS: u32 = 105;
pub fn risk_bucket_040_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_040_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_040_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_040_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_040_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_041_MAX_NOTIONAL: u128 = 41u128 * 1_000_000_000;
pub const RISK_BUCKET_041_OPTION_WEIGHT_BPS: u32 = 600;
pub const RISK_BUCKET_041_PERP_WEIGHT_BPS: u32 = 650;
pub const RISK_BUCKET_041_BRIDGE_WEIGHT_BPS: u32 = 110;
pub fn risk_bucket_041_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_041_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_041_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_041_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_041_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_042_MAX_NOTIONAL: u128 = 42u128 * 1_000_000_000;
pub const RISK_BUCKET_042_OPTION_WEIGHT_BPS: u32 = 625;
pub const RISK_BUCKET_042_PERP_WEIGHT_BPS: u32 = 670;
pub const RISK_BUCKET_042_BRIDGE_WEIGHT_BPS: u32 = 115;
pub fn risk_bucket_042_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_042_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_042_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_042_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_042_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_043_MAX_NOTIONAL: u128 = 43u128 * 1_000_000_000;
pub const RISK_BUCKET_043_OPTION_WEIGHT_BPS: u32 = 650;
pub const RISK_BUCKET_043_PERP_WEIGHT_BPS: u32 = 690;
pub const RISK_BUCKET_043_BRIDGE_WEIGHT_BPS: u32 = 120;
pub fn risk_bucket_043_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_043_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_043_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_043_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_043_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_044_MAX_NOTIONAL: u128 = 44u128 * 1_000_000_000;
pub const RISK_BUCKET_044_OPTION_WEIGHT_BPS: u32 = 675;
pub const RISK_BUCKET_044_PERP_WEIGHT_BPS: u32 = 710;
pub const RISK_BUCKET_044_BRIDGE_WEIGHT_BPS: u32 = 125;
pub fn risk_bucket_044_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_044_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_044_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_044_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_044_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_045_MAX_NOTIONAL: u128 = 45u128 * 1_000_000_000;
pub const RISK_BUCKET_045_OPTION_WEIGHT_BPS: u32 = 700;
pub const RISK_BUCKET_045_PERP_WEIGHT_BPS: u32 = 730;
pub const RISK_BUCKET_045_BRIDGE_WEIGHT_BPS: u32 = 130;
pub fn risk_bucket_045_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_045_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_045_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_045_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_045_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_046_MAX_NOTIONAL: u128 = 46u128 * 1_000_000_000;
pub const RISK_BUCKET_046_OPTION_WEIGHT_BPS: u32 = 725;
pub const RISK_BUCKET_046_PERP_WEIGHT_BPS: u32 = 750;
pub const RISK_BUCKET_046_BRIDGE_WEIGHT_BPS: u32 = 135;
pub fn risk_bucket_046_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_046_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_046_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_046_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_046_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_047_MAX_NOTIONAL: u128 = 47u128 * 1_000_000_000;
pub const RISK_BUCKET_047_OPTION_WEIGHT_BPS: u32 = 750;
pub const RISK_BUCKET_047_PERP_WEIGHT_BPS: u32 = 770;
pub const RISK_BUCKET_047_BRIDGE_WEIGHT_BPS: u32 = 140;
pub fn risk_bucket_047_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_047_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_047_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_047_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_047_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_048_MAX_NOTIONAL: u128 = 48u128 * 1_000_000_000;
pub const RISK_BUCKET_048_OPTION_WEIGHT_BPS: u32 = 775;
pub const RISK_BUCKET_048_PERP_WEIGHT_BPS: u32 = 790;
pub const RISK_BUCKET_048_BRIDGE_WEIGHT_BPS: u32 = 145;
pub fn risk_bucket_048_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_048_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_048_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_048_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_048_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_049_MAX_NOTIONAL: u128 = 49u128 * 1_000_000_000;
pub const RISK_BUCKET_049_OPTION_WEIGHT_BPS: u32 = 800;
pub const RISK_BUCKET_049_PERP_WEIGHT_BPS: u32 = 810;
pub const RISK_BUCKET_049_BRIDGE_WEIGHT_BPS: u32 = 150;
pub fn risk_bucket_049_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_049_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_049_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_049_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_049_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_050_MAX_NOTIONAL: u128 = 50u128 * 1_000_000_000;
pub const RISK_BUCKET_050_OPTION_WEIGHT_BPS: u32 = 825;
pub const RISK_BUCKET_050_PERP_WEIGHT_BPS: u32 = 830;
pub const RISK_BUCKET_050_BRIDGE_WEIGHT_BPS: u32 = 155;
pub fn risk_bucket_050_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_050_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_050_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_050_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_050_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_051_MAX_NOTIONAL: u128 = 51u128 * 1_000_000_000;
pub const RISK_BUCKET_051_OPTION_WEIGHT_BPS: u32 = 850;
pub const RISK_BUCKET_051_PERP_WEIGHT_BPS: u32 = 850;
pub const RISK_BUCKET_051_BRIDGE_WEIGHT_BPS: u32 = 160;
pub fn risk_bucket_051_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_051_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_051_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_051_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_051_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_052_MAX_NOTIONAL: u128 = 52u128 * 1_000_000_000;
pub const RISK_BUCKET_052_OPTION_WEIGHT_BPS: u32 = 875;
pub const RISK_BUCKET_052_PERP_WEIGHT_BPS: u32 = 870;
pub const RISK_BUCKET_052_BRIDGE_WEIGHT_BPS: u32 = 165;
pub fn risk_bucket_052_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_052_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_052_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_052_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_052_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_053_MAX_NOTIONAL: u128 = 53u128 * 1_000_000_000;
pub const RISK_BUCKET_053_OPTION_WEIGHT_BPS: u32 = 900;
pub const RISK_BUCKET_053_PERP_WEIGHT_BPS: u32 = 890;
pub const RISK_BUCKET_053_BRIDGE_WEIGHT_BPS: u32 = 170;
pub fn risk_bucket_053_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_053_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_053_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_053_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_053_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_054_MAX_NOTIONAL: u128 = 54u128 * 1_000_000_000;
pub const RISK_BUCKET_054_OPTION_WEIGHT_BPS: u32 = 925;
pub const RISK_BUCKET_054_PERP_WEIGHT_BPS: u32 = 910;
pub const RISK_BUCKET_054_BRIDGE_WEIGHT_BPS: u32 = 175;
pub fn risk_bucket_054_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_054_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_054_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_054_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_054_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_055_MAX_NOTIONAL: u128 = 55u128 * 1_000_000_000;
pub const RISK_BUCKET_055_OPTION_WEIGHT_BPS: u32 = 950;
pub const RISK_BUCKET_055_PERP_WEIGHT_BPS: u32 = 930;
pub const RISK_BUCKET_055_BRIDGE_WEIGHT_BPS: u32 = 180;
pub fn risk_bucket_055_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_055_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_055_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_055_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_055_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_056_MAX_NOTIONAL: u128 = 56u128 * 1_000_000_000;
pub const RISK_BUCKET_056_OPTION_WEIGHT_BPS: u32 = 975;
pub const RISK_BUCKET_056_PERP_WEIGHT_BPS: u32 = 950;
pub const RISK_BUCKET_056_BRIDGE_WEIGHT_BPS: u32 = 185;
pub fn risk_bucket_056_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_056_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_056_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_056_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_056_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_057_MAX_NOTIONAL: u128 = 57u128 * 1_000_000_000;
pub const RISK_BUCKET_057_OPTION_WEIGHT_BPS: u32 = 1000;
pub const RISK_BUCKET_057_PERP_WEIGHT_BPS: u32 = 970;
pub const RISK_BUCKET_057_BRIDGE_WEIGHT_BPS: u32 = 190;
pub fn risk_bucket_057_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_057_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_057_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_057_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_057_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_058_MAX_NOTIONAL: u128 = 58u128 * 1_000_000_000;
pub const RISK_BUCKET_058_OPTION_WEIGHT_BPS: u32 = 1025;
pub const RISK_BUCKET_058_PERP_WEIGHT_BPS: u32 = 990;
pub const RISK_BUCKET_058_BRIDGE_WEIGHT_BPS: u32 = 50;
pub fn risk_bucket_058_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_058_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_058_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_058_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_058_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_059_MAX_NOTIONAL: u128 = 59u128 * 1_000_000_000;
pub const RISK_BUCKET_059_OPTION_WEIGHT_BPS: u32 = 1050;
pub const RISK_BUCKET_059_PERP_WEIGHT_BPS: u32 = 1010;
pub const RISK_BUCKET_059_BRIDGE_WEIGHT_BPS: u32 = 55;
pub fn risk_bucket_059_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_059_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_059_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_059_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_059_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_060_MAX_NOTIONAL: u128 = 60u128 * 1_000_000_000;
pub const RISK_BUCKET_060_OPTION_WEIGHT_BPS: u32 = 1075;
pub const RISK_BUCKET_060_PERP_WEIGHT_BPS: u32 = 1030;
pub const RISK_BUCKET_060_BRIDGE_WEIGHT_BPS: u32 = 60;
pub fn risk_bucket_060_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_060_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_060_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_060_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_060_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_061_MAX_NOTIONAL: u128 = 61u128 * 1_000_000_000;
pub const RISK_BUCKET_061_OPTION_WEIGHT_BPS: u32 = 1100;
pub const RISK_BUCKET_061_PERP_WEIGHT_BPS: u32 = 1050;
pub const RISK_BUCKET_061_BRIDGE_WEIGHT_BPS: u32 = 65;
pub fn risk_bucket_061_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_061_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_061_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_061_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_061_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_062_MAX_NOTIONAL: u128 = 62u128 * 1_000_000_000;
pub const RISK_BUCKET_062_OPTION_WEIGHT_BPS: u32 = 1125;
pub const RISK_BUCKET_062_PERP_WEIGHT_BPS: u32 = 1070;
pub const RISK_BUCKET_062_BRIDGE_WEIGHT_BPS: u32 = 70;
pub fn risk_bucket_062_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_062_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_062_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_062_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_062_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_063_MAX_NOTIONAL: u128 = 63u128 * 1_000_000_000;
pub const RISK_BUCKET_063_OPTION_WEIGHT_BPS: u32 = 1150;
pub const RISK_BUCKET_063_PERP_WEIGHT_BPS: u32 = 1090;
pub const RISK_BUCKET_063_BRIDGE_WEIGHT_BPS: u32 = 75;
pub fn risk_bucket_063_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_063_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_063_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_063_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_063_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_064_MAX_NOTIONAL: u128 = 64u128 * 1_000_000_000;
pub const RISK_BUCKET_064_OPTION_WEIGHT_BPS: u32 = 1175;
pub const RISK_BUCKET_064_PERP_WEIGHT_BPS: u32 = 1110;
pub const RISK_BUCKET_064_BRIDGE_WEIGHT_BPS: u32 = 80;
pub fn risk_bucket_064_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_064_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_064_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_064_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_064_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_065_MAX_NOTIONAL: u128 = 65u128 * 1_000_000_000;
pub const RISK_BUCKET_065_OPTION_WEIGHT_BPS: u32 = 1200;
pub const RISK_BUCKET_065_PERP_WEIGHT_BPS: u32 = 1130;
pub const RISK_BUCKET_065_BRIDGE_WEIGHT_BPS: u32 = 85;
pub fn risk_bucket_065_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_065_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_065_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_065_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_065_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_066_MAX_NOTIONAL: u128 = 66u128 * 1_000_000_000;
pub const RISK_BUCKET_066_OPTION_WEIGHT_BPS: u32 = 1225;
pub const RISK_BUCKET_066_PERP_WEIGHT_BPS: u32 = 1150;
pub const RISK_BUCKET_066_BRIDGE_WEIGHT_BPS: u32 = 90;
pub fn risk_bucket_066_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_066_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_066_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_066_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_066_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_067_MAX_NOTIONAL: u128 = 67u128 * 1_000_000_000;
pub const RISK_BUCKET_067_OPTION_WEIGHT_BPS: u32 = 1250;
pub const RISK_BUCKET_067_PERP_WEIGHT_BPS: u32 = 1170;
pub const RISK_BUCKET_067_BRIDGE_WEIGHT_BPS: u32 = 95;
pub fn risk_bucket_067_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_067_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_067_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_067_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_067_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_068_MAX_NOTIONAL: u128 = 68u128 * 1_000_000_000;
pub const RISK_BUCKET_068_OPTION_WEIGHT_BPS: u32 = 1275;
pub const RISK_BUCKET_068_PERP_WEIGHT_BPS: u32 = 1190;
pub const RISK_BUCKET_068_BRIDGE_WEIGHT_BPS: u32 = 100;
pub fn risk_bucket_068_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_068_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_068_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_068_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_068_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_069_MAX_NOTIONAL: u128 = 69u128 * 1_000_000_000;
pub const RISK_BUCKET_069_OPTION_WEIGHT_BPS: u32 = 1300;
pub const RISK_BUCKET_069_PERP_WEIGHT_BPS: u32 = 1210;
pub const RISK_BUCKET_069_BRIDGE_WEIGHT_BPS: u32 = 105;
pub fn risk_bucket_069_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_069_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_069_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_069_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_069_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_070_MAX_NOTIONAL: u128 = 70u128 * 1_000_000_000;
pub const RISK_BUCKET_070_OPTION_WEIGHT_BPS: u32 = 1325;
pub const RISK_BUCKET_070_PERP_WEIGHT_BPS: u32 = 1230;
pub const RISK_BUCKET_070_BRIDGE_WEIGHT_BPS: u32 = 110;
pub fn risk_bucket_070_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_070_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_070_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_070_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_070_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_071_MAX_NOTIONAL: u128 = 71u128 * 1_000_000_000;
pub const RISK_BUCKET_071_OPTION_WEIGHT_BPS: u32 = 1350;
pub const RISK_BUCKET_071_PERP_WEIGHT_BPS: u32 = 1250;
pub const RISK_BUCKET_071_BRIDGE_WEIGHT_BPS: u32 = 115;
pub fn risk_bucket_071_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_071_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_071_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_071_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_071_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_072_MAX_NOTIONAL: u128 = 72u128 * 1_000_000_000;
pub const RISK_BUCKET_072_OPTION_WEIGHT_BPS: u32 = 1375;
pub const RISK_BUCKET_072_PERP_WEIGHT_BPS: u32 = 1270;
pub const RISK_BUCKET_072_BRIDGE_WEIGHT_BPS: u32 = 120;
pub fn risk_bucket_072_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_072_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_072_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_072_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_072_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_073_MAX_NOTIONAL: u128 = 73u128 * 1_000_000_000;
pub const RISK_BUCKET_073_OPTION_WEIGHT_BPS: u32 = 1400;
pub const RISK_BUCKET_073_PERP_WEIGHT_BPS: u32 = 1290;
pub const RISK_BUCKET_073_BRIDGE_WEIGHT_BPS: u32 = 125;
pub fn risk_bucket_073_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_073_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_073_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_073_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_073_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_074_MAX_NOTIONAL: u128 = 74u128 * 1_000_000_000;
pub const RISK_BUCKET_074_OPTION_WEIGHT_BPS: u32 = 500;
pub const RISK_BUCKET_074_PERP_WEIGHT_BPS: u32 = 1310;
pub const RISK_BUCKET_074_BRIDGE_WEIGHT_BPS: u32 = 130;
pub fn risk_bucket_074_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_074_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_074_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_074_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_074_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_075_MAX_NOTIONAL: u128 = 75u128 * 1_000_000_000;
pub const RISK_BUCKET_075_OPTION_WEIGHT_BPS: u32 = 525;
pub const RISK_BUCKET_075_PERP_WEIGHT_BPS: u32 = 1330;
pub const RISK_BUCKET_075_BRIDGE_WEIGHT_BPS: u32 = 135;
pub fn risk_bucket_075_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_075_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_075_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_075_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_075_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_076_MAX_NOTIONAL: u128 = 76u128 * 1_000_000_000;
pub const RISK_BUCKET_076_OPTION_WEIGHT_BPS: u32 = 550;
pub const RISK_BUCKET_076_PERP_WEIGHT_BPS: u32 = 1350;
pub const RISK_BUCKET_076_BRIDGE_WEIGHT_BPS: u32 = 140;
pub fn risk_bucket_076_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_076_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_076_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_076_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_076_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_077_MAX_NOTIONAL: u128 = 77u128 * 1_000_000_000;
pub const RISK_BUCKET_077_OPTION_WEIGHT_BPS: u32 = 575;
pub const RISK_BUCKET_077_PERP_WEIGHT_BPS: u32 = 1370;
pub const RISK_BUCKET_077_BRIDGE_WEIGHT_BPS: u32 = 145;
pub fn risk_bucket_077_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_077_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_077_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_077_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_077_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_078_MAX_NOTIONAL: u128 = 78u128 * 1_000_000_000;
pub const RISK_BUCKET_078_OPTION_WEIGHT_BPS: u32 = 600;
pub const RISK_BUCKET_078_PERP_WEIGHT_BPS: u32 = 1390;
pub const RISK_BUCKET_078_BRIDGE_WEIGHT_BPS: u32 = 150;
pub fn risk_bucket_078_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_078_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_078_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_078_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_078_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_079_MAX_NOTIONAL: u128 = 79u128 * 1_000_000_000;
pub const RISK_BUCKET_079_OPTION_WEIGHT_BPS: u32 = 625;
pub const RISK_BUCKET_079_PERP_WEIGHT_BPS: u32 = 1410;
pub const RISK_BUCKET_079_BRIDGE_WEIGHT_BPS: u32 = 155;
pub fn risk_bucket_079_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_079_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_079_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_079_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_079_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_080_MAX_NOTIONAL: u128 = 80u128 * 1_000_000_000;
pub const RISK_BUCKET_080_OPTION_WEIGHT_BPS: u32 = 650;
pub const RISK_BUCKET_080_PERP_WEIGHT_BPS: u32 = 1430;
pub const RISK_BUCKET_080_BRIDGE_WEIGHT_BPS: u32 = 160;
pub fn risk_bucket_080_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_080_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_080_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_080_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_080_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_081_MAX_NOTIONAL: u128 = 81u128 * 1_000_000_000;
pub const RISK_BUCKET_081_OPTION_WEIGHT_BPS: u32 = 675;
pub const RISK_BUCKET_081_PERP_WEIGHT_BPS: u32 = 1450;
pub const RISK_BUCKET_081_BRIDGE_WEIGHT_BPS: u32 = 165;
pub fn risk_bucket_081_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_081_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_081_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_081_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_081_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_082_MAX_NOTIONAL: u128 = 82u128 * 1_000_000_000;
pub const RISK_BUCKET_082_OPTION_WEIGHT_BPS: u32 = 700;
pub const RISK_BUCKET_082_PERP_WEIGHT_BPS: u32 = 650;
pub const RISK_BUCKET_082_BRIDGE_WEIGHT_BPS: u32 = 170;
pub fn risk_bucket_082_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_082_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_082_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_082_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_082_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_083_MAX_NOTIONAL: u128 = 83u128 * 1_000_000_000;
pub const RISK_BUCKET_083_OPTION_WEIGHT_BPS: u32 = 725;
pub const RISK_BUCKET_083_PERP_WEIGHT_BPS: u32 = 670;
pub const RISK_BUCKET_083_BRIDGE_WEIGHT_BPS: u32 = 175;
pub fn risk_bucket_083_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_083_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_083_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_083_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_083_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_084_MAX_NOTIONAL: u128 = 84u128 * 1_000_000_000;
pub const RISK_BUCKET_084_OPTION_WEIGHT_BPS: u32 = 750;
pub const RISK_BUCKET_084_PERP_WEIGHT_BPS: u32 = 690;
pub const RISK_BUCKET_084_BRIDGE_WEIGHT_BPS: u32 = 180;
pub fn risk_bucket_084_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_084_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_084_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_084_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_084_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_085_MAX_NOTIONAL: u128 = 85u128 * 1_000_000_000;
pub const RISK_BUCKET_085_OPTION_WEIGHT_BPS: u32 = 775;
pub const RISK_BUCKET_085_PERP_WEIGHT_BPS: u32 = 710;
pub const RISK_BUCKET_085_BRIDGE_WEIGHT_BPS: u32 = 185;
pub fn risk_bucket_085_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_085_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_085_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_085_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_085_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_086_MAX_NOTIONAL: u128 = 86u128 * 1_000_000_000;
pub const RISK_BUCKET_086_OPTION_WEIGHT_BPS: u32 = 800;
pub const RISK_BUCKET_086_PERP_WEIGHT_BPS: u32 = 730;
pub const RISK_BUCKET_086_BRIDGE_WEIGHT_BPS: u32 = 190;
pub fn risk_bucket_086_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_086_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_086_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_086_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_086_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_087_MAX_NOTIONAL: u128 = 87u128 * 1_000_000_000;
pub const RISK_BUCKET_087_OPTION_WEIGHT_BPS: u32 = 825;
pub const RISK_BUCKET_087_PERP_WEIGHT_BPS: u32 = 750;
pub const RISK_BUCKET_087_BRIDGE_WEIGHT_BPS: u32 = 50;
pub fn risk_bucket_087_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_087_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_087_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_087_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_087_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_088_MAX_NOTIONAL: u128 = 88u128 * 1_000_000_000;
pub const RISK_BUCKET_088_OPTION_WEIGHT_BPS: u32 = 850;
pub const RISK_BUCKET_088_PERP_WEIGHT_BPS: u32 = 770;
pub const RISK_BUCKET_088_BRIDGE_WEIGHT_BPS: u32 = 55;
pub fn risk_bucket_088_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_088_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_088_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_088_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_088_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_089_MAX_NOTIONAL: u128 = 89u128 * 1_000_000_000;
pub const RISK_BUCKET_089_OPTION_WEIGHT_BPS: u32 = 875;
pub const RISK_BUCKET_089_PERP_WEIGHT_BPS: u32 = 790;
pub const RISK_BUCKET_089_BRIDGE_WEIGHT_BPS: u32 = 60;
pub fn risk_bucket_089_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_089_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_089_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_089_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_089_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_090_MAX_NOTIONAL: u128 = 90u128 * 1_000_000_000;
pub const RISK_BUCKET_090_OPTION_WEIGHT_BPS: u32 = 900;
pub const RISK_BUCKET_090_PERP_WEIGHT_BPS: u32 = 810;
pub const RISK_BUCKET_090_BRIDGE_WEIGHT_BPS: u32 = 65;
pub fn risk_bucket_090_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_090_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_090_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_090_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_090_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_091_MAX_NOTIONAL: u128 = 91u128 * 1_000_000_000;
pub const RISK_BUCKET_091_OPTION_WEIGHT_BPS: u32 = 925;
pub const RISK_BUCKET_091_PERP_WEIGHT_BPS: u32 = 830;
pub const RISK_BUCKET_091_BRIDGE_WEIGHT_BPS: u32 = 70;
pub fn risk_bucket_091_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_091_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_091_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_091_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_091_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_092_MAX_NOTIONAL: u128 = 92u128 * 1_000_000_000;
pub const RISK_BUCKET_092_OPTION_WEIGHT_BPS: u32 = 950;
pub const RISK_BUCKET_092_PERP_WEIGHT_BPS: u32 = 850;
pub const RISK_BUCKET_092_BRIDGE_WEIGHT_BPS: u32 = 75;
pub fn risk_bucket_092_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_092_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_092_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_092_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_092_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_093_MAX_NOTIONAL: u128 = 93u128 * 1_000_000_000;
pub const RISK_BUCKET_093_OPTION_WEIGHT_BPS: u32 = 975;
pub const RISK_BUCKET_093_PERP_WEIGHT_BPS: u32 = 870;
pub const RISK_BUCKET_093_BRIDGE_WEIGHT_BPS: u32 = 80;
pub fn risk_bucket_093_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_093_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_093_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_093_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_093_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_094_MAX_NOTIONAL: u128 = 94u128 * 1_000_000_000;
pub const RISK_BUCKET_094_OPTION_WEIGHT_BPS: u32 = 1000;
pub const RISK_BUCKET_094_PERP_WEIGHT_BPS: u32 = 890;
pub const RISK_BUCKET_094_BRIDGE_WEIGHT_BPS: u32 = 85;
pub fn risk_bucket_094_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_094_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_094_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_094_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_094_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_095_MAX_NOTIONAL: u128 = 95u128 * 1_000_000_000;
pub const RISK_BUCKET_095_OPTION_WEIGHT_BPS: u32 = 1025;
pub const RISK_BUCKET_095_PERP_WEIGHT_BPS: u32 = 910;
pub const RISK_BUCKET_095_BRIDGE_WEIGHT_BPS: u32 = 90;
pub fn risk_bucket_095_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_095_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_095_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_095_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_095_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_096_MAX_NOTIONAL: u128 = 96u128 * 1_000_000_000;
pub const RISK_BUCKET_096_OPTION_WEIGHT_BPS: u32 = 1050;
pub const RISK_BUCKET_096_PERP_WEIGHT_BPS: u32 = 930;
pub const RISK_BUCKET_096_BRIDGE_WEIGHT_BPS: u32 = 95;
pub fn risk_bucket_096_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_096_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_096_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_096_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_096_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_097_MAX_NOTIONAL: u128 = 97u128 * 1_000_000_000;
pub const RISK_BUCKET_097_OPTION_WEIGHT_BPS: u32 = 1075;
pub const RISK_BUCKET_097_PERP_WEIGHT_BPS: u32 = 950;
pub const RISK_BUCKET_097_BRIDGE_WEIGHT_BPS: u32 = 100;
pub fn risk_bucket_097_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_097_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_097_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_097_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_097_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_098_MAX_NOTIONAL: u128 = 98u128 * 1_000_000_000;
pub const RISK_BUCKET_098_OPTION_WEIGHT_BPS: u32 = 1100;
pub const RISK_BUCKET_098_PERP_WEIGHT_BPS: u32 = 970;
pub const RISK_BUCKET_098_BRIDGE_WEIGHT_BPS: u32 = 105;
pub fn risk_bucket_098_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_098_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_098_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_098_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_098_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_099_MAX_NOTIONAL: u128 = 99u128 * 1_000_000_000;
pub const RISK_BUCKET_099_OPTION_WEIGHT_BPS: u32 = 1125;
pub const RISK_BUCKET_099_PERP_WEIGHT_BPS: u32 = 990;
pub const RISK_BUCKET_099_BRIDGE_WEIGHT_BPS: u32 = 110;
pub fn risk_bucket_099_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_099_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_099_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_099_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_099_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_100_MAX_NOTIONAL: u128 = 100u128 * 1_000_000_000;
pub const RISK_BUCKET_100_OPTION_WEIGHT_BPS: u32 = 1150;
pub const RISK_BUCKET_100_PERP_WEIGHT_BPS: u32 = 1010;
pub const RISK_BUCKET_100_BRIDGE_WEIGHT_BPS: u32 = 115;
pub fn risk_bucket_100_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_100_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_100_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_100_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_100_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_101_MAX_NOTIONAL: u128 = 101u128 * 1_000_000_000;
pub const RISK_BUCKET_101_OPTION_WEIGHT_BPS: u32 = 1175;
pub const RISK_BUCKET_101_PERP_WEIGHT_BPS: u32 = 1030;
pub const RISK_BUCKET_101_BRIDGE_WEIGHT_BPS: u32 = 120;
pub fn risk_bucket_101_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_101_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_101_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_101_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_101_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_102_MAX_NOTIONAL: u128 = 102u128 * 1_000_000_000;
pub const RISK_BUCKET_102_OPTION_WEIGHT_BPS: u32 = 1200;
pub const RISK_BUCKET_102_PERP_WEIGHT_BPS: u32 = 1050;
pub const RISK_BUCKET_102_BRIDGE_WEIGHT_BPS: u32 = 125;
pub fn risk_bucket_102_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_102_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_102_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_102_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_102_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_103_MAX_NOTIONAL: u128 = 103u128 * 1_000_000_000;
pub const RISK_BUCKET_103_OPTION_WEIGHT_BPS: u32 = 1225;
pub const RISK_BUCKET_103_PERP_WEIGHT_BPS: u32 = 1070;
pub const RISK_BUCKET_103_BRIDGE_WEIGHT_BPS: u32 = 130;
pub fn risk_bucket_103_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_103_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_103_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_103_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_103_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_104_MAX_NOTIONAL: u128 = 104u128 * 1_000_000_000;
pub const RISK_BUCKET_104_OPTION_WEIGHT_BPS: u32 = 1250;
pub const RISK_BUCKET_104_PERP_WEIGHT_BPS: u32 = 1090;
pub const RISK_BUCKET_104_BRIDGE_WEIGHT_BPS: u32 = 135;
pub fn risk_bucket_104_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_104_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_104_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_104_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_104_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_105_MAX_NOTIONAL: u128 = 105u128 * 1_000_000_000;
pub const RISK_BUCKET_105_OPTION_WEIGHT_BPS: u32 = 1275;
pub const RISK_BUCKET_105_PERP_WEIGHT_BPS: u32 = 1110;
pub const RISK_BUCKET_105_BRIDGE_WEIGHT_BPS: u32 = 140;
pub fn risk_bucket_105_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_105_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_105_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_105_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_105_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_106_MAX_NOTIONAL: u128 = 106u128 * 1_000_000_000;
pub const RISK_BUCKET_106_OPTION_WEIGHT_BPS: u32 = 1300;
pub const RISK_BUCKET_106_PERP_WEIGHT_BPS: u32 = 1130;
pub const RISK_BUCKET_106_BRIDGE_WEIGHT_BPS: u32 = 145;
pub fn risk_bucket_106_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_106_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_106_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_106_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_106_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_107_MAX_NOTIONAL: u128 = 107u128 * 1_000_000_000;
pub const RISK_BUCKET_107_OPTION_WEIGHT_BPS: u32 = 1325;
pub const RISK_BUCKET_107_PERP_WEIGHT_BPS: u32 = 1150;
pub const RISK_BUCKET_107_BRIDGE_WEIGHT_BPS: u32 = 150;
pub fn risk_bucket_107_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_107_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_107_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_107_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_107_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_108_MAX_NOTIONAL: u128 = 108u128 * 1_000_000_000;
pub const RISK_BUCKET_108_OPTION_WEIGHT_BPS: u32 = 1350;
pub const RISK_BUCKET_108_PERP_WEIGHT_BPS: u32 = 1170;
pub const RISK_BUCKET_108_BRIDGE_WEIGHT_BPS: u32 = 155;
pub fn risk_bucket_108_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_108_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_108_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_108_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_108_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_109_MAX_NOTIONAL: u128 = 109u128 * 1_000_000_000;
pub const RISK_BUCKET_109_OPTION_WEIGHT_BPS: u32 = 1375;
pub const RISK_BUCKET_109_PERP_WEIGHT_BPS: u32 = 1190;
pub const RISK_BUCKET_109_BRIDGE_WEIGHT_BPS: u32 = 160;
pub fn risk_bucket_109_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_109_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_109_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_109_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_109_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_110_MAX_NOTIONAL: u128 = 110u128 * 1_000_000_000;
pub const RISK_BUCKET_110_OPTION_WEIGHT_BPS: u32 = 1400;
pub const RISK_BUCKET_110_PERP_WEIGHT_BPS: u32 = 1210;
pub const RISK_BUCKET_110_BRIDGE_WEIGHT_BPS: u32 = 165;
pub fn risk_bucket_110_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_110_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_110_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_110_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_110_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_111_MAX_NOTIONAL: u128 = 111u128 * 1_000_000_000;
pub const RISK_BUCKET_111_OPTION_WEIGHT_BPS: u32 = 500;
pub const RISK_BUCKET_111_PERP_WEIGHT_BPS: u32 = 1230;
pub const RISK_BUCKET_111_BRIDGE_WEIGHT_BPS: u32 = 170;
pub fn risk_bucket_111_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_111_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_111_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_111_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_111_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_112_MAX_NOTIONAL: u128 = 112u128 * 1_000_000_000;
pub const RISK_BUCKET_112_OPTION_WEIGHT_BPS: u32 = 525;
pub const RISK_BUCKET_112_PERP_WEIGHT_BPS: u32 = 1250;
pub const RISK_BUCKET_112_BRIDGE_WEIGHT_BPS: u32 = 175;
pub fn risk_bucket_112_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_112_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_112_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_112_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_112_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_113_MAX_NOTIONAL: u128 = 113u128 * 1_000_000_000;
pub const RISK_BUCKET_113_OPTION_WEIGHT_BPS: u32 = 550;
pub const RISK_BUCKET_113_PERP_WEIGHT_BPS: u32 = 1270;
pub const RISK_BUCKET_113_BRIDGE_WEIGHT_BPS: u32 = 180;
pub fn risk_bucket_113_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_113_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_113_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_113_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_113_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_114_MAX_NOTIONAL: u128 = 114u128 * 1_000_000_000;
pub const RISK_BUCKET_114_OPTION_WEIGHT_BPS: u32 = 575;
pub const RISK_BUCKET_114_PERP_WEIGHT_BPS: u32 = 1290;
pub const RISK_BUCKET_114_BRIDGE_WEIGHT_BPS: u32 = 185;
pub fn risk_bucket_114_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_114_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_114_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_114_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_114_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_115_MAX_NOTIONAL: u128 = 115u128 * 1_000_000_000;
pub const RISK_BUCKET_115_OPTION_WEIGHT_BPS: u32 = 600;
pub const RISK_BUCKET_115_PERP_WEIGHT_BPS: u32 = 1310;
pub const RISK_BUCKET_115_BRIDGE_WEIGHT_BPS: u32 = 190;
pub fn risk_bucket_115_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_115_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_115_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_115_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_115_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_116_MAX_NOTIONAL: u128 = 116u128 * 1_000_000_000;
pub const RISK_BUCKET_116_OPTION_WEIGHT_BPS: u32 = 625;
pub const RISK_BUCKET_116_PERP_WEIGHT_BPS: u32 = 1330;
pub const RISK_BUCKET_116_BRIDGE_WEIGHT_BPS: u32 = 50;
pub fn risk_bucket_116_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_116_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_116_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_116_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_116_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_117_MAX_NOTIONAL: u128 = 117u128 * 1_000_000_000;
pub const RISK_BUCKET_117_OPTION_WEIGHT_BPS: u32 = 650;
pub const RISK_BUCKET_117_PERP_WEIGHT_BPS: u32 = 1350;
pub const RISK_BUCKET_117_BRIDGE_WEIGHT_BPS: u32 = 55;
pub fn risk_bucket_117_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_117_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_117_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_117_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_117_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_118_MAX_NOTIONAL: u128 = 118u128 * 1_000_000_000;
pub const RISK_BUCKET_118_OPTION_WEIGHT_BPS: u32 = 675;
pub const RISK_BUCKET_118_PERP_WEIGHT_BPS: u32 = 1370;
pub const RISK_BUCKET_118_BRIDGE_WEIGHT_BPS: u32 = 60;
pub fn risk_bucket_118_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_118_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_118_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_118_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_118_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_119_MAX_NOTIONAL: u128 = 119u128 * 1_000_000_000;
pub const RISK_BUCKET_119_OPTION_WEIGHT_BPS: u32 = 700;
pub const RISK_BUCKET_119_PERP_WEIGHT_BPS: u32 = 1390;
pub const RISK_BUCKET_119_BRIDGE_WEIGHT_BPS: u32 = 65;
pub fn risk_bucket_119_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_119_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_119_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_119_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_119_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_120_MAX_NOTIONAL: u128 = 120u128 * 1_000_000_000;
pub const RISK_BUCKET_120_OPTION_WEIGHT_BPS: u32 = 725;
pub const RISK_BUCKET_120_PERP_WEIGHT_BPS: u32 = 1410;
pub const RISK_BUCKET_120_BRIDGE_WEIGHT_BPS: u32 = 70;
pub fn risk_bucket_120_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_120_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_120_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_120_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_120_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_121_MAX_NOTIONAL: u128 = 121u128 * 1_000_000_000;
pub const RISK_BUCKET_121_OPTION_WEIGHT_BPS: u32 = 750;
pub const RISK_BUCKET_121_PERP_WEIGHT_BPS: u32 = 1430;
pub const RISK_BUCKET_121_BRIDGE_WEIGHT_BPS: u32 = 75;
pub fn risk_bucket_121_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_121_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_121_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_121_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_121_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_122_MAX_NOTIONAL: u128 = 122u128 * 1_000_000_000;
pub const RISK_BUCKET_122_OPTION_WEIGHT_BPS: u32 = 775;
pub const RISK_BUCKET_122_PERP_WEIGHT_BPS: u32 = 1450;
pub const RISK_BUCKET_122_BRIDGE_WEIGHT_BPS: u32 = 80;
pub fn risk_bucket_122_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_122_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_122_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_122_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_122_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_123_MAX_NOTIONAL: u128 = 123u128 * 1_000_000_000;
pub const RISK_BUCKET_123_OPTION_WEIGHT_BPS: u32 = 800;
pub const RISK_BUCKET_123_PERP_WEIGHT_BPS: u32 = 650;
pub const RISK_BUCKET_123_BRIDGE_WEIGHT_BPS: u32 = 85;
pub fn risk_bucket_123_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_123_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_123_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_123_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_123_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_124_MAX_NOTIONAL: u128 = 124u128 * 1_000_000_000;
pub const RISK_BUCKET_124_OPTION_WEIGHT_BPS: u32 = 825;
pub const RISK_BUCKET_124_PERP_WEIGHT_BPS: u32 = 670;
pub const RISK_BUCKET_124_BRIDGE_WEIGHT_BPS: u32 = 90;
pub fn risk_bucket_124_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_124_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_124_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_124_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_124_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_125_MAX_NOTIONAL: u128 = 125u128 * 1_000_000_000;
pub const RISK_BUCKET_125_OPTION_WEIGHT_BPS: u32 = 850;
pub const RISK_BUCKET_125_PERP_WEIGHT_BPS: u32 = 690;
pub const RISK_BUCKET_125_BRIDGE_WEIGHT_BPS: u32 = 95;
pub fn risk_bucket_125_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_125_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_125_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_125_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_125_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_126_MAX_NOTIONAL: u128 = 126u128 * 1_000_000_000;
pub const RISK_BUCKET_126_OPTION_WEIGHT_BPS: u32 = 875;
pub const RISK_BUCKET_126_PERP_WEIGHT_BPS: u32 = 710;
pub const RISK_BUCKET_126_BRIDGE_WEIGHT_BPS: u32 = 100;
pub fn risk_bucket_126_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_126_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_126_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_126_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_126_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_127_MAX_NOTIONAL: u128 = 127u128 * 1_000_000_000;
pub const RISK_BUCKET_127_OPTION_WEIGHT_BPS: u32 = 900;
pub const RISK_BUCKET_127_PERP_WEIGHT_BPS: u32 = 730;
pub const RISK_BUCKET_127_BRIDGE_WEIGHT_BPS: u32 = 105;
pub fn risk_bucket_127_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_127_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_127_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_127_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_127_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_128_MAX_NOTIONAL: u128 = 128u128 * 1_000_000_000;
pub const RISK_BUCKET_128_OPTION_WEIGHT_BPS: u32 = 925;
pub const RISK_BUCKET_128_PERP_WEIGHT_BPS: u32 = 750;
pub const RISK_BUCKET_128_BRIDGE_WEIGHT_BPS: u32 = 110;
pub fn risk_bucket_128_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_128_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_128_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_128_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_128_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_129_MAX_NOTIONAL: u128 = 129u128 * 1_000_000_000;
pub const RISK_BUCKET_129_OPTION_WEIGHT_BPS: u32 = 950;
pub const RISK_BUCKET_129_PERP_WEIGHT_BPS: u32 = 770;
pub const RISK_BUCKET_129_BRIDGE_WEIGHT_BPS: u32 = 115;
pub fn risk_bucket_129_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_129_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_129_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_129_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_129_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_130_MAX_NOTIONAL: u128 = 130u128 * 1_000_000_000;
pub const RISK_BUCKET_130_OPTION_WEIGHT_BPS: u32 = 975;
pub const RISK_BUCKET_130_PERP_WEIGHT_BPS: u32 = 790;
pub const RISK_BUCKET_130_BRIDGE_WEIGHT_BPS: u32 = 120;
pub fn risk_bucket_130_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_130_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_130_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_130_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_130_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_131_MAX_NOTIONAL: u128 = 131u128 * 1_000_000_000;
pub const RISK_BUCKET_131_OPTION_WEIGHT_BPS: u32 = 1000;
pub const RISK_BUCKET_131_PERP_WEIGHT_BPS: u32 = 810;
pub const RISK_BUCKET_131_BRIDGE_WEIGHT_BPS: u32 = 125;
pub fn risk_bucket_131_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_131_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_131_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_131_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_131_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_132_MAX_NOTIONAL: u128 = 132u128 * 1_000_000_000;
pub const RISK_BUCKET_132_OPTION_WEIGHT_BPS: u32 = 1025;
pub const RISK_BUCKET_132_PERP_WEIGHT_BPS: u32 = 830;
pub const RISK_BUCKET_132_BRIDGE_WEIGHT_BPS: u32 = 130;
pub fn risk_bucket_132_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_132_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_132_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_132_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_132_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_133_MAX_NOTIONAL: u128 = 133u128 * 1_000_000_000;
pub const RISK_BUCKET_133_OPTION_WEIGHT_BPS: u32 = 1050;
pub const RISK_BUCKET_133_PERP_WEIGHT_BPS: u32 = 850;
pub const RISK_BUCKET_133_BRIDGE_WEIGHT_BPS: u32 = 135;
pub fn risk_bucket_133_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_133_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_133_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_133_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_133_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_134_MAX_NOTIONAL: u128 = 134u128 * 1_000_000_000;
pub const RISK_BUCKET_134_OPTION_WEIGHT_BPS: u32 = 1075;
pub const RISK_BUCKET_134_PERP_WEIGHT_BPS: u32 = 870;
pub const RISK_BUCKET_134_BRIDGE_WEIGHT_BPS: u32 = 140;
pub fn risk_bucket_134_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_134_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_134_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_134_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_134_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_135_MAX_NOTIONAL: u128 = 135u128 * 1_000_000_000;
pub const RISK_BUCKET_135_OPTION_WEIGHT_BPS: u32 = 1100;
pub const RISK_BUCKET_135_PERP_WEIGHT_BPS: u32 = 890;
pub const RISK_BUCKET_135_BRIDGE_WEIGHT_BPS: u32 = 145;
pub fn risk_bucket_135_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_135_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_135_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_135_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_135_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_136_MAX_NOTIONAL: u128 = 136u128 * 1_000_000_000;
pub const RISK_BUCKET_136_OPTION_WEIGHT_BPS: u32 = 1125;
pub const RISK_BUCKET_136_PERP_WEIGHT_BPS: u32 = 910;
pub const RISK_BUCKET_136_BRIDGE_WEIGHT_BPS: u32 = 150;
pub fn risk_bucket_136_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_136_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_136_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_136_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_136_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_137_MAX_NOTIONAL: u128 = 137u128 * 1_000_000_000;
pub const RISK_BUCKET_137_OPTION_WEIGHT_BPS: u32 = 1150;
pub const RISK_BUCKET_137_PERP_WEIGHT_BPS: u32 = 930;
pub const RISK_BUCKET_137_BRIDGE_WEIGHT_BPS: u32 = 155;
pub fn risk_bucket_137_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_137_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_137_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_137_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_137_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_138_MAX_NOTIONAL: u128 = 138u128 * 1_000_000_000;
pub const RISK_BUCKET_138_OPTION_WEIGHT_BPS: u32 = 1175;
pub const RISK_BUCKET_138_PERP_WEIGHT_BPS: u32 = 950;
pub const RISK_BUCKET_138_BRIDGE_WEIGHT_BPS: u32 = 160;
pub fn risk_bucket_138_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_138_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_138_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_138_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_138_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_139_MAX_NOTIONAL: u128 = 139u128 * 1_000_000_000;
pub const RISK_BUCKET_139_OPTION_WEIGHT_BPS: u32 = 1200;
pub const RISK_BUCKET_139_PERP_WEIGHT_BPS: u32 = 970;
pub const RISK_BUCKET_139_BRIDGE_WEIGHT_BPS: u32 = 165;
pub fn risk_bucket_139_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_139_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_139_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_139_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_139_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_140_MAX_NOTIONAL: u128 = 140u128 * 1_000_000_000;
pub const RISK_BUCKET_140_OPTION_WEIGHT_BPS: u32 = 1225;
pub const RISK_BUCKET_140_PERP_WEIGHT_BPS: u32 = 990;
pub const RISK_BUCKET_140_BRIDGE_WEIGHT_BPS: u32 = 170;
pub fn risk_bucket_140_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_140_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_140_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_140_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_140_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_141_MAX_NOTIONAL: u128 = 141u128 * 1_000_000_000;
pub const RISK_BUCKET_141_OPTION_WEIGHT_BPS: u32 = 1250;
pub const RISK_BUCKET_141_PERP_WEIGHT_BPS: u32 = 1010;
pub const RISK_BUCKET_141_BRIDGE_WEIGHT_BPS: u32 = 175;
pub fn risk_bucket_141_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_141_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_141_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_141_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_141_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_142_MAX_NOTIONAL: u128 = 142u128 * 1_000_000_000;
pub const RISK_BUCKET_142_OPTION_WEIGHT_BPS: u32 = 1275;
pub const RISK_BUCKET_142_PERP_WEIGHT_BPS: u32 = 1030;
pub const RISK_BUCKET_142_BRIDGE_WEIGHT_BPS: u32 = 180;
pub fn risk_bucket_142_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_142_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_142_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_142_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_142_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_143_MAX_NOTIONAL: u128 = 143u128 * 1_000_000_000;
pub const RISK_BUCKET_143_OPTION_WEIGHT_BPS: u32 = 1300;
pub const RISK_BUCKET_143_PERP_WEIGHT_BPS: u32 = 1050;
pub const RISK_BUCKET_143_BRIDGE_WEIGHT_BPS: u32 = 185;
pub fn risk_bucket_143_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_143_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_143_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_143_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_143_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_144_MAX_NOTIONAL: u128 = 144u128 * 1_000_000_000;
pub const RISK_BUCKET_144_OPTION_WEIGHT_BPS: u32 = 1325;
pub const RISK_BUCKET_144_PERP_WEIGHT_BPS: u32 = 1070;
pub const RISK_BUCKET_144_BRIDGE_WEIGHT_BPS: u32 = 190;
pub fn risk_bucket_144_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_144_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_144_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_144_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_144_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_145_MAX_NOTIONAL: u128 = 145u128 * 1_000_000_000;
pub const RISK_BUCKET_145_OPTION_WEIGHT_BPS: u32 = 1350;
pub const RISK_BUCKET_145_PERP_WEIGHT_BPS: u32 = 1090;
pub const RISK_BUCKET_145_BRIDGE_WEIGHT_BPS: u32 = 50;
pub fn risk_bucket_145_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_145_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_145_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_145_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_145_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_146_MAX_NOTIONAL: u128 = 146u128 * 1_000_000_000;
pub const RISK_BUCKET_146_OPTION_WEIGHT_BPS: u32 = 1375;
pub const RISK_BUCKET_146_PERP_WEIGHT_BPS: u32 = 1110;
pub const RISK_BUCKET_146_BRIDGE_WEIGHT_BPS: u32 = 55;
pub fn risk_bucket_146_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_146_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_146_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_146_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_146_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_147_MAX_NOTIONAL: u128 = 147u128 * 1_000_000_000;
pub const RISK_BUCKET_147_OPTION_WEIGHT_BPS: u32 = 1400;
pub const RISK_BUCKET_147_PERP_WEIGHT_BPS: u32 = 1130;
pub const RISK_BUCKET_147_BRIDGE_WEIGHT_BPS: u32 = 60;
pub fn risk_bucket_147_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_147_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_147_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_147_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_147_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_148_MAX_NOTIONAL: u128 = 148u128 * 1_000_000_000;
pub const RISK_BUCKET_148_OPTION_WEIGHT_BPS: u32 = 500;
pub const RISK_BUCKET_148_PERP_WEIGHT_BPS: u32 = 1150;
pub const RISK_BUCKET_148_BRIDGE_WEIGHT_BPS: u32 = 65;
pub fn risk_bucket_148_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_148_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_148_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_148_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_148_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_149_MAX_NOTIONAL: u128 = 149u128 * 1_000_000_000;
pub const RISK_BUCKET_149_OPTION_WEIGHT_BPS: u32 = 525;
pub const RISK_BUCKET_149_PERP_WEIGHT_BPS: u32 = 1170;
pub const RISK_BUCKET_149_BRIDGE_WEIGHT_BPS: u32 = 70;
pub fn risk_bucket_149_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_149_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_149_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_149_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_149_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_150_MAX_NOTIONAL: u128 = 150u128 * 1_000_000_000;
pub const RISK_BUCKET_150_OPTION_WEIGHT_BPS: u32 = 550;
pub const RISK_BUCKET_150_PERP_WEIGHT_BPS: u32 = 1190;
pub const RISK_BUCKET_150_BRIDGE_WEIGHT_BPS: u32 = 75;
pub fn risk_bucket_150_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_150_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_150_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_150_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_150_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_151_MAX_NOTIONAL: u128 = 151u128 * 1_000_000_000;
pub const RISK_BUCKET_151_OPTION_WEIGHT_BPS: u32 = 575;
pub const RISK_BUCKET_151_PERP_WEIGHT_BPS: u32 = 1210;
pub const RISK_BUCKET_151_BRIDGE_WEIGHT_BPS: u32 = 80;
pub fn risk_bucket_151_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_151_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_151_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_151_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_151_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_152_MAX_NOTIONAL: u128 = 152u128 * 1_000_000_000;
pub const RISK_BUCKET_152_OPTION_WEIGHT_BPS: u32 = 600;
pub const RISK_BUCKET_152_PERP_WEIGHT_BPS: u32 = 1230;
pub const RISK_BUCKET_152_BRIDGE_WEIGHT_BPS: u32 = 85;
pub fn risk_bucket_152_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_152_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_152_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_152_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_152_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_153_MAX_NOTIONAL: u128 = 153u128 * 1_000_000_000;
pub const RISK_BUCKET_153_OPTION_WEIGHT_BPS: u32 = 625;
pub const RISK_BUCKET_153_PERP_WEIGHT_BPS: u32 = 1250;
pub const RISK_BUCKET_153_BRIDGE_WEIGHT_BPS: u32 = 90;
pub fn risk_bucket_153_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_153_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_153_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_153_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_153_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_154_MAX_NOTIONAL: u128 = 154u128 * 1_000_000_000;
pub const RISK_BUCKET_154_OPTION_WEIGHT_BPS: u32 = 650;
pub const RISK_BUCKET_154_PERP_WEIGHT_BPS: u32 = 1270;
pub const RISK_BUCKET_154_BRIDGE_WEIGHT_BPS: u32 = 95;
pub fn risk_bucket_154_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_154_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_154_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_154_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_154_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_155_MAX_NOTIONAL: u128 = 155u128 * 1_000_000_000;
pub const RISK_BUCKET_155_OPTION_WEIGHT_BPS: u32 = 675;
pub const RISK_BUCKET_155_PERP_WEIGHT_BPS: u32 = 1290;
pub const RISK_BUCKET_155_BRIDGE_WEIGHT_BPS: u32 = 100;
pub fn risk_bucket_155_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_155_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_155_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_155_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_155_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_156_MAX_NOTIONAL: u128 = 156u128 * 1_000_000_000;
pub const RISK_BUCKET_156_OPTION_WEIGHT_BPS: u32 = 700;
pub const RISK_BUCKET_156_PERP_WEIGHT_BPS: u32 = 1310;
pub const RISK_BUCKET_156_BRIDGE_WEIGHT_BPS: u32 = 105;
pub fn risk_bucket_156_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_156_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_156_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_156_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_156_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_157_MAX_NOTIONAL: u128 = 157u128 * 1_000_000_000;
pub const RISK_BUCKET_157_OPTION_WEIGHT_BPS: u32 = 725;
pub const RISK_BUCKET_157_PERP_WEIGHT_BPS: u32 = 1330;
pub const RISK_BUCKET_157_BRIDGE_WEIGHT_BPS: u32 = 110;
pub fn risk_bucket_157_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_157_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_157_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_157_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_157_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_158_MAX_NOTIONAL: u128 = 158u128 * 1_000_000_000;
pub const RISK_BUCKET_158_OPTION_WEIGHT_BPS: u32 = 750;
pub const RISK_BUCKET_158_PERP_WEIGHT_BPS: u32 = 1350;
pub const RISK_BUCKET_158_BRIDGE_WEIGHT_BPS: u32 = 115;
pub fn risk_bucket_158_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_158_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_158_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_158_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_158_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_159_MAX_NOTIONAL: u128 = 159u128 * 1_000_000_000;
pub const RISK_BUCKET_159_OPTION_WEIGHT_BPS: u32 = 775;
pub const RISK_BUCKET_159_PERP_WEIGHT_BPS: u32 = 1370;
pub const RISK_BUCKET_159_BRIDGE_WEIGHT_BPS: u32 = 120;
pub fn risk_bucket_159_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_159_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_159_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_159_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_159_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_160_MAX_NOTIONAL: u128 = 160u128 * 1_000_000_000;
pub const RISK_BUCKET_160_OPTION_WEIGHT_BPS: u32 = 800;
pub const RISK_BUCKET_160_PERP_WEIGHT_BPS: u32 = 1390;
pub const RISK_BUCKET_160_BRIDGE_WEIGHT_BPS: u32 = 125;
pub fn risk_bucket_160_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_160_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_160_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_160_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_160_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_161_MAX_NOTIONAL: u128 = 161u128 * 1_000_000_000;
pub const RISK_BUCKET_161_OPTION_WEIGHT_BPS: u32 = 825;
pub const RISK_BUCKET_161_PERP_WEIGHT_BPS: u32 = 1410;
pub const RISK_BUCKET_161_BRIDGE_WEIGHT_BPS: u32 = 130;
pub fn risk_bucket_161_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_161_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_161_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_161_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_161_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_162_MAX_NOTIONAL: u128 = 162u128 * 1_000_000_000;
pub const RISK_BUCKET_162_OPTION_WEIGHT_BPS: u32 = 850;
pub const RISK_BUCKET_162_PERP_WEIGHT_BPS: u32 = 1430;
pub const RISK_BUCKET_162_BRIDGE_WEIGHT_BPS: u32 = 135;
pub fn risk_bucket_162_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_162_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_162_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_162_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_162_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_163_MAX_NOTIONAL: u128 = 163u128 * 1_000_000_000;
pub const RISK_BUCKET_163_OPTION_WEIGHT_BPS: u32 = 875;
pub const RISK_BUCKET_163_PERP_WEIGHT_BPS: u32 = 1450;
pub const RISK_BUCKET_163_BRIDGE_WEIGHT_BPS: u32 = 140;
pub fn risk_bucket_163_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_163_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_163_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_163_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_163_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_164_MAX_NOTIONAL: u128 = 164u128 * 1_000_000_000;
pub const RISK_BUCKET_164_OPTION_WEIGHT_BPS: u32 = 900;
pub const RISK_BUCKET_164_PERP_WEIGHT_BPS: u32 = 650;
pub const RISK_BUCKET_164_BRIDGE_WEIGHT_BPS: u32 = 145;
pub fn risk_bucket_164_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_164_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_164_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_164_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_164_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_165_MAX_NOTIONAL: u128 = 165u128 * 1_000_000_000;
pub const RISK_BUCKET_165_OPTION_WEIGHT_BPS: u32 = 925;
pub const RISK_BUCKET_165_PERP_WEIGHT_BPS: u32 = 670;
pub const RISK_BUCKET_165_BRIDGE_WEIGHT_BPS: u32 = 150;
pub fn risk_bucket_165_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_165_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_165_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_165_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_165_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_166_MAX_NOTIONAL: u128 = 166u128 * 1_000_000_000;
pub const RISK_BUCKET_166_OPTION_WEIGHT_BPS: u32 = 950;
pub const RISK_BUCKET_166_PERP_WEIGHT_BPS: u32 = 690;
pub const RISK_BUCKET_166_BRIDGE_WEIGHT_BPS: u32 = 155;
pub fn risk_bucket_166_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_166_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_166_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_166_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_166_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_167_MAX_NOTIONAL: u128 = 167u128 * 1_000_000_000;
pub const RISK_BUCKET_167_OPTION_WEIGHT_BPS: u32 = 975;
pub const RISK_BUCKET_167_PERP_WEIGHT_BPS: u32 = 710;
pub const RISK_BUCKET_167_BRIDGE_WEIGHT_BPS: u32 = 160;
pub fn risk_bucket_167_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_167_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_167_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_167_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_167_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_168_MAX_NOTIONAL: u128 = 168u128 * 1_000_000_000;
pub const RISK_BUCKET_168_OPTION_WEIGHT_BPS: u32 = 1000;
pub const RISK_BUCKET_168_PERP_WEIGHT_BPS: u32 = 730;
pub const RISK_BUCKET_168_BRIDGE_WEIGHT_BPS: u32 = 165;
pub fn risk_bucket_168_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_168_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_168_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_168_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_168_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_169_MAX_NOTIONAL: u128 = 169u128 * 1_000_000_000;
pub const RISK_BUCKET_169_OPTION_WEIGHT_BPS: u32 = 1025;
pub const RISK_BUCKET_169_PERP_WEIGHT_BPS: u32 = 750;
pub const RISK_BUCKET_169_BRIDGE_WEIGHT_BPS: u32 = 170;
pub fn risk_bucket_169_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_169_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_169_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_169_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_169_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_170_MAX_NOTIONAL: u128 = 170u128 * 1_000_000_000;
pub const RISK_BUCKET_170_OPTION_WEIGHT_BPS: u32 = 1050;
pub const RISK_BUCKET_170_PERP_WEIGHT_BPS: u32 = 770;
pub const RISK_BUCKET_170_BRIDGE_WEIGHT_BPS: u32 = 175;
pub fn risk_bucket_170_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_170_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_170_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_170_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_170_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_171_MAX_NOTIONAL: u128 = 171u128 * 1_000_000_000;
pub const RISK_BUCKET_171_OPTION_WEIGHT_BPS: u32 = 1075;
pub const RISK_BUCKET_171_PERP_WEIGHT_BPS: u32 = 790;
pub const RISK_BUCKET_171_BRIDGE_WEIGHT_BPS: u32 = 180;
pub fn risk_bucket_171_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_171_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_171_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_171_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_171_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_172_MAX_NOTIONAL: u128 = 172u128 * 1_000_000_000;
pub const RISK_BUCKET_172_OPTION_WEIGHT_BPS: u32 = 1100;
pub const RISK_BUCKET_172_PERP_WEIGHT_BPS: u32 = 810;
pub const RISK_BUCKET_172_BRIDGE_WEIGHT_BPS: u32 = 185;
pub fn risk_bucket_172_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_172_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_172_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_172_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_172_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_173_MAX_NOTIONAL: u128 = 173u128 * 1_000_000_000;
pub const RISK_BUCKET_173_OPTION_WEIGHT_BPS: u32 = 1125;
pub const RISK_BUCKET_173_PERP_WEIGHT_BPS: u32 = 830;
pub const RISK_BUCKET_173_BRIDGE_WEIGHT_BPS: u32 = 190;
pub fn risk_bucket_173_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_173_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_173_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_173_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_173_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_174_MAX_NOTIONAL: u128 = 174u128 * 1_000_000_000;
pub const RISK_BUCKET_174_OPTION_WEIGHT_BPS: u32 = 1150;
pub const RISK_BUCKET_174_PERP_WEIGHT_BPS: u32 = 850;
pub const RISK_BUCKET_174_BRIDGE_WEIGHT_BPS: u32 = 50;
pub fn risk_bucket_174_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_174_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_174_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_174_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_174_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_175_MAX_NOTIONAL: u128 = 175u128 * 1_000_000_000;
pub const RISK_BUCKET_175_OPTION_WEIGHT_BPS: u32 = 1175;
pub const RISK_BUCKET_175_PERP_WEIGHT_BPS: u32 = 870;
pub const RISK_BUCKET_175_BRIDGE_WEIGHT_BPS: u32 = 55;
pub fn risk_bucket_175_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_175_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_175_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_175_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_175_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_176_MAX_NOTIONAL: u128 = 176u128 * 1_000_000_000;
pub const RISK_BUCKET_176_OPTION_WEIGHT_BPS: u32 = 1200;
pub const RISK_BUCKET_176_PERP_WEIGHT_BPS: u32 = 890;
pub const RISK_BUCKET_176_BRIDGE_WEIGHT_BPS: u32 = 60;
pub fn risk_bucket_176_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_176_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_176_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_176_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_176_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_177_MAX_NOTIONAL: u128 = 177u128 * 1_000_000_000;
pub const RISK_BUCKET_177_OPTION_WEIGHT_BPS: u32 = 1225;
pub const RISK_BUCKET_177_PERP_WEIGHT_BPS: u32 = 910;
pub const RISK_BUCKET_177_BRIDGE_WEIGHT_BPS: u32 = 65;
pub fn risk_bucket_177_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_177_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_177_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_177_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_177_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_178_MAX_NOTIONAL: u128 = 178u128 * 1_000_000_000;
pub const RISK_BUCKET_178_OPTION_WEIGHT_BPS: u32 = 1250;
pub const RISK_BUCKET_178_PERP_WEIGHT_BPS: u32 = 930;
pub const RISK_BUCKET_178_BRIDGE_WEIGHT_BPS: u32 = 70;
pub fn risk_bucket_178_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_178_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_178_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_178_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_178_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_179_MAX_NOTIONAL: u128 = 179u128 * 1_000_000_000;
pub const RISK_BUCKET_179_OPTION_WEIGHT_BPS: u32 = 1275;
pub const RISK_BUCKET_179_PERP_WEIGHT_BPS: u32 = 950;
pub const RISK_BUCKET_179_BRIDGE_WEIGHT_BPS: u32 = 75;
pub fn risk_bucket_179_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_179_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_179_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_179_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_179_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_180_MAX_NOTIONAL: u128 = 180u128 * 1_000_000_000;
pub const RISK_BUCKET_180_OPTION_WEIGHT_BPS: u32 = 1300;
pub const RISK_BUCKET_180_PERP_WEIGHT_BPS: u32 = 970;
pub const RISK_BUCKET_180_BRIDGE_WEIGHT_BPS: u32 = 80;
pub fn risk_bucket_180_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_180_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_180_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_180_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_180_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_181_MAX_NOTIONAL: u128 = 181u128 * 1_000_000_000;
pub const RISK_BUCKET_181_OPTION_WEIGHT_BPS: u32 = 1325;
pub const RISK_BUCKET_181_PERP_WEIGHT_BPS: u32 = 990;
pub const RISK_BUCKET_181_BRIDGE_WEIGHT_BPS: u32 = 85;
pub fn risk_bucket_181_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_181_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_181_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_181_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_181_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_182_MAX_NOTIONAL: u128 = 182u128 * 1_000_000_000;
pub const RISK_BUCKET_182_OPTION_WEIGHT_BPS: u32 = 1350;
pub const RISK_BUCKET_182_PERP_WEIGHT_BPS: u32 = 1010;
pub const RISK_BUCKET_182_BRIDGE_WEIGHT_BPS: u32 = 90;
pub fn risk_bucket_182_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_182_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_182_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_182_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_182_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_183_MAX_NOTIONAL: u128 = 183u128 * 1_000_000_000;
pub const RISK_BUCKET_183_OPTION_WEIGHT_BPS: u32 = 1375;
pub const RISK_BUCKET_183_PERP_WEIGHT_BPS: u32 = 1030;
pub const RISK_BUCKET_183_BRIDGE_WEIGHT_BPS: u32 = 95;
pub fn risk_bucket_183_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_183_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_183_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_183_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_183_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_184_MAX_NOTIONAL: u128 = 184u128 * 1_000_000_000;
pub const RISK_BUCKET_184_OPTION_WEIGHT_BPS: u32 = 1400;
pub const RISK_BUCKET_184_PERP_WEIGHT_BPS: u32 = 1050;
pub const RISK_BUCKET_184_BRIDGE_WEIGHT_BPS: u32 = 100;
pub fn risk_bucket_184_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_184_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_184_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_184_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_184_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_185_MAX_NOTIONAL: u128 = 185u128 * 1_000_000_000;
pub const RISK_BUCKET_185_OPTION_WEIGHT_BPS: u32 = 500;
pub const RISK_BUCKET_185_PERP_WEIGHT_BPS: u32 = 1070;
pub const RISK_BUCKET_185_BRIDGE_WEIGHT_BPS: u32 = 105;
pub fn risk_bucket_185_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_185_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_185_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_185_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_185_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_186_MAX_NOTIONAL: u128 = 186u128 * 1_000_000_000;
pub const RISK_BUCKET_186_OPTION_WEIGHT_BPS: u32 = 525;
pub const RISK_BUCKET_186_PERP_WEIGHT_BPS: u32 = 1090;
pub const RISK_BUCKET_186_BRIDGE_WEIGHT_BPS: u32 = 110;
pub fn risk_bucket_186_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_186_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_186_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_186_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_186_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_187_MAX_NOTIONAL: u128 = 187u128 * 1_000_000_000;
pub const RISK_BUCKET_187_OPTION_WEIGHT_BPS: u32 = 550;
pub const RISK_BUCKET_187_PERP_WEIGHT_BPS: u32 = 1110;
pub const RISK_BUCKET_187_BRIDGE_WEIGHT_BPS: u32 = 115;
pub fn risk_bucket_187_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_187_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_187_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_187_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_187_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_188_MAX_NOTIONAL: u128 = 188u128 * 1_000_000_000;
pub const RISK_BUCKET_188_OPTION_WEIGHT_BPS: u32 = 575;
pub const RISK_BUCKET_188_PERP_WEIGHT_BPS: u32 = 1130;
pub const RISK_BUCKET_188_BRIDGE_WEIGHT_BPS: u32 = 120;
pub fn risk_bucket_188_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_188_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_188_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_188_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_188_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_189_MAX_NOTIONAL: u128 = 189u128 * 1_000_000_000;
pub const RISK_BUCKET_189_OPTION_WEIGHT_BPS: u32 = 600;
pub const RISK_BUCKET_189_PERP_WEIGHT_BPS: u32 = 1150;
pub const RISK_BUCKET_189_BRIDGE_WEIGHT_BPS: u32 = 125;
pub fn risk_bucket_189_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_189_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_189_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_189_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_189_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_190_MAX_NOTIONAL: u128 = 190u128 * 1_000_000_000;
pub const RISK_BUCKET_190_OPTION_WEIGHT_BPS: u32 = 625;
pub const RISK_BUCKET_190_PERP_WEIGHT_BPS: u32 = 1170;
pub const RISK_BUCKET_190_BRIDGE_WEIGHT_BPS: u32 = 130;
pub fn risk_bucket_190_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_190_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_190_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_190_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_190_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_191_MAX_NOTIONAL: u128 = 191u128 * 1_000_000_000;
pub const RISK_BUCKET_191_OPTION_WEIGHT_BPS: u32 = 650;
pub const RISK_BUCKET_191_PERP_WEIGHT_BPS: u32 = 1190;
pub const RISK_BUCKET_191_BRIDGE_WEIGHT_BPS: u32 = 135;
pub fn risk_bucket_191_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_191_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_191_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_191_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_191_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_192_MAX_NOTIONAL: u128 = 192u128 * 1_000_000_000;
pub const RISK_BUCKET_192_OPTION_WEIGHT_BPS: u32 = 675;
pub const RISK_BUCKET_192_PERP_WEIGHT_BPS: u32 = 1210;
pub const RISK_BUCKET_192_BRIDGE_WEIGHT_BPS: u32 = 140;
pub fn risk_bucket_192_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_192_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_192_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_192_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_192_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_193_MAX_NOTIONAL: u128 = 193u128 * 1_000_000_000;
pub const RISK_BUCKET_193_OPTION_WEIGHT_BPS: u32 = 700;
pub const RISK_BUCKET_193_PERP_WEIGHT_BPS: u32 = 1230;
pub const RISK_BUCKET_193_BRIDGE_WEIGHT_BPS: u32 = 145;
pub fn risk_bucket_193_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_193_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_193_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_193_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_193_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_194_MAX_NOTIONAL: u128 = 194u128 * 1_000_000_000;
pub const RISK_BUCKET_194_OPTION_WEIGHT_BPS: u32 = 725;
pub const RISK_BUCKET_194_PERP_WEIGHT_BPS: u32 = 1250;
pub const RISK_BUCKET_194_BRIDGE_WEIGHT_BPS: u32 = 150;
pub fn risk_bucket_194_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_194_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_194_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_194_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_194_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_195_MAX_NOTIONAL: u128 = 195u128 * 1_000_000_000;
pub const RISK_BUCKET_195_OPTION_WEIGHT_BPS: u32 = 750;
pub const RISK_BUCKET_195_PERP_WEIGHT_BPS: u32 = 1270;
pub const RISK_BUCKET_195_BRIDGE_WEIGHT_BPS: u32 = 155;
pub fn risk_bucket_195_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_195_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_195_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_195_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_195_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_196_MAX_NOTIONAL: u128 = 196u128 * 1_000_000_000;
pub const RISK_BUCKET_196_OPTION_WEIGHT_BPS: u32 = 775;
pub const RISK_BUCKET_196_PERP_WEIGHT_BPS: u32 = 1290;
pub const RISK_BUCKET_196_BRIDGE_WEIGHT_BPS: u32 = 160;
pub fn risk_bucket_196_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_196_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_196_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_196_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_196_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_197_MAX_NOTIONAL: u128 = 197u128 * 1_000_000_000;
pub const RISK_BUCKET_197_OPTION_WEIGHT_BPS: u32 = 800;
pub const RISK_BUCKET_197_PERP_WEIGHT_BPS: u32 = 1310;
pub const RISK_BUCKET_197_BRIDGE_WEIGHT_BPS: u32 = 165;
pub fn risk_bucket_197_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_197_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_197_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_197_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_197_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_198_MAX_NOTIONAL: u128 = 198u128 * 1_000_000_000;
pub const RISK_BUCKET_198_OPTION_WEIGHT_BPS: u32 = 825;
pub const RISK_BUCKET_198_PERP_WEIGHT_BPS: u32 = 1330;
pub const RISK_BUCKET_198_BRIDGE_WEIGHT_BPS: u32 = 170;
pub fn risk_bucket_198_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_198_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_198_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_198_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_198_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_199_MAX_NOTIONAL: u128 = 199u128 * 1_000_000_000;
pub const RISK_BUCKET_199_OPTION_WEIGHT_BPS: u32 = 850;
pub const RISK_BUCKET_199_PERP_WEIGHT_BPS: u32 = 1350;
pub const RISK_BUCKET_199_BRIDGE_WEIGHT_BPS: u32 = 175;
pub fn risk_bucket_199_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_199_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_199_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_199_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_199_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_200_MAX_NOTIONAL: u128 = 200u128 * 1_000_000_000;
pub const RISK_BUCKET_200_OPTION_WEIGHT_BPS: u32 = 875;
pub const RISK_BUCKET_200_PERP_WEIGHT_BPS: u32 = 1370;
pub const RISK_BUCKET_200_BRIDGE_WEIGHT_BPS: u32 = 180;
pub fn risk_bucket_200_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_200_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_200_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_200_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_200_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_201_MAX_NOTIONAL: u128 = 201u128 * 1_000_000_000;
pub const RISK_BUCKET_201_OPTION_WEIGHT_BPS: u32 = 900;
pub const RISK_BUCKET_201_PERP_WEIGHT_BPS: u32 = 1390;
pub const RISK_BUCKET_201_BRIDGE_WEIGHT_BPS: u32 = 185;
pub fn risk_bucket_201_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_201_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_201_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_201_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_201_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_202_MAX_NOTIONAL: u128 = 202u128 * 1_000_000_000;
pub const RISK_BUCKET_202_OPTION_WEIGHT_BPS: u32 = 925;
pub const RISK_BUCKET_202_PERP_WEIGHT_BPS: u32 = 1410;
pub const RISK_BUCKET_202_BRIDGE_WEIGHT_BPS: u32 = 190;
pub fn risk_bucket_202_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_202_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_202_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_202_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_202_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_203_MAX_NOTIONAL: u128 = 203u128 * 1_000_000_000;
pub const RISK_BUCKET_203_OPTION_WEIGHT_BPS: u32 = 950;
pub const RISK_BUCKET_203_PERP_WEIGHT_BPS: u32 = 1430;
pub const RISK_BUCKET_203_BRIDGE_WEIGHT_BPS: u32 = 50;
pub fn risk_bucket_203_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_203_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_203_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_203_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_203_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_204_MAX_NOTIONAL: u128 = 204u128 * 1_000_000_000;
pub const RISK_BUCKET_204_OPTION_WEIGHT_BPS: u32 = 975;
pub const RISK_BUCKET_204_PERP_WEIGHT_BPS: u32 = 1450;
pub const RISK_BUCKET_204_BRIDGE_WEIGHT_BPS: u32 = 55;
pub fn risk_bucket_204_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_204_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_204_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_204_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_204_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub const RISK_BUCKET_205_MAX_NOTIONAL: u128 = 205u128 * 1_000_000_000;
pub const RISK_BUCKET_205_OPTION_WEIGHT_BPS: u32 = 1000;
pub const RISK_BUCKET_205_PERP_WEIGHT_BPS: u32 = 650;
pub const RISK_BUCKET_205_BRIDGE_WEIGHT_BPS: u32 = 60;
pub fn risk_bucket_205_margin(notional: u128) -> u128 {
    let capped = min_u128(notional, RISK_BUCKET_205_MAX_NOTIONAL);
    let option_component = mul_bps(capped, RISK_BUCKET_205_OPTION_WEIGHT_BPS);
    let perp_component = mul_bps(capped, RISK_BUCKET_205_PERP_WEIGHT_BPS);
    let bridge_component = mul_bps(capped, RISK_BUCKET_205_BRIDGE_WEIGHT_BPS);
    option_component
        .saturating_add(perp_component)
        .saturating_add(bridge_component)
}

pub fn settlement_lane_001_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_001", account, &amount.to_string(), asset])
}
pub fn auction_lane_001_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_001",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_002_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_002", account, &amount.to_string(), asset])
}
pub fn auction_lane_002_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_002",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_003_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_003", account, &amount.to_string(), asset])
}
pub fn auction_lane_003_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_003",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_004_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_004", account, &amount.to_string(), asset])
}
pub fn auction_lane_004_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_004",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_005_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_005", account, &amount.to_string(), asset])
}
pub fn auction_lane_005_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_005",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_006_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_006", account, &amount.to_string(), asset])
}
pub fn auction_lane_006_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_006",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_007_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_007", account, &amount.to_string(), asset])
}
pub fn auction_lane_007_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_007",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_008_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_008", account, &amount.to_string(), asset])
}
pub fn auction_lane_008_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_008",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_009_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_009", account, &amount.to_string(), asset])
}
pub fn auction_lane_009_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_009",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_010_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_010", account, &amount.to_string(), asset])
}
pub fn auction_lane_010_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_010",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_011_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_011", account, &amount.to_string(), asset])
}
pub fn auction_lane_011_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_011",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_012_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_012", account, &amount.to_string(), asset])
}
pub fn auction_lane_012_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_012",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_013_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_013", account, &amount.to_string(), asset])
}
pub fn auction_lane_013_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_013",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_014_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_014", account, &amount.to_string(), asset])
}
pub fn auction_lane_014_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_014",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_015_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_015", account, &amount.to_string(), asset])
}
pub fn auction_lane_015_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_015",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_016_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_016", account, &amount.to_string(), asset])
}
pub fn auction_lane_016_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_016",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_017_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_017", account, &amount.to_string(), asset])
}
pub fn auction_lane_017_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_017",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_018_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_018", account, &amount.to_string(), asset])
}
pub fn auction_lane_018_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_018",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_019_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_019", account, &amount.to_string(), asset])
}
pub fn auction_lane_019_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_019",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_020_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_020", account, &amount.to_string(), asset])
}
pub fn auction_lane_020_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_020",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_021_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_021", account, &amount.to_string(), asset])
}
pub fn auction_lane_021_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_021",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_022_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_022", account, &amount.to_string(), asset])
}
pub fn auction_lane_022_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_022",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_023_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_023", account, &amount.to_string(), asset])
}
pub fn auction_lane_023_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_023",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_024_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_024", account, &amount.to_string(), asset])
}
pub fn auction_lane_024_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_024",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_025_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_025", account, &amount.to_string(), asset])
}
pub fn auction_lane_025_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_025",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_026_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_026", account, &amount.to_string(), asset])
}
pub fn auction_lane_026_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_026",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_027_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_027", account, &amount.to_string(), asset])
}
pub fn auction_lane_027_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_027",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_028_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_028", account, &amount.to_string(), asset])
}
pub fn auction_lane_028_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_028",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_029_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_029", account, &amount.to_string(), asset])
}
pub fn auction_lane_029_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_029",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_030_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_030", account, &amount.to_string(), asset])
}
pub fn auction_lane_030_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_030",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_031_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_031", account, &amount.to_string(), asset])
}
pub fn auction_lane_031_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_031",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_032_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_032", account, &amount.to_string(), asset])
}
pub fn auction_lane_032_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_032",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_033_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_033", account, &amount.to_string(), asset])
}
pub fn auction_lane_033_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_033",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_034_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_034", account, &amount.to_string(), asset])
}
pub fn auction_lane_034_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_034",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_035_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_035", account, &amount.to_string(), asset])
}
pub fn auction_lane_035_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_035",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_036_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_036", account, &amount.to_string(), asset])
}
pub fn auction_lane_036_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_036",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_037_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_037", account, &amount.to_string(), asset])
}
pub fn auction_lane_037_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_037",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_038_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_038", account, &amount.to_string(), asset])
}
pub fn auction_lane_038_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_038",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_039_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_039", account, &amount.to_string(), asset])
}
pub fn auction_lane_039_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_039",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_040_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_040", account, &amount.to_string(), asset])
}
pub fn auction_lane_040_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_040",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_041_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_041", account, &amount.to_string(), asset])
}
pub fn auction_lane_041_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_041",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_042_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_042", account, &amount.to_string(), asset])
}
pub fn auction_lane_042_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_042",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_043_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_043", account, &amount.to_string(), asset])
}
pub fn auction_lane_043_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_043",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_044_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_044", account, &amount.to_string(), asset])
}
pub fn auction_lane_044_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_044",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_045_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_045", account, &amount.to_string(), asset])
}
pub fn auction_lane_045_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_045",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_046_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_046", account, &amount.to_string(), asset])
}
pub fn auction_lane_046_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_046",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_047_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_047", account, &amount.to_string(), asset])
}
pub fn auction_lane_047_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_047",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_048_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_048", account, &amount.to_string(), asset])
}
pub fn auction_lane_048_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_048",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_049_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_049", account, &amount.to_string(), asset])
}
pub fn auction_lane_049_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_049",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_050_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_050", account, &amount.to_string(), asset])
}
pub fn auction_lane_050_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_050",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_051_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_051", account, &amount.to_string(), asset])
}
pub fn auction_lane_051_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_051",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_052_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_052", account, &amount.to_string(), asset])
}
pub fn auction_lane_052_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_052",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_053_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_053", account, &amount.to_string(), asset])
}
pub fn auction_lane_053_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_053",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_054_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_054", account, &amount.to_string(), asset])
}
pub fn auction_lane_054_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_054",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_055_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_055", account, &amount.to_string(), asset])
}
pub fn auction_lane_055_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_055",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_056_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_056", account, &amount.to_string(), asset])
}
pub fn auction_lane_056_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_056",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_057_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_057", account, &amount.to_string(), asset])
}
pub fn auction_lane_057_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_057",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_058_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_058", account, &amount.to_string(), asset])
}
pub fn auction_lane_058_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_058",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_059_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_059", account, &amount.to_string(), asset])
}
pub fn auction_lane_059_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_059",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_060_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_060", account, &amount.to_string(), asset])
}
pub fn auction_lane_060_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_060",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_061_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_061", account, &amount.to_string(), asset])
}
pub fn auction_lane_061_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_061",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_062_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_062", account, &amount.to_string(), asset])
}
pub fn auction_lane_062_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_062",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_063_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_063", account, &amount.to_string(), asset])
}
pub fn auction_lane_063_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_063",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_064_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_064", account, &amount.to_string(), asset])
}
pub fn auction_lane_064_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_064",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_065_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_065", account, &amount.to_string(), asset])
}
pub fn auction_lane_065_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_065",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_066_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_066", account, &amount.to_string(), asset])
}
pub fn auction_lane_066_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_066",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_067_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_067", account, &amount.to_string(), asset])
}
pub fn auction_lane_067_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_067",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_068_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_068", account, &amount.to_string(), asset])
}
pub fn auction_lane_068_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_068",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_069_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_069", account, &amount.to_string(), asset])
}
pub fn auction_lane_069_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_069",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_070_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_070", account, &amount.to_string(), asset])
}
pub fn auction_lane_070_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_070",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_071_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_071", account, &amount.to_string(), asset])
}
pub fn auction_lane_071_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_071",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_072_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_072", account, &amount.to_string(), asset])
}
pub fn auction_lane_072_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_072",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_073_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_073", account, &amount.to_string(), asset])
}
pub fn auction_lane_073_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_073",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_074_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_074", account, &amount.to_string(), asset])
}
pub fn auction_lane_074_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_074",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_075_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_075", account, &amount.to_string(), asset])
}
pub fn auction_lane_075_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_075",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_076_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_076", account, &amount.to_string(), asset])
}
pub fn auction_lane_076_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_076",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_077_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_077", account, &amount.to_string(), asset])
}
pub fn auction_lane_077_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_077",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_078_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_078", account, &amount.to_string(), asset])
}
pub fn auction_lane_078_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_078",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_079_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_079", account, &amount.to_string(), asset])
}
pub fn auction_lane_079_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_079",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_080_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_080", account, &amount.to_string(), asset])
}
pub fn auction_lane_080_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_080",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_081_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_081", account, &amount.to_string(), asset])
}
pub fn auction_lane_081_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_081",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_082_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_082", account, &amount.to_string(), asset])
}
pub fn auction_lane_082_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_082",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_083_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_083", account, &amount.to_string(), asset])
}
pub fn auction_lane_083_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_083",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_084_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_084", account, &amount.to_string(), asset])
}
pub fn auction_lane_084_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_084",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_085_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_085", account, &amount.to_string(), asset])
}
pub fn auction_lane_085_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_085",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_086_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_086", account, &amount.to_string(), asset])
}
pub fn auction_lane_086_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_086",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_087_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_087", account, &amount.to_string(), asset])
}
pub fn auction_lane_087_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_087",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_088_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_088", account, &amount.to_string(), asset])
}
pub fn auction_lane_088_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_088",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_089_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_089", account, &amount.to_string(), asset])
}
pub fn auction_lane_089_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_089",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_090_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_090", account, &amount.to_string(), asset])
}
pub fn auction_lane_090_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_090",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_091_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_091", account, &amount.to_string(), asset])
}
pub fn auction_lane_091_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_091",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_092_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_092", account, &amount.to_string(), asset])
}
pub fn auction_lane_092_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_092",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_093_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_093", account, &amount.to_string(), asset])
}
pub fn auction_lane_093_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_093",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_094_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_094", account, &amount.to_string(), asset])
}
pub fn auction_lane_094_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_094",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_095_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_095", account, &amount.to_string(), asset])
}
pub fn auction_lane_095_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_095",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_096_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_096", account, &amount.to_string(), asset])
}
pub fn auction_lane_096_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_096",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_097_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_097", account, &amount.to_string(), asset])
}
pub fn auction_lane_097_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_097",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_098_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_098", account, &amount.to_string(), asset])
}
pub fn auction_lane_098_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_098",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_099_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_099", account, &amount.to_string(), asset])
}
pub fn auction_lane_099_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_099",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_100_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_100", account, &amount.to_string(), asset])
}
pub fn auction_lane_100_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_100",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_101_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_101", account, &amount.to_string(), asset])
}
pub fn auction_lane_101_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_101",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_102_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_102", account, &amount.to_string(), asset])
}
pub fn auction_lane_102_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_102",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_103_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_103", account, &amount.to_string(), asset])
}
pub fn auction_lane_103_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_103",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_104_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_104", account, &amount.to_string(), asset])
}
pub fn auction_lane_104_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_104",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn settlement_lane_105_root(account: &str, amount: i128, asset: &str) -> String {
    deterministic_root(&["settlement_lane_105", account, &amount.to_string(), asset])
}
pub fn auction_lane_105_root(account: &str, sealed_bid_root: &str, debt: u128) -> String {
    deterministic_root(&[
        "auction_lane_105",
        account,
        sealed_bid_root,
        &debt.to_string(),
    ])
}

pub fn oracle_band_001_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 260
}

pub fn oracle_band_002_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 270
}

pub fn oracle_band_003_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 280
}

pub fn oracle_band_004_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 290
}

pub fn oracle_band_005_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 300
}

pub fn oracle_band_006_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 310
}

pub fn oracle_band_007_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 320
}

pub fn oracle_band_008_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 330
}

pub fn oracle_band_009_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 340
}

pub fn oracle_band_010_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 350
}

pub fn oracle_band_011_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 360
}

pub fn oracle_band_012_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 370
}

pub fn oracle_band_013_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 380
}

pub fn oracle_band_014_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 390
}

pub fn oracle_band_015_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 400
}

pub fn oracle_band_016_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 410
}

pub fn oracle_band_017_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 420
}

pub fn oracle_band_018_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 430
}

pub fn oracle_band_019_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 440
}

pub fn oracle_band_020_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 450
}

pub fn oracle_band_021_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 460
}

pub fn oracle_band_022_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 470
}

pub fn oracle_band_023_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 480
}

pub fn oracle_band_024_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 490
}

pub fn oracle_band_025_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 500
}

pub fn oracle_band_026_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 510
}

pub fn oracle_band_027_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 520
}

pub fn oracle_band_028_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 530
}

pub fn oracle_band_029_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 540
}

pub fn oracle_band_030_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 550
}

pub fn oracle_band_031_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 560
}

pub fn oracle_band_032_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 570
}

pub fn oracle_band_033_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 580
}

pub fn oracle_band_034_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 590
}

pub fn oracle_band_035_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 600
}

pub fn oracle_band_036_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 610
}

pub fn oracle_band_037_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 620
}

pub fn oracle_band_038_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 630
}

pub fn oracle_band_039_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 640
}

pub fn oracle_band_040_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 650
}

pub fn oracle_band_041_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 660
}

pub fn oracle_band_042_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 670
}

pub fn oracle_band_043_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 680
}

pub fn oracle_band_044_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 690
}

pub fn oracle_band_045_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 700
}

pub fn oracle_band_046_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 710
}

pub fn oracle_band_047_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 720
}

pub fn oracle_band_048_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 730
}

pub fn oracle_band_049_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 740
}

pub fn oracle_band_050_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 750
}

pub fn oracle_band_051_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 760
}

pub fn oracle_band_052_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 770
}

pub fn oracle_band_053_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 780
}

pub fn oracle_band_054_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 790
}

pub fn oracle_band_055_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 800
}

pub fn oracle_band_056_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 810
}

pub fn oracle_band_057_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 820
}

pub fn oracle_band_058_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 830
}

pub fn oracle_band_059_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 840
}

pub fn oracle_band_060_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 850
}

pub fn oracle_band_061_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 860
}

pub fn oracle_band_062_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 870
}

pub fn oracle_band_063_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 880
}

pub fn oracle_band_064_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 890
}

pub fn oracle_band_065_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 900
}

pub fn oracle_band_066_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 910
}

pub fn oracle_band_067_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 920
}

pub fn oracle_band_068_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 930
}

pub fn oracle_band_069_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 940
}

pub fn oracle_band_070_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 950
}

pub fn oracle_band_071_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 960
}

pub fn oracle_band_072_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 970
}

pub fn oracle_band_073_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 980
}

pub fn oracle_band_074_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 990
}

pub fn oracle_band_075_tripped(previous: u128, current: u128) -> bool {
    price_move_bps(previous, current) > 1000
}
