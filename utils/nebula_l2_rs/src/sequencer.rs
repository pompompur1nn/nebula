use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    accounts::AccountRegistry,
    blocks::{build_l2_block, BlockBuildInput, BlockStateRoots, ProducedBlock, Validator},
    consensus::{
        ConsensusState, DowntimeEvidence, EquivocationEvidence, FastFinalityVote,
        FinalityCertificate, ProposerSlot, CONSENSUS_FAST_FINALITY_QUORUM_BPS,
    },
    contracts::ContractState,
    crypto_policy::crypto_policy_root,
    defi::{
        AmmBatchSwap, AmmLiquidityAdd, AmmRouteSwap, AmmSealedBatchSwap, AmmSwap, AssetBurn,
        AssetMint, DarkPoolSwap, DefiStagedTx, DefiState, LendingBorrow, LendingLiquidation,
        LendingRepay, Note, SealedSwapIntentReveal,
    },
    fees::{
        block_packing_selection_from_indices, execution_profile_from_resources, pack_fee_resources,
        BlockExecutionProfile, BlockPackingPolicy, BlockPackingSelection, FeeMarketResource,
        FeeSmoothingLaneBudget, FeeSmoothingState, LowFeeLane,
    },
    hash::{domain_hash, merkle_root, HashPart},
    mempool::{
        mempool_committee_key_id, MempoolAdmission, MempoolAdmissionRequest,
        MempoolAntiCensorshipLaneCommitment, MempoolEncryptedBatchReceipt, MempoolPreconfirmation,
        MempoolRelayFairnessTicket, MempoolState,
    },
    monero::{
        MoneroAnchorObservation, MoneroBlockObservation, MoneroMonitorState, MoneroReorgEvidence,
        MoneroReserveReport, MoneroRpcEndpoint, MoneroRpcObservation, MoneroTxObservation,
        MoneroWithdrawalObservation, MoneroZmqObservation,
    },
    network::{
        build_admission_inventory_announcement, build_node_advertisement,
        build_root_inventory_announcement, validator_node_network_root,
        AdmissionInventoryAnnouncement, NetworkRole, NetworkState, NodeAdvertisement,
        RootConflictEvidence, RootInventoryAnnouncement,
    },
    prover::{devnet_proof_job_request, proof_market_snapshot, ProverCompletionInput, ProverState},
    runtime::WasmRuntimeState,
    settlement::{
        AnchorSubmission, BridgeDepositAddress, BridgeDepositObservation, BridgeReserveReport,
        BridgeSignerSet, BridgeState, BridgeWithdrawalChallengeEvidence,
        BridgeWithdrawalQueueRequest, BridgeWithdrawalRecord, EpochCheckpoint,
    },
    status::{transaction_public_hash, StatusIndex},
    wallet::{
        WalletMoneroEvidenceSources, WalletScanRequest, WalletScanSources, WalletSyncIndex,
        WalletView,
    },
    watchtower::{
        build_block_challenge_report, build_block_watchtower_audit_report, BlockChallengeReport,
        BlockWatchtowerAuditReport, WatchtowerState,
    },
    CHAIN_ID, TARGET_BLOCK_MS,
};

pub type SequencerResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerConfig {
    pub epoch_size: u64,
    pub admission_ttl_blocks: u64,
    pub finality_depth: u64,
    pub block_packing_policy: BlockPackingPolicy,
    pub sequencer_label: String,
    pub proposer_label: String,
    pub anchor_submitter_label: String,
    pub default_relay_path: String,
}

impl Default for SequencerConfig {
    fn default() -> Self {
        Self {
            epoch_size: 10,
            admission_ttl_blocks: 5,
            finality_depth: 10,
            block_packing_policy: BlockPackingPolicy::default(),
            sequencer_label: "devnet-sequencer".to_string(),
            proposer_label: "devnet-proposer".to_string(),
            anchor_submitter_label: "devnet-anchor".to_string(),
            default_relay_path: "direct".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerAdmission {
    pub admission: MempoolAdmission,
    pub preconfirmation: MempoolPreconfirmation,
    pub tx_public_hash: String,
    pub pending_index: u64,
    pub fee_market_root: String,
}

impl SequencerAdmission {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_admission",
            "chain_id": CHAIN_ID,
            "pending_index": self.pending_index,
            "tx_public_hash": self.tx_public_hash,
            "fee_market_root": self.fee_market_root,
            "admission": self.admission.public_record(),
            "preconfirmation": self.preconfirmation.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerBlockSummary {
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub tx_root: String,
    pub da_root: String,
    pub mempool_admission_root: String,
    pub mempool_admission_count: u64,
    pub transaction_count: u64,
    pub privacy_proof_aggregate_root: String,
    pub validity_certificate_root: String,
    pub proof_job_root: String,
    pub prover_receipt_root: String,
    pub prover_state_root: String,
    pub packing: BlockPackingSelection,
    pub packing_policy_satisfied: bool,
    pub packing_local_state_count: u64,
    pub soft_finality: bool,
    pub proposer_slot: ProposerSlot,
    pub fast_finality_certificate: FinalityCertificate,
    pub consensus_state_root: String,
    pub settlement_status: Value,
}

impl SequencerBlockSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_block_summary",
            "chain_id": CHAIN_ID,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "tx_root": self.tx_root,
            "da_root": self.da_root,
            "mempool_admission_root": self.mempool_admission_root,
            "mempool_admission_count": self.mempool_admission_count,
            "transaction_count": self.transaction_count,
            "privacy_proof_aggregate_root": self.privacy_proof_aggregate_root,
            "validity_certificate_root": self.validity_certificate_root,
            "proof_job_root": self.proof_job_root,
            "prover_receipt_root": self.prover_receipt_root,
            "prover_state_root": self.prover_state_root,
            "packing": self.packing.public_record(),
            "packing_policy_satisfied": self.packing_policy_satisfied,
            "packing_local_state_count": self.packing_local_state_count,
            "soft_finality": self.soft_finality,
            "proposer_slot": self.proposer_slot.public_record(),
            "fast_finality_certificate": self.fast_finality_certificate.public_record(),
            "consensus_state_root": self.consensus_state_root,
            "settlement_status": self.settlement_status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerAnchorSummary {
    pub checkpoint: EpochCheckpoint,
    pub anchor_submission: AnchorSubmission,
    pub previous_epoch_checkpoint_root: String,
}

impl SequencerAnchorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_anchor_summary",
            "chain_id": CHAIN_ID,
            "previous_epoch_checkpoint_root": self.previous_epoch_checkpoint_root,
            "checkpoint": self.checkpoint.anchor_record(),
            "anchor_submission": self.anchor_submission.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerBridgeDepositObservationSummary {
    pub bridge_observation: BridgeDepositObservation,
    pub monero_observation: MoneroTxObservation,
    pub bridge_root: String,
    pub monero_monitor_root: String,
}

impl SequencerBridgeDepositObservationSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_bridge_deposit_observation_summary",
            "chain_id": CHAIN_ID,
            "bridge_observation": self.bridge_observation.public_record(),
            "monero_observation": self.monero_observation.public_record(),
            "bridge_root": self.bridge_root,
            "monero_monitor_root": self.monero_monitor_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerReserveReportSummary {
    pub bridge_report: BridgeReserveReport,
    pub monero_report: MoneroReserveReport,
    pub bridge_root: String,
    pub monero_monitor_root: String,
}

impl SequencerReserveReportSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_reserve_report_summary",
            "chain_id": CHAIN_ID,
            "bridge_report": self.bridge_report.public_record(),
            "monero_report": self.monero_report.public_record(),
            "bridge_root": self.bridge_root,
            "monero_monitor_root": self.monero_monitor_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerMoneroReorgSummary {
    pub monero_evidence: MoneroReorgEvidence,
    pub bridge_withdrawal_challenge: Option<BridgeWithdrawalChallengeEvidence>,
    pub bridge_root: String,
    pub monero_monitor_root: String,
}

impl SequencerMoneroReorgSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_monero_reorg_summary",
            "chain_id": CHAIN_ID,
            "monero_evidence": self.monero_evidence.public_record(),
            "bridge_withdrawal_challenge": self.bridge_withdrawal_challenge.as_ref().map(BridgeWithdrawalChallengeEvidence::public_record),
            "bridge_root": self.bridge_root,
            "monero_monitor_root": self.monero_monitor_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PendingSequencerTx {
    public_record: Value,
    state_record: Value,
    fee_resource: FeeMarketResource,
    execution: PendingExecution,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum PendingExecution {
    PublicOnly,
    Defi(DefiStagedTx),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSequencer {
    pub config: SequencerConfig,
    pub defi: DefiState,
    pub admission_defi: DefiState,
    pub contracts: ContractState,
    pub runtime: WasmRuntimeState,
    pub bridge: BridgeState,
    pub prover: ProverState,
    pub watchtower: WatchtowerState,
    pub network: NetworkState,
    pub monero: MoneroMonitorState,
    pub consensus: ConsensusState,
    pub accounts: AccountRegistry,
    pub mempool: MempoolState,
    pub fee_smoothing: FeeSmoothingState,
    pub status: StatusIndex,
    pub validators: Vec<Validator>,
    pending: Vec<PendingSequencerTx>,
    mempool_sequence: u64,
    timestamp_ms: u64,
    last_block_hash: String,
    last_state_root: String,
    previous_epoch_checkpoint_root: String,
}

impl LocalSequencer {
    pub fn new(config: SequencerConfig) -> SequencerResult<Self> {
        if config.epoch_size == 0 {
            return Err("sequencer epoch_size must be positive".to_string());
        }
        if config.admission_ttl_blocks == 0 {
            return Err("sequencer admission ttl must be positive".to_string());
        }
        let validators = vec![
            Validator::new(&config.proposer_label, 1_000)?,
            Validator::new("devnet-validator-b", 750)?,
            Validator::new("devnet-validator-c", 750)?,
        ];
        let committee_key_id = mempool_committee_key_id(&validators);
        let node_network_root = validator_node_network_root(&validators);
        let mut accounts = AccountRegistry::new(committee_key_id, node_network_root);
        accounts.set_height(0);
        let bridge = BridgeState::new("");
        let monero = MoneroMonitorState::new("monero-devnet");
        let mut consensus =
            ConsensusState::new(config.epoch_size, CONSENSUS_FAST_FINALITY_QUORUM_BPS);
        consensus.import_validators(&validators, 0)?;
        let mut status = StatusIndex::new(config.epoch_size);
        status.monero = monero.clone();
        status.consensus = consensus.clone();
        Ok(Self {
            status,
            config,
            defi: DefiState::new(),
            admission_defi: DefiState::new(),
            contracts: ContractState::new(),
            runtime: WasmRuntimeState::new(),
            bridge,
            prover: ProverState::new(),
            watchtower: WatchtowerState::new(),
            network: NetworkState::new(),
            monero,
            consensus,
            accounts,
            mempool: MempoolState::default(),
            fee_smoothing: FeeSmoothingState::empty(0),
            validators,
            pending: Vec::new(),
            mempool_sequence: 0,
            timestamp_ms: 1_700_000_000_000,
            last_block_hash: "GENESIS".to_string(),
            last_state_root: "GENESIS".to_string(),
            previous_epoch_checkpoint_root: merkle_root("EPOCH-CHECKPOINT", &[]),
        })
    }

    pub fn with_validators(
        config: SequencerConfig,
        validators: Vec<Validator>,
    ) -> SequencerResult<Self> {
        if validators.is_empty() {
            return Err("sequencer requires at least one validator".to_string());
        }
        let mut sequencer = Self::new(config)?;
        sequencer.validators = validators;
        let height = sequencer.height();
        let imported_validators = sequencer.validators.clone();
        sequencer
            .consensus
            .import_validators(&imported_validators, height)?;
        sequencer.status.consensus = sequencer.consensus.clone();
        let committee_key_id = mempool_committee_key_id(&sequencer.validators);
        let node_network_root = sequencer.node_network_root();
        sequencer.accounts = AccountRegistry::new(committee_key_id, node_network_root);
        Ok(sequencer)
    }

    pub fn height(&self) -> u64 {
        self.status.current_height()
    }

    pub fn state_roots(&self) -> BlockStateRoots {
        self.state_roots_for_defi(&self.defi)
    }

    pub fn admission_state_roots(&self) -> BlockStateRoots {
        self.state_roots_for_defi(&self.admission_defi)
    }

    pub fn state_roots_for_defi(&self, defi: &DefiState) -> BlockStateRoots {
        BlockStateRoots {
            note_root: defi.note_root(),
            nullifier_root: defi.nullifier_root(),
            contract_root: self.contracts.contract_state_root(),
            wasm_runtime_root: self.runtime.runtime_root(),
            account_root: self.accounts.account_root(),
            asset_root: defi.asset_root(),
            sealed_swap_settlement_receipt_root: defi.sealed_swap_settlement_receipt_root(),
            bridge_root: self.bridge.bridge_root(),
            fee_root: defi.fee_root(),
            crypto_policy_root: crypto_policy_root(),
        }
    }

    pub fn state_root(&self) -> String {
        self.state_roots().state_root()
    }

    pub fn pending_transaction_count(&self) -> u64 {
        self.pending.len() as u64
    }

    pub fn pending_execution_profile(&self) -> BlockExecutionProfile {
        execution_profile_from_resources(&self.pending_fee_resources())
    }

    pub fn next_block_packing(&self) -> BlockPackingSelection {
        pack_fee_resources(
            &self.pending_fee_resources(),
            &self.config.block_packing_policy,
        )
    }

    pub fn next_state_safe_block_packing(&self) -> BlockPackingSelection {
        self.next_block_packing()
    }

    pub fn admit_public_transaction(
        &mut self,
        public_record: Value,
        fee_resource: FeeMarketResource,
        relay_path: Option<&str>,
    ) -> SequencerResult<SequencerAdmission> {
        self.admit_transaction_internal(
            public_record.clone(),
            public_record,
            fee_resource,
            relay_path,
            PendingExecution::PublicOnly,
        )
    }

    pub fn submit_asset_mint(
        &mut self,
        asset_id: &str,
        recipient_view_key: &str,
        amount: u64,
        signer_label: Option<&str>,
        relay_path: Option<&str>,
    ) -> SequencerResult<(AssetMint, SequencerAdmission)> {
        let mut projected = self.admission_defi.clone();
        let tx = projected.submit_asset_mint(asset_id, recipient_view_key, amount, signer_label)?;
        let admission =
            self.admit_staged_defi_transaction(DefiStagedTx::AssetMint(tx.clone()), relay_path)?;
        self.admission_defi = projected;
        Ok((tx, admission))
    }

    pub fn submit_asset_burn(
        &mut self,
        spent_note_id: &str,
        amount: u64,
        signer_label: Option<&str>,
        relay_path: Option<&str>,
    ) -> SequencerResult<(AssetBurn, SequencerAdmission)> {
        let mut projected = self.admission_defi.clone();
        let tx = projected.submit_asset_burn(spent_note_id, amount, signer_label)?;
        let admission =
            self.admit_staged_defi_transaction(DefiStagedTx::AssetBurn(tx.clone()), relay_path)?;
        self.admission_defi = projected;
        Ok((tx, admission))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_amm_liquidity_add(
        &mut self,
        pool_id: &str,
        note_a_id: &str,
        note_b_id: &str,
        amount_a: u64,
        amount_b: u64,
        owner_view_key: &str,
        network_fee: u64,
        signer_label: Option<&str>,
        relay_path: Option<&str>,
    ) -> SequencerResult<(AmmLiquidityAdd, SequencerAdmission)> {
        let mut projected = self.admission_defi.clone();
        let tx = projected.submit_amm_liquidity_add(
            pool_id,
            note_a_id,
            note_b_id,
            amount_a,
            amount_b,
            owner_view_key,
            network_fee,
            signer_label,
        )?;
        let admission = self
            .admit_staged_defi_transaction(DefiStagedTx::AmmLiquidityAdd(tx.clone()), relay_path)?;
        self.admission_defi = projected;
        Ok((tx, admission))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_amm_swap(
        &mut self,
        pool_id: &str,
        note_in_id: &str,
        amount_in: u64,
        min_amount_out: u64,
        recipient_view_key: &str,
        network_fee: u64,
        signer_label: Option<&str>,
        relay_path: Option<&str>,
    ) -> SequencerResult<(AmmSwap, SequencerAdmission)> {
        let mut projected = self.admission_defi.clone();
        let tx = projected.submit_amm_swap(
            pool_id,
            note_in_id,
            amount_in,
            min_amount_out,
            recipient_view_key,
            network_fee,
            signer_label,
        )?;
        let admission =
            self.admit_staged_defi_transaction(DefiStagedTx::AmmSwap(tx.clone()), relay_path)?;
        self.admission_defi = projected;
        Ok((tx, admission))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_amm_batch_swap(
        &mut self,
        pool_id: &str,
        note_in_ids: &[&str],
        amount_ins: &[u64],
        min_total_amount_out: u64,
        recipient_view_key: &str,
        network_fee: u64,
        signer_label: Option<&str>,
        relay_path: Option<&str>,
    ) -> SequencerResult<(AmmBatchSwap, SequencerAdmission)> {
        let mut projected = self.admission_defi.clone();
        let tx = projected.submit_amm_batch_swap(
            pool_id,
            note_in_ids,
            amount_ins,
            min_total_amount_out,
            recipient_view_key,
            network_fee,
            signer_label,
        )?;
        let admission =
            self.admit_staged_defi_transaction(DefiStagedTx::AmmBatchSwap(tx.clone()), relay_path)?;
        self.admission_defi = projected;
        Ok((tx, admission))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_amm_route_swap(
        &mut self,
        pool_ids: &[&str],
        note_in_id: &str,
        amount_in: u64,
        min_amount_out: u64,
        recipient_view_key: &str,
        network_fee: u64,
        signer_label: Option<&str>,
        relay_path: Option<&str>,
    ) -> SequencerResult<(AmmRouteSwap, SequencerAdmission)> {
        let mut projected = self.admission_defi.clone();
        let tx = projected.submit_amm_route_swap(
            pool_ids,
            note_in_id,
            amount_in,
            min_amount_out,
            recipient_view_key,
            network_fee,
            signer_label,
        )?;
        let admission =
            self.admit_staged_defi_transaction(DefiStagedTx::AmmRouteSwap(tx.clone()), relay_path)?;
        self.admission_defi = projected;
        Ok((tx, admission))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_dark_pool_swap(
        &mut self,
        note_a_id: &str,
        note_b_id: &str,
        amount_a: u64,
        amount_b: u64,
        recipient_a_view_key: &str,
        recipient_b_view_key: &str,
        network_fee_a: u64,
        network_fee_b: u64,
        signer_a_label: Option<&str>,
        signer_b_label: Option<&str>,
        match_salt: Option<&str>,
        relay_path: Option<&str>,
    ) -> SequencerResult<(DarkPoolSwap, SequencerAdmission)> {
        let mut projected = self.admission_defi.clone();
        let tx = projected.submit_dark_pool_swap(
            note_a_id,
            note_b_id,
            amount_a,
            amount_b,
            recipient_a_view_key,
            recipient_b_view_key,
            network_fee_a,
            network_fee_b,
            signer_a_label,
            signer_b_label,
            match_salt,
        )?;
        let admission =
            self.admit_staged_defi_transaction(DefiStagedTx::DarkPoolSwap(tx.clone()), relay_path)?;
        self.admission_defi = projected;
        Ok((tx, admission))
    }

    pub fn submit_amm_sealed_batch_swap(
        &mut self,
        pool_id: &str,
        reveals: &[SealedSwapIntentReveal],
        solver_bid_id: Option<&str>,
        solver_label: Option<&str>,
        relay_path: Option<&str>,
    ) -> SequencerResult<(AmmSealedBatchSwap, SequencerAdmission)> {
        let mut projected = self.admission_defi.clone();
        let tx = projected.submit_amm_sealed_batch_swap(
            pool_id,
            reveals,
            solver_bid_id,
            solver_label,
        )?;
        let admission = self.admit_staged_defi_transaction(
            DefiStagedTx::AmmSealedBatchSwap(tx.clone()),
            relay_path,
        )?;
        self.admission_defi = projected;
        Ok((tx, admission))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_lending_borrow(
        &mut self,
        market_id: &str,
        collateral_note_id: &str,
        collateral_amount: u64,
        borrow_amount: u64,
        owner_view_key: &str,
        borrow_fee: u64,
        signer_label: Option<&str>,
        relay_path: Option<&str>,
    ) -> SequencerResult<(LendingBorrow, SequencerAdmission)> {
        let mut projected = self.admission_defi.clone();
        let tx = projected.submit_lending_borrow(
            market_id,
            collateral_note_id,
            collateral_amount,
            borrow_amount,
            owner_view_key,
            borrow_fee,
            signer_label,
        )?;
        let admission = self
            .admit_staged_defi_transaction(DefiStagedTx::LendingBorrow(tx.clone()), relay_path)?;
        self.admission_defi = projected;
        Ok((tx, admission))
    }

    pub fn submit_lending_repay(
        &mut self,
        position_id: &str,
        debt_note_id: &str,
        repay_fee: u64,
        signer_label: Option<&str>,
        relay_path: Option<&str>,
    ) -> SequencerResult<(LendingRepay, SequencerAdmission)> {
        let mut projected = self.admission_defi.clone();
        let tx =
            projected.submit_lending_repay(position_id, debt_note_id, repay_fee, signer_label)?;
        let admission =
            self.admit_staged_defi_transaction(DefiStagedTx::LendingRepay(tx.clone()), relay_path)?;
        self.admission_defi = projected;
        Ok((tx, admission))
    }

    pub fn submit_lending_liquidation(
        &mut self,
        position_id: &str,
        debt_note_id: &str,
        liquidator_view_key: &str,
        liquidation_fee: u64,
        signer_label: Option<&str>,
        relay_path: Option<&str>,
    ) -> SequencerResult<(LendingLiquidation, SequencerAdmission)> {
        let mut projected = self.admission_defi.clone();
        let tx = projected.submit_lending_liquidation(
            position_id,
            debt_note_id,
            liquidator_view_key,
            liquidation_fee,
            signer_label,
        )?;
        let admission = self.admit_staged_defi_transaction(
            DefiStagedTx::LendingLiquidation(tx.clone()),
            relay_path,
        )?;
        self.admission_defi = projected;
        Ok((tx, admission))
    }

    pub fn admit_transaction(
        &mut self,
        public_record: Value,
        state_record: Value,
        fee_resource: FeeMarketResource,
        relay_path: Option<&str>,
    ) -> SequencerResult<SequencerAdmission> {
        self.admit_transaction_internal(
            public_record,
            state_record,
            fee_resource,
            relay_path,
            PendingExecution::PublicOnly,
        )
    }

    pub fn admit_low_fee_transaction(
        &mut self,
        public_record: Value,
        state_record: Value,
        fee_resource: FeeMarketResource,
        low_fee_lane: LowFeeLane,
        relay_path: Option<&str>,
    ) -> SequencerResult<SequencerAdmission> {
        self.admit_transaction_internal(
            public_record,
            state_record,
            fee_resource.with_low_fee_lane(low_fee_lane),
            relay_path,
            PendingExecution::PublicOnly,
        )
    }

    pub fn admit_privacy_transfer_low_fee(
        &mut self,
        public_record: Value,
        state_record: Value,
        fee_resource: FeeMarketResource,
        relay_path: Option<&str>,
    ) -> SequencerResult<SequencerAdmission> {
        self.admit_low_fee_transaction(
            public_record,
            state_record,
            fee_resource,
            LowFeeLane::privacy_transfers(),
            relay_path,
        )
    }

    pub fn admit_monero_bridge_low_fee(
        &mut self,
        public_record: Value,
        state_record: Value,
        fee_resource: FeeMarketResource,
        relay_path: Option<&str>,
    ) -> SequencerResult<SequencerAdmission> {
        self.admit_low_fee_transaction(
            public_record,
            state_record,
            fee_resource,
            LowFeeLane::monero_bridge_ops(),
            relay_path,
        )
    }

    pub fn admit_small_defi_low_fee(
        &mut self,
        public_record: Value,
        state_record: Value,
        fee_resource: FeeMarketResource,
        relay_path: Option<&str>,
    ) -> SequencerResult<SequencerAdmission> {
        self.admit_low_fee_transaction(
            public_record,
            state_record,
            fee_resource,
            LowFeeLane::small_defi_calls(),
            relay_path,
        )
    }

    fn admit_staged_defi_transaction(
        &mut self,
        staged: DefiStagedTx,
        relay_path: Option<&str>,
    ) -> SequencerResult<SequencerAdmission> {
        let public_record = staged.public_record();
        let state_record = staged.state_record();
        let fee_resource = staged.fee_resource();
        self.admit_transaction_internal(
            public_record,
            state_record,
            fee_resource,
            relay_path,
            PendingExecution::Defi(staged),
        )
    }

    fn admit_transaction_internal(
        &mut self,
        public_record: Value,
        state_record: Value,
        fee_resource: FeeMarketResource,
        relay_path: Option<&str>,
        execution: PendingExecution,
    ) -> SequencerResult<SequencerAdmission> {
        let current_height = self.height();
        let relay_path = relay_path
            .unwrap_or(&self.config.default_relay_path)
            .to_string();
        let admission = MempoolAdmission::build(MempoolAdmissionRequest {
            tx_public_record: public_record.clone(),
            tx_state_record: state_record.clone(),
            mempool_sequence: self.mempool_sequence,
            relay_path,
            admitted_at_height: current_height,
            expires_at_height: current_height + self.config.admission_ttl_blocks,
            sequencer_label: self.config.sequencer_label.clone(),
            committee_key_id: mempool_committee_key_id(&self.validators),
        });
        if !admission.verify_authorization() {
            return Err("sequencer admission authorization failed".to_string());
        }
        let mut pending_resources = self
            .pending
            .iter()
            .map(|pending| pending.fee_resource.clone())
            .collect::<Vec<_>>();
        pending_resources.push(fee_resource.clone());
        let fee_market_root = execution_profile_from_resources(&pending_resources)
            .local_fee_market_root
            .clone();
        let mut projected_mempool = self.mempool.clone();
        projected_mempool.insert_admission(admission.clone())?;
        let target_height = self.projected_preconfirmation_target_height(
            &pending_resources,
            pending_resources.len().saturating_sub(1),
            current_height,
            admission.expires_at_height,
        );
        let preconfirmation = MempoolPreconfirmation::build_with_target_height(
            &admission,
            current_height + 1,
            target_height,
            &projected_mempool.admission_root(),
            self.pending.len() as u64 + 1,
            &fee_market_root,
        )?;
        if !preconfirmation.verify_authorization() {
            return Err("sequencer preconfirmation authorization failed".to_string());
        }
        let fairness_ticket = MempoolRelayFairnessTicket::build(
            &admission,
            "private-fast-lane",
            current_height,
            current_height,
            admission.expires_at_height,
            current_height,
            self.config.admission_ttl_blocks,
            &self.config.sequencer_label,
        )?;
        let batch_receipt = MempoolEncryptedBatchReceipt::build(
            &projected_mempool.pending_admissions,
            self.mempool_sequence,
            target_height,
            &self.config.sequencer_label,
        )?;
        let fairness_tickets = vec![fairness_ticket.clone()];
        let encrypted_batch_receipts = vec![batch_receipt.clone()];
        let forced_inclusions = self
            .mempool
            .forced_inclusions
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let anti_censorship_lane = MempoolAntiCensorshipLaneCommitment::build(
            "private-fast-lane",
            current_height,
            current_height,
            admission.expires_at_height,
            std::cmp::max(1, self.config.block_packing_policy.lane_reserve_tx_count),
            1,
            &fairness_tickets,
            &encrypted_batch_receipts,
            &forced_inclusions,
            &self.config.sequencer_label,
        )?;
        self.mempool_sequence += 1;
        self.mempool.insert_admission(admission.clone())?;
        self.mempool
            .insert_preconfirmation(preconfirmation.clone())?;
        self.mempool.insert_relay_fairness_ticket(fairness_ticket)?;
        self.mempool.insert_encrypted_batch_receipt(batch_receipt)?;
        self.mempool
            .insert_anti_censorship_lane_commitment(anti_censorship_lane)?;
        self.pending.push(PendingSequencerTx {
            public_record,
            state_record,
            fee_resource,
            execution,
        });
        self.refresh_status_pending();
        let _ = self.publish_admission_inventory();
        Ok(SequencerAdmission {
            tx_public_hash: admission.tx_public_hash.clone(),
            pending_index: self.pending.len().saturating_sub(1) as u64,
            admission,
            preconfirmation,
            fee_market_root,
        })
    }

    pub fn produce_block(&mut self) -> SequencerResult<SequencerBlockSummary> {
        if self.pending.is_empty() {
            return Err("sequencer has no pending transactions".to_string());
        }
        let height = self.height();
        self.set_component_heights(height);
        self.consensus
            .import_validators(&self.validators, height)
            .map_err(|err| format!("consensus validator import failed: {err}"))?;
        let proposer_slot =
            self.consensus
                .record_proposer_slot(height, 0, &self.last_block_hash)?;
        let proposer_label = proposer_slot.proposer_label.clone();
        let initial_packing = self.next_state_safe_block_packing();
        if initial_packing.selected_indices.is_empty() {
            return Err("no pending transactions fit the block packing policy".to_string());
        }
        let (packing, selected_indices, defi_after, packing_local_state_count) =
            self.executable_block_plan(initial_packing, height)?;
        let transactions = selected_indices
            .iter()
            .map(|index| self.pending[*index].public_record.clone())
            .collect::<Vec<_>>();
        let fee_resources = selected_indices
            .iter()
            .map(|index| self.pending[*index].fee_resource.clone())
            .collect::<Vec<_>>();
        let mempool_admissions = selected_indices
            .iter()
            .map(|index| {
                self.mempool
                    .pending_admissions
                    .get(*index)
                    .ok_or_else(|| "pending mempool admission index mismatch".to_string())
                    .map(MempoolAdmission::public_record)
            })
            .collect::<SequencerResult<Vec<_>>>()?;
        let produced = build_l2_block(BlockBuildInput {
            height,
            epoch: height / self.config.epoch_size,
            timestamp_ms: self.timestamp_ms,
            prev_block_hash: self.last_block_hash.clone(),
            previous_state_root: self.last_state_root.clone(),
            transactions,
            mempool_admissions,
            state_roots: self.state_roots_for_defi(&defi_after),
            fee_resources,
            validators: self.validators.clone(),
            proposer_label: proposer_label.clone(),
        })?;
        self.prover.ensure_default_prover(&proposer_label)?;
        let proof_job = self.prover.submit_block_job(devnet_proof_job_request(
            produced.block.clone(),
            produced.privacy_aggregate.clone(),
            produced.certificate.clone(),
            produced.previous_state_root.clone(),
            &proposer_label,
            "proof-fee-units",
            height,
        ))?;
        self.prover.assign_job(&proof_job.job_id, &proposer_label)?;
        self.prover.complete_job(ProverCompletionInput {
            job_id: proof_job.job_id.clone(),
            block: produced.block.clone(),
            privacy_aggregate: produced.privacy_aggregate.clone(),
            validity_certificate: produced.certificate.clone(),
            previous_state_root: produced.previous_state_root.clone(),
            prover_label: proposer_label.clone(),
            completed_at_height: height,
            proof_time_ms: std::cmp::max(1, TARGET_BLOCK_MS / 5),
            fee_units: proof_job.estimated_fee_units,
        })?;
        let finality_labels = self
            .validators
            .iter()
            .filter(|validator| validator.is_active())
            .map(|validator| validator.label.clone())
            .collect::<Vec<_>>();
        let fast_finality_certificate =
            self.consensus
                .certify_block(&produced.block, 0, &finality_labels, height)?;
        let packing_policy_satisfied = self
            .config
            .block_packing_policy
            .accepts_profile(&packing.selected_profile);
        self.defi = defi_after;
        self.remove_selected_pending(&selected_indices);
        let summary = self.commit_produced_block(
            produced,
            packing,
            packing_policy_satisfied,
            packing_local_state_count,
            proposer_slot,
            fast_finality_certificate,
        )?;
        self.rebuild_admission_defi()?;
        self.refresh_status_pending();
        let _ = self.publish_root_inventory();
        let _ = self.publish_admission_inventory();
        self.timestamp_ms += TARGET_BLOCK_MS;
        Ok(summary)
    }

    pub fn submit_epoch_anchor(
        &mut self,
        block_height: Option<u64>,
        monero_txid: &str,
        confirmations: u64,
    ) -> SequencerResult<SequencerAnchorSummary> {
        if monero_txid.is_empty() {
            return Err("anchor monero txid is required".to_string());
        }
        let block_height = block_height.unwrap_or_else(|| self.height().saturating_sub(1));
        let checkpoint = self.status.epoch_checkpoint_for_block(block_height)?;
        let header = self
            .status
            .blocks
            .get(block_height as usize)
            .ok_or_else(|| "unknown anchor block height".to_string())?
            .header
            .clone();
        let previous = self.previous_epoch_checkpoint_root.clone();
        let submitted = AnchorSubmission::submit(
            &header,
            &checkpoint,
            &previous,
            self.config.anchor_submitter_label.clone(),
            monero_txid.to_string(),
            self.timestamp_ms,
        );
        let submission = submitted.confirm(
            confirmations,
            self.config.finality_depth,
            self.timestamp_ms + TARGET_BLOCK_MS,
        );
        if !submission.verify_authorization() {
            return Err("anchor authorization failed".to_string());
        }
        self.status
            .anchor_submissions
            .insert(submission.anchor_id.clone(), submission.clone());
        self.previous_epoch_checkpoint_root = checkpoint.checkpoint_root();
        Ok(SequencerAnchorSummary {
            checkpoint,
            anchor_submission: submission,
            previous_epoch_checkpoint_root: previous,
        })
    }

    pub fn rotate_bridge_signer_set(
        &mut self,
        signer_labels: &[String],
        threshold: u64,
    ) -> SequencerResult<BridgeSignerSet> {
        self.bridge.rotate_signer_set(
            signer_labels,
            threshold,
            self.height(),
            &self.config.anchor_submitter_label,
        )
    }

    pub fn request_bridge_deposit(
        &mut self,
        recipient_view_key: &str,
    ) -> SequencerResult<BridgeDepositAddress> {
        if recipient_view_key.is_empty() {
            return Err("bridge deposit recipient view key is required".to_string());
        }
        let deposit = BridgeDepositAddress::request(
            recipient_view_key.to_string(),
            self.bridge.deposit_addresses.len() as u64,
            self.mempool_sequence,
            self.timestamp_ms,
        );
        self.bridge
            .deposit_addresses
            .insert(deposit.deposit_id.clone(), deposit.clone());
        Ok(deposit)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_bridge_deposit_from_monero(
        &mut self,
        deposit_id: &str,
        monero_txid: &str,
        amount: u64,
        monero_block_height: u64,
        monero_block_hash: &str,
        confirmations: u64,
        observer_labels: &[String],
    ) -> SequencerResult<SequencerBridgeDepositObservationSummary> {
        let request = self
            .bridge
            .deposit_addresses
            .get(deposit_id)
            .cloned()
            .ok_or_else(|| "unknown bridge deposit address".to_string())?;
        let signer_set = self.bridge.active_signer_set()?.clone();
        let bridge_observation = BridgeDepositObservation::observe(
            &request,
            monero_txid.to_string(),
            amount,
            confirmations,
            &signer_set,
            observer_labels,
        )?;
        self.bridge
            .observations
            .insert(deposit_id.to_string(), bridge_observation.clone());
        self.monero.set_height(self.height());
        let monero_observation = self.monero.observe_tx(
            monero_txid,
            "bridge_deposit",
            amount,
            &request.monero_address,
            None,
            Some(deposit_id.to_string()),
            monero_block_height,
            monero_block_hash,
            0,
            confirmations,
            observer_labels,
        )?;
        self.status.monero = self.monero.clone();
        Ok(SequencerBridgeDepositObservationSummary {
            bridge_observation,
            monero_observation,
            bridge_root: self.bridge.bridge_root(),
            monero_monitor_root: self.monero.state_root(),
        })
    }

    pub fn queue_bridge_withdrawal(
        &mut self,
        spent_note_id: &str,
        nullifier: &str,
        amount: u64,
        monero_address: &str,
        bridge_fee: u64,
        signer_labels: &[String],
    ) -> SequencerResult<BridgeWithdrawalRecord> {
        let signer_set = self.bridge.active_signer_set()?.clone();
        let withdrawal = BridgeWithdrawalRecord::queue(
            BridgeWithdrawalQueueRequest {
                spent_note_id: spent_note_id.to_string(),
                nullifier: nullifier.to_string(),
                amount,
                monero_address: monero_address.to_string(),
                bridge_fee,
                requested_at_height: self.height(),
            },
            &signer_set,
            signer_labels,
        )?;
        self.bridge
            .withdrawals
            .insert(withdrawal.withdrawal_id.clone(), withdrawal.clone());
        Ok(withdrawal)
    }

    pub fn release_bridge_withdrawal(
        &mut self,
        withdrawal_id: &str,
        monero_txid: &str,
        signer_labels: &[String],
    ) -> SequencerResult<BridgeWithdrawalRecord> {
        let signer_set = self.bridge.active_signer_set()?.clone();
        let withdrawal = self
            .bridge
            .withdrawals
            .get(withdrawal_id)
            .cloned()
            .ok_or_else(|| "unknown bridge withdrawal".to_string())?;
        let released = withdrawal.release(
            monero_txid,
            self.height(),
            self.timestamp_ms,
            &signer_set,
            signer_labels,
        )?;
        self.bridge
            .withdrawals
            .insert(withdrawal_id.to_string(), released.clone());
        Ok(released)
    }

    pub fn transaction_status(&self, tx_public_hash: &str) -> SequencerResult<Value> {
        self.status.transaction_status(tx_public_hash)
    }

    pub fn admission_status(&self, admission_id: &str) -> SequencerResult<Value> {
        self.status.mempool_admission_status(admission_id)
    }

    pub fn install_default_fee_smoothing(
        &mut self,
        budget_units_per_lane: u64,
        max_rebate_bps: u64,
        min_settled_fee_units: u64,
    ) -> SequencerResult<FeeSmoothingState> {
        if budget_units_per_lane == 0 {
            return Err("fee smoothing budget must be positive".to_string());
        }
        let epoch = self.height() / self.config.epoch_size;
        let settlement_root = merkle_root(
            "SEQUENCER-FEE-SMOOTHING-SETTLEMENT",
            &[
                json!({"kind": "bridge_root", "root": self.bridge.bridge_root()}),
                json!({"kind": "monero_monitor_root", "root": self.monero.state_root()}),
                json!({"kind": "mempool_admission_root", "root": self.mempool.admission_root()}),
                json!({"kind": "consensus_state_root", "root": self.consensus.state_root()}),
            ],
        );
        self.fee_smoothing = FeeSmoothingState::new(
            epoch,
            vec![
                FeeSmoothingLaneBudget::privacy_transfers(
                    epoch,
                    budget_units_per_lane,
                    max_rebate_bps,
                    min_settled_fee_units,
                    &settlement_root,
                ),
                FeeSmoothingLaneBudget::monero_bridge_ops(
                    epoch,
                    budget_units_per_lane,
                    max_rebate_bps,
                    min_settled_fee_units,
                    &settlement_root,
                ),
                FeeSmoothingLaneBudget::small_defi_calls(
                    epoch,
                    budget_units_per_lane,
                    max_rebate_bps,
                    min_settled_fee_units,
                    &settlement_root,
                ),
            ],
            Vec::new(),
            Vec::new(),
            vec![settlement_root],
        );
        Ok(self.fee_smoothing.clone())
    }

    pub fn smoothed_fee_for_low_fee_lane(&self, lane: LowFeeLane, gross_fee_units: u64) -> Value {
        let rebate_units = self.fee_smoothing.rebate_for_lane_fee(
            &lane.lane_type,
            &lane.lane_key,
            gross_fee_units,
        );
        json!({
            "kind": "smoothed_low_fee_quote",
            "chain_id": CHAIN_ID,
            "lane": lane.public_record(),
            "gross_fee_units": gross_fee_units,
            "rebate_units": rebate_units,
            "settled_fee_units": gross_fee_units.saturating_sub(rebate_units),
            "fee_smoothing_root": self.fee_smoothing.state_root(),
        })
    }

    pub fn fee_smoothing_status(&self) -> Value {
        json!({
            "kind": "fee_smoothing_status",
            "chain_id": CHAIN_ID,
            "height": self.height(),
            "fee_smoothing": self.fee_smoothing.public_record(),
            "fee_smoothing_root": self.fee_smoothing.state_root(),
        })
    }

    pub fn settlement_status(&self, block_height: Option<u64>) -> SequencerResult<Value> {
        self.status.settlement_status(block_height)
    }

    pub fn proof_status(&self, block_height: u64) -> SequencerResult<Value> {
        self.status.proof_status(block_height)
    }

    pub fn network_status(&self) -> Value {
        self.status.network_status()
    }

    pub fn consensus_status(&self) -> Value {
        self.status.consensus_status()
    }

    pub fn monero_status(&self) -> Value {
        self.status.monero_status()
    }

    pub fn submit_fast_finality_vote(
        &mut self,
        block_height: u64,
        round: u64,
        validator_label: &str,
    ) -> SequencerResult<FastFinalityVote> {
        let block = self
            .status
            .blocks
            .get(block_height as usize)
            .cloned()
            .ok_or_else(|| "unknown block height".to_string())?;
        let vote =
            self.consensus
                .submit_finality_vote(&block, round, validator_label, self.height())?;
        self.status.consensus = self.consensus.clone();
        Ok(vote)
    }

    pub fn build_fast_finality_certificate(
        &mut self,
        block_height: u64,
        round: u64,
    ) -> SequencerResult<FinalityCertificate> {
        let block = self
            .status
            .blocks
            .get(block_height as usize)
            .cloned()
            .ok_or_else(|| "unknown block height".to_string())?;
        let certificate = self.consensus.build_finality_certificate(
            block_height,
            round,
            &block.header.block_hash(),
            &block.header.state_root,
            self.height(),
        )?;
        self.status.consensus = self.consensus.clone();
        Ok(certificate)
    }

    pub fn report_consensus_equivocation(
        &mut self,
        left_vote_id: &str,
        right_vote_id: &str,
        reporter_label: &str,
    ) -> SequencerResult<EquivocationEvidence> {
        let evidence = self.consensus.report_equivocation(
            left_vote_id,
            right_vote_id,
            reporter_label,
            self.height(),
        )?;
        self.status.consensus = self.consensus.clone();
        Ok(evidence)
    }

    pub fn report_validator_downtime(
        &mut self,
        validator_id: &str,
        missed_from_height: u64,
        missed_to_height: u64,
        reporter_label: &str,
    ) -> SequencerResult<DowntimeEvidence> {
        let evidence = self.consensus.report_downtime(
            validator_id,
            missed_from_height,
            missed_to_height,
            reporter_label,
            self.height(),
        )?;
        self.status.consensus = self.consensus.clone();
        Ok(evidence)
    }

    pub fn register_monero_endpoint(
        &mut self,
        operator_label: &str,
        endpoint_route: &str,
        advertised_height: u64,
        pruning_mode: &str,
        tls_policy: &str,
    ) -> SequencerResult<MoneroRpcEndpoint> {
        let endpoint = self.monero.register_endpoint(
            operator_label,
            endpoint_route,
            advertised_height,
            pruning_mode,
            tls_policy,
        )?;
        self.status.monero = self.monero.clone();
        Ok(endpoint)
    }

    pub fn record_monero_rpc_observation(
        &mut self,
        endpoint_id: &str,
        request_kind: &str,
        request: &Value,
        response: &Value,
        advertised_height: u64,
        observed_tip_hash: &str,
        latency_ms: u64,
        observer_label: &str,
    ) -> SequencerResult<MoneroRpcObservation> {
        self.monero.set_height(self.height());
        let observation = self.monero.record_rpc_observation(
            endpoint_id,
            request_kind,
            request,
            response,
            advertised_height,
            observed_tip_hash,
            latency_ms,
            observer_label,
        )?;
        self.status.monero = self.monero.clone();
        Ok(observation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_monero_zmq_observation(
        &mut self,
        endpoint_id: &str,
        topic: &str,
        sequence: u64,
        payload: &Value,
        linked_block_height: u64,
        linked_block_hash: &str,
        observer_label: &str,
    ) -> SequencerResult<MoneroZmqObservation> {
        self.monero.set_height(self.height());
        let observation = self.monero.record_zmq_observation(
            endpoint_id,
            topic,
            sequence,
            payload,
            linked_block_height,
            linked_block_hash,
            observer_label,
        )?;
        self.status.monero = self.monero.clone();
        Ok(observation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_monero_block(
        &mut self,
        block_height: u64,
        block_hash: &str,
        previous_block_hash: &str,
        tx_count: u64,
        difficulty: u64,
        cumulative_difficulty: &str,
        observed_tip_hash: &str,
        confirmations: u64,
        endpoint_id: &str,
        observer_labels: &[String],
    ) -> SequencerResult<MoneroBlockObservation> {
        self.monero.set_height(self.height());
        let observation = self.monero.observe_block(
            block_height,
            block_hash,
            previous_block_hash,
            tx_count,
            difficulty,
            cumulative_difficulty,
            observed_tip_hash,
            confirmations,
            endpoint_id,
            observer_labels,
        )?;
        self.status.monero = self.monero.clone();
        Ok(observation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_monero_tx(
        &mut self,
        txid: &str,
        tx_kind: &str,
        amount: u64,
        address: &str,
        anchor_commitment: Option<String>,
        bridge_event_id: Option<String>,
        monero_block_height: u64,
        monero_block_hash: &str,
        unlock_height: u64,
        confirmations: u64,
        observer_labels: &[String],
    ) -> SequencerResult<MoneroTxObservation> {
        self.monero.set_height(self.height());
        let observation = self.monero.observe_tx(
            txid,
            tx_kind,
            amount,
            address,
            anchor_commitment,
            bridge_event_id,
            monero_block_height,
            monero_block_hash,
            unlock_height,
            confirmations,
            observer_labels,
        )?;
        self.status.monero = self.monero.clone();
        Ok(observation)
    }

    pub fn observe_anchor_on_monero(
        &mut self,
        anchor_id: &str,
        monero_block_height: u64,
        monero_block_hash: &str,
        confirmations: u64,
        observer_labels: &[String],
    ) -> SequencerResult<MoneroAnchorObservation> {
        let submission = self
            .status
            .anchor_submissions
            .get(anchor_id)
            .cloned()
            .ok_or_else(|| "unknown anchor submission".to_string())?;
        self.monero.set_height(self.height());
        let observation = self.monero.observe_anchor(
            &submission,
            monero_block_height,
            monero_block_hash,
            confirmations,
            observer_labels,
        )?;
        let confirmed = submission.confirm(
            confirmations,
            self.config.finality_depth,
            self.timestamp_ms + TARGET_BLOCK_MS,
        );
        self.status
            .anchor_submissions
            .insert(anchor_id.to_string(), confirmed);
        self.status.monero = self.monero.clone();
        Ok(observation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_withdrawal_on_monero(
        &mut self,
        withdrawal_id: &str,
        monero_txid: &str,
        recipient_address: &str,
        monero_block_height: u64,
        monero_block_hash: &str,
        confirmations: u64,
        observer_labels: &[String],
    ) -> SequencerResult<MoneroWithdrawalObservation> {
        let withdrawal = self
            .bridge
            .withdrawals
            .get(withdrawal_id)
            .cloned()
            .ok_or_else(|| "unknown bridge withdrawal".to_string())?;
        self.monero.set_height(self.height());
        let observation = self.monero.observe_withdrawal(
            withdrawal_id,
            monero_txid,
            withdrawal.amount,
            recipient_address,
            monero_block_height,
            monero_block_hash,
            confirmations,
            observer_labels,
        )?;
        let confirmed = withdrawal.confirm(
            confirmations,
            self.config.finality_depth,
            self.timestamp_ms + TARGET_BLOCK_MS,
        );
        self.bridge
            .withdrawals
            .insert(withdrawal_id.to_string(), confirmed);
        self.status.monero = self.monero.clone();
        Ok(observation)
    }

    pub fn publish_bridge_reserve_report(
        &mut self,
        reserve_addresses: &[String],
        reported_reserve_amount: u64,
        reporter_labels: &[String],
    ) -> SequencerResult<SequencerReserveReportSummary> {
        let bridge_report = self.bridge.publish_reserve_report(
            reserve_addresses,
            reported_reserve_amount,
            self.height(),
            self.timestamp_ms,
            reporter_labels,
        )?;
        self.monero.set_height(self.height());
        let monero_report = self.monero.publish_reserve_report(
            &self.bridge,
            reserve_addresses,
            reported_reserve_amount,
            reporter_labels,
        )?;
        self.status.monero = self.monero.clone();
        Ok(SequencerReserveReportSummary {
            bridge_report,
            monero_report,
            bridge_root: self.bridge.bridge_root(),
            monero_monitor_root: self.monero.state_root(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn report_monero_reorg(
        &mut self,
        txid: &str,
        old_block_height: u64,
        old_block_hash: &str,
        new_block_height: u64,
        new_block_hash: &str,
        affected_anchor_id: Option<String>,
        affected_withdrawal_id: Option<String>,
        reporter_labels: &[String],
    ) -> SequencerResult<SequencerMoneroReorgSummary> {
        let reporter_label = reporter_labels
            .first()
            .ok_or_else(|| "monero reorg reporter label is required".to_string())?;
        let bridge_withdrawal_challenge =
            if let Some(withdrawal_id) = affected_withdrawal_id.clone() {
                Some(self.bridge.record_withdrawal_reorg_evidence(
                    &withdrawal_id,
                    old_block_height,
                    old_block_hash,
                    new_block_height,
                    new_block_hash,
                    self.height(),
                    self.timestamp_ms,
                    reporter_labels,
                )?)
            } else {
                None
            };
        self.monero.set_height(self.height());
        let evidence = self.monero.report_reorg(
            txid,
            old_block_height,
            old_block_hash,
            new_block_height,
            new_block_hash,
            affected_anchor_id,
            affected_withdrawal_id,
            reporter_label,
        )?;
        self.status.monero = self.monero.clone();
        Ok(SequencerMoneroReorgSummary {
            monero_evidence: evidence,
            bridge_withdrawal_challenge,
            bridge_root: self.bridge.bridge_root(),
            monero_monitor_root: self.monero.state_root(),
        })
    }

    pub fn advertise_network_node(
        &mut self,
        roles: Vec<NetworkRole>,
        route_hint: &str,
        relay_policy: &str,
        capacity_hint: u64,
        observed_fee_floor_units: u64,
    ) -> SequencerResult<NodeAdvertisement> {
        let advertisement = build_node_advertisement(
            &self.config.sequencer_label,
            roles,
            route_hint,
            relay_policy,
            self.height(),
            capacity_hint,
            observed_fee_floor_units,
        )?;
        self.network.record_advertisement(advertisement.clone())?;
        self.status.network = self.network.clone();
        Ok(advertisement)
    }

    pub fn publish_root_inventory(&mut self) -> SequencerResult<RootInventoryAnnouncement> {
        let advertisement = self.ensure_local_network_advertisement()?;
        let (block_hash, da_root, validity_root, aggregate_root) = self.latest_block_roots();
        let fee_resources = self.pending_fee_resources();
        let inventory = build_root_inventory_announcement(
            &advertisement,
            self.height(),
            &block_hash,
            &self.state_root(),
            &da_root,
            &self.mempool,
            &validity_root,
            &aggregate_root,
            &self.prover,
            &self.watchtower,
            &self.bridge.bridge_root(),
            &self.monero.state_root(),
            &self.consensus.state_root(),
            &fee_resources,
        )?;
        self.network.record_root_inventory(inventory.clone())?;
        self.status.network = self.network.clone();
        Ok(inventory)
    }

    pub fn publish_admission_inventory(
        &mut self,
    ) -> SequencerResult<AdmissionInventoryAnnouncement> {
        let advertisement = self.ensure_local_network_advertisement()?;
        let fee_resources = self.pending_fee_resources();
        let inventory = build_admission_inventory_announcement(
            &advertisement,
            self.height(),
            &self.mempool,
            &fee_resources,
        )?;
        self.network.record_admission_inventory(inventory.clone())?;
        self.status.network = self.network.clone();
        Ok(inventory)
    }

    pub fn report_network_root_conflict(
        &mut self,
        left_inventory_id: &str,
        right_inventory_id: &str,
        reporter_label: &str,
    ) -> SequencerResult<RootConflictEvidence> {
        let evidence = self.network.report_root_conflict(
            left_inventory_id,
            right_inventory_id,
            reporter_label,
        )?;
        self.status.network = self.network.clone();
        Ok(evidence)
    }

    pub fn submit_watchtower_audit(
        &mut self,
        block_height: u64,
        watchtower_label: &str,
        shard_indices: &[u64],
    ) -> SequencerResult<BlockWatchtowerAuditReport> {
        let block = self
            .status
            .blocks
            .get(block_height as usize)
            .ok_or_else(|| "unknown block height".to_string())?
            .clone();
        let da_record = self
            .status
            .da_records
            .get(&block_height)
            .ok_or_else(|| "unknown DA record".to_string())?
            .clone();
        let certificate = self
            .status
            .validity_certificates
            .get(&block_height)
            .ok_or_else(|| "unknown validity certificate".to_string())?
            .clone();
        let aggregate = self
            .status
            .privacy_aggregates
            .get(&block_height)
            .ok_or_else(|| "unknown privacy proof aggregate".to_string())?
            .clone();
        let proof_status = self.status.proof_status(block_height)?;
        let proof_status_root =
            domain_hash("PROOF-STATUS-ROOT", &[HashPart::Json(&proof_status)], 32);
        let report = build_block_watchtower_audit_report(
            &block,
            &da_record,
            &certificate,
            &aggregate,
            &proof_status_root,
            watchtower_label,
            self.height(),
            self.timestamp_ms,
            shard_indices,
        )?;
        self.watchtower.record_audit(report.clone())?;
        self.status.watchtower = self.watchtower.clone();
        Ok(report)
    }

    pub fn submit_block_challenge(
        &mut self,
        block_height: u64,
        challenge_kind: &str,
        expected_root: &str,
        observed_root: &str,
        audit_id: Option<String>,
        reporter_label: &str,
    ) -> SequencerResult<BlockChallengeReport> {
        let block = self
            .status
            .blocks
            .get(block_height as usize)
            .ok_or_else(|| "unknown block height".to_string())?
            .clone();
        let report = build_block_challenge_report(
            &block,
            challenge_kind,
            expected_root,
            observed_root,
            audit_id,
            reporter_label,
            self.height(),
        )?;
        self.watchtower.record_challenge(report.clone())?;
        self.status.watchtower = self.watchtower.clone();
        Ok(report)
    }

    pub fn wallet_view(
        &self,
        owner_view_key: &str,
        watched_tx_hashes: &[String],
        watched_nullifiers: &[String],
    ) -> SequencerResult<WalletView> {
        let notes = self
            .admission_defi
            .notes
            .values()
            .cloned()
            .collect::<Vec<Note>>();
        let contract_receipts = self
            .contracts
            .contract_execution_receipts
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let wasm_receipts = self.runtime.receipts.values().cloned().collect::<Vec<_>>();
        let bridge_deposit_addresses = self
            .bridge
            .deposit_addresses
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let bridge_observations = self
            .bridge
            .observations
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let bridge_withdrawals = self
            .bridge
            .withdrawals
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let monero_withdrawal_observations = self
            .monero
            .withdrawal_observations
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let monero_anchor_observations = self
            .monero
            .anchor_observations
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let monero_reorg_evidence = self
            .monero
            .reorg_evidence
            .values()
            .cloned()
            .collect::<Vec<_>>();
        WalletSyncIndex::new().scan_with_monero_evidence(
            WalletScanRequest {
                owner_view_key: owner_view_key.to_string(),
                current_height: self.height(),
                watched_tx_hashes: watched_tx_hashes.to_vec(),
                watched_nullifiers: watched_nullifiers.to_vec(),
            },
            WalletScanSources {
                notes: &notes,
                mempool: Some(&self.mempool),
                contract_receipts: &contract_receipts,
                wasm_receipts: &wasm_receipts,
                bridge_deposit_addresses: &bridge_deposit_addresses,
                bridge_deposit_observations: &bridge_observations,
                bridge_mints: &[],
                bridge_withdrawals: &bridge_withdrawals,
                paymaster_sponsorships: &[],
            }
            .with_monero_evidence(WalletMoneroEvidenceSources {
                withdrawal_observations: &monero_withdrawal_observations,
                anchor_observations: &monero_anchor_observations,
                reorg_evidence: &monero_reorg_evidence,
            }),
        )
    }

    pub fn public_snapshot(&self) -> Value {
        let state_roots = self.state_roots();
        let admission_state_roots = self.admission_state_roots();
        json!({
            "kind": "local_sequencer_snapshot",
            "chain_id": CHAIN_ID,
            "height": self.height(),
            "pending_transaction_count": self.pending_transaction_count(),
            "pending_execution_profile": self.pending_execution_profile().public_record(),
            "next_block_packing": self.next_block_packing().public_record(),
            "next_state_safe_block_packing": self.next_state_safe_block_packing().public_record(),
            "proof_market": proof_market_snapshot(&self.prover),
            "watchtower": self.watchtower.public_record(),
            "network": self.network.public_record(),
            "monero_monitor": self.monero.public_record(),
            "consensus": self.consensus.public_record(),
            "fee_smoothing": self.fee_smoothing.public_record(),
            "state_root": state_roots.state_root(),
            "state_roots": {
                "note_root": state_roots.note_root,
                "nullifier_root": state_roots.nullifier_root,
                "contract_root": state_roots.contract_root,
                "wasm_runtime_root": state_roots.wasm_runtime_root,
                "account_root": state_roots.account_root,
                "asset_root": state_roots.asset_root,
                "sealed_swap_settlement_receipt_root": state_roots.sealed_swap_settlement_receipt_root,
                "bridge_root": state_roots.bridge_root,
                "fee_root": state_roots.fee_root,
                "crypto_policy_root": state_roots.crypto_policy_root,
            },
            "admission_state_root": admission_state_roots.state_root(),
            "admission_state_roots": {
                "note_root": admission_state_roots.note_root,
                "nullifier_root": admission_state_roots.nullifier_root,
                "contract_root": admission_state_roots.contract_root,
                "wasm_runtime_root": admission_state_roots.wasm_runtime_root,
                "account_root": admission_state_roots.account_root,
                "asset_root": admission_state_roots.asset_root,
                "sealed_swap_settlement_receipt_root": admission_state_roots.sealed_swap_settlement_receipt_root,
                "bridge_root": admission_state_roots.bridge_root,
                "fee_root": admission_state_roots.fee_root,
                "crypto_policy_root": admission_state_roots.crypto_policy_root,
            },
            "mempool_admission_root": self.mempool.admission_root(),
            "mempool_preconfirmation_root": self.mempool.preconfirmation_root(),
            "mempool_encrypted_batch_receipt_root": self.mempool.encrypted_batch_receipt_root(),
            "mempool_relay_fairness_ticket_root": self.mempool.relay_fairness_ticket_root(),
            "mempool_anti_censorship_lane_commitment_root": self.mempool.anti_censorship_lane_commitment_root(),
            "fee_smoothing_root": self.fee_smoothing.state_root(),
            "block_count": self.status.blocks.len(),
            "anchor_count": self.status.anchor_submissions.len(),
            "last_block_hash": self.last_block_hash,
            "last_state_root": self.last_state_root,
            "validator_count": self.validators.len(),
        })
    }

    fn commit_produced_block(
        &mut self,
        produced: ProducedBlock,
        packing: BlockPackingSelection,
        packing_policy_satisfied: bool,
        packing_local_state_count: u64,
        proposer_slot: ProposerSlot,
        fast_finality_certificate: FinalityCertificate,
    ) -> SequencerResult<SequencerBlockSummary> {
        let height = produced.block.header.height;
        let block_hash = produced.block.header.block_hash();
        let settlement_status = {
            self.status.blocks.push(produced.block.clone());
            self.status
                .da_records
                .insert(height, produced.da_record.clone());
            self.status
                .validity_certificates
                .insert(height, produced.certificate.clone());
            self.status
                .privacy_aggregates
                .insert(height, produced.privacy_aggregate.clone());
            self.status.current_height = height + 1;
            self.status.mempool = self.mempool.clone();
            self.status.prover = self.prover.clone();
            self.status.watchtower = self.watchtower.clone();
            self.status.network = self.network.clone();
            self.status.monero = self.monero.clone();
            self.status.consensus = self.consensus.clone();
            self.status.settlement_status(Some(height))?
        };
        let summary = SequencerBlockSummary {
            block_height: height,
            block_hash: block_hash.clone(),
            state_root: produced.block.header.state_root.clone(),
            tx_root: produced.block.header.tx_root.clone(),
            da_root: produced.block.header.da_root.clone(),
            mempool_admission_root: produced.block.header.mempool_admission_root.clone(),
            mempool_admission_count: produced.block.header.mempool_admission_count,
            transaction_count: produced.block.transactions.len() as u64,
            privacy_proof_aggregate_root: produced.privacy_aggregate.aggregate_root(),
            validity_certificate_root: produced.certificate.certificate_root(),
            packing,
            packing_policy_satisfied,
            packing_local_state_count,
            proposer_slot,
            fast_finality_certificate,
            consensus_state_root: self.consensus.state_root(),
            proof_job_root: self.prover.job_root(),
            prover_receipt_root: self.prover.receipt_root(),
            prover_state_root: self.prover.state_root(),
            soft_finality: produced.block.header.soft_finality,
            settlement_status,
        };
        self.last_block_hash = block_hash;
        self.last_state_root = produced.block.header.state_root;
        Ok(summary)
    }

    fn refresh_status_pending(&mut self) {
        self.network.set_height(self.height());
        self.monero.set_height(self.height());
        self.status.current_height = self.height();
        self.status.mempool = self.mempool.clone();
        self.status.prover = self.prover.clone();
        self.status.watchtower = self.watchtower.clone();
        self.status.network = self.network.clone();
        self.status.monero = self.monero.clone();
        self.status.consensus = self.consensus.clone();
        self.status.pending_transactions = self
            .pending
            .iter()
            .map(|pending| pending.public_record.clone())
            .collect();
    }

    fn pending_fee_resources(&self) -> Vec<FeeMarketResource> {
        self.pending
            .iter()
            .map(|pending| pending.fee_resource.clone())
            .collect()
    }

    fn ensure_local_network_advertisement(&mut self) -> SequencerResult<NodeAdvertisement> {
        if let Some(advertisement) = self
            .network
            .advertisements
            .values()
            .find(|advertisement| {
                advertisement.label == self.config.sequencer_label
                    && advertisement.is_live(self.height())
            })
            .cloned()
        {
            return Ok(advertisement);
        }
        let default_relay_path = self.config.default_relay_path.clone();
        let capacity_hint = self.config.block_packing_policy.max_tx_count;
        self.advertise_network_node(
            vec![
                NetworkRole::Sequencer,
                NetworkRole::Validator,
                NetworkRole::Prover,
                NetworkRole::Watchtower,
                NetworkRole::DataAvailability,
            ],
            &default_relay_path,
            "committed-relay-path",
            capacity_hint,
            0,
        )
    }

    fn latest_block_roots(&self) -> (String, String, String, String) {
        let block_hash = self.last_block_hash.clone();
        let latest_height = self.height().saturating_sub(1);
        let da_root = self
            .status
            .da_records
            .get(&latest_height)
            .map(|record| record.da_root())
            .unwrap_or_default();
        let validity_root = self
            .status
            .validity_certificates
            .get(&latest_height)
            .map(|certificate| certificate.certificate_root())
            .unwrap_or_default();
        let aggregate_root = self
            .status
            .privacy_aggregates
            .get(&latest_height)
            .map(|aggregate| aggregate.aggregate_root())
            .unwrap_or_default();
        (block_hash, da_root, validity_root, aggregate_root)
    }

    fn remove_selected_pending(&mut self, selected_indices: &[usize]) {
        let selected = selected_indices.iter().copied().collect::<BTreeSet<_>>();
        self.pending = self
            .pending
            .iter()
            .cloned()
            .enumerate()
            .filter_map(|(index, pending)| (!selected.contains(&index)).then_some(pending))
            .collect();
        self.mempool.pending_admissions = self
            .mempool
            .pending_admissions
            .iter()
            .cloned()
            .enumerate()
            .filter_map(|(index, admission)| (!selected.contains(&index)).then_some(admission))
            .collect();
    }

    fn executable_block_plan(
        &self,
        initial_packing: BlockPackingSelection,
        height: u64,
    ) -> SequencerResult<(BlockPackingSelection, Vec<usize>, DefiState, u64)> {
        let mut defi_after = self.defi.clone();
        defi_after.set_height(height);
        let mut selected_indices = Vec::new();
        let mut staged_defi_execution_count = 0_u64;
        for index in initial_packing
            .selected_indices
            .iter()
            .map(|index| *index as usize)
        {
            let pending = self
                .pending
                .get(index)
                .ok_or_else(|| "pending block packing index mismatch".to_string())?;
            match &pending.execution {
                PendingExecution::PublicOnly => selected_indices.push(index),
                PendingExecution::Defi(staged) => {
                    if defi_after.apply_staged_tx(staged).is_ok() {
                        selected_indices.push(index);
                        staged_defi_execution_count += 1;
                    }
                }
            }
        }
        if selected_indices.is_empty() {
            return Err("no selected pending transactions are executable".to_string());
        }
        defi_after.set_nonce_floor(self.admission_defi.nonce);
        let resources = self.pending_fee_resources();
        let packing = block_packing_selection_from_indices(
            &resources,
            &self.config.block_packing_policy,
            &selected_indices,
            initial_packing.fairness_pass_count,
            initial_packing.density_pass_count,
            initial_packing.rejected_low_density_count,
        );
        Ok((
            packing,
            selected_indices,
            defi_after,
            staged_defi_execution_count,
        ))
    }

    fn rebuild_admission_defi(&mut self) -> SequencerResult<()> {
        let mut mirror = self.defi.clone();
        mirror.set_height(self.height());
        for pending in &self.pending {
            if let PendingExecution::Defi(staged) = &pending.execution {
                mirror.apply_staged_tx(staged)?;
            }
        }
        mirror.set_nonce_floor(self.defi.nonce);
        self.admission_defi = mirror;
        Ok(())
    }

    fn projected_preconfirmation_target_height(
        &self,
        projected_resources: &[FeeMarketResource],
        candidate_index: usize,
        current_height: u64,
        expires_at_height: u64,
    ) -> u64 {
        if projected_resources.is_empty() {
            return current_height + 1;
        }
        let mut remaining = projected_resources
            .iter()
            .cloned()
            .enumerate()
            .collect::<Vec<_>>();
        for offset in 1..=self.config.admission_ttl_blocks {
            let resources = remaining
                .iter()
                .map(|(_, resource)| resource.clone())
                .collect::<Vec<_>>();
            let packing = pack_fee_resources(&resources, &self.config.block_packing_policy);
            if packing.selected_indices.is_empty() {
                return expires_at_height;
            }
            let selected = packing
                .selected_indices
                .iter()
                .map(|index| remaining[*index as usize].0)
                .collect::<BTreeSet<_>>();
            if selected.contains(&candidate_index) {
                return std::cmp::min(current_height + offset, expires_at_height);
            }
            remaining = remaining
                .into_iter()
                .filter(|(index, _)| !selected.contains(index))
                .collect();
            if remaining.is_empty() {
                return std::cmp::min(current_height + offset, expires_at_height);
            }
        }
        expires_at_height
    }

    fn set_component_heights(&mut self, height: u64) {
        self.defi.set_height(height);
        self.admission_defi.set_height(height);
        self.prover.set_height(height);
        self.network.set_height(height);
        self.monero.set_height(height);
        self.consensus.set_height(height);
        self.accounts.set_height(height);
    }

    fn node_network_root(&self) -> String {
        validator_node_network_root(&self.validators)
    }
}

pub fn sequencer_tx_hash(public_record: &Value) -> String {
    transaction_public_hash(public_record)
}

pub fn sequencer_epoch_root(summaries: &[SequencerBlockSummary]) -> String {
    merkle_root(
        "SEQUENCER-EPOCH-SUMMARY",
        &summaries
            .iter()
            .map(SequencerBlockSummary::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn sequencer_state_commitment(snapshot: &Value) -> String {
    domain_hash(
        "SEQUENCER-STATE-COMMITMENT",
        &[HashPart::Json(snapshot)],
        32,
    )
}
