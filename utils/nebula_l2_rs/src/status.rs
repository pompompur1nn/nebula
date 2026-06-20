use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    blocks::{
        BlockPrivacyProofAggregate, BlockValidityCertificate, DataAvailabilityRecord, L2Block,
    },
    consensus::ConsensusState,
    hash::{domain_hash, merkle_root, HashPart},
    mempool::{
        mempool_tx_public_hash, MempoolAdmission, MempoolForcedInclusion, MempoolPreconfirmation,
        MempoolPreconfirmationMissEvidence, MempoolState,
    },
    monero::MoneroMonitorState,
    network::NetworkState,
    prover::{proof_market_snapshot, ProverState},
    settlement::{AnchorSubmission, EpochCheckpoint},
    watchtower::WatchtowerState,
    CHAIN_ID,
};

pub type StatusResult<T> = Result<T, String>;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusIndex {
    pub epoch_size: u64,
    pub current_height: u64,
    pub blocks: Vec<L2Block>,
    pub da_records: BTreeMap<u64, DataAvailabilityRecord>,
    pub validity_certificates: BTreeMap<u64, BlockValidityCertificate>,
    pub privacy_aggregates: BTreeMap<u64, BlockPrivacyProofAggregate>,
    pub prover: ProverState,
    pub watchtower: WatchtowerState,
    pub network: NetworkState,
    pub monero: MoneroMonitorState,
    pub consensus: ConsensusState,
    pub mempool: MempoolState,
    pub pending_transactions: Vec<Value>,
    pub anchor_submissions: BTreeMap<String, AnchorSubmission>,
}

impl StatusIndex {
    pub fn new(epoch_size: u64) -> Self {
        Self {
            epoch_size,
            ..Self::default()
        }
    }

    pub fn from_blocks(epoch_size: u64, blocks: Vec<L2Block>) -> Self {
        let current_height = blocks.len() as u64;
        Self {
            epoch_size,
            current_height,
            blocks,
            ..Self::default()
        }
    }

    pub fn current_height(&self) -> u64 {
        self.current_height
    }

    pub fn settlement_status(&self, block_height: Option<u64>) -> StatusResult<Value> {
        if self.blocks.is_empty() {
            return Err("cannot compute settlement status before the first L2 block".to_string());
        }
        if self.epoch_size == 0 {
            return Err("epoch_size must be positive".to_string());
        }
        let block_height = block_height.unwrap_or(self.blocks.len() as u64 - 1);
        let block = self
            .blocks
            .get(block_height as usize)
            .ok_or_else(|| "unknown block height".to_string())?;
        let header = &block.header;
        let local_checkpoint = self.epoch_checkpoint_for_block(block_height)?;
        let reorged_anchor_ids = self
            .monero
            .reorg_evidence
            .values()
            .filter(|evidence| evidence.status != "dismissed")
            .filter_map(|evidence| evidence.affected_anchor_id.clone())
            .collect::<BTreeSet<_>>();
        let mut covering_submissions = self
            .anchor_submissions
            .values()
            .filter(|submission| {
                if reorged_anchor_ids.contains(&submission.anchor_id) {
                    return false;
                }
                if submission.epoch != header.epoch {
                    return false;
                }
                let start_height = submission.epoch_start_height;
                let end_height = submission.epoch_end_height;
                start_height <= block_height && block_height <= end_height
            })
            .cloned()
            .collect::<Vec<_>>();
        covering_submissions.sort_by(compare_anchor_submissions);

        let best_anchor = covering_submissions.first().cloned();
        let anchored = best_anchor.is_some();
        let monero_final = covering_submissions
            .iter()
            .any(|submission| submission.status == "final");
        let status = if monero_final {
            "monero_final"
        } else if anchored {
            "anchored"
        } else if header.soft_finality {
            "soft_final"
        } else {
            "produced"
        };

        Ok(json!({
            "status": status,
            "block_height": block_height,
            "epoch": header.epoch,
            "block_hash": header.block_hash(),
            "soft_finality": header.soft_finality,
            "validator_vote_count": header.validator_vote_count,
            "validator_stake_weight": header.validator_stake_weight,
            "checkpointed": true,
            "local_checkpoint_root": local_checkpoint.checkpoint_root(),
            "local_checkpoint": local_checkpoint.anchor_record(),
            "anchored": anchored,
            "monero_final": monero_final,
            "best_anchor": best_anchor.map(|submission| submission.public_record()),
            "covering_anchor_count": covering_submissions.len(),
            "covering_anchors": covering_submissions.iter().map(AnchorSubmission::public_record).collect::<Vec<_>>(),
            "anchor_submission_root": self.anchor_submission_root(),
            "monero_monitor_root": self.monero.state_root(),
            "monero_anchor_observation_root": self.monero.anchor_observation_root(),
            "monero_withdrawal_observation_root": self.monero.withdrawal_observation_root(),
            "monero_reserve_report_root": self.monero.reserve_report_root(),
            "monero_reorg_evidence_root": self.monero.reorg_evidence_root(),
            "consensus_state_root": self.consensus.state_root(),
            "fast_finality_certificate_root": self.consensus.finality_certificate_root(),
            "reorged_anchor_count": reorged_anchor_ids.len() as u64,
            "reorged_anchor_ids": reorged_anchor_ids.iter().cloned().collect::<Vec<_>>(),
        }))
    }

    pub fn proof_status(&self, block_height: u64) -> StatusResult<Value> {
        let block = self
            .blocks
            .get(block_height as usize)
            .ok_or_else(|| "unknown block height".to_string())?;
        let certificate = self.validity_certificates.get(&block_height);
        let aggregate = self.privacy_aggregates.get(&block_height);
        let receipts = self
            .prover
            .receipts
            .values()
            .filter(|receipt| receipt.block_height == block_height)
            .cloned()
            .collect::<Vec<_>>();
        let jobs = self
            .prover
            .jobs
            .values()
            .filter(|job| job.block_height == block_height)
            .cloned()
            .collect::<Vec<_>>();
        let missing_artifacts = [
            ("validity_certificate", certificate.is_none()),
            ("privacy_proof_aggregate", aggregate.is_none()),
            ("prover_receipt", receipts.is_empty()),
        ]
        .into_iter()
        .filter_map(|(name, missing)| missing.then_some(Value::String(name.to_string())))
        .collect::<Vec<_>>();
        let invalid_receipts = receipts
            .iter()
            .filter(|receipt| !receipt.verify_authorization())
            .map(|receipt| Value::String(receipt.receipt_id.clone()))
            .collect::<Vec<_>>();
        let status = if !invalid_receipts.is_empty() {
            "invalid"
        } else if !missing_artifacts.is_empty() {
            "missing_artifacts"
        } else {
            "proved"
        };
        Ok(json!({
            "kind": "proof_status",
            "chain_id": CHAIN_ID,
            "status": status,
            "block_height": block_height,
            "block_hash": block.header.block_hash(),
            "da_root": block.header.da_root,
            "validity_certificate_root": certificate.map(BlockValidityCertificate::certificate_root).unwrap_or_default(),
            "privacy_proof_aggregate_root": aggregate.map(BlockPrivacyProofAggregate::aggregate_root).unwrap_or_default(),
            "proof_job_root": merkle_root("PROOF-STATUS-JOB", &jobs.iter().map(|job| job.public_record()).collect::<Vec<_>>()),
            "prover_receipt_root": merkle_root("PROOF-STATUS-RECEIPT", &receipts.iter().map(|receipt| receipt.public_record()).collect::<Vec<_>>()),
            "prover_state_root": self.prover.state_root(),
            "watchtower_audit_root": self.watchtower.audit_root(),
            "watchtower_challenge_root": self.watchtower.challenge_root(),
            "network_state_root": self.network.state_root(),
            "consensus_state_root": self.consensus.state_root(),
            "fast_finality_certificate_root": self.consensus.finality_certificate_root(),
            "proof_market": proof_market_snapshot(&self.prover),
            "missing_artifacts": missing_artifacts,
            "invalid_receipts": invalid_receipts,
        }))
    }

    pub fn consensus_status(&self) -> Value {
        json!({
            "kind": "consensus_status",
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "consensus": self.consensus.public_record(),
            "snapshot": self.consensus.validator_set_snapshot(self.current_height).public_record(),
            "consensus_state_root": self.consensus.state_root(),
            "validator_root": self.consensus.validator_root(),
            "proposer_slot_root": self.consensus.proposer_slot_root(),
            "vote_root": self.consensus.vote_root(),
            "finality_certificate_root": self.consensus.finality_certificate_root(),
            "equivocation_root": self.consensus.equivocation_root(),
            "downtime_root": self.consensus.downtime_root(),
            "latest_finality_certificates": self.consensus.finality_certificates.values().map(|certificate| certificate.public_record()).collect::<Vec<_>>(),
            "equivocation_evidence": self.consensus.equivocation_evidence.values().map(|evidence| evidence.public_record()).collect::<Vec<_>>(),
            "downtime_evidence": self.consensus.downtime_evidence.values().map(|evidence| evidence.public_record()).collect::<Vec<_>>(),
        })
    }

    pub fn network_status(&self) -> Value {
        json!({
            "kind": "network_status",
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "network": self.network.public_record(),
            "advertisement_root": self.network.advertisement_root(),
            "root_inventory_root": self.network.root_inventory_root(),
            "admission_inventory_root": self.network.admission_inventory_root(),
            "gossip_envelope_root": self.network.gossip_envelope_root(),
            "root_conflict_root": self.network.root_conflict_root(),
            "peer_score_root": self.network.peer_score_root(),
            "live_peer_count": self.network.advertisements.values().filter(|ad| ad.is_live(self.current_height)).count() as u64,
            "root_conflicts": self.network.root_conflicts.values().map(|evidence| evidence.public_record()).collect::<Vec<_>>(),
            "peer_scores": self.network.peer_scores.values().map(|score| score.public_record()).collect::<Vec<_>>(),
        })
    }

    pub fn monero_status(&self) -> Value {
        json!({
            "kind": "monero_status",
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "monitor": self.monero.public_record(),
            "monero_monitor_root": self.monero.state_root(),
            "endpoint_root": self.monero.endpoint_root(),
            "rpc_observation_root": self.monero.rpc_observation_root(),
            "zmq_observation_root": self.monero.zmq_observation_root(),
            "block_observation_root": self.monero.block_observation_root(),
            "tx_observation_root": self.monero.tx_observation_root(),
            "anchor_observation_root": self.monero.anchor_observation_root(),
            "withdrawal_observation_root": self.monero.withdrawal_observation_root(),
            "reserve_report_root": self.monero.reserve_report_root(),
            "reorg_evidence_root": self.monero.reorg_evidence_root(),
            "rpc_observations": self.monero.rpc_observations.values().map(|observation| observation.public_record()).collect::<Vec<_>>(),
            "zmq_observations": self.monero.zmq_observations.values().map(|observation| observation.public_record()).collect::<Vec<_>>(),
            "block_observations": self.monero.block_observations.values().map(|observation| observation.public_record()).collect::<Vec<_>>(),
            "anchor_observations": self.monero.anchor_observations.values().map(|observation| observation.public_record()).collect::<Vec<_>>(),
            "withdrawal_observations": self.monero.withdrawal_observations.values().map(|observation| observation.public_record()).collect::<Vec<_>>(),
            "reserve_reports": self.monero.reserve_reports.values().map(|report| report.public_record()).collect::<Vec<_>>(),
            "reorg_evidence": self.monero.reorg_evidence.values().map(|evidence| evidence.public_record()).collect::<Vec<_>>(),
        })
    }

    pub fn mempool_admission_status(&self, admission_id: &str) -> StatusResult<Value> {
        if admission_id.is_empty() {
            return Err("admission_id is required".to_string());
        }
        let current_height = self.current_height();
        let inclusion_height = self.admission_inclusion_height(admission_id)?;

        if let Some(admission) = self
            .mempool
            .pending_admissions
            .iter()
            .find(|admission| admission.admission_id == admission_id)
        {
            let preconfirmations = self
                .preconfirmations_for_admission(admission_id)
                .iter()
                .map(|preconfirmation| {
                    self.preconfirmation_status_record(preconfirmation, inclusion_height)
                })
                .collect::<Vec<_>>();
            return Ok(json!({
                "status": "pending",
                "admission_id": admission_id,
                "current_height": current_height,
                "admitted_at_height": admission.admitted_at_height,
                "expires_at_height": admission.expires_at_height,
                "blocks_until_expiry": inclusive_blocks_until(admission.expires_at_height, current_height),
                "admission": admission.public_record(),
                "preconfirmations": preconfirmations,
                "mempool_preconfirmation_root": self.mempool.preconfirmation_root(),
                "mempool_preconfirmation_miss_root": self.mempool.preconfirmation_miss_root(),
                "mempool_admission_root": self.mempool.admission_root(),
                "mempool_omission_evidence_root": self.mempool.omission_evidence_root(),
                "mempool_forced_inclusion_root": self.mempool.forced_inclusion_root(),
                "mempool_encrypted_batch_receipt_root": self.mempool.encrypted_batch_receipt_root(),
                "mempool_relay_fairness_ticket_root": self.mempool.relay_fairness_ticket_root(),
                "mempool_anti_censorship_lane_commitment_root": self.mempool.anti_censorship_lane_commitment_root(),
            }));
        }

        if let Some(evidence) = self
            .mempool
            .omission_evidence
            .values()
            .find(|evidence| evidence.admission_id == admission_id)
        {
            let preconfirmations = self
                .preconfirmations_for_admission(admission_id)
                .iter()
                .map(|preconfirmation| {
                    self.preconfirmation_status_record(preconfirmation, inclusion_height)
                })
                .collect::<Vec<_>>();
            let forced_inclusions = self
                .forced_inclusions_for_admission(admission_id)
                .iter()
                .map(MempoolForcedInclusion::public_record)
                .collect::<Vec<_>>();
            let preconfirmation_misses = self
                .preconfirmation_misses_for_admission(admission_id)
                .iter()
                .map(MempoolPreconfirmationMissEvidence::public_record)
                .collect::<Vec<_>>();
            return Ok(json!({
                "status": "omitted",
                "admission_id": admission_id,
                "current_height": current_height,
                "evidence_status": evidence.status,
                "evidence": evidence.public_record(),
                "forced_inclusion_count": forced_inclusions.len(),
                "forced_inclusions": forced_inclusions,
                "preconfirmations": preconfirmations,
                "preconfirmation_miss_evidence": preconfirmation_misses,
                "mempool_preconfirmation_root": self.mempool.preconfirmation_root(),
                "mempool_preconfirmation_miss_root": self.mempool.preconfirmation_miss_root(),
                "mempool_omission_evidence_root": self.mempool.omission_evidence_root(),
                "mempool_forced_inclusion_root": self.mempool.forced_inclusion_root(),
            }));
        }

        for record in self.da_records.values() {
            let payload = decode_data_availability_payload(record)?;
            let admissions = payload
                .get("mempool_admissions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if let Some(admission) = admissions.iter().find(|admission| {
                admission
                    .get("admission_id")
                    .and_then(Value::as_str)
                    .is_some_and(|candidate| candidate == admission_id)
            }) {
                let preconfirmations = self
                    .preconfirmations_for_admission(admission_id)
                    .iter()
                    .map(|preconfirmation| {
                        self.preconfirmation_status_record(
                            preconfirmation,
                            Some(record.block_height),
                        )
                    })
                    .collect::<Vec<_>>();
                let preconfirmation_misses = self
                    .preconfirmation_misses_for_admission(admission_id)
                    .iter()
                    .map(MempoolPreconfirmationMissEvidence::public_record)
                    .collect::<Vec<_>>();
                let block_hash = self
                    .blocks
                    .get(record.block_height as usize)
                    .map(|block| block.header.block_hash())
                    .unwrap_or_default();
                return Ok(json!({
                    "status": "included",
                    "admission_id": admission_id,
                    "current_height": current_height,
                    "block_height": record.block_height,
                    "block_hash": block_hash,
                    "tx_root": record.tx_root,
                    "da_root": record.da_root(),
                    "payload_hash": record.payload_hash,
                    "mempool_admission_root": payload["mempool_admission_root"],
                    "mempool_admission_count": payload["mempool_admission_count"],
                    "admission": admission,
                    "preconfirmations": preconfirmations,
                    "preconfirmation_miss_evidence": preconfirmation_misses,
                    "mempool_preconfirmation_root": self.mempool.preconfirmation_root(),
                    "mempool_preconfirmation_miss_root": self.mempool.preconfirmation_miss_root(),
                    "mempool_forced_inclusion_root": self.mempool.forced_inclusion_root(),
                    "settlement": self.settlement_status(Some(record.block_height))?,
                }));
            }
        }

        Err("unknown mempool admission".to_string())
    }

    pub fn transaction_status(&self, tx_hash: &str) -> StatusResult<Value> {
        if tx_hash.is_empty() {
            return Err("tx_hash is required".to_string());
        }
        let current_height = self.current_height();

        for (pending_index, transaction) in self.pending_transactions.iter().enumerate() {
            let tx_public_hash = transaction_public_hash(transaction);
            let mempool_hash = mempool_tx_public_hash(transaction);
            if tx_hash != tx_public_hash && tx_hash != mempool_hash {
                continue;
            }
            let admission = self
                .mempool
                .pending_admissions
                .get(pending_index)
                .filter(|admission| admission.tx_public_hash == mempool_hash);
            let preconfirmations = admission
                .map(|admission| {
                    self.preconfirmations_for_admission(&admission.admission_id)
                        .iter()
                        .map(|preconfirmation| {
                            self.preconfirmation_status_record(preconfirmation, None)
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            return Ok(json!({
                "status": "pending",
                "inclusion_status": "pending",
                "current_height": current_height,
                "pending_index": pending_index,
                "tx_public_hash": tx_public_hash,
                "mempool_tx_public_hash": mempool_hash,
                "tx_kind": transaction.get("kind").and_then(Value::as_str).unwrap_or_default(),
                "transaction": transaction,
                "mempool_admission": admission.map(MempoolAdmission::public_record),
                "preconfirmations": preconfirmations,
                "mempool_admission_root": self.mempool.admission_root(),
                "mempool_preconfirmation_root": self.mempool.preconfirmation_root(),
                "settlement": Value::Null,
            }));
        }

        for block in &self.blocks {
            for (tx_index, transaction) in block.transactions.iter().enumerate() {
                let tx_public_hash = transaction_public_hash(transaction);
                let mempool_hash = mempool_tx_public_hash(transaction);
                if tx_hash != tx_public_hash && tx_hash != mempool_hash {
                    continue;
                }
                let height = block.header.height;
                let settlement = self.settlement_status(Some(height))?;
                let certificate = self.validity_certificates.get(&height);
                let aggregate = self.privacy_aggregates.get(&height);
                let proof_item = aggregate.and_then(|aggregate| {
                    aggregate.proof_items.iter().find(|item| {
                        item.get("tx_index")
                            .and_then(Value::as_u64)
                            .is_some_and(|candidate| candidate == tx_index as u64)
                    })
                });
                return Ok(json!({
                    "status": settlement["status"],
                    "inclusion_status": "included",
                    "current_height": current_height,
                    "block_height": height,
                    "tx_index": tx_index,
                    "tx_public_hash": tx_public_hash,
                    "mempool_tx_public_hash": mempool_hash,
                    "tx_kind": transaction.get("kind").and_then(Value::as_str).unwrap_or_default(),
                    "transaction": transaction,
                    "block_hash": block.header.block_hash(),
                    "tx_root": block.header.tx_root,
                    "state_root": block.header.state_root,
                    "sealed_swap_settlement_receipt_root": block.header.sealed_swap_settlement_receipt_root,
                    "da_root": block.header.da_root,
                    "validity_certificate_root": certificate.map(BlockValidityCertificate::certificate_root).unwrap_or_default(),
                    "privacy_proof_aggregate_root": aggregate.map(BlockPrivacyProofAggregate::aggregate_root).unwrap_or_default(),
                    "proof_status": self.proof_status(height)?,
                    "privacy_proof_item": proof_item.cloned(),
                    "settlement": settlement,
                }));
            }
        }

        Err("unknown transaction".to_string())
    }

    pub fn epoch_checkpoint_for_block(&self, block_height: u64) -> StatusResult<EpochCheckpoint> {
        let header = self
            .blocks
            .get(block_height as usize)
            .ok_or_else(|| "unknown block height".to_string())?
            .header
            .clone();
        let start_height = header.epoch * self.epoch_size;
        let headers = self
            .blocks
            .iter()
            .map(|block| block.header.clone())
            .filter(|candidate| {
                candidate.epoch == header.epoch
                    && candidate.height >= start_height
                    && candidate.height <= block_height
            })
            .collect::<Vec<_>>();
        let validity_roots = headers
            .iter()
            .filter_map(|header| {
                self.validity_certificates
                    .get(&header.height)
                    .map(BlockValidityCertificate::certificate_root)
            })
            .collect::<Vec<_>>();
        let aggregate_roots = headers
            .iter()
            .filter_map(|header| {
                self.privacy_aggregates
                    .get(&header.height)
                    .map(BlockPrivacyProofAggregate::aggregate_root)
            })
            .collect::<Vec<_>>();
        EpochCheckpoint::from_headers(&headers, self.epoch_size, &validity_roots, &aggregate_roots)
    }

    fn anchor_submission_root(&self) -> String {
        merkle_root(
            "ANCHOR-SUBMISSION",
            &self
                .anchor_submissions
                .values()
                .map(AnchorSubmission::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn admission_inclusion_height(&self, admission_id: &str) -> StatusResult<Option<u64>> {
        for record in self.da_records.values() {
            let payload = decode_data_availability_payload(record)?;
            let admissions = payload
                .get("mempool_admissions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if admissions.iter().any(|admission| {
                admission
                    .get("admission_id")
                    .and_then(Value::as_str)
                    .is_some_and(|candidate| candidate == admission_id)
            }) {
                return Ok(Some(record.block_height));
            }
        }
        Ok(None)
    }

    fn preconfirmations_for_admission(&self, admission_id: &str) -> Vec<MempoolPreconfirmation> {
        self.mempool
            .preconfirmations
            .values()
            .filter(|preconfirmation| preconfirmation.admission_id == admission_id)
            .cloned()
            .collect()
    }

    fn preconfirmation_misses_for_admission(
        &self,
        admission_id: &str,
    ) -> Vec<MempoolPreconfirmationMissEvidence> {
        self.mempool
            .preconfirmation_misses
            .values()
            .filter(|evidence| evidence.admission_id == admission_id)
            .cloned()
            .collect()
    }

    fn forced_inclusions_for_admission(&self, admission_id: &str) -> Vec<MempoolForcedInclusion> {
        self.mempool
            .forced_inclusions
            .values()
            .filter(|forced| forced.admission_id == admission_id)
            .cloned()
            .collect()
    }

    fn preconfirmation_status_record(
        &self,
        preconfirmation: &MempoolPreconfirmation,
        inclusion_height: Option<u64>,
    ) -> Value {
        let current_height = self.current_height();
        let misses = self
            .mempool
            .preconfirmation_misses
            .values()
            .filter(|evidence| evidence.preconfirmation_id == preconfirmation.preconfirmation_id)
            .map(MempoolPreconfirmationMissEvidence::public_record)
            .collect::<Vec<_>>();
        let status = if let Some(inclusion_height) = inclusion_height {
            if inclusion_height <= preconfirmation.target_height {
                "fulfilled"
            } else {
                "missed_included_late"
            }
        } else if !misses.is_empty() {
            "miss_reported"
        } else if current_height > preconfirmation.target_height {
            "target_missed"
        } else {
            "preconfirmed"
        };
        json!({
            "status": status,
            "current_height": current_height,
            "inclusion_height": inclusion_height,
            "blocks_until_target": inclusive_blocks_until(preconfirmation.target_height, current_height),
            "preconfirmation": preconfirmation.public_record(),
            "miss_evidence": misses,
        })
    }
}

pub fn transaction_public_hash(transaction: &Value) -> String {
    domain_hash("TX-PUBLIC", &[HashPart::Json(transaction)], 32)
}

pub fn decode_data_availability_payload(record: &DataAvailabilityRecord) -> StatusResult<Value> {
    let mut shards = record.shards.clone();
    shards.sort_by_key(|shard| shard.shard_index);
    let payload = shards
        .iter()
        .filter(|shard| shard.shard_kind == "data")
        .map(|shard| shard.data.as_str())
        .collect::<String>();
    let payload_hash = domain_hash("DA-PAYLOAD", &[HashPart::Str(&payload)], 32);
    if payload_hash != record.payload_hash {
        return Err("DA payload hash mismatch".to_string());
    }
    serde_json::from_str(&payload).map_err(|error| format!("invalid DA payload JSON: {error}"))
}

fn compare_anchor_submissions(left: &AnchorSubmission, right: &AnchorSubmission) -> Ordering {
    (
        left.status != "final",
        std::cmp::Reverse(left.confirmations),
        std::cmp::Reverse(left.epoch_end_height),
        left.anchor_id.as_str(),
    )
        .cmp(&(
            right.status != "final",
            std::cmp::Reverse(right.confirmations),
            std::cmp::Reverse(right.epoch_end_height),
            right.anchor_id.as_str(),
        ))
}

fn inclusive_blocks_until(target_height: u64, current_height: u64) -> u64 {
    target_height
        .saturating_sub(current_height)
        .saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blocks::{build_l2_block, BlockBuildInput, BlockStateRoots, Validator},
        fees::{BlockExecutionProfile, FeeMarketResource},
        mempool::{
            mempool_admission_root, mempool_committee_key_id, MempoolAdmissionRequest,
            MempoolOmissionEvidence,
        },
        settlement::AnchorSubmission,
    };

    fn validator() -> Validator {
        Validator::new("devnet-proposer", 1_000).unwrap()
    }

    fn tx_public_record() -> Value {
        json!({"kind": "noop", "nonce": 1})
    }

    fn tx_state_record() -> Value {
        json!({"kind": "noop", "nonce": 1, "private_witness_hash": "hidden"})
    }

    fn admission() -> MempoolAdmission {
        MempoolAdmission::build(MempoolAdmissionRequest {
            tx_public_record: tx_public_record(),
            tx_state_record: tx_state_record(),
            mempool_sequence: 0,
            relay_path: "dandelion-stem-fluff".to_string(),
            admitted_at_height: 0,
            expires_at_height: 10,
            sequencer_label: "devnet-proposer".to_string(),
            committee_key_id: mempool_committee_key_id(&[validator()]),
        })
    }

    fn preconfirmation(admission: &MempoolAdmission) -> MempoolPreconfirmation {
        MempoolPreconfirmation::build(
            admission,
            0,
            &mempool_admission_root(std::slice::from_ref(admission)),
            1,
            &BlockExecutionProfile::empty().local_fee_market_root,
        )
        .unwrap()
    }

    fn produced_block_with_admission(
        admission: &MempoolAdmission,
        height: u64,
    ) -> crate::blocks::ProducedBlock {
        build_l2_block(BlockBuildInput {
            height,
            epoch: height / 10,
            timestamp_ms: 1_700_000_000_000 + height,
            prev_block_hash: if height == 0 {
                "GENESIS".to_string()
            } else {
                "previous".to_string()
            },
            previous_state_root: if height == 0 {
                "GENESIS".to_string()
            } else {
                "previous-state".to_string()
            },
            transactions: vec![tx_public_record()],
            mempool_admissions: vec![admission.public_record()],
            state_roots: BlockStateRoots::empty(),
            fee_resources: vec![FeeMarketResource::operation("noop", 1, "")],
            validators: vec![validator()],
            proposer_label: "devnet-proposer".to_string(),
        })
        .unwrap()
    }

    #[test]
    fn pending_status_reports_preconfirmation_without_raw_relay_path() {
        let admission = admission();
        let preconfirmation = preconfirmation(&admission);
        let mut mempool = MempoolState {
            pending_admissions: vec![admission.clone()],
            ..MempoolState::default()
        };
        mempool.preconfirmations.insert(
            preconfirmation.preconfirmation_id.clone(),
            preconfirmation.clone(),
        );
        let status = StatusIndex {
            epoch_size: 10,
            current_height: 0,
            mempool,
            pending_transactions: vec![tx_public_record()],
            ..StatusIndex::default()
        }
        .mempool_admission_status(&admission.admission_id)
        .unwrap();

        assert_eq!(status["status"], "pending");
        assert_eq!(status["blocks_until_expiry"], 11);
        assert_eq!(status["preconfirmations"][0]["status"], "preconfirmed");
        assert_eq!(
            status["mempool_admission_root"],
            "5ad4edf7354db4f6b4754be0a4f9ef44b35cb81e78cc984e6d45b179bdefba3b"
        );
        assert!(!status.to_string().contains("dandelion-stem-fluff"));

        let tx_status = StatusIndex {
            epoch_size: 10,
            current_height: 0,
            mempool: MempoolState {
                pending_admissions: vec![admission.clone()],
                preconfirmations: [(preconfirmation.preconfirmation_id.clone(), preconfirmation)]
                    .into_iter()
                    .collect(),
                ..MempoolState::default()
            },
            pending_transactions: vec![tx_public_record()],
            ..StatusIndex::default()
        }
        .transaction_status(&mempool_tx_public_hash(&tx_public_record()))
        .unwrap();
        assert_eq!(tx_status["status"], "pending");
        assert_eq!(tx_status["inclusion_status"], "pending");
        assert_eq!(
            tx_status["mempool_admission"]["admission_id"],
            admission.admission_id
        );
    }

    #[test]
    fn omitted_status_reports_evidence_forced_inclusion_and_miss() {
        let admission = admission();
        let preconfirmation = preconfirmation(&admission);
        let sequencer = validator();
        let omission = MempoolOmissionEvidence::report(
            &admission,
            11,
            "watchtower",
            &sequencer.validator_id,
            1,
            999,
        )
        .unwrap();
        let forced_admission = MempoolAdmission::build(MempoolAdmissionRequest {
            tx_public_record: tx_public_record(),
            tx_state_record: tx_state_record(),
            mempool_sequence: 0,
            relay_path: "forced-inclusion".to_string(),
            admitted_at_height: 11,
            expires_at_height: 21,
            sequencer_label: "devnet-proposer".to_string(),
            committee_key_id: admission.committee_key_id.clone(),
        });
        let forced =
            MempoolForcedInclusion::build(&omission, &forced_admission, 11, "devnet-proposer")
                .unwrap();
        let miss = MempoolPreconfirmationMissEvidence::report(
            &preconfirmation,
            2,
            "watchtower",
            &sequencer.validator_id,
            2,
            998,
        )
        .unwrap();

        let status = StatusIndex {
            epoch_size: 10,
            current_height: 12,
            mempool: MempoolState {
                preconfirmations: [(preconfirmation.preconfirmation_id.clone(), preconfirmation)]
                    .into_iter()
                    .collect(),
                preconfirmation_misses: [(miss.evidence_id.clone(), miss.clone())]
                    .into_iter()
                    .collect(),
                omission_evidence: [(omission.evidence_id.clone(), omission.clone())]
                    .into_iter()
                    .collect(),
                forced_inclusions: [(forced.forced_inclusion_id.clone(), forced.clone())]
                    .into_iter()
                    .collect(),
                ..MempoolState::default()
            },
            ..StatusIndex::default()
        }
        .mempool_admission_status(&admission.admission_id)
        .unwrap();

        assert_eq!(status["status"], "omitted");
        assert_eq!(status["evidence_status"], "slashed");
        assert_eq!(status["forced_inclusion_count"], 1);
        assert_eq!(status["preconfirmations"][0]["status"], "miss_reported");
        assert_eq!(
            status["mempool_omission_evidence_root"],
            "829380ddba7ef6fa67cbaab22d0c3547684b085906b870c22ea094ef16f6595d"
        );
        assert_eq!(
            status["mempool_forced_inclusion_root"],
            "d6c569ae47ef980c9a15e86019c0a73b3264ca9724879805ab748aa004a714f8"
        );
    }

    #[test]
    fn included_transaction_status_reports_monero_final_settlement() {
        let admission = admission();
        let preconfirmation = preconfirmation(&admission);
        let produced = produced_block_with_admission(&admission, 0);
        let headers = vec![produced.block.header.clone()];
        let checkpoint = EpochCheckpoint::from_headers(
            &headers,
            10,
            &[produced.certificate.certificate_root()],
            &[produced.privacy_aggregate.aggregate_root()],
        )
        .unwrap();
        let anchor = AnchorSubmission::submit(
            &produced.block.header,
            &checkpoint,
            "GENESIS",
            "anchor-submitter",
            "xmr-anchor-txid",
            1_700_000_000_500,
        )
        .confirm(10, 10, 1_700_000_001_000);

        let index = StatusIndex {
            epoch_size: 10,
            current_height: 1,
            blocks: vec![produced.block.clone()],
            da_records: [(0, produced.da_record.clone())].into_iter().collect(),
            validity_certificates: [(0, produced.certificate.clone())].into_iter().collect(),
            privacy_aggregates: [(0, produced.privacy_aggregate.clone())]
                .into_iter()
                .collect(),
            mempool: MempoolState {
                preconfirmations: [(preconfirmation.preconfirmation_id.clone(), preconfirmation)]
                    .into_iter()
                    .collect(),
                ..MempoolState::default()
            },
            anchor_submissions: [(anchor.anchor_id.clone(), anchor)].into_iter().collect(),
            ..StatusIndex::default()
        };

        let admission_status = index
            .mempool_admission_status(&admission.admission_id)
            .unwrap();
        assert_eq!(admission_status["status"], "included");
        assert_eq!(admission_status["settlement"]["status"], "monero_final");
        assert!(!admission_status
            .to_string()
            .contains("dandelion-stem-fluff"));

        let tx_status = index
            .transaction_status(&transaction_public_hash(&tx_public_record()))
            .unwrap();
        assert_eq!(tx_status["status"], "monero_final");
        assert_eq!(tx_status["inclusion_status"], "included");
        assert_eq!(tx_status["block_height"], 0);
        assert_eq!(
            tx_status["validity_certificate_root"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            tx_status["privacy_proof_aggregate_root"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
    }
}
